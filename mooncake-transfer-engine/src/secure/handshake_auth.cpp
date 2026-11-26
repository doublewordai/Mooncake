#include "handshake_auth.h"

#include <glog/logging.h>
#include <json/json.h>

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "control_auth.h"

namespace mooncake {
namespace secure {
namespace {

namespace ca = control_auth;

const HandshakeFramingHook kFraming{&WriteAuthenticatedHandshake,
                                    &ReadAuthenticatedHandshake};

// ------------------------------------------------- secure push endpoints --

constexpr char kP2dMember[] = "mc_secure_p2d";

struct Endpoint {
    std::string host;
    int port = 0;
};

std::mutex g_p2d_mu;
std::map<std::string, Endpoint> g_p2d_local;  // advertised by this process
std::map<std::string, Endpoint> g_p2d_peers;  // learned from peers

bool ParseJson(const std::string &str, Json::Value *root) {
    Json::CharReaderBuilder b;
    std::unique_ptr<Json::CharReader> r(b.newCharReader());
    std::string errs;
    return r->parse(str.data(), str.data() + str.size(), root, &errs) &&
           root->isObject();
}

// The Metadata body with this process's endpoint for the descriptor's name
// added, or the body unchanged.
std::string AddP2dEndpoint(const std::string &str) {
    {
        std::lock_guard<std::mutex> lock(g_p2d_mu);
        if (g_p2d_local.empty()) return str;
    }
    Json::Value root;
    if (!ParseJson(str, &root) || !root.isMember("name") ||
        !root["name"].isString())
        return str;
    Endpoint ep;
    {
        std::lock_guard<std::mutex> lock(g_p2d_mu);
        auto it = g_p2d_local.find(root["name"].asString());
        if (it == g_p2d_local.end()) return str;
        ep = it->second;
    }
    Json::Value v(Json::objectValue);
    v["host"] = ep.host;
    v["port"] = ep.port;
    root[kP2dMember] = v;
    return Json::FastWriter{}.write(root);
}

// Records the endpoint an authenticated Metadata body carries, if any.
void RecordP2dEndpoint(const std::string &str) {
    if (str.find(kP2dMember) == std::string::npos) return;
    Json::Value root;
    if (!ParseJson(str, &root) || !root.isMember("name") ||
        !root["name"].isString() || !root.isMember(kP2dMember))
        return;
    const Json::Value &v = root[kP2dMember];
    if (!v.isObject() || !v.isMember("host") || !v["host"].isString() ||
        !v.isMember("port") || !v["port"].isInt())
        return;
    const int port = v["port"].asInt();
    const std::string host = v["host"].asString();
    if (port <= 0 || port > 65535 || host.empty() || host.size() > 255)
        return;
    std::lock_guard<std::mutex> lock(g_p2d_mu);
    g_p2d_peers[root["name"].asString()] = {host, port};
}

}  // namespace

void AdvertiseP2dEndpoint(const std::string &segment, const std::string &host,
                          int port) {
    std::lock_guard<std::mutex> lock(g_p2d_mu);
    g_p2d_local[segment] = {host, port};
}

void WithdrawP2dEndpoint(const std::string &segment) {
    std::lock_guard<std::mutex> lock(g_p2d_mu);
    g_p2d_local.erase(segment);
}

bool LookupP2dEndpoint(const std::string &segment, std::string *host,
                       int *port) {
    std::lock_guard<std::mutex> lock(g_p2d_mu);
    auto it = g_p2d_peers.find(segment);
    if (it == g_p2d_peers.end()) return false;
    *host = it->second.host;
    *port = it->second.port;
    return true;
}

int WriteAuthenticatedHandshake(int fd, HandShakeRequestType type,
                                const std::string &str) {
    if (type == HandShakeRequestType::OldProtocol) {
        LOG(ERROR) << "handshake: old protocol refused in secure mode";
        return ERR_REJECT_HANDSHAKE;
    }
    std::string bound;
    bound.reserve(1 + str.size());
    bound.push_back(static_cast<char>(type));
    if (type == HandShakeRequestType::Metadata)
        bound.append(AddP2dEndpoint(str));
    else
        bound.append(str);
    const std::string tag = ca::MakeTag(ca::Domain::kHandshake, bound);
    if (tag.empty()) {
        LOG(ERROR) << "handshake: secure mode has no usable key ("
                   << ca::ConfigError() << ")";
        return ERR_REJECT_HANDSHAKE;
    }
    uint64_t length = tag.size() + bound.size();
    if (writeFullySocket(fd, &length, sizeof(length)) !=
        (ssize_t)sizeof(length))
        return ERR_SOCKET;
    if (writeFullySocket(fd, tag.data(), tag.size()) != (ssize_t)tag.size())
        return ERR_SOCKET;
    if (writeFullySocket(fd, bound.data(), bound.size()) !=
        (ssize_t)bound.size())
        return ERR_SOCKET;
    return 0;
}

std::pair<HandShakeRequestType, std::string> ReadAuthenticatedHandshake(
    int fd) {
    const std::pair<HandShakeRequestType, std::string> invalid{
        HandShakeRequestType::Invalid, ""};
    if (!ca::Ready()) {
        LOG(ERROR) << "handshake: secure mode has no usable key ("
                   << ca::ConfigError() << ")";
        return invalid;
    }
    uint64_t length = 0;
    ssize_t n = readFully(fd, &length, sizeof(length));
    if (n != (ssize_t)sizeof(length)) {
        LOG(WARNING) << "handshake: incomplete length, got: " << n;
        return invalid;
    }
    if (length <= ca::kTagSize ||
        length > getHandshakeMaxLength() + ca::kTagSize) {
        LOG(ERROR) << "handshake: rejected unauthenticated or oversized "
                      "message, length: "
                   << length;
        return invalid;
    }
    std::vector<char> buffer(length);
    n = readFully(fd, buffer.data(), length);
    if (n != (ssize_t)length) {
        LOG(ERROR) << "handshake: unexpected length, got: " << n
                   << ", expected: " << length;
        return invalid;
    }
    std::string_view tag(buffer.data(), ca::kTagSize);
    std::string_view bound(buffer.data() + ca::kTagSize,
                           length - ca::kTagSize);
    auto verdict = ca::VerifyTag(ca::Domain::kHandshake, tag, bound);
    if (verdict != ca::Verdict::kOk) {
        LOG(ERROR) << "handshake: rejected message: "
                   << ca::VerdictName(verdict);
        return invalid;
    }
    if (static_cast<uint8_t>(bound[0]) >
        static_cast<uint8_t>(HandShakeRequestType::Probe)) {
        LOG(ERROR) << "handshake: unknown message type in secure mode";
        return invalid;
    }
    const auto type = static_cast<HandShakeRequestType>(bound[0]);
    std::string body(bound.substr(1));
    if (type == HandShakeRequestType::Metadata) RecordP2dEndpoint(body);
    return {type, std::move(body)};
}

void OnTransferMetadataCreated(const std::string &conn_string) {
    if (!ca::Enabled()) return;
    if (conn_string != "P2PHANDSHAKE") {
        LOG(FATAL) << "Secure mode (MC_SECURE_MODE) requires the "
                      "P2PHANDSHAKE metadata mode; refusing '"
                   << conn_string << "'";
    }
    if (!ca::Ready()) {
        // The hook still goes in: every handshake then fails closed.
        LOG(ERROR) << "Secure mode is on but has no usable key ("
                   << ca::ConfigError() << "); all handshakes will fail";
    }
    InstallHandshakeAuth();
}

void InstallHandshakeAuth() {
    g_handshake_framing_hook = &kFraming;
}

void UninstallHandshakeAuthForTesting() {
    g_handshake_framing_hook = nullptr;
}

}  // namespace secure
}  // namespace mooncake
