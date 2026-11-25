#include "handshake_auth.h"

#include <glog/logging.h>

#include <vector>

#include "control_auth.h"

namespace mooncake {
namespace secure {
namespace {

namespace ca = control_auth;

const HandshakeFramingHook kFraming{&WriteAuthenticatedHandshake,
                                    &ReadAuthenticatedHandshake};

}  // namespace

int WriteAuthenticatedHandshake(int fd, HandShakeRequestType type,
                                const std::string &str) {
    if (type == HandShakeRequestType::OldProtocol) {
        LOG(ERROR) << "handshake: old protocol refused in secure mode";
        return ERR_REJECT_HANDSHAKE;
    }
    std::string bound;
    bound.reserve(1 + str.size());
    bound.push_back(static_cast<char>(type));
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
    return {static_cast<HandShakeRequestType>(bound[0]),
            std::string(bound.substr(1))};
}

void OnTransferMetadataCreated(const std::string &conn_string) {
    if (!ca::Enabled()) return;
    if (conn_string != "P2PHANDSHAKE") {
        LOG(FATAL) << "Secure mode (MC_CONTROL_AUTH) requires the "
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
