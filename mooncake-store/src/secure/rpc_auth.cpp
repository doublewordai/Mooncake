#include "rpc_auth.h"

#include <glog/logging.h>
#include <openssl/evp.h>

#include <cstdlib>
#include <mutex>

#include "control_auth.h"

namespace mooncake {
namespace secure {
namespace {

namespace ca = control_auth;

}  // namespace

std::string RpcBound(uint32_t func_id, std::string_view args_digest) {
    std::string b(4, '\0');
    for (int i = 3; i >= 0; --i) {
        b[i] = static_cast<char>(func_id & 0xff);
        func_id >>= 8;
    }
    b.append(args_digest);
    return b;
}

Sha256::Sha256() : ctx_(EVP_MD_CTX_new()) {
    auto *c = static_cast<EVP_MD_CTX *>(ctx_);
    CHECK(c && EVP_DigestInit_ex(c, EVP_sha256(), nullptr) == 1);
}

Sha256::~Sha256() { EVP_MD_CTX_free(static_cast<EVP_MD_CTX *>(ctx_)); }

void Sha256::Update(std::string_view data) {
    CHECK(EVP_DigestUpdate(static_cast<EVP_MD_CTX *>(ctx_), data.data(),
                           data.size()) == 1);
}

std::string Sha256::Final() {
    std::string out(32, '\0');
    unsigned int n = 0;
    CHECK(EVP_DigestFinal_ex(static_cast<EVP_MD_CTX *>(ctx_),
                             reinterpret_cast<unsigned char *>(out.data()),
                             &n) == 1 &&
          n == 32);
    return out;
}

bool RpcAuthEnabled() { return ca::Enabled(); }

bool RpcAuthEnabledForServer() {
    if (!ca::Enabled()) return false;
    if (!ca::Ready()) {
        LOG(FATAL) << "Secure mode (MC_SECURE_MODE) is on but has no usable "
                      "key ("
                   << ca::ConfigError() << "); refusing to serve RPC";
    }
    return true;
}

bool RefuseUnauthenticatedListener(const char *what) {
    if (!ca::Enabled()) return false;
    LOG(ERROR) << "Secure mode (MC_SECURE_MODE) refuses to start the "
               << what << ": it has no authentication";
    return true;
}

std::string AdminBindHost(const std::string &requested) {
    if (!ca::Enabled()) return requested;
    std::string host = "127.0.0.1";
    if (const char *v = std::getenv("MC_SECURE_ADMIN_BIND"); v && *v)
        host = v;
    if (host != requested)
        LOG(WARNING) << "Secure mode: the admin/metrics HTTP server binds to "
                     << host << ", not " << requested
                     << " (it is unauthenticated; set MC_SECURE_ADMIN_BIND to "
                        "choose)";
    return host;
}

std::string MakeRpcToken(uint32_t func_id, std::string_view args_digest) {
    std::string tag =
        ca::MakeTag(ca::Domain::kRpcRequest, RpcBound(func_id, args_digest));
    if (tag.empty()) {
        LOG_EVERY_N(ERROR, 1000)
            << "Secure mode has no usable key (" << ca::ConfigError()
            << "); RPC requests go untagged and will be refused";
    }
    return tag;
}

void CheckRpcTokenOrThrow(std::string_view attachment, uint32_t func_id,
                          std::string_view args_digest) {
    auto verdict = ca::VerifyTag(ca::Domain::kRpcRequest, attachment,
                                 RpcBound(func_id, args_digest));
    if (verdict == ca::Verdict::kOk) return;
    LOG_EVERY_N(WARNING, 100) << "Refused unauthenticated RPC (route key "
                              << func_id << "): " << ca::VerdictName(verdict);
    throw coro_rpc::rpc_error{
        coro_rpc::err_code{static_cast<coro_rpc::errc>(kUnauthenticated)},
        std::string("unauthenticated: ") + ca::VerdictName(verdict)};
}

namespace detail {
void KeepForever(std::shared_ptr<void> handler) {
    static std::mutex mu;
    static auto *kept = new std::vector<std::shared_ptr<void>>();
    std::lock_guard<std::mutex> lock(mu);
    kept->push_back(std::move(handler));
}
}  // namespace detail

}  // namespace secure
}  // namespace mooncake
