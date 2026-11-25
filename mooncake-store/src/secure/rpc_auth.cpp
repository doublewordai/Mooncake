#include "rpc_auth.h"

#include <glog/logging.h>

#include <mutex>

#include "control_auth.h"

namespace mooncake {
namespace secure {
namespace {

namespace ca = control_auth;

std::string BoundFor(uint32_t func_id) {
    std::string b(4, '\0');
    for (int i = 3; i >= 0; --i) {
        b[i] = static_cast<char>(func_id & 0xff);
        func_id >>= 8;
    }
    return b;
}

}  // namespace

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

std::string MakeRpcToken(uint32_t func_id) {
    std::string tag = ca::MakeTag(ca::Domain::kRpcRequest, BoundFor(func_id));
    if (tag.empty()) {
        LOG_EVERY_N(ERROR, 1000)
            << "Secure mode has no usable key (" << ca::ConfigError()
            << "); RPC requests go untagged and will be refused";
    }
    return tag;
}

void CheckRpcTokenOrThrow(std::string_view attachment, uint32_t func_id) {
    auto verdict =
        ca::VerifyTag(ca::Domain::kRpcRequest, attachment, BoundFor(func_id));
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
