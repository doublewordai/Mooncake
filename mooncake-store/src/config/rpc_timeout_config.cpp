#include "config/rpc_timeout_config.h"

#include <cstdlib>

#include "environ.h"
#include "environment_variables.h"

namespace mooncake {

RpcTimeoutConfig RpcTimeoutConfig::FromEnvironment() {
    RpcTimeoutConfig config;
    using Variables = RpcTimeoutEnvironmentVariables;
    if (const auto value = Environ::Read(Variables::MC_RPC_TIMEOUT_MS)) {
        config.request_timeout =
            std::chrono::milliseconds{std::atoll(value->c_str())};
    }
    if (const auto value =
            Environ::Read(Variables::MC_RPC_CONNECT_TIMEOUT_MS)) {
        config.connect_timeout =
            std::chrono::milliseconds{std::atoll(value->c_str())};
    }
    if (const auto value = Environ::Read(Variables::MC_RPC_CONNECT_RETRIES)) {
        const long long retries = std::atoll(value->c_str());
        config.connect_retries =
            static_cast<uint32_t>(retries < 0 ? 0 : retries);
    }
    if (const auto value =
            Environ::Read(Variables::MC_RPC_RECONNECT_WAIT_MS)) {
        const long long wait = std::atoll(value->c_str());
        config.reconnect_wait = std::chrono::milliseconds{wait < 0 ? 0 : wait};
    }
    return config;
}

}  // namespace mooncake
