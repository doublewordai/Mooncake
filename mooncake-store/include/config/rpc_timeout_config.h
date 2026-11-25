#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

namespace mooncake {

struct RpcTimeoutConfig {
    // An absent override leaves the caller's connection policy unchanged.
    std::optional<std::chrono::milliseconds> request_timeout;
    std::optional<std::chrono::milliseconds> connect_timeout;
    // The master client's foreground pool only (the HA control pools always
    // make one bounded attempt): connect attempts after the first, and the
    // wait between attempts. A store client whose leader has gone otherwise
    // spends (1 + retries) x wait in that pool before its call fails.
    std::optional<uint32_t> connect_retries;
    std::optional<std::chrono::milliseconds> reconnect_wait;

    static RpcTimeoutConfig FromEnvironment();
};

}  // namespace mooncake
