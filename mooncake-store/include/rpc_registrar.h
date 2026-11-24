// The seams where secure mode (-DWITH_SECURE_KV=ON, src/secure/) authenticates
// coro_rpc. Without that build option these forward to coro_rpc unchanged.

#pragma once

#include <utility>

#include <ylt/coro_rpc/coro_rpc_client.hpp>
#include <ylt/coro_rpc/coro_rpc_server.hpp>

#ifdef MOONCAKE_WITH_SECURE_KV
#include "rpc_auth.h"
#endif

namespace mooncake {

// Stands in for a coro_rpc_server when registering handlers directly. In
// secure mode each handler is registered behind a tag check; the choice is
// made once, here, at registration.
class RpcRegistrar {
   public:
    explicit RpcRegistrar(coro_rpc::coro_rpc_server &server)
        : server_(server) {}

    template <auto... Methods, typename Service>
    void register_handler(Service *service) {
#ifdef MOONCAKE_WITH_SECURE_KV
        if (secure::RegisterDirectAuthed<Methods...>(server_, service)) return;
#endif
        server_.template register_handler<Methods...>(service);
    }

   private:
    coro_rpc::coro_rpc_server &server_;
};

// client.send_request<Method>(args...), with the request's tag attached in
// secure mode.
template <auto Method, typename... Args>
auto RpcSendRequest(coro_rpc::coro_rpc_client &client, Args &&...args) {
#ifdef MOONCAKE_WITH_SECURE_KV
    if (secure::RpcAuthEnabled())
        return secure::SendAuthedRequest<Method>(client,
                                                 std::forward<Args>(args)...);
#endif
    return client.template send_request<Method>(std::forward<Args>(args)...);
}

}  // namespace mooncake
