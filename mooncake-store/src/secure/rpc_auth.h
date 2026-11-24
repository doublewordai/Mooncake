// Secure-mode authentication of the store's coro_rpc requests.
//
// Each request carries, as its coro_rpc request attachment, a control_auth tag
// bound to the function it calls (its route key). Every handler registered
// through RpcWorkerPool::Register or RpcRegistrar is wrapped in AuthedHandler,
// which checks the tag before the handler body runs and answers a request
// without a valid one with kUnauthenticated. Clients add the tag in
// RpcSendRequest. Nothing here is compiled without -DWITH_SECURE_KV=ON, and
// nothing is installed unless MC_CONTROL_AUTH is on.

#pragma once

#include <async_simple/coro/Lazy.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <ylt/coro_io/coro_io.hpp>
#include <ylt/coro_rpc/coro_rpc_client.hpp>
#include <ylt/coro_rpc/coro_rpc_server.hpp>
#include <ylt/util/type_traits.h>

namespace mooncake {
namespace secure {

// The coro_rpc error code of a refused request.
constexpr uint16_t kUnauthenticated = 401;

// Whether requests are tagged and checked (MC_CONTROL_AUTH on).
bool RpcAuthEnabled();
// For servers: like RpcAuthEnabled, but aborts the process if secure mode is
// on without a usable key, so a misconfigured server never starts serving.
bool RpcAuthEnabledForServer();

// True (and logs why) in secure mode: a listener with no authentication,
// such as the HTTP metadata server, which serves and accepts segment
// descriptors (rkeys included) from anyone, must not start.
bool RefuseUnauthenticatedListener(const char *what);

std::string MakeRpcToken(uint32_t func_id);
// Throws coro_rpc::rpc_error{kUnauthenticated} unless `attachment` is a valid,
// fresh, unreplayed tag for `func_id`.
void CheckRpcTokenOrThrow(std::string_view attachment, uint32_t func_id);

namespace detail {

// ylt reports the parameters of a function that takes none as void.
template <auto Method>
using HandlerParams = std::conditional_t<
    std::is_void_v<::util::function_parameters_t<decltype(Method)>>,
    std::tuple<>, ::util::function_parameters_t<decltype(Method)>>;

template <typename T>
struct LazyValue {
    using type = T;
};
template <typename T>
struct LazyValue<async_simple::coro::Lazy<T>> {
    using type = T;
};
template <auto Method>
using Returned = ::util::function_return_type_t<decltype(Method)>;
template <auto Method>
using HandlerResult = typename LazyValue<Returned<Method>>::type;

// Keeps handlers registered without an owner alive for the process: the
// router holds only raw pointers to them, as it does to the services.
void KeepForever(std::shared_ptr<void> handler);

}  // namespace detail

template <auto Method>
async_simple::coro::Lazy<void> CheckCurrentRequest() {
    auto *ctx = co_await coro_rpc::get_context_in_coro();
    CheckRpcTokenOrThrow(ctx->get_request_attachment(),
                         coro_rpc::func_id<Method>());
}

// Calls Method on a service as the handler coro_rpc would have registered.
template <auto Method, typename Service,
          typename Params = detail::HandlerParams<Method>>
class DirectInvoker;

template <auto Method, typename Service, typename... Params>
class DirectInvoker<Method, Service, std::tuple<Params...>> {
    using Ret = detail::Returned<Method>;
    using Result = detail::HandlerResult<Method>;

   public:
    explicit DirectInvoker(Service *service) : service_(service) {}

    async_simple::coro::Lazy<Result> Handle(Params... params) {
        if constexpr (coro_io::is_lazy_v<Ret>) {
            if constexpr (std::is_void_v<Result>) {
                co_await(service_->*Method)(std::move(params)...);
            } else {
                co_return co_await(service_->*Method)(std::move(params)...);
            }
        } else if constexpr (std::is_void_v<Result>) {
            (service_->*Method)(std::move(params)...);
        } else {
            co_return(service_->*Method)(std::move(params)...);
        }
    }

   private:
    Service *service_;
};

// Checks the request's tag, then runs Inner's handler for Method.
template <auto Method, typename Inner,
          typename Params = detail::HandlerParams<Method>>
class AuthedHandler;

template <auto Method, typename Inner, typename... Params>
class AuthedHandler<Method, Inner, std::tuple<Params...>> {
    using Result = detail::HandlerResult<Method>;

   public:
    explicit AuthedHandler(std::shared_ptr<Inner> inner)
        : inner_(std::move(inner)) {}

    async_simple::coro::Lazy<Result> Handle(Params... params) {
        co_await CheckCurrentRequest<Method>();
        if constexpr (std::is_void_v<Result>) {
            co_await inner_->Handle(std::move(params)...);
        } else {
            co_return co_await inner_->Handle(std::move(params)...);
        }
    }

   private:
    std::shared_ptr<Inner> inner_;
};

// Registers Inner's handler for Method behind AuthedHandler, under Method's
// route key, and returns true; returns false (registering nothing) when
// secure mode is off. `keep` owns the wrapper.
template <auto Method, typename Inner>
bool RegisterAuthed(coro_rpc::coro_rpc_server &server,
                    std::shared_ptr<Inner> inner,
                    std::vector<std::shared_ptr<void>> &keep) {
    if (!RpcAuthEnabledForServer()) return false;
    using Handler = AuthedHandler<Method, Inner>;
    auto handler = std::make_shared<Handler>(std::move(inner));
    server.register_handler<&Handler::Handle>(handler.get(),
                                              coro_rpc::func_id<Method>());
    keep.push_back(std::move(handler));
    return true;
}

// The direct-registration counterpart: what server.register_handler<Methods
// ...>(service) would register, each behind AuthedHandler.
template <auto... Methods, typename Service>
bool RegisterDirectAuthed(coro_rpc::coro_rpc_server &server,
                          Service *service) {
    if (!RpcAuthEnabledForServer()) return false;
    std::vector<std::shared_ptr<void>> keep;
    (RegisterAuthed<Methods>(
         server, std::make_shared<DirectInvoker<Methods, Service>>(service),
         keep),
     ...);
    for (auto &h : keep) detail::KeepForever(std::move(h));
    return true;
}

// client.send_request<Method>(args...) with a tag for Method attached. The
// tag lives in this coroutine's frame until the request is written.
template <auto Method, typename... Args>
auto SendAuthedRequest(coro_rpc::coro_rpc_client &client, Args &&...args)
    -> decltype(client.template send_request<Method>(
        std::forward<Args>(args)...)) {
    const std::string token = MakeRpcToken(coro_rpc::func_id<Method>());
    co_return co_await client.template send_request_with_attachment<Method>(
        std::string_view(token), std::forward<Args>(args)...);
}

}  // namespace secure
}  // namespace mooncake
