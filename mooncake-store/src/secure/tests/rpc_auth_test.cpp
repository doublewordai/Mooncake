// coro_rpc in secure mode, over TCP: handlers registered directly
// (RpcRegistrar) and through RpcWorkerPool, and the real master service with
// MasterClient. Each guard has a case that proves the request is refused and
// the handler body never runs.

#include <gtest/gtest.h>

#include <async_simple/coro/SyncAwait.h>
#include <ylt/coro_rpc/coro_rpc_client.hpp>
#include <ylt/coro_rpc/coro_rpc_server.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#include "common/network.h"
#include "control_auth.h"
#include "http_metadata_server.h"
#include "master_client.h"
#include "rpc_auth.h"
#include "rpc_registrar.h"
#include "rpc_service.h"
#include "rpc_worker_pool.h"

namespace mooncake {
namespace {

namespace ca = control_auth;
using async_simple::coro::syncAwait;

const std::string kSecretA(40, 'a');
const std::string kSecretB(40, 'b');

int64_t NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Sends a request and waits for its response.
template <typename T>
async_simple::coro::Lazy<T> Flatten(
    async_simple::coro::Lazy<async_simple::coro::Lazy<T>> outer) {
    auto inner = co_await std::move(outer);
    co_return co_await std::move(inner);
}

class Store {
   public:
    int Put(std::string key) {
        ++puts;
        return static_cast<int>(key.size());
    }
    void Clear() { ++clears; }
    async_simple::coro::Lazy<int> LazyGet(int x) { co_return x + 1; }
    int Other() { return 7; }

    std::atomic<int> puts{0};
    std::atomic<int> clears{0};
};

class RpcAuthTest : public ::testing::Test {
   protected:
    void SetUp() override {
        ca::ConfigureForTesting(true, kSecretA);
        const auto ports = getFreeTcpPorts(1);
        ASSERT_EQ(ports.size(), 1u);
        port_ = ports.front();
    }
    void TearDown() override { ca::ResetForTesting(); }

    std::unique_ptr<coro_rpc::coro_rpc_server> Serve(Store &store,
                                                     RpcWorkerPool *pool) {
        auto server = std::make_unique<coro_rpc::coro_rpc_server>(
            1, port_, "127.0.0.1", std::chrono::seconds(0), true);
        if (pool) {
            pool->Register<&Store::Put>(*server, store);
            pool->Register<&Store::Clear>(*server, store);
            pool->Register<&Store::Other>(*server, store);
        } else {
            RpcRegistrar(*server)
                .register_handler<&Store::Put, &Store::Clear, &Store::LazyGet,
                                  &Store::Other>(&store);
        }
        auto started = server->async_start();
        EXPECT_FALSE(started.hasResult());
        return server;
    }

    void Connect(coro_rpc::coro_rpc_client &client) {
        auto ec = syncAwait(client.connect("127.0.0.1", std::to_string(port_)));
        ASSERT_FALSE(ec) << ec.message();
    }

    // Sends Put with a chosen attachment; returns the coro_rpc error code.
    uint16_t PutWith(coro_rpc::coro_rpc_client &client,
                     std::string_view attachment) {
        auto r = syncAwait(Flatten(client.send_request_with_attachment<&Store::Put>(
            attachment, std::string("k"))));
        return r ? 0 : static_cast<uint16_t>(r.error().code.ec);
    }

    // A request through the client seam, as the Store's clients send them.
    template <auto Method, typename... Args>
    auto AuthedCall(coro_rpc::coro_rpc_client &client, Args &&...args) {
        return syncAwait(Flatten(
            RpcSendRequest<Method>(client, std::forward<Args>(args)...)));
    }

    int port_ = 0;
};

TEST_F(RpcAuthTest, TaggedRequestsAreServed) {
    Store store;
    auto server = Serve(store, nullptr);
    coro_rpc::coro_rpc_client client;
    ASSERT_NO_FATAL_FAILURE(Connect(client));
    auto put = AuthedCall<&Store::Put>(client, std::string("abc"));
    ASSERT_TRUE(put) << put.error().msg;
    EXPECT_EQ(put->result(), 3);
    auto lazy = AuthedCall<&Store::LazyGet>(client, 41);
    ASSERT_TRUE(lazy) << lazy.error().msg;
    EXPECT_EQ(lazy->result(), 42);
    auto clear = AuthedCall<&Store::Clear>(client);
    ASSERT_TRUE(clear) << clear.error().msg;
    EXPECT_EQ(store.puts.load(), 1);
    EXPECT_EQ(store.clears.load(), 1);
}

TEST_F(RpcAuthTest, UntaggedRequestIsRefused) {
    Store store;
    auto server = Serve(store, nullptr);
    coro_rpc::coro_rpc_client client;
    ASSERT_NO_FATAL_FAILURE(Connect(client));
    auto r = syncAwait(client.call<&Store::Put>(std::string("abc")));
    ASSERT_FALSE(r);
    EXPECT_EQ(static_cast<uint16_t>(r.error().code.ec),
              secure::kUnauthenticated);
    auto c = syncAwait(client.call<&Store::Clear>());
    ASSERT_FALSE(c);
    EXPECT_EQ(store.puts.load(), 0);
    EXPECT_EQ(store.clears.load(), 0);
}

TEST_F(RpcAuthTest, WrongKeyIsRefused) {
    Store store;
    auto server = Serve(store, nullptr);
    coro_rpc::coro_rpc_client client;
    ASSERT_NO_FATAL_FAILURE(Connect(client));
    ca::ConfigureForTesting(true, kSecretB);
    const std::string token =
        secure::MakeRpcToken(coro_rpc::func_id<&Store::Put>());
    ca::ConfigureForTesting(true, kSecretA);
    EXPECT_EQ(PutWith(client, token), secure::kUnauthenticated);
    EXPECT_EQ(store.puts.load(), 0);
}

TEST_F(RpcAuthTest, ReplayedTokenIsRefused) {
    Store store;
    auto server = Serve(store, nullptr);
    coro_rpc::coro_rpc_client client;
    ASSERT_NO_FATAL_FAILURE(Connect(client));
    const std::string token =
        secure::MakeRpcToken(coro_rpc::func_id<&Store::Put>());
    EXPECT_EQ(PutWith(client, token), 0);
    EXPECT_EQ(PutWith(client, token), secure::kUnauthenticated);
    EXPECT_EQ(store.puts.load(), 1);
}

TEST_F(RpcAuthTest, StaleTokenIsRefused) {
    ca::ConfigureForTesting(true, kSecretA, /*max_skew_ms=*/5000);
    Store store;
    auto server = Serve(store, nullptr);
    coro_rpc::coro_rpc_client client;
    ASSERT_NO_FATAL_FAILURE(Connect(client));
    std::string bound(4, '\0');
    uint32_t id = coro_rpc::func_id<&Store::Put>();
    for (int i = 3; i >= 0; --i, id >>= 8) bound[i] = char(id & 0xff);
    const std::string token = ca::MakeTagAtForTesting(
        ca::Domain::kRpcRequest, bound, NowMs() - 6000);
    EXPECT_EQ(PutWith(client, token), secure::kUnauthenticated);
    EXPECT_EQ(store.puts.load(), 0);
}

TEST_F(RpcAuthTest, TokenForAnotherFunctionIsRefused) {
    Store store;
    auto server = Serve(store, nullptr);
    coro_rpc::coro_rpc_client client;
    ASSERT_NO_FATAL_FAILURE(Connect(client));
    const std::string token =
        secure::MakeRpcToken(coro_rpc::func_id<&Store::Other>());
    EXPECT_EQ(PutWith(client, token), secure::kUnauthenticated);
    EXPECT_EQ(store.puts.load(), 0);
}

TEST_F(RpcAuthTest, WorkerPoolHandlersAreGuarded) {
    Store store;
    RpcWorkerPool pool(2);
    auto server = Serve(store, &pool);
    coro_rpc::coro_rpc_client client;
    ASSERT_NO_FATAL_FAILURE(Connect(client));
    auto refused = syncAwait(client.call<&Store::Put>(std::string("abc")));
    ASSERT_FALSE(refused);
    EXPECT_EQ(static_cast<uint16_t>(refused.error().code.ec),
              secure::kUnauthenticated);
    EXPECT_EQ(store.puts.load(), 0);
    auto put = AuthedCall<&Store::Put>(client, std::string("abc"));
    ASSERT_TRUE(put) << put.error().msg;
    EXPECT_EQ(put->result(), 3);
    EXPECT_EQ(store.puts.load(), 1);
    server->stop();
}

TEST_F(RpcAuthTest, OffRegistersAndCallsAsUpstream) {
    ca::ConfigureForTesting(false, "");
    Store store;
    auto server = Serve(store, nullptr);
    coro_rpc::coro_rpc_client client;
    ASSERT_NO_FATAL_FAILURE(Connect(client));
    auto r = syncAwait(client.call<&Store::Put>(std::string("abc")));
    ASSERT_TRUE(r) << r.error().msg;
    EXPECT_EQ(r.value(), 3);
}

TEST_F(RpcAuthTest, ServerWithoutKeyRefusesToStart) {
    ca::ConfigureForTesting(true, "");
    Store store;
    coro_rpc::coro_rpc_server server(1, port_, "127.0.0.1");
    EXPECT_DEATH(
        RpcRegistrar(server).register_handler<&Store::Put>(&store),
        "no usable key");
}

TEST_F(RpcAuthTest, HttpMetadataServerRefusesToStart) {
    HttpMetadataServer meta(static_cast<uint16_t>(port_), "127.0.0.1");
    EXPECT_FALSE(meta.start());
}

// The master as deployed: RegisterRpcService with a worker pool, and
// MasterClient as its clients use it.
TEST_F(RpcAuthTest, MasterServesTaggedClientsAndRefusesOthers) {
    WrappedMasterServiceConfig config;
    config.default_kv_lease_ttl = 0;
    config.enable_metric_reporting = false;
    auto service = std::make_shared<WrappedMasterService>(config);
    coro_rpc::coro_rpc_server server(2, port_, "127.0.0.1",
                                     std::chrono::seconds(0), true);
    RpcWorkerPool pool(2);
    RegisterRpcService(server, *service, &pool);
    ASSERT_FALSE(server.async_start().hasResult());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const UUID client_id = generate_uuid();
    Segment segment;
    segment.id = generate_uuid();
    segment.name = "secure_segment";
    segment.base = 0x300000000;
    segment.size = 16 * 1024 * 1024;
    ASSERT_TRUE(service->MountSegment(segment, client_id).has_value());
    ReplicateConfig replicate;
    replicate.replica_num = 1;
    ASSERT_TRUE(service->PutStart(client_id, "victim", 1024, replicate)
                    .has_value());
    ASSERT_TRUE(service
                    ->PutEnd(client_id, ObjectMeta{"victim", std::nullopt},
                             ReplicaType::MEMORY)
                    .has_value());

    // An attacker without the key: Remove and ExistKey are refused.
    coro_rpc::coro_rpc_client attacker;
    ASSERT_NO_FATAL_FAILURE(Connect(attacker));
    auto removed = syncAwait(attacker.call<&WrappedMasterService::Remove>(
        std::string("victim"), true, std::string("default")));
    ASSERT_FALSE(removed);
    EXPECT_EQ(static_cast<uint16_t>(removed.error().code.ec),
              secure::kUnauthenticated);
    auto ping = syncAwait(attacker.call<&WrappedMasterService::ServiceReady>());
    ASSERT_FALSE(ping);
    auto exists = service->ExistKey("victim");
    ASSERT_TRUE(exists.has_value());
    EXPECT_TRUE(exists.value());

    // A client with the key.
    MasterClient client(client_id);
    ASSERT_EQ(client.Connect("127.0.0.1:" + std::to_string(port_)),
              ErrorCode::OK);
    auto seen = client.ExistKey("victim");
    ASSERT_TRUE(seen.has_value()) << toString(seen.error());
    EXPECT_TRUE(seen.value());

    server.stop();
}

}  // namespace
}  // namespace mooncake
