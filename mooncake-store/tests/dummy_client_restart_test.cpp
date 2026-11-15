// dummy_client_restart_test.cpp
// A RealClient that restarts at the same address faster than one ping
// interval must still be noticed by an attached DummyClient, which then
// re-registers its shared memory so puts work again.

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>

#include "common/network.h"
#include "dummy_client.h"
#include "real_client.h"
#include "test_server_helpers.h"

namespace mooncake {
namespace testing {

static constexpr size_t kMB = 1024ULL * 1024;
static constexpr size_t kSegmentSize = 64 * kMB;
static constexpr size_t kLocalBufSize = 16 * kMB;
static constexpr size_t kPoolSize = 16 * kMB;

class DummyClientRestartTest : public ::testing::Test {
   protected:
    static void SetUpTestSuite() {
        google::InitGoogleLogging("DummyClientRestartTest");
        FLAGS_logtostderr = 1;
    }
    static void TearDownTestSuite() { google::ShutdownGoogleLogging(); }

    void TearDown() override {
        easylog::set_min_severity(easylog::Severity::FATAL);
        if (dummy_client_) dummy_client_->tearDownAll();
        StopRealClient();
        master_.Stop();
        easylog::set_min_severity(easylog::Severity::WARN);
    }

    // with_instance_id=false registers the handlers an older RealClient
    // build has, i.e. without get_instance_id_internal.
    bool StartRealClient(bool with_instance_id) {
        real_client_ = RealClient::create();
        if (real_client_->setup_real(
                "localhost:" + std::to_string(te_port_), "P2PHANDSHAKE",
                kSegmentSize, kLocalBufSize, "tcp", "",
                master_.master_address(), nullptr, ipc_path_) != 0) {
            return false;
        }
        rpc_server_ = std::make_unique<coro_rpc::coro_rpc_server>(
            /*thread_num=*/2, /*port=*/rpc_port_, /*address=*/"127.0.0.1",
            std::chrono::seconds(0), /*tcp_no_delay=*/true);
        auto &rc = *real_client_;
        rpc_server_->register_handler<&RealClient::service_ready_internal>(&rc);
        rpc_server_->register_handler<&RealClient::ping>(&rc);
        if (with_instance_id) {
            rpc_server_
                ->register_handler<&RealClient::get_instance_id_internal>(&rc);
        }
        rpc_server_->register_handler<&RealClient::map_shm_internal>(&rc);
        rpc_server_->register_handler<&RealClient::unmap_shm_internal>(&rc);
        rpc_server_->register_handler<&RealClient::put_dummy_helper>(&rc);
        rpc_server_->register_handler<&RealClient::isExist_internal>(&rc);
        rpc_server_->register_handler<&RealClient::acquire_hot_cache>(&rc);
        rpc_server_->register_handler<&RealClient::release_hot_cache>(&rc);
        auto ec = rpc_server_->async_start();
        if (ec.hasResult()) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        return true;
    }

    void StopRealClient() {
        if (rpc_server_) rpc_server_->stop();
        rpc_server_.reset();
        if (real_client_) real_client_->tearDownAll();
        real_client_.reset();
    }

    bool SetupStack(bool with_instance_id) {
        if (!master_.Start(InProcMasterConfigBuilder().build())) return false;
        rpc_port_ = getFreeTcpPort();
        te_port_ = getFreeTcpPort();
        ipc_path_ = "@dummy_restart_test_" + std::to_string(getpid()) + ".sock";
        if (!StartRealClient(with_instance_id)) return false;
        dummy_client_ = std::make_shared<DummyClient>();
        return dummy_client_->setup_dummy(
                   kPoolSize, kLocalBufSize,
                   "127.0.0.1:" + std::to_string(rpc_port_), ipc_path_) == 0;
    }

    int Put(const std::string &key) {
        const std::string data(4096, 'r');
        ReplicateConfig config;
        config.replica_num = 1;
        return dummy_client_->put(key, std::span<const char>(data), config);
    }

    // Restart the RealClient at the same RPC port and IPC socket with no
    // gap, i.e. well inside one 1 s ping interval.
    void FastRestart(bool with_instance_id) {
        StopRealClient();
        ASSERT_TRUE(StartRealClient(with_instance_id));
    }

    // Seconds until a put succeeds, or -1 after timeout_s.
    double SecondsUntilPutSucceeds(const std::string &prefix,
                                   double timeout_s) {
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0;; ++i) {
            double elapsed = std::chrono::duration<double>(
                                 std::chrono::steady_clock::now() - t0)
                                 .count();
            if (elapsed > timeout_s) return -1;
            if (Put(prefix + std::to_string(i)) == 0) return elapsed;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    InProcMaster master_;
    std::shared_ptr<RealClient> real_client_;
    std::shared_ptr<DummyClient> dummy_client_;
    std::unique_ptr<coro_rpc::coro_rpc_server> rpc_server_;
    int rpc_port_ = 0;
    int te_port_ = 0;
    std::string ipc_path_;
};

// End-to-end regression: a zero-gap restart at the same address must end in
// a working dummy. In-process the restart also breaks the pooled RPC
// connection, so this can recover through the ping-failure path as well as
// through the instance id; the test below pins down the new trigger.
TEST_F(DummyClientRestartTest, FastRestartRecovers) {
    ASSERT_TRUE(SetupStack(/*with_instance_id=*/true));
    ASSERT_EQ(Put("before"), 0);

    FastRestart(/*with_instance_id=*/true);

    double recovered = SecondsUntilPutSucceeds("after-", 10.0);
    ASSERT_GE(recovered, 0) << "dummy never recovered after a fast restart";
    LOG(INFO) << "recovered " << recovered << " s after the restart";
    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(Put("steady-" + std::to_string(i)), 0)
            << "put failed after recovery";
    }
}

// The RealClient drops the dummy's mappings while the connection, the ping
// and the instance id all stay the same: only the CLIENT_NOT_FOUND answer can
// tell the dummy, and it must re-register without waiting for a failed ping.
class DummyClientForgottenTest : public DummyClientRestartTest,
                                 public ::testing::WithParamInterface<bool> {};

TEST_P(DummyClientForgottenTest, ClientNotFoundTriggersReregistration) {
    const bool with_instance_id = GetParam();
    ASSERT_TRUE(SetupStack(with_instance_id));
    ASSERT_EQ(Put("before"), 0);

    ASSERT_TRUE(real_client_->unmap_shm_internal(dummy_client_->client_id())
                    .has_value());

    EXPECT_EQ(Put("first-after"), toInt(ErrorCode::CLIENT_NOT_FOUND))
        << "an unknown client_id must be reported as CLIENT_NOT_FOUND";
    double recovered = SecondsUntilPutSucceeds("after-", 5.0);
    ASSERT_GE(recovered, 0) << "CLIENT_NOT_FOUND did not trigger recovery";
    // Well inside the 1 s ping interval: the trigger, not a ping, did it.
    EXPECT_LT(recovered, 1.0);
    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(Put("steady-" + std::to_string(i)), 0)
            << "put failed after recovery";
    }
}

// true: current RealClient; false: one without get_instance_id_internal, as
// from an older build (the mixed-version case).
INSTANTIATE_TEST_SUITE_P(WithAndWithoutInstanceId, DummyClientForgottenTest,
                         ::testing::Bool());

}  // namespace testing
}  // namespace mooncake

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    gflags::ParseCommandLineFlags(&argc, &argv, false);
    return RUN_ALL_TESTS();
}
