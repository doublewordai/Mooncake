// Copyright 2026 KVCache.AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "cuda_alike.h"
#include "transfer_engine.h"

#ifdef MOONCAKE_TCP_TRANSPORT_TEST_HOOKS
namespace mooncake {
void tcpTransportResetStagingStatsForTest() noexcept;
size_t tcpTransportStagingBufferAllocationCountForTest() noexcept;
size_t tcpTransportStagingDeviceQueryCountForTest() noexcept;
}  // namespace mooncake
#endif

namespace {

using namespace mooncake;

class ScopedEnvVar {
   public:
    ScopedEnvVar(const char* name, const char* value) : name_(name) {
        const char* current = std::getenv(name);
        if (current) old_value_ = current;
        setenv(name, value, 1);
    }

    ~ScopedEnvVar() {
        if (old_value_)
            setenv(name_.c_str(), old_value_->c_str(), 1);
        else
            unsetenv(name_.c_str());
    }

   private:
    std::string name_;
    std::optional<std::string> old_value_;
};

class DeviceBuffer {
   public:
    ~DeviceBuffer() {
        if (data_) cudaFree(data_);
    }

    void** out() { return &data_; }
    void* get() const { return data_; }

   private:
    void* data_ = nullptr;
};

TransferStatusEnum runOne(TransferEngine* engine,
                          const TransferRequest& request) {
    auto batch_id = engine->allocateBatchID(1);
    if (!engine->submitTransfer(batch_id, {request}).ok()) {
        (void)engine->freeBatchID(batch_id);
        return TransferStatusEnum::FAILED;
    }
    TransferStatus status;
    status.s = TransferStatusEnum::WAITING;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (status.s != TransferStatusEnum::COMPLETED &&
           status.s != TransferStatusEnum::FAILED &&
           std::chrono::steady_clock::now() < deadline) {
        if (!engine->getTransferStatus(batch_id, 0, status).ok()) {
            status.s = TransferStatusEnum::FAILED;
            break;
        }
        if (status.s == TransferStatusEnum::WAITING)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (status.s == TransferStatusEnum::WAITING)
        status.s = TransferStatusEnum::TIMEOUT;
    (void)engine->freeBatchID(batch_id);
    return status.s;
}

TEST(TcpCudaStagingTest, ReusesStagingAcrossChunksAndRequests) {
    int device_count = 0;
    cudaError_t cuda_status = cudaGetDeviceCount(&device_count);
    if (cuda_status != cudaSuccess || device_count == 0) {
        GTEST_SKIP() << "CUDA device unavailable";
    }
    ASSERT_EQ(cudaSetDevice(0), cudaSuccess);

    ScopedEnvVar connection_pool("MC_TCP_ENABLE_CONNECTION_POOL", "1");
    ScopedEnvVar lanes("MC_TCP_LANES_PER_PEER", "1");
    ScopedEnvVar slice_size("MC_TCP_SLICE_SIZE", "65536");

    constexpr size_t kChunkSize = 64 * 1024;
    constexpr size_t kTransferSize = 8 * kChunkSize;
    constexpr size_t kBufferSize = 3 * kTransferSize;

    DeviceBuffer device_buffer;
    ASSERT_EQ(cudaMalloc(device_buffer.out(), kBufferSize), cudaSuccess);
    ASSERT_EQ(cudaMemset(device_buffer.get(), 0, kBufferSize), cudaSuccess);

    std::vector<unsigned char> pattern(kTransferSize);
    for (size_t i = 0; i < pattern.size(); ++i)
        pattern[i] = static_cast<unsigned char>((i * 37 + 11) & 0xFF);
    ASSERT_EQ(cudaMemcpy(device_buffer.get(), pattern.data(), pattern.size(),
                         cudaMemcpyHostToDevice),
              cudaSuccess);

    auto engine = std::make_unique<TransferEngine>(false);
    const std::string server_name = "127.0.0.2:17931";
    const auto hostname_port = parseHostNameWithPort(server_name);
    ASSERT_EQ(engine->init(P2PHANDSHAKE, server_name,
                           hostname_port.first.c_str(), hostname_port.second),
              0);
    ASSERT_NE(engine->installTransport("tcp", nullptr), nullptr);
    ASSERT_EQ(
        engine->registerLocalMemory(device_buffer.get(), kBufferSize, "cuda:0"),
        0);

    const auto segment_id = engine->openSegment(engine->getLocalIpAndPort());
    const auto segment_desc =
        engine->getMetadata()->getSegmentDescByID(segment_id);
    ASSERT_NE(segment_desc, nullptr);
    ASSERT_FALSE(segment_desc->buffers.empty());
    const uint64_t remote_base = segment_desc->buffers[0].addr;
    auto* device_bytes = static_cast<unsigned char*>(device_buffer.get());

    tcpTransportResetStagingStatsForTest();
    TransferRequest write;
    write.opcode = TransferRequest::WRITE;
    write.length = kTransferSize;
    write.source = device_bytes;
    write.target_id = segment_id;
    write.target_offset = remote_base + kTransferSize;
    ASSERT_EQ(runOne(engine.get(), write), TransferStatusEnum::COMPLETED);
    EXPECT_EQ(tcpTransportStagingDeviceQueryCountForTest(), 2u);
    EXPECT_EQ(tcpTransportStagingBufferAllocationCountForTest(), 2u);

    std::vector<unsigned char> actual(kTransferSize);
    ASSERT_EQ(cudaMemcpy(actual.data(), device_bytes + kTransferSize,
                         actual.size(), cudaMemcpyDeviceToHost),
              cudaSuccess);
    EXPECT_EQ(actual, pattern);

    tcpTransportResetStagingStatsForTest();
    TransferRequest read;
    read.opcode = TransferRequest::READ;
    read.length = kTransferSize;
    read.source = device_bytes + 2 * kTransferSize;
    read.target_id = segment_id;
    read.target_offset = remote_base + kTransferSize;
    ASSERT_EQ(runOne(engine.get(), read), TransferStatusEnum::COMPLETED);
    EXPECT_EQ(tcpTransportStagingDeviceQueryCountForTest(), 2u);
    // The persistent server session retains its staging buffer, and the new
    // client session reuses the pinned block released by the WRITE's session.
    EXPECT_EQ(tcpTransportStagingBufferAllocationCountForTest(), 0u);

    ASSERT_EQ(cudaMemcpy(actual.data(), device_bytes + 2 * kTransferSize,
                         actual.size(), cudaMemcpyDeviceToHost),
              cudaSuccess);
    EXPECT_EQ(actual, pattern);

    EXPECT_EQ(engine->unregisterLocalMemory(device_buffer.get()), 0);
    engine.reset();
}

// Holds every blocking stream on the current device (and therefore the
// legacy default stream) until release() is called, standing in for an
// application whose kernels keep the GPU busy.
class LegacyStreamBlocker {
   public:
    LegacyStreamBlocker() {
        if (cudaStreamCreate(&stream_) != cudaSuccess) return;
        if (cudaLaunchHostFunc(stream_, &LegacyStreamBlocker::wait,
                               &released_) != cudaSuccess)
            return;
        armed_ = true;
    }
    ~LegacyStreamBlocker() {
        release();
        if (stream_) {
            cudaStreamSynchronize(stream_);
            cudaStreamDestroy(stream_);
        }
    }
    bool armed() const { return armed_; }
    void release() { released_.store(true); }

   private:
    static void wait(void* flag) {
        auto* released = static_cast<std::atomic<bool>*>(flag);
        while (!released->load())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    cudaStream_t stream_ = nullptr;
    std::atomic<bool> released_{false};
    bool armed_ = false;
};

// Device<->staging copies must not be ordered behind the application's work:
// with the legacy default stream every slice waited for all queued kernels.
TEST(TcpCudaStagingTest, DeviceTransfersDoNotWaitForBusyBlockingStreams) {
    int device_count = 0;
    cudaError_t cuda_status = cudaGetDeviceCount(&device_count);
    if (cuda_status != cudaSuccess || device_count == 0) {
        GTEST_SKIP() << "CUDA device unavailable";
    }
    ASSERT_EQ(cudaSetDevice(0), cudaSuccess);

    ScopedEnvVar connection_pool("MC_TCP_ENABLE_CONNECTION_POOL", "1");
    ScopedEnvVar lanes("MC_TCP_LANES_PER_PEER", "1");
    ScopedEnvVar slice_size("MC_TCP_SLICE_SIZE", "65536");

    constexpr size_t kTransferSize = 4 * 64 * 1024;
    constexpr size_t kBufferSize = 3 * kTransferSize;

    DeviceBuffer device_buffer;
    ASSERT_EQ(cudaMalloc(device_buffer.out(), kBufferSize), cudaSuccess);
    std::vector<unsigned char> pattern(kTransferSize);
    for (size_t i = 0; i < pattern.size(); ++i)
        pattern[i] = static_cast<unsigned char>((i * 13 + 5) & 0xFF);
    ASSERT_EQ(cudaMemcpy(device_buffer.get(), pattern.data(), pattern.size(),
                         cudaMemcpyHostToDevice),
              cudaSuccess);

    auto engine = std::make_unique<TransferEngine>(false);
    const std::string server_name = "127.0.0.2:17933";
    const auto hostname_port = parseHostNameWithPort(server_name);
    ASSERT_EQ(engine->init(P2PHANDSHAKE, server_name,
                           hostname_port.first.c_str(), hostname_port.second),
              0);
    ASSERT_NE(engine->installTransport("tcp", nullptr), nullptr);
    ASSERT_EQ(
        engine->registerLocalMemory(device_buffer.get(), kBufferSize, "cuda:0"),
        0);
    const auto segment_id = engine->openSegment(engine->getLocalIpAndPort());
    const auto segment_desc =
        engine->getMetadata()->getSegmentDescByID(segment_id);
    ASSERT_NE(segment_desc, nullptr);
    ASSERT_FALSE(segment_desc->buffers.empty());
    const uint64_t remote_base = segment_desc->buffers[0].addr;
    auto* device_bytes = static_cast<unsigned char*>(device_buffer.get());

    TransferStatusEnum write_status, read_status;
    {
        LegacyStreamBlocker blocker;
        ASSERT_TRUE(blocker.armed());

        TransferRequest write;
        write.opcode = TransferRequest::WRITE;
        write.length = kTransferSize;
        write.source = device_bytes;
        write.target_id = segment_id;
        write.target_offset = remote_base + kTransferSize;
        write_status = runOne(engine.get(), write);

        TransferRequest read;
        read.opcode = TransferRequest::READ;
        read.length = kTransferSize;
        read.source = device_bytes + 2 * kTransferSize;
        read.target_id = segment_id;
        read.target_offset = remote_base + kTransferSize;
        read_status = runOne(engine.get(), read);
        // Release before asserting so a regression fails instead of hanging
        // in the blocker's destructor behind a stuck copy.
        blocker.release();
    }
    EXPECT_EQ(write_status, TransferStatusEnum::COMPLETED);
    EXPECT_EQ(read_status, TransferStatusEnum::COMPLETED);

    std::vector<unsigned char> actual(kTransferSize);
    ASSERT_EQ(cudaMemcpy(actual.data(), device_bytes + 2 * kTransferSize,
                         actual.size(), cudaMemcpyDeviceToHost),
              cudaSuccess);
    EXPECT_EQ(actual, pattern);

    EXPECT_EQ(engine->unregisterLocalMemory(device_buffer.get()), 0);
    engine.reset();
}

}  // namespace
