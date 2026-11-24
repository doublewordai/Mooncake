// Secure mode (DW-1288): the transport decorator over TCP loopback.
// Memory reaches the NIC (the published segment) only inside a
// CiphertextRegistrationScope, and transfers from other memory are refused.

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <memory>
#include <vector>

#include "secure/kv_crypto.h"
#include "secure/secure_transport.h"
#include "secure/staging_pool.h"
#include "transfer_engine.h"
#include "transport/transport.h"

namespace mooncake {
namespace secure {
namespace {

class SecureTransportTest : public ::testing::Test {
   protected:
    static void SetUpTestSuite() {
        SecureConfig cfg;
        cfg.enabled = true;
        cfg.key_inline = std::string(64, '7');
        SecureContext::ResetForTesting(
            SecureContext::CreateForTesting(cfg, nullptr));
        ASSERT_TRUE(SecureContext::Global().enabled());
        ASSERT_FALSE(SecureContext::Global().failed());
    }
    static void TearDownTestSuite() { SecureContext::ResetForTesting(nullptr); }

    void SetUp() override {
        engine_ = std::make_unique<TransferEngine>(false);
        ASSERT_EQ(engine_->init("P2PHANDSHAKE", "127.0.0.1:17123", "127.0.0.1",
                                17123),
                  0);
        xport_ = engine_->installTransport("tcp", nullptr);
        ASSERT_NE(xport_, nullptr);
        seg_ = engine_->openSegment(engine_->getLocalIpAndPort());
    }

    void TearDown() override { engine_.reset(); }

    size_t PublishedBuffers() {
        auto desc = engine_->getMetadata()->getSegmentDescByID(seg_, true);
        return desc ? desc->buffers.size() : 0;
    }

    bool Published(void* p) {
        auto desc = engine_->getMetadata()->getSegmentDescByID(seg_, true);
        if (!desc) return false;
        for (auto& b : desc->buffers)
            if (b.addr == reinterpret_cast<uint64_t>(p)) return true;
        return false;
    }

    Status Write(void* src, void* dst, size_t len) {
        auto batch = engine_->allocateBatchID(1);
        TransferRequest r;
        r.opcode = TransferRequest::WRITE;
        r.source = src;
        r.target_id = seg_;
        r.target_offset = reinterpret_cast<uint64_t>(dst);
        r.length = len;
        Status s = engine_->submitTransfer(batch, {r});
        if (s.ok()) {
            TransferStatus st;
            auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (std::chrono::steady_clock::now() < deadline) {
                engine_->getTransferStatus(batch, 0, st);
                if (st.s == TransferStatusEnum::COMPLETED ||
                    st.s == TransferStatusEnum::FAILED)
                    break;
            }
            if (st.s != TransferStatusEnum::COMPLETED)
                s = Status::Context("transfer did not complete");
        }
        engine_->freeBatchID(batch);
        return s;
    }

    std::unique_ptr<TransferEngine> engine_;
    Transport* xport_ = nullptr;
    Transport::SegmentHandle seg_ = 0;
};

TEST_F(SecureTransportTest, InstalledTransportIsTheDecorator) {
    EXPECT_NE(dynamic_cast<SecureTransport*>(xport_), nullptr);
}

TEST_F(SecureTransportTest, OnlyCiphertextMemoryIsPublished) {
    std::vector<char> user(1 << 16, 'p');  // "plaintext" (e.g. a KV cache)
    ASSERT_EQ(engine_->registerLocalMemory(user.data(), user.size(), "cpu:0"),
              0);
    EXPECT_FALSE(Published(user.data()));
    // Registering local-only memory brings up the secure push receiver,
    // whose receive staging is published.
    ASSERT_TRUE(dynamic_cast<SecureTransport*>(xport_)
                    ->push_service()
                    ->receiver_enabled());
    const size_t before = PublishedBuffers();

    StagingPool pool(
        1 << 20, 8 << 20,
        [&](void* p, size_t n) {
            CiphertextRegistrationScope scope;
            return engine_->registerLocalMemory(p, n, "cpu:0");
        },
        [&](void* p) { return engine_->unregisterLocalMemory(p); });
    auto a = pool.Allocate(4096);
    auto b = pool.Allocate(4096);
    ASSERT_TRUE(a && b);
    EXPECT_EQ(PublishedBuffers(), before + 1);  // the staging region only

    auto* st = dynamic_cast<SecureTransport*>(xport_);
    EXPECT_TRUE(st->IsCiphertextMemory(a.data(), 4096));
    EXPECT_FALSE(st->IsCiphertextMemory(user.data(), 16));

    // Staging to staging works.
    std::memset(a.data(), 0x5c, 4096);
    std::memset(b.data(), 0, 4096);
    ASSERT_TRUE(Write(a.data(), b.data(), 4096).ok());
    EXPECT_EQ(static_cast<uint8_t*>(b.data())[4095], 0x5c);

    // A write from local-only memory becomes a secure push, which the
    // receiver refuses because the destination is ciphertext memory, not
    // local-only memory.
    Status s = Write(user.data(), b.data(), 4096);
    EXPECT_FALSE(s.ok());
    EXPECT_EQ(static_cast<uint8_t*>(b.data())[0], 0x5c);

    // A transfer that runs off the end of a staging region is refused too.
    auto* region_end = static_cast<char*>(a.data()) + (1 << 20) - 16;
    EXPECT_FALSE(st->IsCiphertextMemory(region_end, 4096));

    ASSERT_EQ(engine_->unregisterLocalMemory(user.data()), 0);
}

}  // namespace
}  // namespace secure
}  // namespace mooncake
