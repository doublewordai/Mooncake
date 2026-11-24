// Secure mode (DW-1288): the store decorator end to end, two clients over TCP
// with an in-process master. Values are sealed before they leave the caller,
// stored as ciphertext, verified on get, and every path the decorator cannot
// authenticate is refused.

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "real_client.h"
#include "secure/kv_crypto.h"
#include "secure/secure_py_client.h"
#include "secure/secure_transport.h"
#include "test_server_helpers.h"

namespace mooncake {
namespace secure {
namespace {

using mooncake::testing::InProcMaster;
using mooncake::InProcMasterConfigBuilder;

std::vector<char> Pattern(size_t n, uint32_t seed) {
    std::mt19937 g(seed);
    std::vector<char> v(n);
    for (auto& c : v) c = static_cast<char>('a' + g() % 26);
    return v;
}

bool Contains(const char* hay, size_t n, const std::vector<char>& needle,
              size_t needle_len) {
    std::string h(hay, n), s(needle.data(), needle_len);
    return h.find(s) != std::string::npos;
}

class SecureStoreTest : public ::testing::Test {
   protected:
    static void SetUpTestSuite() {
        SecureConfig cfg;
        cfg.enabled = true;
        cfg.key_inline = std::string(64, 'c');
        cfg.staging_region_bytes = 4 << 20;
        cfg.staging_max_bytes = 8 << 20;
        SecureContext::ResetForTesting(
            SecureContext::CreateForTesting(cfg, nullptr));
        ASSERT_FALSE(SecureContext::Global().failed());
    }
    static void TearDownTestSuite() { SecureContext::ResetForTesting(nullptr); }

    void SetUp() override {
        ASSERT_TRUE(master_.Start(InProcMasterConfigBuilder().build()));
        inner_a_ = RealClient::create();
        inner_b_ = RealClient::create();
        a_ = std::make_shared<SecurePyClient>(inner_a_);
        b_ = std::make_shared<SecurePyClient>(inner_b_);
        ASSERT_EQ(Setup(*a_, "localhost:17941"), 0);
        ASSERT_EQ(Setup(*b_, "localhost:17942"), 0);
    }

    void TearDown() override {
        if (a_) a_->tearDownAll();
        if (b_) b_->tearDownAll();
        a_.reset();
        b_.reset();
        inner_a_.reset();
        inner_b_.reset();
        master_.Stop();
    }

    int Setup(SecurePyClient& c, const std::string& host) {
        return c.setup_real(host, "P2PHANDSHAKE", 32 << 20, 16 << 20, "tcp",
                            "", master_.master_address(), nullptr, "", false,
                            "", "default", false, DEFAULT_CLIENT_HTTP_PORT);
    }

    ReplicateConfig On(const std::string& host) {
        ReplicateConfig c;
        c.replica_num = 1;
        c.preferred_segment = host;
        return c;
    }

    InProcMaster master_;
    std::shared_ptr<RealClient> inner_a_, inner_b_;
    std::shared_ptr<SecurePyClient> a_, b_;
};

TEST_F(SecureStoreTest, RoundTripLocalAndRemote) {
    for (const char* where : {"localhost:17941", "localhost:17942"}) {
        const std::string key = std::string("rt-") + where;
        auto value = Pattern(300000, 1);
        ASSERT_EQ(a_->put_from(key, value.data(), value.size(), On(where)), 0);
        EXPECT_EQ(a_->getSize(key), int64_t(value.size()));
        for (auto* reader : {a_.get(), b_.get()}) {
            std::vector<char> out(value.size() + 100, 0);
            ASSERT_EQ(reader->get_into(key, out.data(), out.size()),
                      int64_t(value.size()))
                << where;
            EXPECT_EQ(0, std::memcmp(out.data(), value.data(), value.size()));
        }
    }
}

TEST_F(SecureStoreTest, StoredBytesAreCiphertextBoundToTheKey) {
    auto value = Pattern(50000, 2);
    ASSERT_EQ(a_->put_from("ct", value.data(), value.size(),
                           On("localhost:17942")),
              0);
    // The store holds header + ciphertext + tag.
    const int64_t sealed = inner_a_->getSize("ct");
    ASSERT_EQ(sealed, int64_t(value.size() + kOverhead));

    // Read the raw object through the inner client into staging.
    auto raw = a_->staging()->Allocate(sealed);
    ASSERT_TRUE(raw);
    ASSERT_EQ(inner_a_->get_into("ct", raw.data(), sealed), sealed);
    SealedInfo info;
    ASSERT_EQ(ParseHeader({raw.data(), size_t(sealed)}, &info), Error::kOk);
    EXPECT_EQ(info.purpose, Purpose::kStoreObject);
    EXPECT_EQ(info.plaintext_len, value.size());
    EXPECT_FALSE(Contains(static_cast<char*>(raw.data()), sealed, value, 32));

    // Re-storing those exact bytes under another key does not open there.
    ASSERT_EQ(inner_a_->put_from("ct-moved", raw.data(), sealed,
                                 On("localhost:17941")),
              0);
    std::vector<char> out(value.size(), 'x');
    EXPECT_EQ(b_->get_into("ct-moved", out.data(), out.size()),
              toInt(ErrorCode::CHECKSUM_MISMATCH));
    EXPECT_TRUE(std::all_of(out.begin(), out.end(),
                            [](char c) { return c == 0; }));

    // A flipped byte is detected and the caller's buffer stays zeroed.
    static_cast<char*>(raw.data())[kHeaderSize + 1000] ^= 1;
    ASSERT_EQ(inner_a_->put_from("ct-tampered", raw.data(), sealed,
                                 On("localhost:17942")),
              0);
    std::fill(out.begin(), out.end(), 'x');
    EXPECT_EQ(a_->get_into("ct-tampered", out.data(), out.size()),
              toInt(ErrorCode::CHECKSUM_MISMATCH));
    EXPECT_TRUE(std::all_of(out.begin(), out.end(),
                            [](char c) { return c == 0; }));
}

TEST_F(SecureStoreTest, BatchMultiBufferRoundTripUnderStagingPressure) {
    // 8 MiB staging cap, 6 x 1.5 MiB values: the decorator has to split the
    // batch.
    std::vector<std::string> keys;
    std::vector<std::vector<char>> values;
    std::vector<std::vector<void*>> bufs;
    std::vector<std::vector<size_t>> sizes;
    for (int i = 0; i < 6; ++i) {
        keys.push_back("batch-" + std::to_string(i));
        values.push_back(Pattern(1536 * 1024, 10 + i));
        auto& v = values.back();
        bufs.push_back({v.data(), v.data() + 1000});
        sizes.push_back({1000, v.size() - 1000});
    }
    auto put = a_->batch_put_from_multi_buffers(keys, bufs, sizes,
                                                On("localhost:17942"));
    for (int r : put) EXPECT_EQ(r, 0);

    std::vector<std::vector<char>> outs(6);
    std::vector<std::vector<void*>> obufs;
    std::vector<std::vector<size_t>> osizes;
    for (int i = 0; i < 6; ++i) {
        outs[i].assign(values[i].size(), 0);
        obufs.push_back({outs[i].data(), outs[i].data() + 7});
        osizes.push_back({7, outs[i].size() - 7});
    }
    auto got = b_->batch_get_into_multi_buffers(keys, obufs, osizes, false);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(got[i], int(values[i].size()));
        EXPECT_EQ(outs[i], values[i]);
    }
    EXPECT_EQ(b_->staging()->free_bytes(), b_->staging()->mapped_bytes());
}

TEST_F(SecureStoreTest, PathsThatCannotBeAuthenticatedAreRefused) {
    auto value = Pattern(4096, 3);
    ASSERT_EQ(a_->put_from("r", value.data(), value.size(), On("localhost:17941")),
              0);
    std::vector<char> out(4096);
    auto ranges = a_->get_into_ranges(
        {out.data()}, {{"r"}}, {{{0}}}, {{{0}}}, {{{100}}}, nullptr);
    ASSERT_EQ(ranges.size(), 1u);
    EXPECT_LT(ranges[0][0][0], 0);
    EXPECT_EQ(a_->get_buffer("r"), nullptr);
    EXPECT_LT(a_->put_from_with_metadata("m", value.data(), value.data(), 10,
                                         10, ReplicateConfig{}),
              0);
    EXPECT_LT(a_->setup_dummy(1, 1, "", ""), 0);
    auto sess = a_->batch_put_session_start({"s"}, {10}, ReplicateConfig{});
    EXPECT_LT(sess[0], 0);
    EXPECT_FALSE(a_->allocate_client_buffer(10).has_value());
}

TEST_F(SecureStoreTest, PlaintextCannotReachTheFabricEvenThroughTheInner) {
    // Someone bypassing the decorator with a caller buffer: it is registered
    // local-only, so a write to a remote segment is refused by the transport.
    auto value = Pattern(65536, 4);
    ASSERT_EQ(inner_a_->register_buffer(value.data(), value.size()), 0);
    EXPECT_NE(inner_a_->put_from("leak", value.data(), value.size(),
                                 On("localhost:17942")),
              0);
    EXPECT_NE(inner_a_->isExist("leak"), 1);
    inner_a_->unregister_buffer(value.data());
}

}  // namespace
}  // namespace secure
}  // namespace mooncake
