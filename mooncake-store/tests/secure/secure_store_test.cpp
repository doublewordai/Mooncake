// Secure mode (DW-1288): the store decorator end to end, two clients over TCP
// with an in-process master. Values are sealed before they leave the caller,
// from host or GPU memory, stored as sealed objects of independently
// authenticated segments, verified on get before any plaintext reaches the
// caller, and every path the decorator cannot authenticate is refused.

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef USE_CUDA
#include <cuda_runtime.h>
#endif

#include "real_client.h"
#include "secure/kv_crypto.h"
#include "store_c.h"
#include "secure/sealed_object.h"
#include "secure/secure_py_client.h"
#include "secure/secure_transport.h"
#include "test_server_helpers.h"

namespace mooncake {
namespace secure {
namespace {

using mooncake::testing::InProcMaster;
using mooncake::InProcMasterConfigBuilder;

constexpr size_t kTestSegment = 64 << 10;  // MC_SECURE_STORE_SEGMENT_BYTES

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

bool AllEqual(const std::vector<char>& v, char c) {
    return std::all_of(v.begin(), v.end(), [c](char x) { return x == c; });
}

bool HaveGpu() {
#ifdef USE_CUDA
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess || count == 0) {
        cudaGetLastError();
        return false;
    }
    return true;
#else
    return false;
#endif
}

#ifdef USE_CUDA
// Device memory filled with `fill`, or holding a copy of `init`.
struct DevBuf {
    void* p = nullptr;
    size_t n = 0;
    explicit DevBuf(size_t bytes, int fill = 0) : n(bytes) {
        EXPECT_EQ(cudaMalloc(&p, n), cudaSuccess);
        EXPECT_EQ(cudaMemset(p, fill, n), cudaSuccess);
    }
    explicit DevBuf(const std::vector<char>& init) : DevBuf(init.size()) {
        EXPECT_EQ(cudaMemcpy(p, init.data(), n, cudaMemcpyHostToDevice),
                  cudaSuccess);
    }
    ~DevBuf() {
        if (p) cudaFree(p);
    }
    char* at(size_t off) const { return static_cast<char*>(p) + off; }
    std::vector<char> Host() const {
        std::vector<char> v(n);
        EXPECT_EQ(cudaMemcpy(v.data(), p, n, cudaMemcpyDeviceToHost),
                  cudaSuccess);
        return v;
    }
};
#endif

// --------------------------------------------------------------- fixture --

class SecureStoreTest : public ::testing::Test {
   protected:
    static void SetUpTestSuite() {
        setenv("MC_SECURE_STORE_SEGMENT_BYTES",
               std::to_string(kTestSegment).c_str(), 1);
        setenv("MC_SECURE_STORE_THREADS", "4", 1);
        SecureConfig cfg;
        cfg.enabled = true;
        cfg.key_inline = std::string(64, 'c');
        cfg.staging_region_bytes = 4 << 20;
        cfg.staging_max_bytes = 8 << 20;
        SecureContext::ResetForTesting(
            SecureContext::CreateForTesting(cfg, nullptr));
        ASSERT_FALSE(SecureContext::Global().failed());
    }
    static void TearDownTestSuite() {
        SecureContext::ResetForTesting(nullptr);
        unsetenv("MC_SECURE_STORE_SEGMENT_BYTES");
        unsetenv("MC_SECURE_STORE_THREADS");
    }

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

    // The stored (sealed) bytes of `key`, read around the decorator.
    std::vector<char> Raw(const std::string& key) {
        const int64_t sealed = inner_a_->getSize(key);
        EXPECT_GT(sealed, 0);
        if (sealed <= 0) return {};
        auto buf = a_->staging()->Allocate(sealed);
        EXPECT_TRUE(buf);
        EXPECT_EQ(inner_a_->get_into(key, buf.data(), sealed), sealed);
        auto* p = static_cast<char*>(buf.data());
        return std::vector<char>(p, p + sealed);
    }

    // Stores `bytes` as `key` around the decorator, as someone with access to
    // the store (but not the key) could.
    void PutRaw(const std::string& key, const std::vector<char>& bytes,
                const std::string& where = "localhost:17942") {
        auto buf = a_->staging()->Allocate(bytes.size());
        ASSERT_TRUE(buf);
        std::memcpy(buf.data(), bytes.data(), bytes.size());
        ASSERT_EQ(inner_a_->put_from(key, buf.data(), bytes.size(), On(where)),
                  0);
    }

    // Both readers get CHECKSUM_MISMATCH for `key`, and a host buffer holds
    // no plaintext: the length the (tampered) header claims is zeroed, the
    // rest untouched (all of it untouched if rejected before opening).
    void ExpectRejected(const std::string& key, size_t size,
                        const std::string& why) {
        for (auto* reader : {a_.get(), b_.get()}) {
            std::vector<char> out(size, 'x');
            EXPECT_EQ(reader->get_into(key, out.data(), out.size()),
                      toInt(ErrorCode::CHECKSUM_MISMATCH))
                << why;
            auto rest = std::find_if(out.begin(), out.end(),
                                     [](char c) { return c != 0; });
            EXPECT_TRUE(std::all_of(rest, out.end(),
                                    [](char c) { return c == 'x'; }))
                << why;
        }
    }

    InProcMaster master_;
    std::shared_ptr<RealClient> inner_a_, inner_b_;
    std::shared_ptr<SecurePyClient> a_, b_;
};

ObjectLayout LayoutOf(const std::vector<char>& raw) {
    ObjectLayout l;
    EXPECT_TRUE(ParseObject({raw.data(), raw.size()}, raw.size(), &l));
    return l;
}

// Byte range [begin, end) of segment i inside a sealed object.
std::pair<size_t, size_t> SegmentRange(const ObjectLayout& l, uint32_t i) {
    const size_t b = l.SealedOffset(i);
    return {b, b + kOverhead + l.PlainLength(i)};
}

// ------------------------------------------------------------------ host --

TEST_F(SecureStoreTest, RoundTripLocalAndRemote) {
    for (const char* where : {"localhost:17941", "localhost:17942"}) {
        const std::string key = std::string("rt-") + where;
        auto value = Pattern(300000, 1);  // 5 segments, the last partial
        ASSERT_EQ(a_->put_from(key, value.data(), value.size(), On(where)), 0);
        EXPECT_EQ(a_->getSize(key), int64_t(value.size()));
        EXPECT_EQ(b_->getSize(key), int64_t(value.size()));
        for (auto* reader : {a_.get(), b_.get()}) {
            std::vector<char> out(value.size() + 100, 0);
            ASSERT_EQ(reader->get_into(key, out.data(), out.size()),
                      int64_t(value.size()))
                << where;
            EXPECT_EQ(0, std::memcmp(out.data(), value.data(), value.size()));
        }
    }
}

TEST_F(SecureStoreTest, EmptyAndSegmentBoundaryValues) {
    for (size_t n : {size_t(0), size_t(1), kTestSegment - 1, kTestSegment,
                     kTestSegment + 1, 3 * kTestSegment}) {
        const std::string key = "edge-" + std::to_string(n);
        auto value = Pattern(n, 7);
        ASSERT_EQ(a_->put_from(key, value.data(), n, On("localhost:17942")), 0)
            << n;
        EXPECT_EQ(Raw(key).size(), SealedObjectSize(n, kTestSegment)) << n;
        std::vector<char> out(n + 1, 'x');
        ASSERT_EQ(b_->get_into(key, out.data(), out.size()), int64_t(n)) << n;
        EXPECT_EQ(0, std::memcmp(out.data(), value.data(), n)) << n;
        EXPECT_EQ(out[n], 'x') << n;  // nothing past the plaintext
    }
}

TEST_F(SecureStoreTest, StoredBytesAreSegmentedCiphertextBoundToTheKey) {
    auto value = Pattern(200000, 2);
    ASSERT_EQ(a_->put_from("ct", value.data(), value.size(),
                           On("localhost:17942")),
              0);
    auto raw = Raw("ct");
    ASSERT_EQ(raw.size(), SealedObjectSize(value.size(), kTestSegment));
    const ObjectLayout l = LayoutOf(raw);
    EXPECT_EQ(l.version, kObjectVersion);
    EXPECT_EQ(l.plaintext_len, value.size());
    EXPECT_EQ(l.segment_bytes, kTestSegment);
    ASSERT_EQ(l.segment_count, 4u);
    for (uint32_t i = 0; i < l.segment_count; ++i) {
        auto [b, e] = SegmentRange(l, i);
        SealedInfo info;
        ASSERT_EQ(ParseHeader({raw.data() + b, e - b}, &info), Error::kOk);
        EXPECT_EQ(info.purpose, Purpose::kStoreObject);
        EXPECT_EQ(info.plaintext_len, l.PlainLength(i));
    }
    EXPECT_FALSE(Contains(raw.data(), raw.size(), value, 32));

    // Re-storing those exact bytes under another key does not open there.
    PutRaw("ct-moved", raw, "localhost:17941");
    ExpectRejected("ct-moved", value.size(), "moved to another key");
}

TEST_F(SecureStoreTest, TamperingWithAnySegmentOrTheHeaderIsDetected) {
    auto value = Pattern(300000, 3);
    ASSERT_EQ(a_->put_from("t", value.data(), value.size(),
                           On("localhost:17942")),
              0);
    const auto raw = Raw("t");
    const ObjectLayout l = LayoutOf(raw);
    ASSERT_EQ(l.segment_count, 5u);
    int n = 0;
    for (uint32_t i = 0; i < l.segment_count; ++i) {
        auto [b, e] = SegmentRange(l, i);
        // the segment's header, its ciphertext, its tag
        for (size_t at : {b + 20, b + kHeaderSize + 7, e - 1}) {
            auto bad = raw;
            bad[at] ^= 1;
            const std::string key = "t-" + std::to_string(n++);
            PutRaw(key, bad);
            ExpectRejected(key, value.size(),
                           "segment " + std::to_string(i) + " byte " +
                               std::to_string(at));
        }
    }
    for (size_t at = 0; at < kObjectHeaderSize; ++at) {
        auto bad = raw;
        bad[at] ^= 1;
        const std::string key = "t-h" + std::to_string(at);
        PutRaw(key, bad);
        ExpectRejected(key, value.size(), "header byte " + std::to_string(at));
    }
}

TEST_F(SecureStoreTest, ReorderSpliceDuplicateAndTruncateAreDetected) {
    auto va = Pattern(4 * kTestSegment, 4);
    auto vb = Pattern(4 * kTestSegment, 5);
    ASSERT_EQ(a_->put_from("A", va.data(), va.size(), On("localhost:17942")),
              0);
    ASSERT_EQ(a_->put_from("B", vb.data(), vb.size(), On("localhost:17942")),
              0);
    const auto ra = Raw("A"), rb = Raw("B");
    const ObjectLayout l = LayoutOf(ra);
    ASSERT_EQ(l.segment_count, 4u);
    auto seg = [&](const std::vector<char>& r, uint32_t i) {
        auto [b, e] = SegmentRange(l, i);
        return std::vector<char>(r.begin() + b, r.begin() + e);
    };
    auto with = [&](std::vector<char> r, uint32_t i,
                    const std::vector<char>& s) {
        std::copy(s.begin(), s.end(), r.begin() + SegmentRange(l, i).first);
        return r;
    };
    auto set_header = [](std::vector<char>& r, uint32_t count, uint32_t segb,
                         uint64_t len) {
        std::memcpy(r.data() + 8, &count, 4);
        std::memcpy(r.data() + 12, &segb, 4);
        std::memcpy(r.data() + 16, &len, 8);
        ObjectLayout t;
        EXPECT_TRUE(ParseObject({r.data(), r.size()}, r.size(), &t));
    };

    // Reorder: segments 1 and 2 swapped (full segments of the same size).
    PutRaw("A-swap", with(with(ra, 1, seg(ra, 2)), 2, seg(ra, 1)));
    ExpectRejected("A-swap", va.size(), "reordered");
    // Duplicate: segment 0 in place of segment 1.
    PutRaw("A-dup", with(ra, 1, seg(ra, 0)));
    ExpectRejected("A-dup", va.size(), "duplicated");
    // Splice: B's segment 2 in A's place 2.
    PutRaw("A-splice", with(ra, 2, seg(rb, 2)));
    ExpectRejected("A-splice", va.size(), "spliced across objects");
    // A header that parses and keeps the size but moves the segment
    // boundaries.
    {
        auto r = ra;
        set_header(r, 4, 70000, 4 * kTestSegment);
        PutRaw("A-reseg", r);
        ExpectRejected("A-reseg", va.size(), "re-segmented header");
    }
    // Truncate: the last segment dropped, header unchanged (fails the size
    // check) ...
    {
        std::vector<char> r(ra.begin(), ra.begin() + SegmentRange(l, 3).first);
        PutRaw("A-trunc", r);
        ExpectRejected("A-trunc", va.size(), "truncated");
    }
    // ... and with the header rewritten to claim three segments (every
    // remaining segment authenticated the original header).
    {
        std::vector<char> r(ra.begin(), ra.begin() + SegmentRange(l, 3).first);
        set_header(r, 3, kTestSegment, 3 * kTestSegment);
        PutRaw("A-trunc-hdr", r);
        ExpectRejected("A-trunc-hdr", va.size(), "truncated, header fixed");
    }
    // Extend: B's last segment appended, header fixed to five segments.
    {
        auto r = ra;
        auto extra = seg(rb, 3);
        r.insert(r.end(), extra.begin(), extra.end());
        set_header(r, 5, kTestSegment, 5 * kTestSegment);
        PutRaw("A-ext", r);
        ExpectRejected("A-ext", 5 * kTestSegment, "extended");
    }
    // The untouched object still opens.
    std::vector<char> out(va.size());
    EXPECT_EQ(b_->get_into("A", out.data(), out.size()), int64_t(va.size()));
    EXPECT_EQ(out, va);
}

TEST_F(SecureStoreTest, VersionOneObjectsStillOpen) {
    // A value sealed whole in the previous format (one message, AAD binding
    // the key).
    auto value = Pattern(100000, 6);
    auto& sealer = SecureContext::Global().sealer(Purpose::kStoreObject);
    std::vector<char> raw(SealedSize(value.size()));
    const std::string aad = LegacyObjectAad("v1");
    ConstSpan in{value.data(), value.size()};
    size_t n = 0;
    ASSERT_EQ(sealer.Seal(&in, 1, {aad.data(), aad.size()},
                          {raw.data(), raw.size()}, &n),
              Error::kOk);
    PutRaw("v1", raw);
    EXPECT_EQ(b_->getSize("v1"), int64_t(value.size()));
    std::vector<char> out(value.size());
    ASSERT_EQ(b_->get_into("v1", out.data(), out.size()),
              int64_t(value.size()));
    EXPECT_EQ(out, value);
    PutRaw("v1-moved", raw);
    ExpectRejected("v1-moved", value.size(), "v1 moved to another key");
    // A version-2 segment presented as a whole version-1 object.
    ASSERT_EQ(a_->put_from("v2", value.data(), value.size(),
                           On("localhost:17942")),
              0);
    const auto r2 = Raw("v2");
    auto [b, e] = SegmentRange(LayoutOf(r2), 0);
    PutRaw("v2-seg-as-v1", std::vector<char>(r2.begin() + b, r2.begin() + e));
    ExpectRejected("v2-seg-as-v1", value.size(), "v2 segment as a v1 object");
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

TEST_F(SecureStoreTest, ConcurrentPutsAndGets) {
    constexpr int kThreads = 8, kRounds = 6;
    std::atomic<int> failures{0};
    std::vector<std::thread> ts;
    for (int t = 0; t < kThreads; ++t) {
        ts.emplace_back([&, t] {
            auto* writer = (t % 2) ? a_.get() : b_.get();
            auto* reader = (t % 2) ? b_.get() : a_.get();
            for (int r = 0; r < kRounds; ++r) {
                const std::string key =
                    "cc-" + std::to_string(t) + "-" + std::to_string(r);
                auto value = Pattern(200000 + 977 * t + r, 100 * t + r);
                // Three pieces, so segments straddle buffers.
                std::vector<void*> in{value.data(), value.data() + 70001,
                                      value.data() + 140003};
                std::vector<size_t> ins{70001, 70002, value.size() - 140003};
                auto put = writer->batch_put_from_multi_buffers(
                    {key}, {in}, {ins},
                    On(t % 3 ? "localhost:17942" : "localhost:17941"));
                if (put.size() != 1 || put[0] != 0) {
                    ++failures;
                    continue;
                }
                std::vector<char> out(value.size(), 0);
                auto got = reader->batch_get_into_multi_buffers(
                    {key}, {{out.data()}}, {{out.size()}}, false);
                if (got.size() != 1 || got[0] != int(value.size()) ||
                    out != value)
                    ++failures;
                writer->remove(key, true);
            }
        });
    }
    for (auto& t : ts) t.join();
    EXPECT_EQ(failures.load(), 0);
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

// Entry points that do not seal refuse to operate in secure mode: the C API
// (and so the Rust and Go bindings, which wrap it) creates no client, and a
// RealClient set up anywhere but inside SecurePyClient refuses setup, so no
// plaintext put can reach a store segment through it.
TEST_F(SecureStoreTest, EntryPointsAroundTheDecoratorAreRefused) {
    EXPECT_EQ(mooncake_store_create(), nullptr);

    auto direct = RealClient::create();
    EXPECT_NE(direct->setup_real("localhost:17943", "P2PHANDSHAKE", 32 << 20,
                                 16 << 20, "tcp", "", master_.master_address(),
                                 nullptr, "", false, "", "default", false,
                                 DEFAULT_CLIENT_HTTP_PORT),
              0);
    EXPECT_NE(direct->initAll("tcp", "", 32 << 20), 0);
    auto value = Pattern(4096, 9);
    EXPECT_NE(direct->put_from("direct", value.data(), value.size(),
                               On("localhost:17943")),
              0);
    EXPECT_NE(a_->isExist("direct"), 1);

    // The decorator's own setup is not refused (the fixture set up a_, b_),
    // and a client set up through it still works.
    ASSERT_EQ(a_->put_from("sealed", value.data(), value.size(),
                           On("localhost:17941")),
              0);
    std::vector<char> out(value.size());
    EXPECT_EQ(b_->get_into("sealed", out.data(), out.size()),
              static_cast<int64_t>(out.size()));
    EXPECT_EQ(out, value);
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

// ------------------------------------------------------------------- GPU --

#ifdef USE_CUDA

TEST_F(SecureStoreTest, DevicePutAndGetRoundTrip) {
    if (!HaveGpu()) GTEST_SKIP() << "no GPU";
    // The vLLM connector's shape: one key, many device pieces (layers) whose
    // boundaries do not line up with segments; plus a host piece.
    const size_t n = 5 * kTestSegment + 12345;
    auto value = Pattern(n, 8);
    DevBuf src(value);
    std::vector<void*> in;
    std::vector<size_t> ins;
    size_t off = 0;
    for (size_t piece : {size_t(1000), 3 * kTestSegment, size_t(77777)}) {
        in.push_back(src.at(off));
        ins.push_back(piece);
        off += piece;
    }
    in.push_back(value.data() + off);  // host tail
    ins.push_back(n - off);
    for (const char* where : {"localhost:17941", "localhost:17942"}) {
        const std::string key = std::string("dev-") + where;
        auto put =
            a_->batch_put_from_multi_buffers({key}, {in}, {ins}, On(where));
        ASSERT_EQ(put[0], 0) << where;
        const auto raw = Raw(key);
        EXPECT_EQ(LayoutOf(raw).segment_count, 6u);
        EXPECT_FALSE(Contains(raw.data(), raw.size(), value, 32));
        for (auto* reader : {a_.get(), b_.get()}) {
            // Into device pieces ...
            DevBuf dst(n + 4096, 0x5a);
            auto got = reader->batch_get_into_multi_buffers(
                {key}, {{dst.at(0), dst.at(9999)}}, {{9999, n + 4096 - 9999}},
                false);
            ASSERT_EQ(got[0], int(n)) << where;
            auto host = dst.Host();
            EXPECT_EQ(0, std::memcmp(host.data(), value.data(), n)) << where;
            EXPECT_TRUE(std::all_of(host.begin() + n, host.end(),
                                    [](char c) { return c == 0x5a; }));
            // ... and into host memory.
            std::vector<char> out(n);
            ASSERT_EQ(reader->get_into(key, out.data(), out.size()),
                      int64_t(n));
            EXPECT_EQ(out, value);
        }
    }
    // A host-written value read into device memory.
    ASSERT_EQ(a_->put_from("h2d", value.data(), n, On("localhost:17942")), 0);
    DevBuf dst(n);
    ASSERT_EQ(b_->get_into("h2d", dst.p, n), int64_t(n));
    EXPECT_EQ(dst.Host(), value);
    EXPECT_EQ(b_->crypto()->scratch().free_bytes(),
              b_->crypto()->scratch().mapped_bytes());
}

TEST_F(SecureStoreTest, FailedDeviceGetLeavesTheDeviceUntouched) {
    if (!HaveGpu()) GTEST_SKIP() << "no GPU";
    const size_t n = 6 * kTestSegment + 100;
    auto value = Pattern(n, 9);
    ASSERT_EQ(a_->put_from("dt", value.data(), n, On("localhost:17942")), 0);
    const auto raw = Raw("dt");
    const ObjectLayout l = LayoutOf(raw);
    ASSERT_EQ(l.segment_count, 7u);
    auto untouched = [](const DevBuf& d) {
        auto h = d.Host();
        return std::all_of(h.begin(), h.end(),
                           [](char c) { return c == char(0xab); });
    };
    for (uint32_t i : {0u, 3u, 6u}) {
        auto bad = raw;
        bad[SegmentRange(l, i).first + kHeaderSize + 5] ^= 1;
        const std::string key = "dt-" + std::to_string(i);
        PutRaw(key, bad);
        DevBuf dst(n, 0xab);
        std::vector<char> host_part(4096, 'x');
        // Device and host destinations together: neither is written.
        auto got = b_->batch_get_into_multi_buffers(
            {key}, {{host_part.data(), dst.p}}, {{4096, n}}, false);
        EXPECT_EQ(got[0], toInt(ErrorCode::CHECKSUM_MISMATCH)) << i;
        EXPECT_TRUE(untouched(dst)) << "segment " << i << " reached the device";
        EXPECT_TRUE(AllEqual(host_part, 'x')) << i;
    }
    // Reordered segments.
    auto swapped = raw;
    auto [b1, e1] = SegmentRange(l, 1);
    auto [b2, e2] = SegmentRange(l, 2);
    ASSERT_EQ(e1 - b1, e2 - b2);
    std::swap_ranges(swapped.begin() + b1, swapped.begin() + e1,
                     swapped.begin() + b2);
    PutRaw("dt-swap", swapped);
    DevBuf dst(n, 0xab);
    EXPECT_EQ(b_->get_into("dt-swap", dst.p, n),
              toInt(ErrorCode::CHECKSUM_MISMATCH));
    EXPECT_TRUE(untouched(dst));
    // The intact object still opens into the device.
    ASSERT_EQ(b_->get_into("dt", dst.p, n), int64_t(n));
    EXPECT_EQ(dst.Host(), value);
}

TEST_F(SecureStoreTest, ConcurrentDevicePutsAndGets) {
    if (!HaveGpu()) GTEST_SKIP() << "no GPU";
    constexpr int kThreads = 6, kRounds = 4;
    std::atomic<int> failures{0};
    std::vector<std::thread> ts;
    for (int t = 0; t < kThreads; ++t) {
        ts.emplace_back([&, t] {
            cudaSetDevice(0);
            auto* writer = (t % 2) ? a_.get() : b_.get();
            auto* reader = (t % 2) ? b_.get() : a_.get();
            for (int r = 0; r < kRounds; ++r) {
                const std::string key =
                    "dcc-" + std::to_string(t) + "-" + std::to_string(r);
                auto value =
                    Pattern(3 * kTestSegment + 991 * t + r, t * 10 + r);
                DevBuf src(value);
                auto put = writer->batch_put_from_multi_buffers(
                    {key}, {{src.p}}, {{value.size()}},
                    On("localhost:17942"));
                if (put[0] != 0) {
                    ++failures;
                    continue;
                }
                DevBuf dst(value.size());
                auto got = reader->batch_get_into_multi_buffers(
                    {key}, {{dst.p}}, {{value.size()}}, false);
                if (got[0] != int(value.size()) || dst.Host() != value)
                    ++failures;
                writer->remove(key, true);
            }
        });
    }
    for (auto& t : ts) t.join();
    EXPECT_EQ(failures.load(), 0);
}

#endif  // USE_CUDA

// ----------------------------------------------------------------- large --

// Objects over 1 GiB with the default segment size and thread count. Run with
// SECURE_STORE_LARGE=1.
class SecureStoreLargeTest : public SecureStoreTest {
   protected:
    static void SetUpTestSuite() {
        SecureConfig cfg;
        cfg.enabled = true;
        cfg.key_inline = std::string(64, 'd');
        cfg.staging_region_bytes = 256 << 20;
        cfg.staging_max_bytes = 6ull << 30;
        SecureContext::ResetForTesting(
            SecureContext::CreateForTesting(cfg, nullptr));
        ASSERT_FALSE(SecureContext::Global().failed());
    }
    static void TearDownTestSuite() { SecureContext::ResetForTesting(nullptr); }

    void SetUp() override {
        if (!getenv("SECURE_STORE_LARGE")) GTEST_SKIP() << "SECURE_STORE_LARGE";
        ASSERT_TRUE(master_.Start(InProcMasterConfigBuilder().build()));
        started_ = true;
        inner_a_ = RealClient::create();
        inner_b_ = RealClient::create();
        a_ = std::make_shared<SecurePyClient>(inner_a_);
        b_ = std::make_shared<SecurePyClient>(inner_b_);
        ASSERT_EQ(Setup(*a_, "localhost:17951"), 0);
        ASSERT_EQ(Setup(*b_, "localhost:17952"), 0);
    }
    void TearDown() override {
        if (started_) SecureStoreTest::TearDown();
    }
    int Setup(SecurePyClient& c, const std::string& host) {
        return c.setup_real(host, "P2PHANDSHAKE", 3ull << 30, 64 << 20, "tcp",
                            "", master_.master_address(), nullptr, "", false,
                            "", "default", false, DEFAULT_CLIENT_HTTP_PORT);
    }
    bool started_ = false;
};

TEST_F(SecureStoreLargeTest, OverOneGiBRoundTrip) {
    const size_t n = (1ull << 30) + 4097;
    auto value = Pattern(n, 11);
    const bool gpu = HaveGpu();
    std::vector<char> out(gpu ? 0 : n);
    void* in = value.data();
    void* to = out.data();
#ifdef USE_CUDA
    std::unique_ptr<DevBuf> src, dst;
    if (gpu) {
        src = std::make_unique<DevBuf>(value);
        dst = std::make_unique<DevBuf>(n);
        in = src->p;
        to = dst->p;
    }
#endif
    for (const char* where : {"localhost:17951", "localhost:17952"}) {
        const std::string key = std::string("big-") + where;
        auto t0 = std::chrono::steady_clock::now();
        auto put = a_->batch_put_from_multi_buffers({key}, {{in}}, {{n}},
                                                    On(where));
        auto t1 = std::chrono::steady_clock::now();
        ASSERT_EQ(put[0], 0) << where;
        auto got =
            a_->batch_get_into_multi_buffers({key}, {{to}}, {{n}}, false);
        auto t2 = std::chrono::steady_clock::now();
        ASSERT_EQ(got[0], int(n)) << where;
        LOG(INFO) << "large object: " << n << " bytes ("
                  << (gpu ? "gpu" : "host") << ", " << where << "): put "
                  << std::chrono::duration<double, std::milli>(t1 - t0).count()
                  << " ms, get "
                  << std::chrono::duration<double, std::milli>(t2 - t1).count()
                  << " ms";
#ifdef USE_CUDA
        if (gpu) {
            EXPECT_TRUE(dst->Host() == value) << where;
            ASSERT_EQ(cudaMemset(dst->p, 0, n), cudaSuccess);
        } else
#endif
        {
            EXPECT_TRUE(out == value) << where;
        }
        // A tampered last segment of the large object: rejected, device
        // untouched.
        if (std::string(where) == "localhost:17952") {
            auto raw_len = inner_a_->getSize(key);
            ASSERT_GT(raw_len, 0);
            auto st = a_->staging()->Allocate(raw_len);
            ASSERT_TRUE(st);
            ASSERT_EQ(inner_a_->get_into(key, st.data(), raw_len), raw_len);
            static_cast<char*>(st.data())[raw_len - 1] ^= 1;
            ASSERT_EQ(inner_a_->put_from("big-bad", st.data(), raw_len,
                                         On(where)),
                      0);
            auto bad =
                a_->batch_get_into_multi_buffers({"big-bad"}, {{to}}, {{n}},
                                                 false);
            EXPECT_EQ(bad[0], toInt(ErrorCode::CHECKSUM_MISMATCH));
#ifdef USE_CUDA
            if (gpu) {
                auto h = dst->Host();
                EXPECT_TRUE(std::all_of(h.begin(), h.end(),
                                        [](char c) { return c == 0; }));
            }
#endif
            a_->remove("big-bad", true);
        }
        a_->remove(key, true);
    }
}

// -------------------------------------------------------------- benchmark --

// Put and get throughput for one process, plain or secure as the environment
// says (MC_SECURE_MODE etc.). Run with SECURE_STORE_BENCH=1;
// SECURE_STORE_BENCH_SIZES (MiB, default 32,128,1024), _ITERS (5), _PIECES
// (buffers per object, default 64), _REMOTE=1 to store into a second
// client's segment over TCP instead of the local one.
TEST(SecureStoreBench, Throughput) {
    if (!getenv("SECURE_STORE_BENCH")) GTEST_SKIP() << "SECURE_STORE_BENCH";
    auto& ctx = SecureContext::Global();
    ASSERT_FALSE(ctx.failed()) << ctx.reason();
    const bool secure = ctx.enabled();
    auto env = [](const char* k, const char* d) {
        const char* v = getenv(k);
        return std::string(v && *v ? v : d);
    };
    std::vector<size_t> sizes_mib;
    {
        std::stringstream ss(env("SECURE_STORE_BENCH_SIZES", "32,128,1024"));
        std::string x;
        while (std::getline(ss, x, ',')) sizes_mib.push_back(std::stoul(x));
    }
    const int iters = std::stoi(env("SECURE_STORE_BENCH_ITERS", "5"));
    const size_t pieces = std::stoul(env("SECURE_STORE_BENCH_PIECES", "64"));
    const bool remote = env("SECURE_STORE_BENCH_REMOTE", "0") == "1";
    const bool gpu = HaveGpu();
    size_t max_bytes = 0;
    for (size_t m : sizes_mib) max_bytes = std::max(max_bytes, m << 20);

    InProcMaster master;
    ASSERT_TRUE(master.Start(InProcMasterConfigBuilder().build()));
    std::vector<std::shared_ptr<RealClient>> inners;
    std::vector<std::shared_ptr<PyClient>> clients;
    const std::vector<std::string> hosts{"localhost:17961", "localhost:17962"};
    for (size_t i = 0; i < (remote ? 2u : 1u); ++i) {
        auto inner = RealClient::create();
        std::shared_ptr<PyClient> client = inner;
        if (secure) client = std::make_shared<SecurePyClient>(inner);
        ASSERT_EQ(client->setup_real(hosts[i], "P2PHANDSHAKE",
                                     max_bytes * 2 + (256 << 20), 64 << 20,
                                     "tcp", "", master.master_address(),
                                     nullptr, "", false, "", "default", false,
                                     DEFAULT_CLIENT_HTTP_PORT),
                  0);
        inners.push_back(inner);
        clients.push_back(client);
    }
    PyClient& c = *clients[0];
    ReplicateConfig cfg;
    cfg.replica_num = 1;
    cfg.preferred_segment = hosts[remote ? 1 : 0];

    std::vector<char> pattern = Pattern(max_bytes, 12);
    void* src = nullptr;
    void* dst = nullptr;
    std::vector<char> hsrc, hdst;
#ifdef USE_CUDA
    if (gpu) {
        ASSERT_EQ(cudaMalloc(&src, max_bytes), cudaSuccess);
        ASSERT_EQ(cudaMalloc(&dst, max_bytes), cudaSuccess);
        ASSERT_EQ(cudaMemcpy(src, pattern.data(), max_bytes,
                             cudaMemcpyHostToDevice),
                  cudaSuccess);
    }
#endif
    if (!gpu) {
        hsrc = pattern;
        hdst.resize(max_bytes);
        src = hsrc.data();
        dst = hdst.data();
    }
    // As the connector does (a no-op in secure mode).
    EXPECT_EQ(c.register_buffer(src, max_bytes), 0);
    EXPECT_EQ(c.register_buffer(dst, max_bytes), 0);

    auto ms = [](auto a, auto b) {
        return std::chrono::duration<double, std::milli>(b - a).count();
    };
    auto p50 = [](std::vector<double> v) {
        if (v.empty()) return 0.0;
        std::sort(v.begin(), v.end());
        return v[v.size() / 2];
    };
    for (size_t mib : sizes_mib) {
        const size_t n = mib << 20;
        std::vector<void*> in, out;
        std::vector<size_t> len;
        const size_t piece = n / pieces;
        for (size_t p = 0; p < pieces; ++p) {
            in.push_back(static_cast<char*>(src) + piece * p);
            out.push_back(static_cast<char*>(dst) + piece * p);
            len.push_back(p + 1 == pieces ? n - piece * p : piece);
        }
        std::vector<double> put_ms, get_ms;
        int fails = 0;
        bool verified = false;
        for (int it = -1; it < iters; ++it) {  // it == -1: warm-up
            const std::string key =
                "bench-" + std::to_string(mib) + "-" + std::to_string(it);
            auto t0 = std::chrono::steady_clock::now();
            auto put = c.batch_put_from_multi_buffers({key}, {in}, {len}, cfg);
            auto t1 = std::chrono::steady_clock::now();
            auto got =
                c.batch_get_into_multi_buffers({key}, {out}, {len}, false);
            auto t2 = std::chrono::steady_clock::now();
            if (put[0] != 0 || got[0] != int(n)) {
                ++fails;
                LOG(ERROR) << "bench: put=" << put[0] << " get=" << got[0];
            } else if (it == 0) {
                std::vector<char> back(n);
#ifdef USE_CUDA
                if (gpu)
                    cudaMemcpy(back.data(), dst, n, cudaMemcpyDeviceToHost);
                else
#endif
                    std::memcpy(back.data(), dst, n);
                verified = std::memcmp(back.data(), pattern.data(), n) == 0;
            }
            if (it >= 0) {
                put_ms.push_back(ms(t0, t1));
                get_ms.push_back(ms(t1, t2));
            }
            c.remove(key, true);
        }
        const double put50 = p50(put_ms), get50 = p50(get_ms);
        printf(
            "B RESULT mode=%s where=%s mem=%s size_mib=%zu pieces=%zu iters=%d "
            "fails=%d put_p50_ms=%.2f put_GBps=%.2f get_p50_ms=%.2f "
            "get_GBps=%.2f verified=%d threads=%s seg=%s\n",
            secure ? "secure" : "plain", remote ? "remote-tcp" : "local",
            gpu ? "gpu" : "host", mib, pieces, iters, fails, put50,
            put50 > 0 ? n / put50 / 1e6 : 0, get50,
            get50 > 0 ? n / get50 / 1e6 : 0, verified ? 1 : 0,
            env("MC_SECURE_STORE_THREADS", "8").c_str(),
            env("MC_SECURE_STORE_SEGMENT_BYTES", "2097152").c_str());
        fflush(stdout);
        EXPECT_EQ(fails, 0);
        EXPECT_TRUE(verified);

        // Secure only: the crypto alone (seal from and open into the same
        // buffers, nothing stored).
        if (secure) {
            auto* sc = static_cast<SecurePyClient*>(&c);
            std::vector<Buf> bin, bout;
            const int dev = gpu ? 0 : -1;
            for (size_t p = 0; p < pieces; ++p) {
                bin.push_back({in[p], len[p], dev});
                bout.push_back({out[p], len[p], dev});
            }
            const size_t sealed = sc->crypto()->SealedSize(n);
            auto staging = sc->staging()->Allocate(sealed);
            ASSERT_TRUE(staging);
            std::vector<double> seal_ms, open_ms;
            const std::string key = "crypto";
            for (int it = -1; it < iters; ++it) {
                std::vector<ObjectCrypto::SealJob> sj(1);
                sj[0].key = &key;
                sj[0].in = bin;
                sj[0].out = {staging.data(), sealed};
                auto t0 = std::chrono::steady_clock::now();
                sc->crypto()->Seal(sj);
                auto t1 = std::chrono::steady_clock::now();
                ASSERT_EQ(sj[0].result, Error::kOk);
                std::vector<ObjectCrypto::OpenJob> oj(1);
                oj[0].key = &key;
                oj[0].sealed = {staging.data(), sealed};
                ASSERT_TRUE(ParseObject(oj[0].sealed, sealed, &oj[0].layout));
                oj[0].out = bout;
                auto t2 = std::chrono::steady_clock::now();
                sc->crypto()->Open(oj);
                auto t3 = std::chrono::steady_clock::now();
                ASSERT_EQ(oj[0].result, Error::kOk);
                if (it >= 0) {
                    seal_ms.push_back(ms(t0, t1));
                    open_ms.push_back(ms(t2, t3));
                }
            }
            const double s50 = p50(seal_ms), o50 = p50(open_ms);
            printf(
                "B CRYPTO mem=%s size_mib=%zu seal_p50_ms=%.2f "
                "seal_GBps=%.2f open_p50_ms=%.2f open_GBps=%.2f threads=%s\n",
                gpu ? "gpu" : "host", mib, s50, n / s50 / 1e6, o50,
                n / o50 / 1e6, env("MC_SECURE_STORE_THREADS", "8").c_str());
            fflush(stdout);
        }
    }
    c.unregister_buffer(src);
    c.unregister_buffer(dst);
#ifdef USE_CUDA
    if (gpu) {
        cudaFree(src);
        cudaFree(dst);
    }
#endif
    for (auto& cl : clients) cl->tearDownAll();
    clients.clear();
    inners.clear();
    master.Stop();
}

}  // namespace
}  // namespace secure
}  // namespace mooncake
