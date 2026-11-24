// Secure mode (DW-1288): the crypto module and the staging pool.

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "secure/kv_crypto.h"
#include "secure/staging_pool.h"

namespace mooncake {
namespace secure {
namespace {

std::array<uint8_t, kKeySize> TestKey(uint8_t seed) {
    std::array<uint8_t, kKeySize> k;
    for (size_t i = 0; i < kKeySize; ++i) k[i] = static_cast<uint8_t>(seed + i);
    return k;
}

std::shared_ptr<const KeyRing> Ring(std::vector<uint8_t> seeds) {
    std::vector<std::array<uint8_t, kKeySize>> keys;
    for (auto s : seeds) keys.push_back(TestKey(s));
    Error e;
    auto r = KeyRing::FromKeys(keys, &e);
    EXPECT_EQ(e, Error::kOk);
    return r;
}

std::vector<uint8_t> Random(size_t n, uint32_t seed = 1) {
    std::mt19937 g(seed);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = static_cast<uint8_t>(g());
    return v;
}

struct Sealed {
    std::vector<uint8_t> bytes;
};

Sealed SealOne(Sealer& s, const std::vector<uint8_t>& pt,
               const std::string& aad) {
    Sealed out;
    out.bytes.resize(SealedSize(pt.size()));
    ConstSpan in{pt.data(), pt.size()};
    size_t n = 0;
    EXPECT_EQ(s.Seal(&in, 1, {aad.data(), aad.size()},
                     {out.bytes.data(), out.bytes.size()}, &n),
              Error::kOk);
    EXPECT_EQ(n, out.bytes.size());
    return out;
}

Error OpenOne(Opener& o, const Sealed& s, const std::string& aad,
              std::vector<uint8_t>* pt, Purpose p = Purpose::kStoreObject,
              SealedInfo* info = nullptr) {
    pt->assign(s.bytes.size() >= kOverhead ? s.bytes.size() - kOverhead : 0,
               0xAA);
    MutableSpan out{pt->data(), pt->size()};
    return o.Open({s.bytes.data(), s.bytes.size()}, p, {aad.data(), aad.size()},
                  &out, 1, info);
}

class CryptoTest : public ::testing::TestWithParam<Algorithm> {};

TEST_P(CryptoTest, RoundTripSizes) {
    auto ring = Ring({1});
    Error e;
    auto sealer = Sealer::Create(ring, Purpose::kStoreObject, GetParam(), &e);
    ASSERT_TRUE(sealer) << ToString(e);
    Opener opener(ring);
    for (size_t n : {0ul, 1ul, 15ul, 16ul, 17ul, 4095ul, 1ul << 20}) {
        auto pt = Random(n, n);
        auto s = SealOne(*sealer, pt, "key-a");
        std::vector<uint8_t> got;
        SealedInfo info;
        ASSERT_EQ(OpenOne(opener, s, "key-a", &got, Purpose::kStoreObject,
                          &info),
                  Error::kOk)
            << n;
        EXPECT_EQ(got, pt);
        EXPECT_EQ(info.plaintext_len, n);
        EXPECT_EQ(info.algorithm, GetParam());
        EXPECT_EQ(info.key_id, ring->current().id());
        // The ciphertext is not the plaintext.
        if (n >= 16)
            EXPECT_NE(0, std::memcmp(s.bytes.data() + kHeaderSize, pt.data(),
                                     n));
    }
}

TEST_P(CryptoTest, GatherSealScatterOpen) {
    auto ring = Ring({2});
    Error e;
    auto sealer = Sealer::Create(ring, Purpose::kTransfer, GetParam(), &e);
    Opener opener(ring);
    auto pt = Random(100000, 7);
    std::vector<ConstSpan> parts = {{pt.data(), 1},
                                    {pt.data() + 1, 4999},
                                    {pt.data() + 5000, 0},
                                    {pt.data() + 5000, 95000}};
    std::vector<uint8_t> sealed(SealedSize(pt.size()));
    size_t n = 0;
    ASSERT_EQ(sealer->Seal(parts.data(), parts.size(), {"x", 1},
                           {sealed.data(), sealed.size()}, &n),
              Error::kOk);
    std::vector<uint8_t> a(33333), b(1), c(100000 - 33334);
    std::vector<MutableSpan> outs = {
        {a.data(), a.size()}, {b.data(), b.size()}, {c.data(), c.size()}};
    ASSERT_EQ(opener.Open({sealed.data(), sealed.size()}, Purpose::kTransfer,
                          {"x", 1}, outs.data(), outs.size()),
              Error::kOk);
    std::vector<uint8_t> joined(a);
    joined.insert(joined.end(), b.begin(), b.end());
    joined.insert(joined.end(), c.begin(), c.end());
    EXPECT_EQ(joined, pt);
}

TEST_P(CryptoTest, EveryTamperedByteFailsAndZeroesOutput) {
    auto ring = Ring({3});
    Error e;
    auto sealer = Sealer::Create(ring, Purpose::kStoreObject, GetParam(), &e);
    Opener opener(ring);
    auto pt = Random(200, 3);
    auto s = SealOne(*sealer, pt, "obj");
    for (size_t i = 0; i < s.bytes.size(); ++i) {
        Sealed t = s;
        t.bytes[i] ^= 0x01;
        std::vector<uint8_t> got;
        Error r = OpenOne(opener, t, "obj", &got);
        EXPECT_NE(r, Error::kOk) << "byte " << i;
        EXPECT_TRUE(std::all_of(got.begin(), got.end(),
                                [](uint8_t x) { return x == 0; }))
            << "output not zeroed after failure at byte " << i;
    }
    // Truncation and extension.
    for (int delta : {-1, 1}) {
        Sealed t = s;
        t.bytes.resize(t.bytes.size() + delta);
        std::vector<uint8_t> got(pt.size());
        MutableSpan out{got.data(), got.size()};
        EXPECT_NE(opener.Open({t.bytes.data(), t.bytes.size()},
                              Purpose::kStoreObject, {"obj", 3}, &out, 1),
                  Error::kOk);
    }
}

TEST_P(CryptoTest, BoundToAadPurposeAndKey) {
    auto ring = Ring({4});
    Error e;
    auto sealer = Sealer::Create(ring, Purpose::kStoreObject, GetParam(), &e);
    Opener opener(ring);
    auto pt = Random(64, 4);
    auto s = SealOne(*sealer, pt, "key-1");
    std::vector<uint8_t> got;
    EXPECT_EQ(OpenOne(opener, s, "key-2", &got), Error::kAuthFailed);
    EXPECT_EQ(OpenOne(opener, s, "key-1", &got, Purpose::kTransfer),
              Error::kBadHeader);
    Opener other(Ring({5}));
    EXPECT_EQ(OpenOne(other, s, "key-1", &got), Error::kUnknownKeyId);
}

INSTANTIATE_TEST_SUITE_P(Algorithms, CryptoTest,
                         ::testing::Values(Algorithm::kAes256Gcm,
                                           Algorithm::kChaCha20Poly1305));

TEST(CryptoTest2, NoncesNeverRepeatAcrossThreadsAndSealers) {
    auto ring = Ring({6});
    Error e;
    auto a = Sealer::Create(ring, Purpose::kStoreObject, Algorithm::kAes256Gcm,
                            &e);
    auto b = Sealer::Create(ring, Purpose::kStoreObject, Algorithm::kAes256Gcm,
                            &e);
    constexpr int kThreads = 8, kPer = 2000;
    std::vector<std::vector<std::string>> ids(kThreads * 2);
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads * 2; ++t) {
        threads.emplace_back([&, t] {
            Sealer& s = (t % 2) ? *a : *b;
            uint8_t pt[8] = {};
            ConstSpan in{pt, sizeof(pt)};
            std::vector<uint8_t> out(SealedSize(sizeof(pt)));
            for (int i = 0; i < kPer; ++i) {
                size_t n;
                ASSERT_EQ(s.Seal(&in, 1, {}, {out.data(), out.size()}, &n),
                          Error::kOk);
                SealedInfo info;
                ASSERT_EQ(ParseHeader({out.data(), out.size()}, &info),
                          Error::kOk);
                ids[t].emplace_back(
                    std::string(info.salt.begin(), info.salt.end()) +
                    std::string(info.nonce.begin(), info.nonce.end()));
            }
        });
    }
    for (auto& th : threads) th.join();
    std::set<std::string> all;
    for (auto& v : ids) all.insert(v.begin(), v.end());
    EXPECT_EQ(all.size(), size_t(kThreads * 2 * kPer));
}

TEST(CryptoTest2, CounterExhaustionRedrawsSalt) {
    auto ring = Ring({7});
    Error e;
    auto s = Sealer::Create(ring, Purpose::kStoreObject, Algorithm::kAes256Gcm,
                            &e);
    Opener o(ring);
    auto pt = Random(10);
    auto first = SealOne(*s, pt, "k");
    s->SetCounterForTesting((1ull << 62) - 1);
    auto last = SealOne(*s, pt, "k");
    auto after = SealOne(*s, pt, "k");
    SealedInfo i1, i2, i3;
    ParseHeader({first.bytes.data(), first.bytes.size()}, &i1);
    ParseHeader({last.bytes.data(), last.bytes.size()}, &i2);
    ParseHeader({after.bytes.data(), after.bytes.size()}, &i3);
    EXPECT_EQ(i1.salt, i2.salt);
    EXPECT_EQ(i2.counter(), (1ull << 62) - 1);
    EXPECT_NE(i3.salt, i2.salt);
    EXPECT_EQ(i3.counter(), 0u);
    std::vector<uint8_t> got;
    EXPECT_EQ(OpenOne(o, after, "k", &got), Error::kOk);
    EXPECT_EQ(got, pt);
}

TEST(CryptoTest2, ForkedChildDrawsANewSalt) {
    auto ring = Ring({8});
    Error e;
    auto s = Sealer::Create(ring, Purpose::kStoreObject, Algorithm::kAes256Gcm,
                            &e);
    auto pt = Random(10);
    auto parent = SealOne(*s, pt, "k");
    SealedInfo pi;
    ParseHeader({parent.bytes.data(), parent.bytes.size()}, &pi);
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    pid_t pid = fork();
    if (pid == 0) {
        auto child = SealOne(*s, pt, "k");
        SealedInfo ci;
        ParseHeader({child.bytes.data(), child.bytes.size()}, &ci);
        ssize_t w = write(fds[1], ci.salt.data(), ci.salt.size());
        _exit(w == ssize_t(kSaltSize) ? 0 : 1);
    }
    std::array<uint8_t, kSaltSize> child_salt{};
    ASSERT_EQ(read(fds[0], child_salt.data(), kSaltSize), ssize_t(kSaltSize));
    int status = 0;
    waitpid(pid, &status, 0);
    EXPECT_NE(child_salt, pi.salt);
}

// Regression: the HKDF info had an uninitialised trailing byte, so a subkey
// depended on stack contents and a message sealed on one thread (or process)
// failed to open on another. The info is exactly label | algorithm | purpose.
TEST(CryptoTest2, SubkeyIsAFunctionOfItsInputsOnly) {
    auto key = TestKey(1);
    MasterKey master(DeriveKeyId(key.data()), key.data());
    std::array<uint8_t, kSaltSize> salt;
    for (size_t i = 0; i < kSaltSize; ++i) salt[i] = static_cast<uint8_t>(i);
    std::array<uint8_t, kKeySize> here{}, there{};
    ASSERT_EQ(DeriveSubkey(master, salt.data(), Algorithm::kAes256Gcm,
                           Purpose::kTransfer, &here),
              Error::kOk);
    std::thread([&] {
        volatile uint8_t dirty[4096];
        for (size_t i = 0; i < sizeof(dirty); ++i) dirty[i] = 0xA5;
        ASSERT_EQ(DeriveSubkey(master, salt.data(), Algorithm::kAes256Gcm,
                               Purpose::kTransfer, &there),
                  Error::kOk);
    }).join();
    EXPECT_EQ(here, there);
    // HKDF-SHA256(key, salt, "mooncake-secure-v1" | 0x01 | 0x02).
    const uint8_t expected[kKeySize] = {
        0x09, 0x8b, 0x56, 0xc7, 0x2c, 0xde, 0xce, 0xf0, 0x96, 0x18, 0x9f,
        0xd2, 0x38, 0xb8, 0x06, 0x93, 0x76, 0x9b, 0x0f, 0x46, 0x09, 0x39,
        0xe7, 0x58, 0x9a, 0x58, 0x43, 0xae, 0xc0, 0xa5, 0x1d, 0xa3};
    EXPECT_EQ(memcmp(here.data(), expected, kKeySize), 0);
}

TEST(CryptoTest2, RotationAcceptsPreviousKey) {
    auto old_ring = Ring({9});
    auto new_ring = Ring({10, 9});  // new current, old previous
    Error e;
    auto old_sealer = Sealer::Create(old_ring, Purpose::kStoreObject,
                                     Algorithm::kAes256Gcm, &e);
    auto new_sealer = Sealer::Create(new_ring, Purpose::kStoreObject,
                                     Algorithm::kAes256Gcm, &e);
    Opener new_opener(new_ring), old_opener(old_ring);
    auto pt = Random(50);
    std::vector<uint8_t> got;
    EXPECT_EQ(OpenOne(new_opener, SealOne(*old_sealer, pt, "k"), "k", &got),
              Error::kOk);
    EXPECT_EQ(OpenOne(new_opener, SealOne(*new_sealer, pt, "k"), "k", &got),
              Error::kOk);
    EXPECT_EQ(OpenOne(old_opener, SealOne(*new_sealer, pt, "k"), "k", &got),
              Error::kUnknownKeyId);
}

TEST(CryptoTest2, KeyParsingAndLoading) {
    std::array<uint8_t, kKeySize> k;
    EXPECT_EQ(ParseKeyMaterial(std::string(64, 'a'), &k), Error::kOk);
    EXPECT_EQ(k[0], 0xaa);
    // base64 of 32 zero bytes
    EXPECT_EQ(ParseKeyMaterial("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
                               &k),
              Error::kOk);
    EXPECT_EQ(k[31], 0);
    EXPECT_NE(ParseKeyMaterial("short", &k), Error::kOk);
    EXPECT_NE(ParseKeyMaterial(std::string(63, 'a'), &k), Error::kOk);

    char path[] = "/tmp/mc_secure_keyXXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    std::string content = std::string(64, '1') + "\n# comment\n" +
                          std::string(64, '2') + "\n";
    ASSERT_EQ(write(fd, content.data(), content.size()),
              ssize_t(content.size()));
    close(fd);
    SecureConfig cfg;
    cfg.enabled = true;
    cfg.key_file = path;
    Error e;
    std::string why;
    auto ring = LoadKeyRing(cfg, &e, &why);
    ASSERT_TRUE(ring) << why;
    EXPECT_EQ(ring->size(), 2u);
    std::array<uint8_t, kKeySize> k1;
    ParseKeyMaterial(std::string(64, '1'), &k1);
    EXPECT_EQ(ring->current().id(), DeriveKeyId(k1.data()));
    unlink(path);

    cfg.key_file = "/nonexistent/key";
    EXPECT_FALSE(LoadKeyRing(cfg, &e, &why));
    EXPECT_EQ(e, Error::kNoKey);
    EXPECT_EQ(why.find(std::string(64, '1')), std::string::npos);
}

TEST(CryptoTest2, ContextFailsClosedWithoutKey) {
    SecureConfig cfg;
    cfg.enabled = true;  // but no key
    auto ctx = SecureContext::CreateForTesting(cfg, nullptr);
    EXPECT_TRUE(ctx->enabled());
    EXPECT_TRUE(ctx->failed());
    SecureConfig off;
    auto ctx2 = SecureContext::CreateForTesting(off, nullptr);
    EXPECT_FALSE(ctx2->enabled());
    EXPECT_FALSE(ctx2->failed());
}

TEST(CryptoTest2, OffByDefault) {
    unsetenv("MC_SECURE_MODE");
    EXPECT_FALSE(SecureConfig::FromEnv().enabled);
}

TEST(StagingPoolTest, AllocateFreeCoalesceAndCap) {
    int registered = 0, unregistered = 0;
    {
        StagingPool pool(
            1 << 20, 2 << 20,
            [&](void*, size_t) {
                ++registered;
                return 0;
            },
            [&](void*) {
                ++unregistered;
                return 0;
            });
        auto a = pool.Allocate(1000);
        auto b = pool.Allocate(1000);
        ASSERT_TRUE(a && b);
        EXPECT_EQ(reinterpret_cast<uintptr_t>(a.data()) % 64, 0u);
        EXPECT_TRUE(pool.Contains(a.data(), 1000));
        EXPECT_FALSE(pool.Contains(&registered, 4));
        std::memset(a.data(), 1, a.size());
        auto big = pool.Allocate((1 << 20) + 1);  // needs a second region
        EXPECT_FALSE(big);  // 1 MiB + 4 KiB region would exceed the 2 MiB cap
        auto second = pool.Allocate(1 << 20);
        EXPECT_TRUE(second);
        EXPECT_EQ(registered, 2);
        EXPECT_FALSE(pool.Allocate(1 << 20));  // capped
        a = StagingBuffer();
        b = StagingBuffer();
        second = StagingBuffer();
        EXPECT_EQ(pool.free_bytes(), pool.mapped_bytes());
        auto whole = pool.Allocate(1 << 20);  // coalesced back into one block
        EXPECT_TRUE(whole);
    }
    EXPECT_EQ(unregistered, registered);
}

TEST(StagingPoolTest, ConcurrentAllocations) {
    StagingPool pool(4 << 20, 64 << 20, nullptr, nullptr);
    std::vector<std::thread> ts;
    std::atomic<int> failures{0};
    for (int t = 0; t < 8; ++t) {
        ts.emplace_back([&, t] {
            for (int i = 0; i < 500; ++i) {
                auto b = pool.Allocate(1 + (i * 977 + t) % 65536);
                if (!b) {
                    ++failures;
                    continue;
                }
                std::memset(b.data(), t, b.size());
                for (size_t j = 0; j < b.size(); j += 4096)
                    if (static_cast<uint8_t*>(b.data())[j] != t) ++failures;
            }
        });
    }
    for (auto& t : ts) t.join();
    EXPECT_EQ(failures.load(), 0);
    EXPECT_EQ(pool.free_bytes(), pool.mapped_bytes());
}

}  // namespace
}  // namespace secure
}  // namespace mooncake
