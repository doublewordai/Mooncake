// Secure mode (DW-1288): the secure P->D push over TCP loopback between
// engines in one process. A WRITE from local-only (KV cache) memory to
// local-only memory on the peer is sealed through staging, committed over the
// authenticated control channel and reported complete only after the peer
// has verified and decrypted it.

#include <arpa/inet.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <thread>
#include <vector>

#ifdef USE_CUDA
#include <cuda_runtime.h>
#endif

#include "control_auth.h"
#include "handshake_auth.h"
#include "secure/kv_crypto.h"
#include "secure/secure_push.h"
#include "secure/secure_transport.h"
#include "transfer_engine.h"
#include "transport/transport.h"

namespace mooncake {
namespace secure {
namespace {

using TR = Transport::TransferRequest;

struct Piece {
    void* src;
    void* dst;
    size_t len;
};

struct Node {
    std::unique_ptr<TransferEngine> engine;
    SecureTransport* xport = nullptr;
};

std::vector<uint8_t> Random(size_t n, uint32_t seed) {
    std::mt19937 g(seed);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = static_cast<uint8_t>(g());
    return v;
}

// The control-message AAD, as the service builds it (label, NUL, then the
// length-prefixed receiver name).
std::string RequestAad(const std::string& receiver) {
    std::string a("mcp2d-req-v1", sizeof("mcp2d-req-v1"));
    uint32_t n = static_cast<uint32_t>(receiver.size());
    for (int i = 0; i < 4; ++i) a.push_back(static_cast<char>(n >> (8 * i)));
    return a + receiver;
}

class SecurePushTest : public ::testing::Test {
   protected:
    static void SetUpTestSuite() {
        // Small segments and staging so modest transfers use many windows
        // and many slots.
        setenv("MC_SECURE_P2D_SEGMENT_BYTES", "65536", 1);
        setenv("MC_SECURE_P2D_WINDOW_SEGMENTS", "4", 1);
        // Ramped first and last segments (16, 32 KiB), so every test
        // exercises segments of more than one size.
        setenv("MC_SECURE_P2D_FIRST_SEGMENT_BYTES", "16384", 1);
        setenv("MC_SECURE_P2D_RX_BYTES", std::to_string(4 << 20).c_str(), 1);
        setenv("MC_SECURE_P2D_TIMEOUT_MS", "10000", 1);
        SecureConfig cfg;
        cfg.enabled = true;
        cfg.key_inline = std::string(64, '3');
        SecureContext::ResetForTesting(
            SecureContext::CreateForTesting(cfg, nullptr));
        ASSERT_TRUE(SecureContext::Global().enabled());
        ASSERT_FALSE(SecureContext::Global().failed());
        // Both halves, as MC_SECURE_MODE switches them on: the handshake hook
        // (installed as each engine's metadata is created) carries the push
        // endpoints.
        control_auth::ConfigureForTesting(true, std::string(40, 'h'));
        nodes_ = new std::vector<Node>(3);
        for (int i = 0; i < 3; ++i) {
            auto& n = (*nodes_)[i];
            const int port = 17311 + i;
            n.engine = std::make_unique<TransferEngine>(false);
            ASSERT_EQ(n.engine->init("P2PHANDSHAKE",
                                     "127.0.0.1:" + std::to_string(port),
                                     "127.0.0.1", port),
                      0);
            n.xport = dynamic_cast<SecureTransport*>(
                n.engine->installTransport("tcp", nullptr));
            ASSERT_NE(n.xport, nullptr);
            ASSERT_NE(n.xport->push_service(), nullptr);
        }
    }

    static void TearDownTestSuite() {
        delete nodes_;
        nodes_ = nullptr;
        UninstallHandshakeAuthForTesting();
        control_auth::ResetForTesting();
        SecureContext::ResetForTesting(nullptr);
    }

    void SetUp() override {
        for (auto& n : *nodes_) n.xport->push_service()->test_hooks() = {};
    }

    static Node& A() { return (*nodes_)[0]; }  // sender
    static Node& B() { return (*nodes_)[1]; }  // receiver
    static Node& C() { return (*nodes_)[2]; }  // second sender

    static Transport::SegmentHandle Open(Node& from, Node& to) {
        auto h = from.engine->openSegment(to.engine->getLocalIpAndPort());
        EXPECT_NE(h, (Transport::SegmentHandle)-1);
        return h;
    }

    // Submits through the engine (MultiTransport -> SecureTransport), the
    // path batch_transfer_sync_write takes, and waits.
    static Transport::TransferStatusEnum Transfer(
        Node& from, Transport::SegmentHandle seg,
        const std::vector<Piece>& pieces, TR::OpCode op = TR::WRITE,
        Status* submit = nullptr) {
        auto& e = *from.engine;
        auto batch = e.allocateBatchID(pieces.size());
        std::vector<TR> reqs;
        for (auto& p : pieces) {
            TR r;
            r.opcode = op;
            r.source = p.src;
            r.target_id = seg;
            r.target_offset = reinterpret_cast<uint64_t>(p.dst);
            r.length = p.len;
            reqs.push_back(r);
        }
        Status s = e.submitTransfer(batch, reqs);
        if (submit) *submit = s;
        Transport::TransferStatus st{Transport::TransferStatusEnum::FAILED, 0};
        if (s.ok()) {
            auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(60);
            while (std::chrono::steady_clock::now() < deadline) {
                e.getBatchTransferStatus(batch, st);
                if (st.s == Transport::TransferStatusEnum::COMPLETED ||
                    st.s == Transport::TransferStatusEnum::FAILED)
                    break;
                std::this_thread::sleep_for(std::chrono::microseconds(50));
            }
        }
        e.freeBatchID(batch);
        return s.ok() ? st.s : Transport::TransferStatusEnum::FAILED;
    }

    static void FloodThenPush(Node& sender, Node& receiver, int addresses);

    static std::vector<Node>* nodes_;
};

std::vector<Node>* SecurePushTest::nodes_ = nullptr;

// A host buffer registered (local-only) with one engine, freed on exit.
struct Buf {
    Buf(Node& n, size_t size, uint8_t fill) : node(n), mem(size, fill) {
        EXPECT_EQ(node.engine->registerLocalMemory(mem.data(), mem.size()), 0);
    }
    ~Buf() { node.engine->unregisterLocalMemory(mem.data()); }
    uint8_t* data() { return mem.data(); }
    size_t size() const { return mem.size(); }
    Node& node;
    std::vector<uint8_t> mem;
};

// Scattered pieces: source offsets in order with gaps, destinations shuffled.
std::vector<Piece> Scatter(uint8_t* src, uint8_t* dst, size_t size,
                           size_t count, uint32_t seed, size_t max_len) {
    std::mt19937 g(seed);
    std::vector<std::pair<size_t, size_t>> slots;  // offset, length
    size_t off = 0;
    while (slots.size() < count) {
        size_t len = 1 + g() % max_len;
        size_t gap = g() % 97;
        if (off + gap + len > size) break;
        slots.emplace_back(off + gap, len);
        off += gap + len;
    }
    std::vector<size_t> order(slots.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::shuffle(order.begin(), order.end(), g);
    // Destination i gets the slot order[i]'s position but source slot i's
    // length; lay destinations out sequentially to keep them disjoint.
    std::vector<Piece> pieces;
    size_t doff = 0;
    for (size_t i = 0; i < slots.size(); ++i) {
        size_t len = slots[order[i]].second;
        doff += g() % 61;
        if (doff + len > size) break;
        pieces.push_back({src + slots[order[i]].first, dst + doff, len});
        doff += len;
    }
    return pieces;
}

// A TCP connection to host:port from the local address `src`, or -1.
int ConnectFrom(const std::string& src, const std::string& host, int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    if (inet_pton(AF_INET, src.c_str(), &a.sin_addr) != 1 ||
        ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(fd);
        return -1;
    }
    sockaddr_in d{};
    d.sin_family = AF_INET;
    d.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &d.sin_addr) != 1 ||
        ::connect(fd, reinterpret_cast<sockaddr*>(&d), sizeof(d)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

bool RaiseFdLimit(rlim_t want) {
    rlimit rl{};
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return false;
    if (rl.rlim_cur >= want) return true;
    if (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < want) return false;
    rl.rlim_cur = want;
    return setrlimit(RLIMIT_NOFILE, &rl) == 0;
}

bool WaitFor(const std::function<bool()>& pred, int timeout_ms) {
    auto until = std::chrono::steady_clock::now() +
                 std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < until) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return pred();
}

// True while the peer has neither closed nor sent anything.
bool StillOpen(int fd) {
    pollfd p{fd, POLLIN, 0};
    return ::poll(&p, 1, 0) == 0;
}

// Milliseconds until the peer closed `fd` (EOF or reset), or -1 if it is
// still open after timeout_ms. Discards anything the peer sends.
int MsUntilClosed(int fd, int timeout_ms) {
    auto t0 = std::chrono::steady_clock::now();
    for (;;) {
        auto el = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
        if (el >= timeout_ms) return -1;
        pollfd p{fd, POLLIN, 0};
        int r = ::poll(&p, 1, static_cast<int>(timeout_ms - el));
        if (r <= 0) continue;
        char buf[4096];
        ssize_t k = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (k == 0 || (k < 0 && errno != EAGAIN && errno != EINTR))
            return static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count());
    }
}

// A sealed HELLO for `receiver`, framed as on the wire.
std::string HelloFrame(const std::string& receiver) {
    std::string body(1, '\x03');
    const std::string sender = "test-sender";
    uint32_t n = static_cast<uint32_t>(sender.size());
    for (int i = 0; i < 4; ++i) body.push_back(static_cast<char>(n >> (8 * i)));
    body += sender;
    const std::string aad = RequestAad(receiver);
    std::string sealed(SealedSize(body.size()), '\0');
    ConstSpan pt{body.data(), body.size()};
    EXPECT_EQ(SecureContext::Global()
                  .sealer(Purpose::kControl)
                  .Seal(&pt, 1, {aad.data(), aad.size()},
                        {sealed.data(), sealed.size()}, nullptr),
              Error::kOk);
    uint32_t len = htonl(static_cast<uint32_t>(sealed.size()));
    return std::string(reinterpret_cast<const char*>(&len), 4) + sealed;
}

bool SendRaw(int fd, const std::string& bytes) {
    return ::send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL) ==
           static_cast<ssize_t>(bytes.size());
}

void ExpectDelivered(const std::vector<Piece>& pieces) {
    for (size_t i = 0; i < pieces.size(); ++i)
        ASSERT_EQ(memcmp(pieces[i].src, pieces[i].dst, pieces[i].len), 0)
            << "piece " << i;
}

TEST_F(SecurePushTest, ScatteredRoundTrip) {
    Buf src(A(), 3 << 20, 0);
    Buf dst(B(), 3 << 20, 0xEE);
    auto data = Random(src.size(), 7);
    memcpy(src.data(), data.data(), data.size());
    auto seg = Open(A(), B());
    auto pieces = Scatter(src.data(), dst.data(), src.size(), 400, 11, 20000);
    ASSERT_GT(pieces.size(), 100u);
    EXPECT_EQ(Transfer(A(), seg, pieces),
              Transport::TransferStatusEnum::COMPLETED);
    ExpectDelivered(pieces);
    // Bytes between destinations are untouched.
    std::vector<bool> covered(dst.size(), false);
    for (auto& p : pieces)
        for (size_t i = 0; i < p.len; ++i)
            covered[static_cast<uint8_t*>(p.dst) - dst.data() + i] = true;
    for (size_t i = 0; i < dst.size(); ++i)
        if (!covered[i]) ASSERT_EQ(dst.data()[i], 0xEE) << i;
}

TEST_F(SecurePushTest, ReadIntoLocalOnlyMemoryIsRefused) {
    Buf src(A(), 1 << 16, 1);
    Buf dst(B(), 1 << 16, 2);
    auto seg = Open(A(), B());
    Status submit;
    EXPECT_EQ(Transfer(A(), seg, {{src.data(), dst.data(), 4096}}, TR::READ,
                       &submit),
              Transport::TransferStatusEnum::FAILED);
    EXPECT_FALSE(submit.ok());
    EXPECT_EQ(src.data()[0], 1);
}

TEST_F(SecurePushTest, UnregisteredSourceIsRefused) {
    std::vector<uint8_t> src(4096, 9);
    Buf dst(B(), 4096, 0);
    auto seg = Open(A(), B());
    Status submit;
    EXPECT_EQ(Transfer(A(), seg, {{src.data(), dst.data(), 4096}}, TR::WRITE,
                       &submit),
              Transport::TransferStatusEnum::FAILED);
    EXPECT_FALSE(submit.ok());
    EXPECT_EQ(dst.data()[0], 0);
}

TEST_F(SecurePushTest, TamperedStagingIsDetected) {
    Buf src(A(), 1 << 15, 0x5A);
    Buf dst(B(), 1 << 15, 0xEE);
    auto seg = Open(A(), B());
    int tampered = 0;
    A().xport->push_service()->test_hooks().before_commit =
        [&](const std::vector<std::pair<uint64_t, size_t>>& slots) {
            // In-process, the peer's slot is addressable here: flip one
            // ciphertext byte as a co-tenant on the fabric could.
            auto* p = reinterpret_cast<uint8_t*>(slots[0].first);
            p[kHeaderSize + 100] ^= 1;
            ++tampered;
        };
    EXPECT_EQ(Transfer(A(), seg, {{src.data(), dst.data(), src.size()}}),
              Transport::TransferStatusEnum::FAILED);
    EXPECT_GE(tampered, 1);
    // Opening failed: the destination holds zeros, never the plaintext.
    for (size_t i = 0; i < dst.size(); ++i) ASSERT_EQ(dst.data()[i], 0) << i;
}

TEST_F(SecurePushTest, TamperedHeaderIsDetected) {
    Buf src(A(), 1 << 15, 0x5A);
    Buf dst(B(), 1 << 15, 0xEE);
    auto seg = Open(A(), B());
    A().xport->push_service()->test_hooks().before_commit =
        [&](const std::vector<std::pair<uint64_t, size_t>>& slots) {
            auto* p = reinterpret_cast<uint8_t*>(slots[0].first);
            p[30] ^= 0x80;  // a nonce byte
        };
    EXPECT_EQ(Transfer(A(), seg, {{src.data(), dst.data(), src.size()}}),
              Transport::TransferStatusEnum::FAILED);
    for (size_t i = 0; i < dst.size(); ++i) ASSERT_NE(dst.data()[i], 0x5A);
}

TEST_F(SecurePushTest, ReplayedCommitIsRefused) {
    Buf src(A(), 1 << 16, 0x11);
    Buf dst(B(), 1 << 16, 0);
    auto seg = Open(A(), B());
    std::vector<std::string> frames;
    A().xport->push_service()->test_hooks().on_frame_sent =
        [&](const std::string& f) { frames.push_back(f); };
    ASSERT_EQ(Transfer(A(), seg, {{src.data(), dst.data(), 4096}}),
              Transport::TransferStatusEnum::COMPLETED);
    ASSERT_EQ(frames.size(), 2u);  // RESERVE, COMMIT
    ASSERT_EQ(dst.data()[0], 0x11);
    memset(dst.data(), 0x77, dst.size());

    auto* rx = B().xport->push_service();
    const auto rejected = rx->rejected_requests();
    for (auto& f : frames) {
        EXPECT_TRUE(SecurePushService::SendRawFrameForTesting(
                        rx->control_host(), rx->control_port(), f, 5000)
                        .empty());
    }
    EXPECT_EQ(rx->rejected_requests(), rejected + 2);
    for (size_t i = 0; i < dst.size(); ++i) ASSERT_EQ(dst.data()[i], 0x77);
}

TEST_F(SecurePushTest, UnauthenticatedCommitIsRefused) {
    Buf src(A(), 1 << 16, 0x22);
    Buf dst(B(), 1 << 16, 0);
    auto seg = Open(A(), B());
    std::vector<std::string> frames;
    A().xport->push_service()->test_hooks().on_frame_sent =
        [&](const std::string& f) { frames.push_back(f); };
    ASSERT_EQ(Transfer(A(), seg, {{src.data(), dst.data(), 4096}}),
              Transport::TransferStatusEnum::COMPLETED);
    ASSERT_EQ(frames.size(), 2u);
    memset(dst.data(), 0x77, dst.size());

    // The genuine commit body, for forging variants of it.
    std::string body(frames[1].size() - kOverhead, '\0');
    MutableSpan out{body.data(), body.size()};
    const std::string aad = RequestAad(B().engine->getLocalIpAndPort());
    ASSERT_EQ(SecureContext::Global().opener().Open(
                  {frames[1].data(), frames[1].size()}, Purpose::kControl,
                  {aad.data(), aad.size()}, &out, 1),
              Error::kOk);

    std::vector<std::string> forged;
    // 1. Garbage.
    forged.push_back(std::string(200, 'x'));
    // 2. The commit with one ciphertext bit flipped.
    forged.push_back(frames[1]);
    forged.back()[kHeaderSize + 3] ^= 1;
    // 3. The commit body sealed under a key the receiver does not hold.
    {
        std::array<uint8_t, kKeySize> k;
        k.fill(0x42);
        Error e;
        auto ring = KeyRing::FromKeys({k}, &e);
        auto sealer = Sealer::Create(ring, Purpose::kControl,
                                     Algorithm::kAes256Gcm, &e);
        std::string f(SealedSize(body.size()), '\0');
        ConstSpan pt{body.data(), body.size()};
        ASSERT_EQ(sealer->Seal(&pt, 1, {aad.data(), aad.size()},
                               {f.data(), f.size()}, nullptr),
                  Error::kOk);
        forged.push_back(f);
    }
    // 4. The right key but the data purpose.
    {
        std::string f(SealedSize(body.size()), '\0');
        ConstSpan pt{body.data(), body.size()};
        ASSERT_EQ(SecureContext::Global()
                      .sealer(Purpose::kTransfer)
                      .Seal(&pt, 1, {aad.data(), aad.size()},
                            {f.data(), f.size()}, nullptr),
                  Error::kOk);
        forged.push_back(f);
    }
    // 5. The right key and purpose, bound to another receiver.
    {
        const std::string other = RequestAad("127.0.0.1:1");
        std::string f(SealedSize(body.size()), '\0');
        ConstSpan pt{body.data(), body.size()};
        ASSERT_EQ(SecureContext::Global()
                      .sealer(Purpose::kControl)
                      .Seal(&pt, 1, {other.data(), other.size()},
                            {f.data(), f.size()}, nullptr),
                  Error::kOk);
        forged.push_back(f);
    }
    auto* rx = B().xport->push_service();
    const auto rejected = rx->rejected_requests();
    for (auto& f : forged)
        EXPECT_TRUE(SecurePushService::SendRawFrameForTesting(
                        rx->control_host(), rx->control_port(), f, 5000)
                        .empty());
    EXPECT_EQ(rx->rejected_requests(), rejected + forged.size());
    for (size_t i = 0; i < dst.size(); ++i) ASSERT_EQ(dst.data()[i], 0x77);
}

TEST_F(SecurePushTest, DestinationOutsideRegisteredMemoryIsRefused) {
    Buf src(A(), 1 << 16, 0x33);
    Buf dst(B(), 1 << 16, 0);
    std::vector<uint8_t> unregistered(1 << 16, 0x44);
    auto seg = Open(A(), B());
    // Entirely unregistered.
    EXPECT_EQ(Transfer(A(), seg, {{src.data(), unregistered.data(), 4096}}),
              Transport::TransferStatusEnum::FAILED);
    for (auto b : unregistered) ASSERT_EQ(b, 0x44);
    // Running off the end of a registered region.
    EXPECT_EQ(
        Transfer(A(), seg,
                 {{src.data(), dst.data() + dst.size() - 1000, 4096}}),
        Transport::TransferStatusEnum::FAILED);
    ASSERT_TRUE(B().xport->push_service()->receiver_enabled());
    // One good and one bad piece in the same window: nothing is opened.
    EXPECT_EQ(Transfer(A(), seg,
                       {{src.data(), dst.data(), 4096},
                        {src.data() + 4096, unregistered.data(), 4096}}),
              Transport::TransferStatusEnum::FAILED);
    for (size_t i = 0; i < 4096; ++i) ASSERT_EQ(dst.data()[i], 0) << i;
    for (auto b : unregistered) ASSERT_EQ(b, 0x44);
    // The receiver still serves good pushes afterwards.
    EXPECT_EQ(Transfer(A(), seg, {{src.data(), dst.data(), 4096}}),
              Transport::TransferStatusEnum::COMPLETED);
    EXPECT_EQ(dst.data()[4095], 0x33);
}

TEST_F(SecurePushTest, ConcurrentSenders) {
    constexpr int kThreads = 8;
    constexpr size_t kPer = 1 << 20;
    Buf srcA(A(), kThreads * kPer, 0);
    Buf srcC(C(), kThreads * kPer, 0);
    Buf dst(B(), 2 * kThreads * kPer, 0);
    auto a = Random(srcA.size(), 21), c = Random(srcC.size(), 22);
    memcpy(srcA.data(), a.data(), a.size());
    memcpy(srcC.data(), c.data(), c.size());
    auto segA = Open(A(), B());
    auto segC = Open(C(), B());
    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 2 * kThreads; ++t) {
        threads.emplace_back([&, t] {
            const bool fromA = t < kThreads;
            Node& n = fromA ? A() : C();
            auto* s = (fromA ? srcA.data() : srcC.data()) + (t % kThreads) * kPer;
            auto* d = dst.data() + t * kPer;
            for (int round = 0; round < 4; ++round) {
                auto pieces = Scatter(s, d, kPer, 64, 100 * t + round, 30000);
                if (Transfer(n, fromA ? segA : segC, pieces) !=
                    Transport::TransferStatusEnum::COMPLETED) {
                    ++failures;
                    continue;
                }
                for (auto& p : pieces)
                    if (memcmp(p.src, p.dst, p.len) != 0) ++failures;
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(failures.load(), 0);
}

TEST_F(SecurePushTest, LargeWindowedTransfer) {
    size_t mb = 64;
    if (const char* v = getenv("SECURE_PUSH_TEST_LARGE_MB")) mb = atoi(v);
    const size_t n = mb << 20;
    Buf src(A(), n, 0);
    Buf dst(B(), n, 0);
    for (size_t i = 0; i < n; i += 8) {
        uint64_t v = i * 0x9E3779B97F4A7C15ull;
        memcpy(src.data() + i, &v, 8);
    }
    auto seg = Open(A(), B());
    // A few large pieces plus a long tail of small ones.
    std::vector<Piece> pieces;
    size_t off = 0;
    for (size_t len : {n / 4, n / 4, n / 8}) {
        pieces.push_back({src.data() + off, dst.data() + n - off - len, len});
        off += len;
    }
    while (off < n) {
        size_t len = std::min<size_t>(4096 + off % 777, n - off);
        pieces.push_back({src.data() + off, dst.data() + off - 5 * n / 8, len});
        off += len;
    }
    std::atomic<size_t> segments{0};
    A().xport->push_service()->test_hooks().on_segment_sealed =
        [&](const SealedInfo&) { ++segments; };
    auto t0 = std::chrono::steady_clock::now();
    EXPECT_EQ(Transfer(A(), seg, pieces),
              Transport::TransferStatusEnum::COMPLETED);
    auto ms = std::chrono::duration<double, std::milli>(
                  std::chrono::steady_clock::now() - t0)
                  .count();
    LOG(INFO) << "large transfer: " << mb << " MiB in " << ms << " ms ("
              << segments << " segments)";
    // Every segment sealed exactly once (no reseal on the happy path).
    EXPECT_EQ(segments.load(),
              PlanPushSegments(n, 65536, 16384,
                               PushOptions::FromEnv().threads)
                  .size());
    ExpectDelivered(pieces);
}

TEST_F(SecurePushTest, RetryUsesFreshNoncesAndTransferId) {
    Buf src(A(), 1 << 18, 0x66);
    Buf dst(B(), 1 << 18, 0);
    auto seg = Open(A(), B());
    auto* hooks = &A().xport->push_service()->test_hooks();
    std::mutex mu;
    std::set<std::string> nonces;
    size_t sealed = 0;
    hooks->on_segment_sealed = [&](const SealedInfo& h) {
        std::lock_guard<std::mutex> lock(mu);
        nonces.insert(std::string(h.salt.begin(), h.salt.end()) +
                      std::string(h.nonce.begin(), h.nonce.end()));
        ++sealed;
    };
    std::vector<std::string> commits;
    hooks->on_frame_sent = [&](const std::string& f) { commits.push_back(f); };
    bool first = true;
    hooks->before_commit =
        [&](const std::vector<std::pair<uint64_t, size_t>>& slots) {
            if (!first) return;
            first = false;
            reinterpret_cast<uint8_t*>(slots[0].first)[kHeaderSize] ^= 1;
        };
    std::vector<Piece> pieces = {{src.data(), dst.data(), src.size()}};
    // batch_transfer_sync_write retries a FAILED batch by resubmitting it.
    EXPECT_EQ(Transfer(A(), seg, pieces),
              Transport::TransferStatusEnum::FAILED);
    EXPECT_EQ(Transfer(A(), seg, pieces),
              Transport::TransferStatusEnum::COMPLETED);
    ExpectDelivered(pieces);
    EXPECT_EQ(nonces.size(), sealed);  // no (salt, nonce) reused
    EXPECT_GE(sealed, 2 * (src.size() / 65536));
    std::set<std::string> unique(commits.begin(), commits.end());
    EXPECT_EQ(unique.size(), commits.size());
}

#ifdef USE_CUDA
TEST_F(SecurePushTest, DeviceMemoryRoundTrip) {
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess || count == 0) {
        cudaGetLastError();
        GTEST_SKIP() << "no GPU";
    }
    const size_t n = 48 << 20;
    void *dsrc = nullptr, *ddst = nullptr;
    ASSERT_EQ(cudaMalloc(&dsrc, n), cudaSuccess);
    ASSERT_EQ(cudaMalloc(&ddst, n), cudaSuccess);
    ASSERT_EQ(cudaMemset(ddst, 0, n), cudaSuccess);
    auto host = Random(n, 99);
    ASSERT_EQ(cudaMemcpy(dsrc, host.data(), n, cudaMemcpyHostToDevice),
              cudaSuccess);
    ASSERT_EQ(A().engine->registerLocalMemory(dsrc, n, "cuda:0"), 0);
    ASSERT_EQ(B().engine->registerLocalMemory(ddst, n, "cuda:0"), 0);
    auto seg = Open(A(), B());
    auto* s = static_cast<uint8_t*>(dsrc);
    auto* d = static_cast<uint8_t*>(ddst);
    // Scattered device -> device blocks, like KV cache pages.
    std::vector<Piece> pieces;
    const size_t block = 256 << 10;
    for (size_t i = 0; i < n / block; ++i)
        pieces.push_back({s + i * block, d + ((i * 7) % (n / block)) * block,
                          block});
    EXPECT_EQ(Transfer(A(), seg, pieces),
              Transport::TransferStatusEnum::COMPLETED);
    std::vector<uint8_t> back(n);
    ASSERT_EQ(cudaMemcpy(back.data(), ddst, n, cudaMemcpyDeviceToHost),
              cudaSuccess);
    for (size_t i = 0; i < n / block; ++i)
        ASSERT_EQ(memcmp(host.data() + i * block,
                         back.data() + ((i * 7) % (n / block)) * block, block),
                  0)
            << "block " << i;

    // Host source -> device destination, and a tampered device push leaves
    // the device destination untouched.
    Buf hsrc(A(), 1 << 20, 0xA5);
    EXPECT_EQ(Transfer(A(), seg, {{hsrc.data(), d, 1 << 20}}),
              Transport::TransferStatusEnum::COMPLETED);
    ASSERT_EQ(cudaMemcpy(back.data(), ddst, 1 << 20, cudaMemcpyDeviceToHost),
              cudaSuccess);
    for (size_t i = 0; i < (1u << 20); ++i) ASSERT_EQ(back[i], 0xA5) << i;
    A().xport->push_service()->test_hooks().before_commit =
        [&](const std::vector<std::pair<uint64_t, size_t>>& slots) {
            reinterpret_cast<uint8_t*>(slots[0].first)[kHeaderSize] ^= 1;
        };
    EXPECT_EQ(Transfer(A(), seg, {{s, d, 1 << 20}}),
              Transport::TransferStatusEnum::FAILED);
    ASSERT_EQ(cudaMemcpy(back.data(), ddst, 1 << 20, cudaMemcpyDeviceToHost),
              cudaSuccess);
    // The tampered segment (the first 64 KiB) never reaches the device;
    // other segments of the failed push hold either the old bytes or the
    // authentic ones, never anything else.
    for (size_t i = 0; i < (1u << 16); ++i) ASSERT_EQ(back[i], 0xA5) << i;
    for (size_t i = 0; i < (1u << 20); ++i)
        ASSERT_TRUE(back[i] == 0xA5 || back[i] == host[i]) << i;

    A().engine->unregisterLocalMemory(dsrc);
    B().engine->unregisterLocalMemory(ddst);
    cudaFree(dsrc);
    cudaFree(ddst);
}
#endif

// Discovery reads nothing a fabric peer can write: with every buffer the
// receiver publishes overwritten (the reported attack wrote 4 KiB of junk at
// offset 0 of the receive staging), a sender that has never pushed to it
// still finds it and pushes.
TEST_F(SecurePushTest, OverwrittenStagingDoesNotBreakDiscovery) {
    Buf src(C(), 1 << 16, 0x5A);
    Buf dst(B(), 1 << 16, 0);
    auto seg = Open(C(), B());
    ASSERT_TRUE(B().xport->push_service()->receiver_enabled());
    auto desc = C().engine->getMetadata()->getSegmentDescByID(seg, true);
    ASSERT_TRUE(desc);
    ASSERT_FALSE(desc->buffers.empty());
    for (auto& b : desc->buffers)
        memset(reinterpret_cast<void*>(b.addr), 0xCC, b.length);
    C().xport->push_service()->ForgetPeersForTesting();
    EXPECT_EQ(Transfer(C(), seg, {{src.data(), dst.data(), src.size()}}),
              Transport::TransferStatusEnum::COMPLETED);
    for (size_t i = 0; i < dst.size(); ++i) ASSERT_EQ(dst.data()[i], 0x5A) << i;
}

// 1100 idle unauthenticated connections (the reported lock-out used 1100
// against a 1024 cap) from `addresses` source addresses; then a sender with
// no pooled connection still connects and pushes.
void SecurePushTest::FloodThenPush(Node& sender, Node& receiver,
                                   int addresses) {
    constexpr int kFlood = 1100;
    if (!RaiseFdLimit(kFlood + 2048)) GTEST_SKIP() << "RLIMIT_NOFILE too low";
    const auto opt = PushOptions::FromEnv();
    Buf src(sender, 1 << 16, 0x6B);
    Buf dst(receiver, 1 << 16, 0);
    auto seg = sender.engine->openSegment(receiver.engine->getLocalIpAndPort());
    ASSERT_NE(seg, (Transport::SegmentHandle)-1);
    auto* rx = receiver.xport->push_service();
    ASSERT_TRUE(rx->receiver_enabled());
    const auto before = rx->control_stats();
    std::vector<int> flood;
    for (int i = 0; i < kFlood; ++i) {
        const int a = i % addresses;
        const std::string from = "127.0." + std::to_string(1 + a / 250) + "." +
                                 std::to_string(2 + a % 250);
        int fd = ConnectFrom(from, rx->control_host(), rx->control_port());
        if (fd < 0 && i == 0) GTEST_SKIP() << "cannot connect from " << from;
        ASSERT_GE(fd, 0) << "connection " << i << " from " << from;
        flood.push_back(fd);
    }
    // The server has taken every one (admitted or displaced).
    EXPECT_TRUE(WaitFor(
        [&] {
            auto st = rx->control_stats();
            return st.evicted_conns - before.evicted_conns + st.preauth_conns >=
                   static_cast<uint64_t>(kFlood);
        },
        30000));
    auto st = rx->control_stats();
    EXPECT_LE(st.preauth_conns, opt.max_preauth);
    if (addresses == 1) EXPECT_LE(st.preauth_conns, opt.max_preauth_per_ip);

    sender.xport->push_service()->ForgetPeersForTesting();
    EXPECT_EQ(Transfer(sender, seg, {{src.data(), dst.data(), src.size()}}),
              Transport::TransferStatusEnum::COMPLETED);
    for (size_t i = 0; i < dst.size(); ++i) ASSERT_EQ(dst.data()[i], 0x6B) << i;
    for (int fd : flood) ::close(fd);
}

TEST_F(SecurePushTest, UnauthenticatedFloodFromOneAddressDoesNotLockOut) {
    FloodThenPush(A(), B(), 1);
}

TEST_F(SecurePushTest, UnauthenticatedFloodFromManyAddressesDoesNotLockOut) {
    // 8 per address: under the per-address cap, so only the total cap and
    // its eviction stand between the flood and the sender.
    FloodThenPush(C(), B(), 138);
}

// A flood spread one connection per address ties every address. The
// connection displaced for a newcomer is the one that has waited longest
// without authenticating, not an arbitrary one of the tied addresses, so a
// sender's fresh connection (authenticated a round trip after connecting)
// outlives the flood connections opened before it.
TEST_F(SecurePushTest, TiedAddressesDisplaceTheStalestConnection) {
    auto* rx = B().xport->push_service();
    ASSERT_TRUE(rx->receiver_enabled());
    const auto opt = PushOptions::FromEnv();
    if (!RaiseFdLimit(opt.max_preauth + 2048))
        GTEST_SKIP() << "RLIMIT_NOFILE too low";
    // Unauthenticated leftovers of earlier tests time out first.
    ASSERT_TRUE(WaitFor([&] { return rx->control_stats().preauth_conns == 0; },
                        3 * opt.handshake_timeout_ms));
    std::vector<int> fds;
    for (size_t i = 0; i < opt.max_preauth; ++i) {
        const std::string from = "127.1." + std::to_string(i / 250) + "." +
                                 std::to_string(2 + i % 250);
        int fd = ConnectFrom(from, rx->control_host(), rx->control_port());
        if (fd < 0 && i == 0) GTEST_SKIP() << "cannot connect from " << from;
        ASSERT_GE(fd, 0) << from;
        fds.push_back(fd);
    }
    ASSERT_TRUE(WaitFor(
        [&] { return rx->control_stats().preauth_conns >= opt.max_preauth; },
        opt.handshake_timeout_ms / 2));
    const auto before = rx->control_stats();
    int late = ConnectFrom("127.1.250.2", rx->control_host(), rx->control_port());
    ASSERT_GE(late, 0);
    ASSERT_TRUE(WaitFor(
        [&] {
            return rx->control_stats().evicted_conns > before.evicted_conns;
        },
        opt.handshake_timeout_ms / 2));
    EXPECT_EQ(rx->control_stats().evicted_conns, before.evicted_conns + 1);
    EXPECT_GE(MsUntilClosed(fds.front(), 1000), 0);  // the stalest went
    for (size_t i = fds.size() - 8; i < fds.size(); ++i)
        EXPECT_LT(MsUntilClosed(fds[i], 20), 0) << i;  // newer ones stay
    EXPECT_LT(MsUntilClosed(late, 20), 0);
    for (int fd : fds) ::close(fd);
    ::close(late);
}

// An unauthenticated connection's length claim over the cap is refused
// before anything is allocated for it; one at the cap is read and refused
// as unauthenticated.
TEST_F(SecurePushTest, OversizedUnauthenticatedFrameIsNotAllocated) {
    Buf dst(B(), 1 << 16, 0);
    auto* rx = B().xport->push_service();
    ASSERT_TRUE(rx->receiver_enabled());
    const auto opt = PushOptions::FromEnv();
    const auto before = rx->control_stats();
    const auto rejected = rx->rejected_requests();
    constexpr int kClaims = 32;
    std::vector<int> fds;
    for (int i = 0; i < kClaims; ++i) {
        int fd = ConnectFrom("127.0.0.1", rx->control_host(), rx->control_port());
        ASSERT_GE(fd, 0);
        uint32_t len = htonl(60u << 20);
        ASSERT_TRUE(SendRaw(fd, std::string(reinterpret_cast<char*>(&len), 4) +
                                    std::string(4096, 'z')));
        fds.push_back(fd);
    }
    for (int fd : fds) {
        EXPECT_GE(MsUntilClosed(fd, 3000), 0);
        ::close(fd);
    }
    auto st = rx->control_stats();
    EXPECT_EQ(st.oversized_frames - before.oversized_frames,
              static_cast<uint64_t>(kClaims));
    EXPECT_LE(st.preauth_buffer_peak,
              opt.max_preauth * kMaxUnauthenticatedFrameBytes);

    // At the cap: read, then refused as unauthenticated, not as oversized.
    // One byte over: refused unread.
    for (size_t n : {kMaxUnauthenticatedFrameBytes,
                     kMaxUnauthenticatedFrameBytes + 1}) {
        int fd = ConnectFrom("127.0.0.1", rx->control_host(), rx->control_port());
        ASSERT_GE(fd, 0);
        uint32_t len = htonl(static_cast<uint32_t>(n));
        SendRaw(fd, std::string(reinterpret_cast<char*>(&len), 4) +
                        std::string(n, 'y'));
        EXPECT_GE(MsUntilClosed(fd, 3000), 0);
        ::close(fd);
    }
    st = rx->control_stats();
    EXPECT_EQ(st.oversized_frames - before.oversized_frames,
              static_cast<uint64_t>(kClaims + 1));
    EXPECT_EQ(rx->rejected_requests() - rejected,
              static_cast<uint64_t>(kClaims + 2));
}

// A connection that never authenticates (silent, or trickling a frame) is
// closed after the handshake timeout; an authenticated one outlives it and is
// closed after the idle timeout.
TEST_F(SecurePushTest, UnauthenticatedAndIdleConnectionsAreClosed) {
    PushOptions o;
    o.threads = 1;
    o.segment_bytes = 65536;
    o.rx_bytes = 1 << 20;
    o.handshake_timeout_ms = 300;
    o.idle_timeout_ms = 1500;
    PushFabric f;
    f.register_ciphertext = [](void*, size_t) { return 0; };
    f.unregister = [](void*) { return 0; };
    f.is_local_only = [](const void*, size_t) { return false; };
    f.local_name = "127.0.0.1:1";
    SecurePushService svc(f, o);
    ASSERT_EQ(svc.EnableReceiver(), 0);
    const std::string host = svc.control_host();
    const int port = svc.control_port();

    const auto t0 = std::chrono::steady_clock::now();
    int silent = ConnectFrom("127.0.0.1", host, port);
    int slow = ConnectFrom("127.0.0.1", host, port);
    int authed = ConnectFrom("127.0.0.1", host, port);
    ASSERT_GE(silent, 0);
    ASSERT_GE(slow, 0);
    ASSERT_GE(authed, 0);
    // A 200-byte frame, a byte every 50 ms: 10 s if it were let finish.
    uint32_t len = htonl(200);
    ASSERT_TRUE(SendRaw(slow, std::string(reinterpret_cast<char*>(&len), 4)));
    std::atomic<bool> trickling{true};
    std::thread trickle([&] {
        for (int i = 0; i < 200 && trickling.load(); ++i) {
            if (!SendRaw(slow, "x")) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });
    // HELLO authenticates; the reply comes back.
    ASSERT_TRUE(SendRaw(authed, HelloFrame(f.local_name)));
    uint32_t rlen = 0;
    ASSERT_EQ(::recv(authed, &rlen, 4, MSG_WAITALL), 4);
    std::string reply(ntohl(rlen), '\0');
    ASSERT_EQ(::recv(authed, reply.data(), reply.size(), MSG_WAITALL),
              static_cast<ssize_t>(reply.size()));
    EXPECT_TRUE(WaitFor([&] { return svc.control_stats().auth_conns == 1; },
                        1000));

    EXPECT_GE(MsUntilClosed(silent, 3000), 0);
    EXPECT_GE(MsUntilClosed(slow, 3000), 0);
    trickling.store(false);
    trickle.join();
    const auto unauth_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - t0)
                               .count();
    EXPECT_GE(unauth_ms, 250);
    EXPECT_LT(unauth_ms, 3000);
    // Past the handshake timeout, the authenticated connection is still up.
    std::this_thread::sleep_until(t0 + std::chrono::milliseconds(800));
    EXPECT_TRUE(StillOpen(authed));
    EXPECT_GE(MsUntilClosed(authed, 5000), 0);
    EXPECT_GE(svc.control_stats().timed_out_conns, 3u);
    EXPECT_TRUE(WaitFor(
        [&] {
            auto st = svc.control_stats();
            return st.preauth_conns + st.auth_conns == 0;
        },
        2000));
    ::close(silent);
    ::close(slow);
    ::close(authed);
}

// The segment plan covers the push exactly, in order, never over the
// segment size, starting and ending with the small segments.
TEST(SecurePushOptions, SegmentPlan) {
    const size_t seg = 2 << 20, first = 256 << 10;
    for (size_t total : {size_t(1), size_t(4095), size_t(first), size_t(first + 1),
                         size_t(1) << 20, size_t(7) << 20, size_t(32) << 20,
                         size_t(230) << 20, (size_t(1) << 30) + 12345}) {
        for (size_t ramp : {1, 8}) {
            auto plan = PlanPushSegments(total, seg, first, ramp);
            ASSERT_FALSE(plan.empty()) << total;
            size_t off = 0;
            for (auto& [o, len] : plan) {
                ASSERT_EQ(o, off) << total;
                ASSERT_GT(len, 0u) << total;
                ASSERT_LE(len, seg) << total;
                off += len;
            }
            EXPECT_EQ(off, total);
            EXPECT_LE(plan.front().second, first) << total;
            EXPECT_LE(plan.back().second, first) << total;
        }
    }
    // No ramp: full-size segments, the last one partial.
    for (size_t f : {size_t(0), seg, 2 * seg}) {
        auto plan = PlanPushSegments(5 * seg + 7, seg, f, 8);
        ASSERT_EQ(plan.size(), 6u);
        for (size_t i = 0; i < 5; ++i) EXPECT_EQ(plan[i].second, seg);
        EXPECT_EQ(plan.back().second, 7u);
    }
    EXPECT_TRUE(PlanPushSegments(0, seg, first, 8).empty());
}

TEST(SecurePushOptions, CpuList) {
    std::vector<int> c;
    EXPECT_TRUE(ParseCpuList("0-3,8,10-11", &c));
    EXPECT_EQ(c, (std::vector<int>{0, 1, 2, 3, 8, 10, 11}));
    EXPECT_FALSE(ParseCpuList("3-1", &c));
    EXPECT_FALSE(ParseCpuList("x", &c));
}

}  // namespace
}  // namespace secure
}  // namespace mooncake
