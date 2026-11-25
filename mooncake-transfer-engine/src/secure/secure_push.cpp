// Copyright 2026 Doubleword AI
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

#include "secure/secure_push.h"

#include "secure/device_copy.h"

#include "handshake_auth.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <glog/logging.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <bitset>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <list>
#include <unordered_map>

#ifdef USE_CUDA
#include <cuda_runtime.h>
#endif

namespace mooncake {
namespace secure {

namespace {

using Clock = std::chrono::steady_clock;

constexpr uint32_t kHelloVersion = 1;
constexpr size_t kMaxFrame = 64ull << 20;
constexpr uint32_t kMaxPiecesPerSegment = 1u << 20;

constexpr uint8_t kReqReserve = 1;
constexpr uint8_t kReqCommit = 2;
constexpr uint8_t kReqHello = 3;
constexpr uint8_t kRespReserve = 0x81;
constexpr uint8_t kRespCommit = 0x82;
constexpr uint8_t kRespHello = 0x83;
constexpr uint8_t kCommitLast = 1;

constexpr int32_t kOk = 0;
constexpr int32_t kErrBadRequest = 1;
constexpr int32_t kErrBadDestination = 2;
constexpr int32_t kErrOpen = 3;
constexpr int32_t kErrLease = 4;

const char kAadReq[] = "mcp2d-req-v1";
const char kAadResp[] = "mcp2d-resp-v1";
const char kAadData[] = "mcp2d-data-v1";

size_t EnvSize(const char* name, size_t def) {
    const char* v = getenv(name);
    if (!v || !*v) return def;
    char* end = nullptr;
    unsigned long long x = strtoull(v, &end, 10);
    if (end == v) return def;
    return static_cast<size_t>(x);
}

uint64_t NsSince(Clock::time_point t0) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - t0)
            .count());
}

void AtomicMax(std::atomic<uint64_t>& m, uint64_t v) {
    uint64_t cur = m.load(std::memory_order_relaxed);
    while (v > cur &&
           !m.compare_exchange_weak(cur, v, std::memory_order_relaxed)) {
    }
}

// A sum and a maximum, for one push's breakdown.
struct SumMax {
    std::atomic<uint64_t> sum{0}, max{0};
    void Add(uint64_t ns) {
        sum.fetch_add(ns, std::memory_order_relaxed);
        AtomicMax(max, ns);
    }
    void Reset() {
        sum.store(0, std::memory_order_relaxed);
        max.store(0, std::memory_order_relaxed);
    }
};

std::string Ms(uint64_t ns) {
    char b[32];
    snprintf(b, sizeof(b), "%.2f", ns / 1e6);
    return b;
}

std::string Ms(const SumMax& v) {
    return Ms(v.sum.load(std::memory_order_relaxed)) + "/" +
           Ms(v.max.load(std::memory_order_relaxed));
}

// ------------------------------------------------------------- encoding --

class Writer {
   public:
    void U8(uint8_t v) { s_.push_back(static_cast<char>(v)); }
    void U32(uint32_t v) {
        for (int i = 0; i < 4; ++i) U8(static_cast<uint8_t>(v >> (8 * i)));
    }
    void U64(uint64_t v) {
        for (int i = 0; i < 8; ++i) U8(static_cast<uint8_t>(v >> (8 * i)));
    }
    void I32(int32_t v) { U32(static_cast<uint32_t>(v)); }
    void Bytes(const void* p, size_t n) {
        s_.append(static_cast<const char*>(p), n);
    }
    void Str(const std::string& v) {
        U32(static_cast<uint32_t>(v.size()));
        s_.append(v);
    }
    std::string& str() { return s_; }

   private:
    std::string s_;
};

class Reader {
   public:
    Reader(const void* p, size_t n)
        : p_(static_cast<const uint8_t*>(p)), n_(n) {}
    bool U8(uint8_t* v) {
        if (n_ - off_ < 1) return false;
        *v = p_[off_++];
        return true;
    }
    bool U32(uint32_t* v) {
        if (n_ - off_ < 4) return false;
        uint32_t x = 0;
        for (int i = 0; i < 4; ++i) x |= uint32_t(p_[off_ + i]) << (8 * i);
        off_ += 4;
        *v = x;
        return true;
    }
    bool U64(uint64_t* v) {
        if (n_ - off_ < 8) return false;
        uint64_t x = 0;
        for (int i = 0; i < 8; ++i) x |= uint64_t(p_[off_ + i]) << (8 * i);
        off_ += 8;
        *v = x;
        return true;
    }
    bool I32(int32_t* v) {
        uint32_t x;
        if (!U32(&x)) return false;
        *v = static_cast<int32_t>(x);
        return true;
    }
    bool Bytes(void* out, size_t n) {
        if (n_ - off_ < n) return false;
        memcpy(out, p_ + off_, n);
        off_ += n;
        return true;
    }
    bool Str(std::string* v, size_t max = 4096) {
        uint32_t len;
        if (!U32(&len) || len > max || n_ - off_ < len) return false;
        v->assign(reinterpret_cast<const char*>(p_ + off_), len);
        off_ += len;
        return true;
    }
    size_t remaining() const { return n_ - off_; }

   private:
    const uint8_t* p_;
    size_t n_;
    size_t off_ = 0;
};

std::string Aad(const char* label, const std::string& receiver,
                const void* extra = nullptr, size_t extra_len = 0) {
    Writer w;
    w.Bytes(label, strlen(label) + 1);
    w.Str(receiver);
    if (extra_len) w.Bytes(extra, extra_len);
    return std::move(w.str());
}

struct Segment {
    std::vector<ConstSpan> src;   // local source pieces
    std::vector<PushPiece> dst;   // .dst/.len used: remote destinations
    size_t bytes = 0;
};

std::string DataAad(const std::string& receiver, const std::string& sender,
                    const uint8_t transfer_id[16], uint32_t index,
                    uint32_t total, const std::vector<PushPiece>& dst) {
    Writer w;
    w.Bytes(kAadData, sizeof(kAadData));
    w.Str(receiver);
    w.Str(sender);
    w.Bytes(transfer_id, 16);
    w.U32(index);
    w.U32(total);
    w.U32(static_cast<uint32_t>(dst.size()));
    for (auto& d : dst) {
        w.U64(d.dst);
        w.U64(d.len);
    }
    return std::move(w.str());
}

// Seals a control message into a frame (the sealed bytes).
bool SealControl(const std::string& body, const std::string& aad,
                 std::string* frame) {
    auto& sealer = SecureContext::Global().sealer(Purpose::kControl);
    frame->resize(SealedSize(body.size()));
    ConstSpan pt{body.data(), body.size()};
    size_t n = 0;
    Error e = sealer.Seal(&pt, 1, {aad.data(), aad.size()},
                          {frame->data(), frame->size()}, &n);
    if (e != Error::kOk) {
        LOG(ERROR) << "secure push: sealing a control message failed: "
                   << ToString(e);
        return false;
    }
    return true;
}

bool OpenControl(const std::string& frame, const std::string& aad,
                 std::string* body, SealedInfo* info) {
    size_t pt_len;
    if (!PlaintextSize(frame.size(), &pt_len)) return false;
    body->assign(pt_len, '\0');
    MutableSpan out{body->data(), body->size()};
    Error e = SecureContext::Global().opener().Open(
        {frame.data(), frame.size()}, Purpose::kControl,
        {aad.data(), aad.size()}, &out, 1, info);
    return e == Error::kOk;
}

// --------------------------------------------------------------- sockets --

bool SendAll(int fd, const void* p, size_t n) {
    auto* c = static_cast<const char*>(p);
    while (n) {
        ssize_t k = ::send(fd, c, n, MSG_NOSIGNAL);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return false;
        c += k;
        n -= static_cast<size_t>(k);
    }
    return true;
}

bool RecvAll(int fd, void* p, size_t n) {
    auto* c = static_cast<char*>(p);
    while (n) {
        ssize_t k = ::recv(fd, c, n, 0);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return false;
        c += k;
        n -= static_cast<size_t>(k);
    }
    return true;
}

bool SendFrame(int fd, const std::string& frame) {
    uint32_t len = htonl(static_cast<uint32_t>(frame.size()));
    return SendAll(fd, &len, 4) && SendAll(fd, frame.data(), frame.size());
}

bool RecvFrame(int fd, std::string* frame) {
    uint32_t len;
    if (!RecvAll(fd, &len, 4)) return false;
    len = ntohl(len);
    if (len > kMaxFrame) return false;
    frame->resize(len);
    return RecvAll(fd, frame->data(), len);
}

enum class Rx { kOk, kClosed, kTimeout, kTooLarge };

// Reads exactly n bytes by `deadline`, however slowly the peer trickles them.
Rx RecvBy(int fd, void* p, size_t n, Clock::time_point deadline) {
    auto* c = static_cast<char*>(p);
    while (n) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - Clock::now())
                              .count();
        if (left <= 0) return Rx::kTimeout;
        pollfd pf{fd, POLLIN, 0};
        int r = ::poll(&pf, 1, static_cast<int>(std::min<int64_t>(left, 1000)));
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return Rx::kClosed;
        if (r == 0) continue;
        ssize_t k = ::recv(fd, c, n, MSG_DONTWAIT);
        if (k < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (k <= 0) return Rx::kClosed;
        c += k;
        n -= static_cast<size_t>(k);
    }
    return Rx::kOk;
}

// Server side: one frame whose length prefix must arrive by
// `header_deadline` and whose body by `body_deadline`. A length over
// `max_len` is refused before anything is allocated for it. `on_alloc` is
// told the body size before the buffer grows and after the frame is read
// (or not).
Rx RecvFrameBy(int fd, std::string* frame, size_t max_len,
               Clock::time_point header_deadline,
               Clock::time_point body_deadline,
               const std::function<void(size_t)>& on_alloc,
               uint32_t* claimed = nullptr) {
    uint32_t len;
    Rx r = RecvBy(fd, &len, 4, header_deadline);
    if (r != Rx::kOk) return r;
    len = ntohl(len);
    if (claimed) *claimed = len;
    if (len > max_len) return Rx::kTooLarge;
    if (on_alloc) on_alloc(len);
    frame->resize(len);
    return RecvBy(fd, frame->data(), len, body_deadline);
}

void SetTimeouts(int fd, int timeout_ms) {
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

int Connect(const std::string& host, int port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints,
                    &res) != 0)
        return -1;
    int fd = -1;
    for (auto* ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
                      ai->ai_protocol);
        if (fd < 0) continue;
        SetTimeouts(fd, timeout_ms);
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

// True if a pooled idle connection is still usable (no EOF/error pending).
bool IdleConnAlive(int fd) {
    pollfd p{fd, POLLIN, 0};
    int r = ::poll(&p, 1, 0);
    return r == 0;
}

// --------------------------------------------------------------- memory --

// Private copy of a remotely writable receive slot (see OpenSegment).
thread_local std::vector<uint8_t> t_private;

// ----------------------------------------------------------- replay guard --

class ReplayGuard {
   public:
    bool Accept(const SealedInfo& h) {
        std::string key(reinterpret_cast<const char*>(&h.key_id), 4);
        key.append(reinterpret_cast<const char*>(h.salt.data()), kSaltSize);
        const uint64_t c = h.counter();
        std::lock_guard<std::mutex> lock(mu_);
        auto it = windows_.find(key);
        if (it == windows_.end()) {
            if (windows_.size() >= kMaxSenders) EvictOldest();
            it = windows_.emplace(key, Window{}).first;
            it->second.top = c;
            it->second.seen.set(c % kWindow);
            it->second.last_use = ++tick_;
            return true;
        }
        Window& w = it->second;
        w.last_use = ++tick_;
        if (c > w.top) {
            const uint64_t shift = c - w.top;
            if (shift >= kWindow) {
                w.seen.reset();
            } else {
                for (uint64_t x = w.top + 1; x <= c; ++x)
                    w.seen.reset(x % kWindow);
            }
            w.top = c;
            w.seen.set(c % kWindow);
            return true;
        }
        if (w.top - c >= kWindow) return false;
        if (w.seen.test(c % kWindow)) return false;
        w.seen.set(c % kWindow);
        return true;
    }

   private:
    static constexpr uint64_t kWindow = 4096;
    static constexpr size_t kMaxSenders = 65536;
    struct Window {
        uint64_t top = 0;
        uint64_t last_use = 0;
        std::bitset<kWindow> seen;
    };
    void EvictOldest() {
        auto oldest = windows_.begin();
        for (auto it = windows_.begin(); it != windows_.end(); ++it)
            if (it->second.last_use < oldest->second.last_use) oldest = it;
        windows_.erase(oldest);
    }
    std::mutex mu_;
    std::map<std::string, Window> windows_;
    uint64_t tick_ = 0;
};

std::string HostPart(const std::string& name) {
    if (!name.empty() && name[0] == '[') {
        auto end = name.find(']');
        if (end != std::string::npos) return name.substr(1, end - 1);
    }
    auto colon = name.rfind(':');
    if (colon == std::string::npos || name.find(':') != colon) return name;
    return name.substr(0, colon);
}

}  // namespace

// --------------------------------------------------------------- options --

bool ParseCpuList(const std::string& text, std::vector<int>* out) {
    out->clear();
    size_t i = 0;
    while (i < text.size()) {
        size_t j = text.find(',', i);
        if (j == std::string::npos) j = text.size();
        std::string part = text.substr(i, j - i);
        i = j + 1;
        if (part.empty()) continue;
        char* end = nullptr;
        long a = strtol(part.c_str(), &end, 10);
        if (end == part.c_str() || a < 0) return false;
        long b = a;
        if (*end == '-') {
            const char* s = end + 1;
            b = strtol(s, &end, 10);
            if (end == s || b < a) return false;
        }
        if (*end != '\0' || b - a > 4096) return false;
        for (long c = a; c <= b; ++c) out->push_back(static_cast<int>(c));
    }
    return true;
}

std::vector<std::pair<size_t, size_t>> PlanPushSegments(size_t total,
                                                        size_t segment_bytes,
                                                        size_t first_bytes,
                                                        size_t ramp) {
    std::vector<std::pair<size_t, size_t>> out;
    if (total == 0 || segment_bytes == 0) return out;
    ramp = std::max<size_t>(1, ramp);
    std::vector<size_t> up;  // first, 2 first, ... below segment_bytes
    if (first_bytes > 0)
        for (size_t s = first_bytes; s < segment_bytes; s *= 2) up.push_back(s);
    size_t tail = 0;
    for (size_t s : up) tail += s;
    size_t off = 0, rem = total;
    auto take = [&](size_t n) {
        out.emplace_back(off, n);
        off += n;
        rem -= n;
    };
    if (total <= tail) {
        // Small: all first-size segments, sealed in parallel.
        while (rem) take(std::min(first_bytes, rem));
        return out;
    }
    // Ramp up, keeping back exactly `tail` bytes for the ramp down.
    for (size_t s : up)
        for (size_t r = 0; r < ramp && rem > tail; ++r)
            take(std::min(s, rem - tail));
    while (rem > tail) take(std::min(segment_bytes, rem - tail));
    for (auto it = up.rbegin(); it != up.rend(); ++it) take(*it);
    return out;
}

PushOptions PushOptions::FromEnv() {
    PushOptions o;
    o.threads = std::max<size_t>(1, EnvSize("MC_SECURE_P2D_THREADS", o.threads));
    o.segment_bytes = std::max<size_t>(
        4096, EnvSize("MC_SECURE_P2D_SEGMENT_BYTES", o.segment_bytes));
    o.segment_bytes = (o.segment_bytes + 63) & ~size_t(63);
    o.window_segments = std::max<size_t>(
        1, EnvSize("MC_SECURE_P2D_WINDOW_SEGMENTS", o.window_segments));
    o.first_segment_bytes = EnvSize("MC_SECURE_P2D_FIRST_SEGMENT_BYTES",
                                    o.first_segment_bytes);
    o.first_segment_bytes = (o.first_segment_bytes + 63) & ~size_t(63);
    o.rx_bytes = EnvSize("MC_SECURE_P2D_RX_BYTES", o.rx_bytes);
    o.tx_bytes = EnvSize("MC_SECURE_P2D_TX_BYTES", o.tx_bytes);
    o.port = static_cast<int>(EnvSize("MC_SECURE_P2D_PORT", 0));
    o.timeout_ms = static_cast<int>(
        std::max<size_t>(100, EnvSize("MC_SECURE_P2D_TIMEOUT_MS", 30000)));
    o.rx_copy = EnvSize("MC_SECURE_P2D_RX_COPY", 1) != 0;
    o.max_conns =
        std::max<size_t>(1, EnvSize("MC_SECURE_P2D_MAX_CONNS", o.max_conns));
    o.max_preauth = std::max<size_t>(
        1, EnvSize("MC_SECURE_P2D_MAX_PREAUTH", o.max_preauth));
    o.max_preauth_per_ip = std::max<size_t>(
        1, EnvSize("MC_SECURE_P2D_MAX_PREAUTH_PER_IP", o.max_preauth_per_ip));
    o.handshake_timeout_ms = static_cast<int>(std::min<size_t>(
        600000, std::max<size_t>(100, EnvSize("MC_SECURE_P2D_HANDSHAKE_TIMEOUT_MS",
                                              o.handshake_timeout_ms))));
    o.idle_timeout_ms = static_cast<int>(std::min<size_t>(
        86400000, std::max<size_t>(100, EnvSize("MC_SECURE_P2D_IDLE_TIMEOUT_MS",
                                                o.idle_timeout_ms))));
    if (const char* v = getenv("MC_SECURE_P2D_NUMA_NODE"); v && *v) {
        const std::string t(v);
        char* end = nullptr;
        const long node = strtol(v, &end, 10);
        if (t == "auto") {
            o.numa_node = PushOptions::kNumaAuto;
        } else if (t == "none" || t == "off") {
            o.numa_node = PushOptions::kNumaNone;
        } else if (end != v && *end == '\0' && node >= 0 && node < 256) {
            o.numa_node = static_cast<int>(node);
        } else {
            LOG(WARNING) << "secure push: ignoring malformed "
                            "MC_SECURE_P2D_NUMA_NODE="
                         << v << " (auto)";
        }
    }
    o.stats_interval_s = static_cast<int>(std::min<size_t>(
        86400, EnvSize("MC_SECURE_P2D_STATS_INTERVAL_S",
                       static_cast<size_t>(o.stats_interval_s))));
    if (const char* h = getenv("MC_SECURE_P2D_HOST")) o.host = h;
    if (const char* c = getenv("MC_SECURE_P2D_CPUS")) {
        if (!ParseCpuList(c, &o.cpus)) {
            LOG(WARNING) << "secure push: ignoring malformed MC_SECURE_P2D_CPUS="
                         << c;
            o.cpus.clear();
        }
    }
    return o;
}

// ----------------------------------------------------------- crypto pool --

CryptoPool::CryptoPool(size_t threads, const std::vector<int>& cpus,
                       const char* name, bool each)
    : cpus_(cpus), each_(each) {
    for (size_t i = 0; i < threads; ++i) {
        threads_.emplace_back([this, i] { Loop(i); });
        pthread_setname_np(threads_.back().native_handle(), name);
    }
}

CryptoPool::~CryptoPool() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        stop_ = true;
    }
    cv_.notify_all();
    for (auto& t : threads_) t.join();
}

void CryptoPool::Run(std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        queue_.push_back(std::move(fn));
    }
    cv_.notify_one();
}

void CryptoPool::Loop(size_t index) {
    if (!cpus_.empty()) {
        cpu_set_t set;
        CPU_ZERO(&set);
        if (each_) {
            CPU_SET(cpus_[index % cpus_.size()], &set);
        } else {
            for (int c : cpus_)
                if (c >= 0 && c < CPU_SETSIZE) CPU_SET(c, &set);
        }
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }
    for (;;) {
        std::function<void()> fn;
        {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait(lock, [&] { return stop_ || !queue_.empty(); });
            if (queue_.empty()) return;
            fn = std::move(queue_.front());
            queue_.pop_front();
        }
        fn();
    }
}

// ------------------------------------------------------------- telemetry --

const char* PushStageName(PushStage s) {
    switch (s) {
        case PushStage::kD2H: return "d2h";
        case PushStage::kSeal: return "seal";
        case PushStage::kWrite: return "write";
        case PushStage::kCommitRtt: return "commit_rtt";
        case PushStage::kSealWait: return "wait_seal";
        case PushStage::kWriteWait: return "wait_write";
        case PushStage::kAckWait: return "wait_ack";
        case PushStage::kPush: return "push";
        case PushStage::kRxCopy: return "rx_copy";
        case PushStage::kOpen: return "open";
        case PushStage::kH2D: return "h2d";
        default: return "?";
    }
}

uint64_t StageStats::QuantileUpperUs(double q) const {
    if (count == 0) return 0;
    const double want = q * static_cast<double>(count);
    uint64_t seen = 0;
    for (int b = 0; b < kStageBuckets; ++b) {
        seen += buckets[b];
        if (static_cast<double>(seen) >= want && buckets[b])
            return b == 0 ? 1 : (1ull << b);
    }
    return 1ull << (kStageBuckets - 1);
}

std::string PushStats::ToString() const {
    std::string out = "pushes=" + std::to_string(pushes) +
                      " failed=" + std::to_string(failed_pushes) +
                      " bytes=" + std::to_string(bytes) +
                      " rx_segments=" + std::to_string(rx_segments) +
                      " node=" + std::to_string(numa_node);
    for (int i = 0; i < static_cast<int>(PushStage::kCount); ++i) {
        const StageStats& st = stage[i];
        if (!st.count) continue;
        char b[160];
        snprintf(b, sizeof(b),
                 " %s{n=%llu mean_us=%.0f max_us=%.0f p50_le_us=%llu "
                 "p99_le_us=%llu}",
                 PushStageName(static_cast<PushStage>(i)),
                 static_cast<unsigned long long>(st.count),
                 st.sum_ns / 1e3 / static_cast<double>(st.count),
                 st.max_ns / 1e3,
                 static_cast<unsigned long long>(st.QuantileUpperUs(0.5)),
                 static_cast<unsigned long long>(st.QuantileUpperUs(0.99)));
        out += b;
    }
    return out;
}

// Lock-free cumulative counters: a few relaxed atomic adds per segment.
struct SecurePushService::Telemetry {
    struct Stage {
        std::atomic<uint64_t> count{0}, sum_ns{0}, max_ns{0};
        std::atomic<uint64_t> buckets[kStageBuckets];
        Stage() {
            for (auto& b : buckets) b.store(0, std::memory_order_relaxed);
        }
    };
    Stage stage[static_cast<int>(PushStage::kCount)];
    std::atomic<uint64_t> pushes{0}, failed{0}, bytes{0}, rx_segments{0};
    std::atomic<int64_t> last_summary_s{0};

    static int Bucket(uint64_t ns) {
        const uint64_t us = ns / 1000;
        if (us == 0) return 0;
        const int b = 64 - __builtin_clzll(us);
        return std::min(b, kStageBuckets - 1);
    }
    void Record(PushStage s, uint64_t ns) {
        Stage& st = stage[static_cast<int>(s)];
        st.count.fetch_add(1, std::memory_order_relaxed);
        st.sum_ns.fetch_add(ns, std::memory_order_relaxed);
        AtomicMax(st.max_ns, ns);
        st.buckets[Bucket(ns)].fetch_add(1, std::memory_order_relaxed);
    }
    PushStats Snapshot() const {
        PushStats p;
        for (int i = 0; i < static_cast<int>(PushStage::kCount); ++i) {
            const Stage& st = stage[i];
            p.stage[i].count = st.count.load(std::memory_order_relaxed);
            p.stage[i].sum_ns = st.sum_ns.load(std::memory_order_relaxed);
            p.stage[i].max_ns = st.max_ns.load(std::memory_order_relaxed);
            for (int b = 0; b < kStageBuckets; ++b)
                p.stage[i].buckets[b] =
                    st.buckets[b].load(std::memory_order_relaxed);
        }
        p.pushes = pushes.load(std::memory_order_relaxed);
        p.failed_pushes = failed.load(std::memory_order_relaxed);
        p.bytes = bytes.load(std::memory_order_relaxed);
        p.rx_segments = rx_segments.load(std::memory_order_relaxed);
        return p;
    }
};

// --------------------------------------------------------------- receiver --

struct SecurePushService::Receiver {
    SecurePushService* svc = nullptr;
    void* base = nullptr;
    size_t bytes = 0;
    size_t slot_bytes = 0;
    uint32_t nslots = 0;
    std::string host;
    int port = 0;
    int listen_fd = -1;
    std::atomic<bool> stop{false};
    std::thread accept_thread;
    std::unique_ptr<CryptoPool> open_pool;
    ReplayGuard replay;

    std::mutex slots_mu;
    std::vector<uint64_t> slot_lease;  // 0: free

    // A control connection. `fd` is closed only by its owner (the reaper or
    // Stop, under conns_mu, after joining), so shutting a live one down
    // never hits a reused descriptor.
    struct Conn {
        int fd = -1;
        std::string ip;
        Clock::time_point accepted;
        std::thread thread;
        std::atomic<bool> done{false};
        std::atomic<bool> authed{false};
        std::atomic<bool> evicted{false};
        // Its first frame arrived whole and is being verified: about to be
        // authenticated or dropped, so never displaced for a newcomer.
        std::atomic<bool> verifying{false};
    };
    std::mutex conns_mu;
    std::list<std::unique_ptr<Conn>> conns;

    // Accounting (ControlStats).
    std::atomic<uint64_t> refused{0}, evicted{0}, timed_out{0}, oversized{0};
    std::atomic<size_t> preauth_buffered{0}, preauth_peak{0};

    uint8_t* slot_ptr(uint32_t s) const {
        return static_cast<uint8_t*>(base) + size_t(s) * slot_bytes;
    }

    ~Receiver() { Stop(); }

    void Stop() {
        if (stop.exchange(true)) return;
        if (listen_fd >= 0) ::shutdown(listen_fd, SHUT_RDWR);
        if (accept_thread.joinable()) accept_thread.join();
        if (listen_fd >= 0) ::close(listen_fd);
        listen_fd = -1;
        std::list<std::unique_ptr<Conn>> all;
        {
            std::lock_guard<std::mutex> lock(conns_mu);
            for (auto& c : conns) ::shutdown(c->fd, SHUT_RDWR);
            all.swap(conns);
        }
        for (auto& c : all) {
            if (c->thread.joinable()) c->thread.join();
            ::close(c->fd);
        }
        open_pool.reset();
    }

    ControlStats Stats() {
        ControlStats st;
        {
            std::lock_guard<std::mutex> lock(conns_mu);
            for (auto& c : conns) {
                if (c->done.load()) continue;
                if (c->authed.load())
                    ++st.auth_conns;
                else if (!c->evicted.load())
                    ++st.preauth_conns;
            }
        }
        st.refused_conns = refused.load();
        st.evicted_conns = evicted.load();
        st.timed_out_conns = timed_out.load();
        st.oversized_frames = oversized.load();
        st.preauth_buffer_peak = preauth_peak.load();
        return st;
    }

    std::vector<uint32_t> Lease(uint64_t lease_id, uint32_t want) {
        std::vector<uint32_t> got;
        const uint32_t cap = std::max<uint32_t>(1, nslots / 2);
        want = std::min(want, cap);
        std::lock_guard<std::mutex> lock(slots_mu);
        for (uint32_t s = 0; s < nslots && got.size() < want; ++s) {
            if (slot_lease[s] == 0) {
                slot_lease[s] = lease_id;
                got.push_back(s);
            }
        }
        return got;
    }

    void Release(uint64_t lease_id) {
        if (!lease_id) return;
        std::lock_guard<std::mutex> lock(slots_mu);
        for (auto& l : slot_lease)
            if (l == lease_id) l = 0;
    }

    // conns_mu held.
    void Reap() {
        for (auto it = conns.begin(); it != conns.end();) {
            if ((*it)->done.load()) {
                (*it)->thread.join();
                ::close((*it)->fd);
                it = conns.erase(it);
            } else {
                ++it;
            }
        }
    }

    // conns_mu held. Makes room for one more unauthenticated connection from
    // `ip`: if that address is at its cap, drops its oldest; else if all
    // unauthenticated connections are taken, drops the oldest of the address
    // holding the most, and among addresses holding equally many, the
    // connection that has waited longest without sending a whole first
    // frame. A connection whose first frame is being verified is never
    // dropped. The newcomer is always admitted, so a flood only ever
    // displaces itself or the largest (then the stalest) flooder, and a
    // sender that authenticates within a round trip is not kept out even by
    // a flood spread one connection per address.
    void MakeRoom(const std::string& ip) {
        const auto& o = svc->opt_;
        // ip -> (unauthenticated connections, oldest that may be dropped)
        std::unordered_map<std::string, std::pair<size_t, Conn*>> by_ip;
        size_t total = 0;
        for (auto& c : conns) {
            if (c->done.load() || c->authed.load() || c->evicted.load())
                continue;
            ++total;
            auto& e = by_ip[c->ip];
            ++e.first;
            if (c->verifying.load()) continue;
            if (!e.second || c->accepted < e.second->accepted)
                e.second = c.get();
        }
        Conn* victim = nullptr;
        auto mine = by_ip.find(ip);
        if (mine != by_ip.end() &&
            mine->second.first >= std::max<size_t>(1, o.max_preauth_per_ip)) {
            victim = mine->second.second;
        } else if (total >= std::max<size_t>(1, o.max_preauth)) {
            size_t most = 0;
            for (auto& kv : by_ip) {
                Conn* cand = kv.second.second;
                if (!cand) continue;
                if (kv.second.first > most ||
                    (kv.second.first == most &&
                     cand->accepted < victim->accepted)) {
                    most = kv.second.first;
                    victim = cand;
                }
            }
        }
        if (victim) {
            victim->evicted.store(true);
            ::shutdown(victim->fd, SHUT_RDWR);
            if (evicted.fetch_add(1) % 1000 == 0)
                LOG(WARNING) << "secure push: dropping unauthenticated control "
                                "connections to admit new ones (from "
                             << victim->ip << "; " << evicted.load()
                             << " so far)";
        }
    }

    // At most once a minute, at the default log level: what the control
    // server dropped since the last summary (each drop logs only at VLOG(1)
    // or rate-limited).
    Clock::time_point last_summary = Clock::now();
    uint64_t sum_evicted = 0, sum_timed_out = 0, sum_oversized = 0,
             sum_refused = 0, sum_rejected = 0;
    void MaybeSummarize() {
        const auto now = Clock::now();
        if (now - last_summary < std::chrono::seconds(60)) return;
        last_summary = now;
        const uint64_t e = evicted.load(), t = timed_out.load(),
                       o = oversized.load(), r = refused.load(),
                       j = svc->rejected_.load();
        const uint64_t de = e - sum_evicted, dt = t - sum_timed_out,
                       dov = o - sum_oversized, dr = r - sum_refused,
                       dj = j - sum_rejected;
        sum_evicted = e;
        sum_timed_out = t;
        sum_oversized = o;
        sum_refused = r;
        sum_rejected = j;
        if (!de && !dt && !dov && !dr && !dj) return;
        const std::string msg =
            "secure push: control server, last minute: " + std::to_string(de) +
            " unauthenticated connections evicted, " + std::to_string(dt) +
            " closed on handshake or idle timeout, " + std::to_string(dov) +
            " oversized frame claims, " + std::to_string(dr) +
            " authenticated connections refused (cap), " + std::to_string(dj) +
            " requests rejected (totals " + std::to_string(e) + ", " +
            std::to_string(t) + ", " + std::to_string(o) + ", " +
            std::to_string(r) + ", " + std::to_string(j) + ")";
        if (de || dov || dr || dj)
            LOG(WARNING) << msg;
        else
            LOG(INFO) << msg;
    }

    void AcceptLoop() {
        while (!stop.load()) {
            pollfd pf{listen_fd, POLLIN, 0};
            int pr = ::poll(&pf, 1, 500);
            if (stop.load()) return;
            MaybeSummarize();
            if (pr <= 0) {
                std::lock_guard<std::mutex> lock(conns_mu);
                Reap();
                continue;
            }
            sockaddr_storage ss{};
            socklen_t sl = sizeof(ss);
            int fd = ::accept4(listen_fd, reinterpret_cast<sockaddr*>(&ss), &sl,
                               SOCK_CLOEXEC);
            if (fd < 0) {
                if (stop.load()) return;
                if (errno == EINTR || errno == ECONNABORTED || errno == EAGAIN)
                    continue;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            // Replies go only to authenticated peers; never block on one
            // that stops reading for longer than a step.
            timeval tv{};
            tv.tv_sec = svc->opt_.timeout_ms / 1000;
            tv.tv_usec = (svc->opt_.timeout_ms % 1000) * 1000;
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            char ip[INET6_ADDRSTRLEN] = "?";
            if (ss.ss_family == AF_INET6)
                inet_ntop(AF_INET6,
                          &reinterpret_cast<sockaddr_in6*>(&ss)->sin6_addr, ip,
                          sizeof(ip));
            else if (ss.ss_family == AF_INET)
                inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(&ss)->sin_addr,
                          ip, sizeof(ip));
            std::lock_guard<std::mutex> lock(conns_mu);
            Reap();
            MakeRoom(ip);
            auto c = std::make_unique<Conn>();
            c->fd = fd;
            c->ip = ip;
            c->accepted = Clock::now();
            Conn* raw = c.get();
            c->thread = std::thread([this, raw] {
                Serve(raw);
                raw->done.store(true);
            });
            conns.push_back(std::move(c));
        }
    }

    // Marks `c` authenticated unless that would exceed MC_SECURE_P2D_MAX_CONNS.
    bool Authenticate(Conn* c) {
        std::lock_guard<std::mutex> lock(conns_mu);
        if (c->evicted.load()) return false;
        size_t n = 0;
        for (auto& o : conns)
            if (!o->done.load() && o->authed.load()) ++n;
        if (n >= svc->opt_.max_conns) {
            if (refused.fetch_add(1) % 1000 == 0)
                LOG(WARNING) << "secure push: too many authenticated control "
                                "connections ("
                             << n << ")";
            return false;
        }
        c->authed.store(true);
        return true;
    }

    bool Reply(int fd, const std::string& req_header, const std::string& body) {
        std::string frame;
        if (!SealControl(body, Aad(kAadResp, svc->fabric_.local_name,
                                   req_header.data(), req_header.size()),
                         &frame))
            return false;
        return SendFrame(fd, frame);
    }

    // One connection's replies, sent in request order. A commit's reply
    // waits until its segments are opened, while later requests are read
    // and their segments opened in parallel.
    struct Replies {
        struct Entry {
            std::string header, body;
            bool ready = false;
            bool release = false;  // the push's last commit: free its slots
            bool fatal = false;    // close the connection after this reply
        };
        std::mutex mu;
        std::condition_variable cv;
        std::deque<std::shared_ptr<Entry>> q;
        size_t outstanding = 0;  // commits being opened
        uint64_t lease_id = 0;
        bool failed = false;
        // This lease's (push's) receive stages, for its VLOG(1) line.
        SumMax copy, open, h2d;
        std::atomic<uint64_t> segs{0}, bytes{0};
        Clock::time_point first{};
    };

    // R.mu held. Sends every reply at the head of the queue that is ready.
    // The slots of a push are freed before its last reply goes out, so the
    // sender's next RESERVE on this connection finds them free.
    void Flush(int fd, Replies& R) {
        while (!R.q.empty() && R.q.front()->ready) {
            auto e = std::move(R.q.front());
            R.q.pop_front();
            if (e->release) {
                Release(R.lease_id);
                R.lease_id = 0;
                if (VLOG_IS_ON(1))
                    VLOG(1) << "secure push rx: "
                            << R.bytes.load(std::memory_order_relaxed)
                            << " B in "
                            << R.segs.load(std::memory_order_relaxed)
                            << " segments in " << Ms(NsSince(R.first))
                            << " ms since the first commit; sum/max ms: "
                               "copy-out "
                            << Ms(R.copy) << ", open " << Ms(R.open)
                            << ", h2d " << Ms(R.h2d) << " (node "
                            << svc->numa_node_ << ")";
                R.copy.Reset();
                R.open.Reset();
                R.h2d.Reset();
                R.segs.store(0, std::memory_order_relaxed);
                R.bytes.store(0, std::memory_order_relaxed);
                R.first = Clock::time_point{};
            }
            if (!R.failed && !Reply(fd, e->header, e->body)) R.failed = true;
            if (e->fatal) R.failed = true;
            // The peer sees the close; Serve's next read fails and it exits.
            if (R.failed) ::shutdown(fd, SHUT_RDWR);
        }
    }

    static std::string CommitReply(int32_t st, uint32_t window) {
        Writer w;
        w.U8(kRespCommit);
        w.I32(st);
        w.U32(window);
        return std::move(w.str());
    }

    void Serve(Conn* c) {
        const int fd = c->fd;
        const auto& o = svc->opt_;
        Replies R;
        // Commits in flight on one connection; a legitimate sender has at
        // most one per slot it holds.
        const size_t max_outstanding = std::max<uint32_t>(1, nslots);
        std::string frame, body;
        const std::string req_aad = Aad(kAadReq, svc->fabric_.local_name);
        const auto handshake_deadline =
            c->accepted + std::chrono::milliseconds(o.handshake_timeout_ms);
        auto push_ready = [&](const std::string& header, std::string reply,
                              bool fatal) {
            auto e = std::make_shared<Replies::Entry>();
            e->header = header;
            e->body = std::move(reply);
            e->ready = true;
            e->fatal = fatal;
            std::lock_guard<std::mutex> lock(R.mu);
            R.q.push_back(std::move(e));
            Flush(fd, R);
        };
        while (!stop.load()) {
            uint64_t lease_id;
            {
                std::lock_guard<std::mutex> lock(R.mu);
                if (R.failed) break;
                lease_id = R.lease_id;
            }
            const bool authed = c->authed.load();
            Clock::time_point header_deadline = handshake_deadline;
            if (authed) {
                // Between the segments of a push the sender seals and writes,
                // so a held lease waits at least a step.
                const int idle = lease_id ? std::max(o.idle_timeout_ms,
                                                     o.timeout_ms)
                                          : o.idle_timeout_ms;
                header_deadline = Clock::now() + std::chrono::milliseconds(idle);
            }
            size_t accounted = 0;
            uint32_t claimed = 0;
            Rx rr = RecvFrameBy(
                fd, &frame, authed ? kMaxFrame : kMaxUnauthenticatedFrameBytes,
                header_deadline,
                authed ? Clock::now() + std::chrono::milliseconds(o.timeout_ms)
                       : handshake_deadline,
                [&](size_t n) {
                    if (authed) return;
                    accounted = n;
                    const size_t now = preauth_buffered.fetch_add(n) + n;
                    size_t peak = preauth_peak.load();
                    while (now > peak &&
                           !preauth_peak.compare_exchange_weak(peak, now)) {
                    }
                },
                &claimed);
            if (accounted) preauth_buffered.fetch_sub(accounted);
            if (rr == Rx::kTimeout) {
                timed_out.fetch_add(1);
                VLOG(1) << "secure push: closing "
                        << (authed ? "an idle" : "an unauthenticated")
                        << " control connection from " << c->ip;
                break;
            }
            if (rr == Rx::kTooLarge) {
                oversized.fetch_add(1);
                svc->rejected_.fetch_add(1);
                LOG(WARNING) << "secure push: dropping a control connection from "
                             << c->ip << " that claimed a " << claimed
                             << "-byte " << (authed ? "" : "unauthenticated ")
                             << "frame";
                break;
            }
            if (rr != Rx::kOk) break;
            if (!authed) c->verifying.store(true);
            SealedInfo info;
            if (frame.size() < kHeaderSize ||
                !OpenControl(frame, req_aad, &body, &info)) {
                svc->rejected_.fetch_add(1);
                LOG(WARNING) << "secure push: dropping a control connection "
                                "from "
                             << c->ip << " that sent an unauthenticated request";
                break;
            }
            if (!replay.Accept(info)) {
                svc->rejected_.fetch_add(1);
                LOG(WARNING) << "secure push: dropping a control connection "
                                "from "
                             << c->ip << " that replayed a request";
                break;
            }
            if (!authed && !Authenticate(c)) break;
            // Now, not before the read: a commit that completed meanwhile
            // may have ended the lease.
            {
                std::lock_guard<std::mutex> lock(R.mu);
                lease_id = R.lease_id;
            }
            const std::string header = frame.substr(0, kHeaderSize);
            Reader r(body.data(), body.size());
            uint8_t type;
            std::string sender;
            if (!r.U8(&type) || !r.Str(&sender)) {
                svc->rejected_.fetch_add(1);
                break;
            }
            if (type == kReqHello) {
                Writer w;
                w.U8(kRespHello);
                w.I32(kOk);
                w.U32(kHelloVersion);
                w.U64(reinterpret_cast<uint64_t>(base));
                w.U64(slot_bytes);
                w.U32(nslots);
                push_ready(header, std::move(w.str()), false);
            } else if (type == kReqReserve) {
                uint32_t want;
                Writer w;
                w.U8(kRespReserve);
                if (!r.U32(&want) || lease_id != 0) {
                    w.I32(kErrLease);
                    push_ready(header, std::move(w.str()), true);
                    break;
                }
                uint64_t id = 0;
                RAND_bytes(reinterpret_cast<uint8_t*>(&id), sizeof(id));
                id |= 1;
                auto slots = Lease(id, want);
                if (!slots.empty()) {
                    std::lock_guard<std::mutex> lock(R.mu);
                    R.lease_id = id;
                }
                w.I32(kOk);
                w.U64(slots.empty() ? 0 : id);
                w.U64(slot_bytes);
                w.U32(static_cast<uint32_t>(slots.size()));
                for (auto s : slots) w.U32(s);
                push_ready(header, std::move(w.str()), false);
            } else if (type == kReqCommit) {
                {
                    std::unique_lock<std::mutex> lock(R.mu);
                    R.cv.wait(lock, [&] {
                        return R.outstanding < max_outstanding || R.failed;
                    });
                    if (R.failed) break;
                }
                auto job = std::make_shared<CommitJob>();
                job->sender = sender;
                int32_t st = ParseCommit(r, lease_id, job.get());
                if (st != kOk) {
                    svc->rejected_.fetch_add(1);
                    push_ready(header, CommitReply(st, job->window), true);
                    break;
                }
                auto e = std::make_shared<Replies::Entry>();
                e->header = header;
                e->release = job->last;
                job->entry = e;
                job->remaining.store(job->segs.size());
                {
                    std::lock_guard<std::mutex> lock(R.mu);
                    R.q.push_back(e);
                    ++R.outstanding;
                    if (R.first == Clock::time_point{}) R.first = Clock::now();
                }
                for (size_t i = 0; i < job->segs.size(); ++i) {
                    open_pool->Run([this, job, i, fd, &R] {
                        OpenTiming t;
                        if (!OpenSegment(job->segs[i], job->sender, job->tid,
                                         job->total, &t)) {
                            job->ok.store(false);
                        } else {
                            auto& tm = *svc->tm_;
                            if (t.copy_ns) {
                                tm.Record(PushStage::kRxCopy, t.copy_ns);
                                R.copy.Add(t.copy_ns);
                            }
                            tm.Record(PushStage::kOpen, t.open_ns);
                            R.open.Add(t.open_ns);
                            if (t.h2d_ns) {
                                tm.Record(PushStage::kH2D, t.h2d_ns);
                                R.h2d.Add(t.h2d_ns);
                            }
                            tm.rx_segments.fetch_add(1,
                                                     std::memory_order_relaxed);
                            R.segs.fetch_add(1, std::memory_order_relaxed);
                            R.bytes.fetch_add(
                                job->segs[i].sealed_len - kOverhead,
                                std::memory_order_relaxed);
                        }
                        if (job->remaining.fetch_sub(1) != 1) return;
                        const bool ok = job->ok.load();
                        if (!ok) svc->rejected_.fetch_add(1);
                        std::lock_guard<std::mutex> lock(R.mu);
                        job->entry->body =
                            CommitReply(ok ? kOk : kErrOpen, job->window);
                        job->entry->fatal = !ok;
                        job->entry->ready = true;
                        --R.outstanding;
                        Flush(fd, R);
                        R.cv.notify_all();
                    });
                }
            } else {
                svc->rejected_.fetch_add(1);
                break;
            }
            // Do not hold a large commit's buffers while idle.
            if (frame.capacity() > (1u << 20)) std::string().swap(frame);
            if (body.capacity() > (1u << 20)) std::string().swap(body);
        }
        // Opens in flight read slots of this lease and reply on this
        // connection: let them finish (their replies flush as they do).
        uint64_t lease_left;
        {
            std::unique_lock<std::mutex> lock(R.mu);
            R.cv.wait(lock, [&] { return R.outstanding == 0; });
            lease_left = R.lease_id;
            R.lease_id = 0;
        }
        Release(lease_left);
        // The peer sees the close now; the descriptor itself is closed by
        // the reaper.
        ::shutdown(fd, SHUT_RDWR);
    }

    struct SegCommit {
        uint32_t index;
        uint32_t slot;
        uint64_t sealed_len;
        std::vector<PushPiece> dst;
    };

    // One COMMIT being opened.
    struct CommitJob {
        std::string sender;  // authenticated in the commit's sealed body
        uint8_t tid[16];
        uint32_t window = 0, total = 0;
        bool last = false;
        std::vector<SegCommit> segs;
        std::atomic<size_t> remaining{0};
        std::atomic<bool> ok{true};
        std::shared_ptr<Replies::Entry> entry;
    };

    // Parses and checks a COMMIT body into `job`. kOk only if every slot is
    // this connection's and every destination is local-only memory.
    int32_t ParseCommit(Reader& r, uint64_t lease_id, CommitJob* job) {
        uint64_t lease;
        uint32_t nseg;
        uint8_t flags;
        if (!r.U64(&lease) || !r.Bytes(job->tid, 16) || !r.U32(&job->window) ||
            !r.U32(&job->total) || !r.U8(&flags) || !r.U32(&nseg))
            return kErrBadRequest;
        job->last = (flags & kCommitLast) != 0;
        if (lease == 0 || lease != lease_id) return kErrLease;
        if (nseg == 0 || nseg > nslots) return kErrBadRequest;
        auto& segs = job->segs;
        segs.resize(nseg);
        {
            std::lock_guard<std::mutex> lock(slots_mu);
            for (auto& s : segs) {
                uint32_t np;
                if (!r.U32(&s.index) || !r.U32(&s.slot) ||
                    !r.U64(&s.sealed_len) || !r.U32(&np) ||
                    np > kMaxPiecesPerSegment || r.remaining() < np * 16ull)
                    return kErrBadRequest;
                if (s.slot >= nslots || slot_lease[s.slot] != lease_id)
                    return kErrLease;
                if (s.sealed_len > slot_bytes || s.index >= job->total)
                    return kErrBadRequest;
                s.dst.resize(np);
                uint64_t sum = 0;
                for (auto& d : s.dst) {
                    uint64_t len;
                    r.U64(&d.dst);
                    r.U64(&len);
                    d.len = len;
                    d.src = nullptr;
                    if (len == 0 || d.dst + len < d.dst) return kErrBadRequest;
                    sum += len;
                }
                if (s.sealed_len != SealedSize(sum)) return kErrBadRequest;
            }
        }
        if (r.remaining() != 0) return kErrBadRequest;
        // Every destination must be this process's own local-only memory
        // (registered, never NIC-registered): a commit cannot direct
        // plaintext into staging, a store segment or unregistered memory.
        for (auto& s : segs)
            for (auto& d : s.dst)
                if (!svc->fabric_.is_local_only(
                        reinterpret_cast<const void*>(d.dst), d.len)) {
                    LOG(ERROR) << "secure push: refusing a commit whose "
                                  "destination "
                               << reinterpret_cast<void*>(d.dst) << "+"
                               << d.len
                               << " is not local-only registered memory";
                    return kErrBadDestination;
                }
        return kOk;
    }

    struct OpenTiming {
        uint64_t copy_ns = 0, open_ns = 0, h2d_ns = 0;
    };

    // `sender` is the name authenticated in the commit's sealed body.
    bool OpenSegment(const SegCommit& s, const std::string& sender,
                     const uint8_t tid[16], uint32_t total, OpenTiming* t) {
        const uint8_t* slot = slot_ptr(s.slot);
        const uint8_t* sealed = slot;
        if (svc->opt_.rx_copy) {
            // Read the remotely writable slot exactly once into private
            // memory, so the bytes authenticated are the bytes decrypted.
            // Sized for a whole slot on first use, so it never regrows.
            const auto t0 = Clock::now();
            if (t_private.size() < s.sealed_len)
                t_private.resize(std::max<size_t>(s.sealed_len, slot_bytes));
            memcpy(t_private.data(), slot, s.sealed_len);
            sealed = t_private.data();
            t->copy_ns = NsSince(t0);
        }
        const std::string aad =
            DataAad(svc->fabric_.local_name, sender, tid, s.index,
                    total, s.dst);
        std::vector<MutableSpan> out;
        out.reserve(s.dst.size());
        std::vector<std::pair<size_t, int>> dev;  // (piece index, device)
        for (size_t i = 0; i < s.dst.size(); ++i) {
            int d = DeviceOf(reinterpret_cast<void*>(s.dst[i].dst));
            if (d >= 0) dev.emplace_back(i, d);
            out.push_back({reinterpret_cast<void*>(s.dst[i].dst), s.dst[i].len});
        }
        bool direct = dev.empty();
        if (!direct) {
            // A registered device backend may open straight into device
            // memory; otherwise bounce through pinned host memory.
            ConstSpan in{sealed, s.sealed_len};
            direct = SelectAeadBackend(SecureContext::Global().config().algorithm,
                                       &in, 1, out.data(), out.size()) !=
                     &HostAeadBackend();
        }
        if (direct) {
            const auto t0 = Clock::now();
            Error e = SecureContext::Global().opener().Open(
                {sealed, s.sealed_len}, Purpose::kTransfer,
                {aad.data(), aad.size()}, out.data(), out.size());
            t->open_ns = NsSince(t0);
            if (e != Error::kOk)
                LOG(ERROR) << "secure push: segment " << s.index
                           << " failed to open: " << ToString(e);
            return e == Error::kOk;
        }
        const size_t pt = s.sealed_len - kOverhead;
        // Sized for a whole slot on first use, so it never regrows (each
        // growth frees and re-pins host memory).
        auto* bounce = static_cast<uint8_t*>(
            ThreadBounce(std::max(pt, slot_bytes - kOverhead)));
        if (!bounce) return false;
        MutableSpan b{bounce, pt};
        auto t0 = Clock::now();
        Error e = SecureContext::Global().opener().Open(
            {sealed, s.sealed_len}, Purpose::kTransfer, {aad.data(), aad.size()},
            &b, 1);
        t->open_ns = NsSince(t0);
        if (e != Error::kOk) {
            LOG(ERROR) << "secure push: segment " << s.index
                       << " failed to open: " << ToString(e);
            return false;
        }
        // Scatter: host pieces copied here, device pieces on the copy engine.
        t0 = Clock::now();
        size_t off = 0, di = 0;
        std::vector<DevCopy> copies;
        for (size_t i = 0; i < s.dst.size(); ++i) {
            if (di < dev.size() && dev[di].first == i) {
                copies.push_back(
                    {out[i].data, bounce + off, out[i].size, dev[di].second});
                ++di;
            } else {
                memcpy(out[i].data, bounce + off, out[i].size);
            }
            off += out[i].size;
        }
        const bool ok = CopyDevice(copies);
        t->h2d_ns = NsSince(t0);
        OPENSSL_cleanse(bounce, pt);
        return ok;
    }
};

// ------------------------------------------------------------------ peer --

struct SecurePushService::Peer {
    std::string name;
    std::string host;
    int port = 0;
    uint64_t rx_base = 0;
    uint64_t slot_bytes = 0;
    uint32_t nslots = 0;
    int idle_ms = 60000;  // pooled connections older than this are dropped
    std::mutex mu;
    std::vector<std::pair<int, Clock::time_point>> idle;
    ~Peer() {
        for (auto& [fd, t] : idle) ::close(fd);
    }
    // A pooled connection (*reused = true) or a new one.
    int Take(int timeout_ms, bool* reused) {
        {
            std::lock_guard<std::mutex> lock(mu);
            const auto now = Clock::now();
            while (!idle.empty()) {
                auto [fd, t] = idle.back();
                idle.pop_back();
                if (now - t < std::chrono::milliseconds(idle_ms) &&
                    IdleConnAlive(fd)) {
                    *reused = true;
                    return fd;
                }
                ::close(fd);
            }
        }
        *reused = false;
        return Connect(host, port, timeout_ms);
    }
    void Give(int fd) {
        std::lock_guard<std::mutex> lock(mu);
        if (idle.size() < 64)
            idle.emplace_back(fd, Clock::now());
        else
            ::close(fd);
    }
};

// ---------------------------------------------------------------- service --

SecurePushService::SecurePushService(PushFabric fabric, PushOptions options)
    : fabric_(std::move(fabric)),
      opt_(std::move(options)),
      tm_(std::make_unique<Telemetry>()) {}

SecurePushService::~SecurePushService() {
    WithdrawP2dEndpoint(fabric_.local_name);
    {
        std::unique_lock<std::mutex> lock(jobs_mu_);
        stopping_ = true;
        jobs_cv_.wait(lock, [&] { return active_jobs_ == 0; });
    }
    std::unique_ptr<Receiver> rx;
    {
        std::lock_guard<std::mutex> lock(mu_);
        rx = std::move(rx_);
        peers_.clear();
    }
    if (rx) {
        rx->Stop();
        if (rx->base) {
            fabric_.unregister(rx->base);
            munmap(rx->base, rx->bytes);
        }
    }
    seal_pool_.reset();
    tx_pool_.reset();
}

bool SecurePushService::receiver_enabled() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mu_));
    return rx_ != nullptr;
}

PushStats SecurePushService::push_stats() const {
    PushStats p = tm_->Snapshot();
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mu_));
    p.numa_node = numa_node_;
    return p;
}

void SecurePushService::ResolvePlacementLocked(const void* near) {
    if (placed_) return;
    placed_ = true;
    int node = -1;
    if (opt_.numa_node >= 0)
        node = opt_.numa_node;
    else if (opt_.numa_node == PushOptions::kNumaAuto)
        node = HomeNumaNode(near);
    numa_node_ = node;
    std::vector<int> node_cpus = NumaNodeCpus(node);
    if (!opt_.cpus.empty()) {
        crypto_cpus_ = opt_.cpus;
        crypto_cpus_each_ = true;
    } else {
        // The whole node, so the scheduler balances crypto threads over its
        // cores; another rank's threads stay on their own node.
        crypto_cpus_ = node_cpus;
        crypto_cpus_each_ = false;
    }
    std::string cpus;
    if (!crypto_cpus_.empty())
        cpus = std::to_string(crypto_cpus_.front()) + ".." +
               std::to_string(crypto_cpus_.back()) + " (" +
               std::to_string(crypto_cpus_.size()) + ")";
    LOG(INFO) << "secure push: staging on NUMA node " << node
              << (opt_.numa_node == PushOptions::kNumaAuto
                      ? " (auto)"
                      : opt_.numa_node == PushOptions::kNumaNone ? " (none)"
                                                                 : "")
              << ", crypto threads on CPUs "
              << (cpus.empty() ? std::string("any") : cpus);
}

ControlStats SecurePushService::control_stats() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mu_));
    return rx_ ? rx_->Stats() : ControlStats{};
}

void SecurePushService::ForgetPeersForTesting() {
    std::lock_guard<std::mutex> lock(mu_);
    peers_.clear();
}

std::string SecurePushService::control_host() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mu_));
    return rx_ ? rx_->host : std::string();
}

int SecurePushService::control_port() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mu_));
    return rx_ ? rx_->port : 0;
}

int SecurePushService::EnableReceiver(const void* near) {
    std::lock_guard<std::mutex> lock(mu_);
    if (rx_) return 0;
    ResolvePlacementLocked(near);
    auto rx = std::make_unique<Receiver>();
    rx->svc = this;
    rx->slot_bytes = (SealedSize(opt_.segment_bytes) + 4095) & ~size_t(4095);
    rx->nslots = static_cast<uint32_t>(
        std::max<size_t>(2, opt_.rx_bytes / rx->slot_bytes));
    rx->bytes = size_t(rx->nslots) * rx->slot_bytes;
    rx->slot_lease.assign(rx->nslots, 0);
    rx->host = opt_.host.empty() ? HostPart(fabric_.local_name) : opt_.host;

    // Control server.
    int fd = ::socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    bool v6 = fd >= 0;
    if (!v6) fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        PLOG(ERROR) << "secure push: socket";
        return -1;
    }
    int one = 1, zero = 0;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int rc;
    if (v6) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        sockaddr_in6 a{};
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons(static_cast<uint16_t>(opt_.port));
        rc = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    } else {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons(static_cast<uint16_t>(opt_.port));
        rc = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    }
    if (rc != 0 || ::listen(fd, 256) != 0) {
        PLOG(ERROR) << "secure push: cannot listen on port " << opt_.port;
        ::close(fd);
        return -1;
    }
    sockaddr_storage ss{};
    socklen_t sl = sizeof(ss);
    getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &sl);
    rx->port = ss.ss_family == AF_INET6
                   ? ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port)
                   : ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
    rx->listen_fd = fd;

    // Receive staging: slots only. Peers can write any of it; it only ever
    // holds sealed bytes, and nothing about discovery lives in it.
    // On the staging node, so the NIC the engine picks for it is that
    // node's (the one the GPU's own transfers use) and the copy-out reads
    // local memory.
    void* base = MapOnNode(rx->bytes, numa_node_, NumaNodeCpus(numa_node_));
    if (!base) {
        PLOG(ERROR) << "secure push: cannot map " << rx->bytes
                    << " bytes of receive staging";
        return -1;
    }
    rx->base = base;

    // Advertised before the staging shows up in a descriptor a sender could
    // fetch; connections wait in the listen backlog until the accept thread
    // starts.
    AdvertiseP2dEndpoint(fabric_.local_name, rx->host, rx->port);
    if (fabric_.register_ciphertext(base, rx->bytes, numa_node_) != 0) {
        WithdrawP2dEndpoint(fabric_.local_name);
        LOG(ERROR) << "secure push: cannot register receive staging";
        munmap(base, rx->bytes);
        rx->base = nullptr;
        return -1;
    }
    rx->open_pool = std::make_unique<CryptoPool>(
        opt_.threads, crypto_cpus_, "mc-p2d-open", crypto_cpus_each_);
    Receiver* raw = rx.get();
    rx->accept_thread = std::thread([raw] { raw->AcceptLoop(); });
    LOG(INFO) << "secure push: receiver " << fabric_.local_name << " up, control " << rx->host << ":"
              << rx->port << ", " << rx->nslots << " slots of "
              << rx->slot_bytes << " bytes on NUMA node " << NodeOfPage(base);
    rx_ = std::move(rx);
    return 0;
}

bool SecurePushService::EnsureSender(const void* near) {
    std::lock_guard<std::mutex> lock(mu_);
    if (seal_pool_) return true;
    ResolvePlacementLocked(near);
    const size_t region = std::min<size_t>(opt_.tx_bytes, 256ull << 20);
    tx_pool_ = std::make_unique<StagingPool>(
        region, opt_.tx_bytes,
        [this, node = numa_node_](void* p, size_t n) {
            return fabric_.register_ciphertext(p, n, node);
        },
        [this](void* p) { return fabric_.unregister(p); });
    tx_pool_->set_numa_node(numa_node_, NumaNodeCpus(numa_node_));
    seal_pool_ = std::make_unique<CryptoPool>(
        opt_.threads, crypto_cpus_, "mc-p2d-seal", crypto_cpus_each_);
    return true;
}

std::shared_ptr<SecurePushService::Peer> SecurePushService::Discover(
    Transport::SegmentID target, bool force) {
    if (!force) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = peers_.find(target);
        if (it != peers_.end()) return it->second;
    }
    auto desc = fabric_.segment_desc(target, force);
    if (!desc) return nullptr;
    // The endpoint came with the descriptor over the authenticated
    // handshake; the layout comes from the receiver itself over the sealed
    // control channel. Nothing here is read from fabric-writable memory.
    auto peer = std::make_shared<Peer>();
    peer->name = desc->name;
    peer->idle_ms = std::max(1, opt_.idle_timeout_ms / 2);
    if (!LookupP2dEndpoint(desc->name, &peer->host, &peer->port)) {
        if (force)
            LOG(ERROR) << "secure push: no secure receiver found on segment "
                       << desc->name
                       << " (its descriptor advertises no secure push "
                          "endpoint)";
        return nullptr;
    }
    int fd = Connect(peer->host, peer->port, opt_.timeout_ms);
    if (fd < 0) {
        LOG(WARNING) << "secure push: cannot connect to " << desc->name
                     << " at " << peer->host << ":" << peer->port;
        return nullptr;
    }
    Writer w;
    w.U8(kReqHello);
    w.Str(fabric_.local_name);
    std::string frame, reply, body;
    SealedInfo info;
    bool ok = SealControl(w.str(), Aad(kAadReq, desc->name), &frame) &&
              SendFrame(fd, frame) && RecvFrame(fd, &reply) &&
              OpenControl(reply,
                          Aad(kAadResp, desc->name, frame.data(), kHeaderSize),
                          &body, &info);
    Reader r(body.data(), body.size());
    uint8_t type = 0;
    int32_t st = -1;
    uint32_t ver = 0;
    ok = ok && r.U8(&type) && type == kRespHello && r.I32(&st) && st == kOk &&
         r.U32(&ver) && ver == kHelloVersion && r.U64(&peer->rx_base) &&
         r.U64(&peer->slot_bytes) && r.U32(&peer->nslots) &&
         peer->slot_bytes > kOverhead && peer->nslots > 0 &&
         peer->slot_bytes * peer->nslots / peer->nslots == peer->slot_bytes;
    // The slots must lie in one buffer the (authenticated) descriptor
    // publishes, i.e. the receiver's registered staging.
    bool published = false;
    if (ok) {
        const uint64_t span = peer->slot_bytes * peer->nslots;
        for (const auto& b : desc->buffers)
            if (peer->rx_base >= b.addr && span <= b.length &&
                peer->rx_base - b.addr <= b.length - span)
                published = true;
    }
    if (!ok || !published) {
        LOG(WARNING) << "secure push: " << desc->name
                     << (ok ? " described receive slots outside its published "
                              "buffers"
                            : " did not answer the discovery request");
        ::close(fd);
        return nullptr;
    }
    peer->Give(fd);
    std::lock_guard<std::mutex> lock(mu_);
    peers_[target] = peer;
    return peer;
}

// ------------------------------------------------------------------- job --

struct SecurePushService::Job {
    Transport::SegmentID target = 0;
    std::vector<PushPiece> pieces;
    std::vector<size_t> prefix;  // byte offset of each piece
    size_t total = 0;
    uint8_t tid[16];

    // The pieces of [off, off+len) of the concatenated stream.
    Segment Slice(size_t off, size_t len) const {
        Segment s;
        s.bytes = len;
        size_t i = std::upper_bound(prefix.begin(), prefix.end(), off) -
                   prefix.begin() - 1;
        while (len) {
            const auto& p = pieces[i];
            size_t in = off - prefix[i];
            size_t n = std::min(len, p.len - in);
            s.src.push_back({static_cast<const uint8_t*>(p.src) + in, n});
            s.dst.push_back({nullptr, p.dst + in, n});
            off += n;
            len -= n;
            ++i;
        }
        return s;
    }
};

namespace {

struct SealTiming {
    uint64_t d2h_ns = 0, seal_ns = 0;
};

// Seals one segment into `out` (send staging). A device source bounces
// through this thread's pinned buffer, sized at least `bounce_min` so it is
// allocated once rather than regrown as segment sizes ramp up.
bool SealSegment(const Segment& seg, const std::string& aad, uint8_t* out,
                 size_t out_size, size_t* sealed_len, SealedInfo* info,
                 Algorithm alg, size_t bounce_min, SealTiming* t) {
    std::vector<ConstSpan> in = seg.src;
    std::vector<std::pair<size_t, int>> dev;
    for (size_t i = 0; i < in.size(); ++i) {
        int d = DeviceOf(in[i].data);
        if (d >= 0) dev.emplace_back(i, d);
    }
    if (!dev.empty()) {
        MutableSpan o{out, out_size};
        if (SelectAeadBackend(alg, in.data(), in.size(), &o, 1) ==
            &HostAeadBackend()) {
            // Path B: device -> pinned host with the copy engine, seal on the
            // CPU. A device backend, when registered, seals in place instead.
            auto* bounce = static_cast<uint8_t*>(
                ThreadBounce(std::max(seg.bytes, bounce_min)));
            if (!bounce) return false;
            const auto t0 = Clock::now();
            size_t off = 0, di = 0;
            std::vector<DevCopy> copies;
            for (size_t i = 0; i < in.size(); ++i) {
                if (di < dev.size() && dev[di].first == i) {
                    copies.push_back(
                        {bounce + off, in[i].data, in[i].size, dev[di].second});
                    in[i].data = bounce + off;
                    ++di;
                }
                off += in[i].size;
            }
            if (!CopyDevice(copies)) return false;
            t->d2h_ns = NsSince(t0);
        }
    }
    auto& sealer = SecureContext::Global().sealer(Purpose::kTransfer);
    const auto t1 = Clock::now();
    Error e = sealer.Seal(in.data(), in.size(), {aad.data(), aad.size()},
                          {out, out_size}, sealed_len);
    t->seal_ns = NsSince(t1);
    if (!dev.empty()) CleanseThreadBounce(seg.bytes);
    if (e != Error::kOk) {
        LOG(ERROR) << "secure push: seal failed: " << ToString(e);
        return false;
    }
    if (info) ParseHeader({out, *sealed_len}, info);
    return true;
}

}  // namespace

bool SecurePushService::PushAsync(Transport::SegmentID target,
                                  std::vector<PushPiece> pieces,
                                  std::function<void(bool)> done) {
    if (!SecureContext::Global().enabled() || SecureContext::Global().failed())
        return false;
    {
        std::lock_guard<std::mutex> lock(jobs_mu_);
        if (stopping_) return false;
        ++active_jobs_;
    }
    auto job = std::make_shared<Job>();
    job->target = target;
    for (auto& p : pieces) {
        if (p.len == 0) continue;
        job->prefix.push_back(job->total);
        job->total += p.len;
        job->pieces.push_back(p);
    }
    std::thread([this, job, done = std::move(done)] {
        const auto t0 = Clock::now();
        bool ok = RunJob(*job);
        if (ok && job->total) {
            tm_->Record(PushStage::kPush, NsSince(t0));
            tm_->pushes.fetch_add(1, std::memory_order_relaxed);
            tm_->bytes.fetch_add(job->total, std::memory_order_relaxed);
        } else if (!ok) {
            tm_->failed.fetch_add(1, std::memory_order_relaxed);
        }
        MaybeLogStats();
        done(ok);
        std::lock_guard<std::mutex> lock(jobs_mu_);
        if (--active_jobs_ == 0) jobs_cv_.notify_all();
    }).detach();
    return true;
}

Status SecurePushService::Push(Transport::SegmentID target,
                               std::vector<PushPiece> pieces) {
    std::mutex mu;
    std::condition_variable cv;
    bool finished = false, result = false;
    if (!PushAsync(target, std::move(pieces), [&](bool ok) {
            std::lock_guard<std::mutex> lock(mu);
            finished = true;
            result = ok;
            cv.notify_all();
        }))
        return Status::InvalidArgument("secure push could not start");
    std::unique_lock<std::mutex> lock(mu);
    cv.wait(lock, [&] { return finished; });
    return result ? Status::OK() : Status::Context("secure push failed");
}

// ---------------------------------------------------------------- stream --

// The sender side of one push. Segment i is sealed into send staging stride
// i % S once the segment that last used that stride has been written; it is
// written to slot i % g as soon as it is sealed and the segment that last
// used that slot has been acknowledged; it is committed, in order, once its
// write completed.
struct SecurePushService::Stream {
    SecurePushService* svc = nullptr;
    const Job* job = nullptr;
    std::string peer_name;
    size_t seg_bytes = 0;
    std::vector<std::pair<size_t, size_t>> plan;
    uint32_t n = 0;  // segments
    uint32_t S = 0;  // send staging strides
    size_t stride = 0;
    StagingBuffer tx;
    uint8_t* txb = nullptr;
    Algorithm alg{};
    bool started = false;

    struct Seg {
        Segment seg;
        std::string aad;
        int state = 0;  // 0 sealing or not launched, 1 sealed, 2 failed
        size_t sealed_len = 0;
        bool posted = false, waited = false;
        void* handle = nullptr;
        uint64_t remote = 0;
        Clock::time_point posted_at{}, commit_sent_at{};
    };
    std::mutex mu;
    std::condition_variable cv;
    std::vector<Seg> segs;
    size_t sealing = 0;
    bool aborted = false;
    // Set once the receiver granted slots.
    bool granted = false;
    std::vector<uint32_t> slots;
    uint64_t rx_base = 0, slot_bytes = 0;
    uint32_t acked = 0;
    // This push's stages (per-segment sums/maxima; the waits are the
    // committer's), also recorded in the service's cumulative telemetry.
    SumMax d2h, seal, write, rtt, wait_seal, wait_write, wait_ack;

    ~Stream() { Drain(); }

    uint8_t* Staging(uint32_t i) const {
        return txb + size_t(i % S) * stride;
    }

    bool Start() {
        tx = svc->tx_pool_->Allocate(stride * S);
        if (!tx) {
            LOG(ERROR) << "secure push: send staging exhausted";
            return false;
        }
        txb = static_cast<uint8_t*>(tx.data());
        std::lock_guard<std::mutex> lock(mu);
        for (uint32_t i = 0; i < S && i < n; ++i) Launch(i);
        started = true;
        return true;
    }

    // mu held.
    void Launch(uint32_t i) {
        Seg& sg = segs[i];
        sg.seg = job->Slice(plan[i].first, plan[i].second);
        sg.aad = DataAad(peer_name, svc->fabric_.local_name, job->tid, i, n,
                         sg.seg.dst);
        ++sealing;
        uint8_t* out = Staging(i);
        svc->seal_pool_->Run([this, i, out] {
            Seg& mine = segs[i];
            SealedInfo info;
            size_t len = 0;
            SealTiming t;
            const bool ok = SealSegment(mine.seg, mine.aad, out, stride, &len,
                                        &info, alg, seg_bytes, &t);
            if (ok) {
                if (t.d2h_ns) {
                    svc->tm_->Record(PushStage::kD2H, t.d2h_ns);
                    d2h.Add(t.d2h_ns);
                }
                svc->tm_->Record(PushStage::kSeal, t.seal_ns);
                seal.Add(t.seal_ns);
            }
            if (ok && svc->hooks_.on_segment_sealed)
                svc->hooks_.on_segment_sealed(info);
            std::lock_guard<std::mutex> lock(mu);
            mine.sealed_len = len;
            mine.state = ok ? 1 : 2;
            if (ok) TryPostLocked(i);
            --sealing;
            cv.notify_all();
        });
    }

    // mu held. Writes segment i if it is sealed and its slot is free.
    void TryPostLocked(uint32_t i) {
        Seg& sg = segs[i];
        const uint32_t g = static_cast<uint32_t>(slots.size());
        if (aborted || !granted || sg.state != 1 || sg.posted ||
            i >= acked + g)
            return;
        Transport::TransferRequest req;
        req.opcode = Transport::TransferRequest::WRITE;
        req.source = Staging(i);
        req.target_id = job->target;
        req.target_offset = rx_base + uint64_t(slots[i % g]) * slot_bytes;
        req.length = sg.sealed_len;
        sg.remote = req.target_offset;
        sg.posted_at = Clock::now();
        sg.handle = svc->fabric_.begin_ops({req});
        sg.posted = true;
    }

    // mu held.
    void PostReadyLocked() {
        const uint32_t end =
            std::min<uint32_t>(n, acked + static_cast<uint32_t>(slots.size()));
        for (uint32_t i = acked; i < end; ++i) TryPostLocked(i);
    }

    // Waits for every seal in flight and every write posted but not waited,
    // so nothing still reads the job's memory or the send staging.
    void Drain() {
        std::vector<void*> handles;
        {
            std::unique_lock<std::mutex> lock(mu);
            aborted = true;
            cv.wait(lock, [&] { return sealing == 0; });
            for (auto& sg : segs)
                if (sg.posted && !sg.waited) {
                    sg.waited = true;
                    handles.push_back(sg.handle);
                }
        }
        for (void* h : handles)
            svc->fabric_.wait_ops(h, svc->opt_.timeout_ms);
    }
};

void SecurePushService::MaybeLogStats() {
    if (opt_.stats_interval_s <= 0) return;
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            Clock::now().time_since_epoch())
                            .count();
    int64_t last = tm_->last_summary_s.load(std::memory_order_relaxed);
    if (last == 0) {
        // The first push starts the interval.
        tm_->last_summary_s.compare_exchange_strong(last, now);
        return;
    }
    if (now - last < opt_.stats_interval_s ||
        !tm_->last_summary_s.compare_exchange_strong(last, now))
        return;
    LOG(INFO) << "secure push: stage timings since start: "
              << push_stats().ToString();
}

bool SecurePushService::RunJob(Job& job) {
    if (job.total == 0) return true;
    if (!EnsureSender(job.pieces.front().src)) return false;
    const auto t_start = Clock::now();
    RAND_bytes(job.tid, sizeof(job.tid));
    const auto deadline_ms = opt_.timeout_ms;
    std::shared_ptr<Peer> peer;
    int fd = -1;
    // Request headers awaiting replies, in order.
    std::deque<std::string> pending;
    auto send = [&](const std::string& body) {
        std::string frame;
        if (!SealControl(body, Aad(kAadReq, peer->name), &frame)) return false;
        if (hooks_.on_frame_sent) hooks_.on_frame_sent(frame);
        pending.push_back(frame.substr(0, kHeaderSize));
        return SendFrame(fd, frame);
    };
    // Reads the next reply; returns its body.
    auto recv = [&](std::string* body) {
        std::string frame;
        if (pending.empty() || !RecvFrame(fd, &frame)) return false;
        const std::string hdr = pending.front();
        pending.pop_front();
        SealedInfo info;
        if (!OpenControl(frame, Aad(kAadResp, peer->name, hdr.data(), hdr.size()),
                         body, &info)) {
            LOG(ERROR) << "secure push: unauthenticated reply from "
                       << peer->name;
            return false;
        }
        return true;
    };

    // Declared after the connection state it uses and destroyed first: its
    // destructor waits for seals and writes in flight.
    std::unique_ptr<Stream> st;
    std::vector<uint32_t> slots;
    uint64_t lease = 0;

    // Reserve slots, sealing meanwhile. A connection that fails before its
    // reserve is answered (a pooled one the receiver closed as idle, a new
    // one dropped while unauthenticated) is replaced; a new connection that
    // fails sends the sender back to discovery, with backoff, until the step
    // timeout. Segments already sealed for the same receiver and segment
    // size are kept.
    {
        constexpr int kMaxConnectAttempts = 6;
        const auto until = Clock::now() + std::chrono::milliseconds(deadline_ms);
        int backoff_us = 100;
        int conn_backoff_ms = 1;
        int conn_failures = 0;
        for (;;) {
            if (!peer) {
                peer = Discover(job.target, conn_failures > 0);
                if (!peer && conn_failures == 0)
                    peer = Discover(job.target, true);
            }
            bool reused = false;
            if (peer) fd = peer->Take(deadline_ms, &reused);
            if (peer && fd >= 0) {
                // Segment size: ours, capped by the peer's slot.
                const size_t seg_bytes =
                    std::min(opt_.segment_bytes,
                             size_t(peer->slot_bytes) - kOverhead) &
                    ~size_t(63);
                if (!st || st->peer_name != peer->name ||
                    st->seg_bytes != seg_bytes) {
                    st.reset();
                    st = std::make_unique<Stream>();
                    st->svc = this;
                    st->job = &job;
                    st->peer_name = peer->name;
                    st->seg_bytes = seg_bytes;
                    st->plan = PlanPushSegments(job.total, seg_bytes,
                                                opt_.first_segment_bytes,
                                                opt_.threads);
                    st->n = static_cast<uint32_t>(st->plan.size());
                    st->S = static_cast<uint32_t>(std::min<size_t>(
                        st->n, 2 * opt_.window_segments));
                    st->stride = (SealedSize(seg_bytes) + 63) & ~size_t(63);
                    st->segs.resize(st->n);
                    st->alg = SecureContext::Global().config().algorithm;
                }
                const uint32_t want = st->S;
                pending.clear();
                enum { kGranted, kConnLost, kRefused } rc = kGranted;
                for (;;) {
                    Writer w;
                    w.U8(kReqReserve);
                    w.Str(fabric_.local_name);
                    w.U32(want);
                    std::string body;
                    if (!send(w.str())) {
                        rc = kConnLost;
                        break;
                    }
                    // Seal while the request is in flight: sealing needs no
                    // slots.
                    if (!st->started && !st->Start()) {
                        rc = kRefused;
                        break;
                    }
                    if (!recv(&body)) {
                        rc = kConnLost;
                        break;
                    }
                    Reader r(body.data(), body.size());
                    uint8_t type;
                    int32_t status;
                    uint64_t slot_bytes;
                    uint32_t n;
                    if (!r.U8(&type) || type != kRespReserve ||
                        !r.I32(&status) || status != kOk || !r.U64(&lease) ||
                        !r.U64(&slot_bytes) || !r.U32(&n) ||
                        n > peer->nslots || n > want ||
                        slot_bytes != peer->slot_bytes) {
                        rc = kRefused;
                        break;
                    }
                    slots.resize(n);
                    for (auto& sl : slots)
                        if (!r.U32(&sl) || sl >= peer->nslots) rc = kRefused;
                    if (rc != kGranted || n > 0) break;
                    if (Clock::now() > until) {
                        LOG(ERROR) << "secure push: " << peer->name
                                   << " granted no receive slots before the "
                                      "timeout";
                        rc = kRefused;
                        break;
                    }
                    std::this_thread::sleep_for(
                        std::chrono::microseconds(backoff_us));
                    backoff_us = std::min(backoff_us * 2, 5000);
                }
                if (rc == kGranted) break;
                ::close(fd);
                fd = -1;
                if (rc == kRefused) {
                    LOG(ERROR) << "secure push: " << peer->name
                               << " refused the slot reservation";
                    return false;
                }
                if (reused) continue;  // try the next pooled one, or a new one
            }
            {
                std::lock_guard<std::mutex> lock(mu_);
                peers_.erase(job.target);  // rediscover
            }
            peer.reset();
            if (++conn_failures >= kMaxConnectAttempts ||
                Clock::now() > until) {
                LOG(ERROR) << "secure push: cannot reach the secure receiver "
                              "of segment "
                           << job.target << " after " << conn_failures
                           << " attempts";
                return false;
            }
            std::this_thread::sleep_for(
                std::chrono::milliseconds(conn_backoff_ms));
            conn_backoff_ms = std::min(conn_backoff_ms * 4, 250);
        }
    }

    const uint32_t n = st->n;
    const uint32_t g = static_cast<uint32_t>(slots.size());
    {
        std::lock_guard<std::mutex> lock(st->mu);
        st->slots = slots;
        st->rx_base = peer->rx_base;
        st->slot_bytes = peer->slot_bytes;
        st->granted = true;
        st->PostReadyLocked();
    }

    // Reads one commit reply.
    auto read_ack = [&]() {
        std::string body;
        if (!recv(&body)) return false;
        Reader r(body.data(), body.size());
        uint8_t type;
        int32_t status;
        uint32_t win;
        std::lock_guard<std::mutex> lock(st->mu);
        if (!r.U8(&type) || type != kRespCommit || !r.I32(&status) ||
            !r.U32(&win) || win != st->acked) {
            LOG(ERROR) << "secure push: malformed commit reply";
            return false;
        }
        {
            const uint64_t ns = NsSince(st->segs[win].commit_sent_at);
            tm_->Record(PushStage::kCommitRtt, ns);
            st->rtt.Add(ns);
        }
        if (status != kOk) {
            LOG(ERROR) << "secure push: " << peer->name << " refused segment "
                       << win << " (status " << status << ")";
            return false;
        }
        ++st->acked;
        st->PostReadyLocked();
        return true;
    };
    auto readable = [&] {
        pollfd p{fd, POLLIN, 0};
        return ::poll(&p, 1, 0) > 0;
    };

    bool ok = true;
    uint32_t c = 0;  // next segment to commit
    while (ok) {
        std::unique_lock<std::mutex> lk(st->mu);
        if (st->acked == n) break;
        if (c < n && st->segs[c].state == 2) {
            ok = false;
            break;
        }
        if (c < n && st->segs[c].posted) {
            auto& sg = st->segs[c];
            void* h = sg.handle;
            sg.waited = true;
            const uint64_t remote = sg.remote;
            const size_t len = sg.sealed_len;
            const uint32_t slot = st->slots[c % g];
            const auto posted_at = sg.posted_at;
            lk.unlock();
            const auto tw = Clock::now();
            Status s = fabric_.wait_ops(h, deadline_ms);
            {
                const uint64_t waited = NsSince(tw);
                const uint64_t lat = NsSince(posted_at);
                tm_->Record(PushStage::kWriteWait, waited);
                tm_->Record(PushStage::kWrite, lat);
                st->wait_write.Add(waited);
                st->write.Add(lat);
            }
            if (!s.ok()) {
                LOG(ERROR) << "secure push: fabric write to " << peer->name
                           << " failed: " << s.ToString();
                ok = false;
                break;
            }
            if (hooks_.before_commit) hooks_.before_commit({{remote, len}});
            Writer cw;
            cw.U8(kReqCommit);
            cw.Str(fabric_.local_name);
            cw.U64(lease);
            cw.Bytes(job.tid, 16);
            cw.U32(c);
            cw.U32(n);
            cw.U8(c + 1 == n ? kCommitLast : 0);
            cw.U32(1);
            cw.U32(c);
            cw.U32(slot);
            cw.U64(len);
            const auto& dst = st->segs[c].seg.dst;
            cw.U32(static_cast<uint32_t>(dst.size()));
            for (auto& d : dst) {
                cw.U64(d.dst);
                cw.U64(d.len);
            }
            st->segs[c].commit_sent_at = Clock::now();
            if (!send(cw.str())) {
                ok = false;
                break;
            }
            lk.lock();
            // Segment c's staging is free: seal the segment that reuses it.
            if (c + st->S < n) st->Launch(c + st->S);
            ++c;
            lk.unlock();
            while (ok && !pending.empty() && readable()) ok = read_ack();
            continue;
        }
        if (c > st->acked && (c == n || st->segs[c].state == 1)) {
            // Nothing to commit until a slot frees up (or all committed).
            lk.unlock();
            const auto ta = Clock::now();
            ok = read_ack();
            const uint64_t waited = NsSince(ta);
            tm_->Record(PushStage::kAckWait, waited);
            st->wait_ack.Add(waited);
            continue;
        }
        // Wait for segment c's seal.
        const auto ts = Clock::now();
        if (!st->cv.wait_for(lk, std::chrono::milliseconds(deadline_ms),
                             [&] { return st->segs[c].state != 0; })) {
            LOG(ERROR) << "secure push: sealing segment " << c
                       << " timed out";
            ok = false;
        }
        const uint64_t waited = NsSince(ts);
        tm_->Record(PushStage::kSealWait, waited);
        st->wait_seal.Add(waited);
    }
    if (ok && VLOG_IS_ON(1)) {
        const uint64_t ns = NsSince(t_start);
        VLOG(1) << "secure push: " << job.total << " B in " << n
                << " segments to " << peer->name << " in " << Ms(ns)
                << " ms (" << (ns ? job.total / static_cast<double>(ns) : 0)
                << " GB/s), node " << numa_node_
                << "; per segment sum/max ms: d2h " << Ms(st->d2h)
                << ", seal " << Ms(st->seal) << ", write " << Ms(st->write)
                << ", commit_rtt " << Ms(st->rtt)
                << "; committer waited sum/max ms: seal "
                << Ms(st->wait_seal) << ", write " << Ms(st->wait_write)
                << ", ack " << Ms(st->wait_ack);
    }
    st.reset();  // waits for anything still in flight
    if (!ok) {
        ::close(fd);
        return false;
    }
    peer->Give(fd);
    return true;
}

std::string SecurePushService::SendRawFrameForTesting(const std::string& host,
                                                      int port,
                                                      const std::string& frame,
                                                      int timeout_ms) {
    int fd = Connect(host, port, timeout_ms);
    if (fd < 0) return {};
    std::string reply;
    if (!SendFrame(fd, frame) || !RecvFrame(fd, &reply)) reply.clear();
    ::close(fd);
    return reply;
}

}  // namespace secure
}  // namespace mooncake
