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

#include "secure/sealed_object.h"

#include <glog/logging.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>

#include "secure/device_copy.h"
#include "secure/secure_push.h"  // CryptoPool, ParseCpuList

namespace mooncake {
namespace secure {

namespace {

const char kSegmentAadLabel[] = "mooncake-store-object-v2";
const char kLegacyAadLabel[] = "mooncake-store-object";

constexpr size_t kMinSegmentBytes = 64ull << 10;
constexpr size_t kMaxSegmentBytes = 1ull << 30;
constexpr auto kScratchWait = std::chrono::seconds(30);

void Put32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
void Put64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
uint32_t Get32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= uint32_t(p[i]) << (8 * i);
    return v;
}
uint64_t Get64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i);
    return v;
}

uint64_t SegmentCount(uint64_t plaintext_len, uint64_t segment_bytes) {
    if (plaintext_len == 0) return 1;
    return plaintext_len / segment_bytes +
           (plaintext_len % segment_bytes != 0 ? 1 : 0);
}

size_t EnvSize(const char* name, size_t def) {
    const char* v = getenv(name);
    if (!v || !*v) return def;
    char* end = nullptr;
    unsigned long long x = strtoull(v, &end, 10);
    if (end == v) return def;
    return static_cast<size_t>(x);
}

// The layout of a new version-2 object.
ObjectLayout MakeLayout(uint64_t plaintext_len, size_t segment_bytes) {
    ObjectLayout l;
    l.version = kObjectVersion;
    l.plaintext_len = plaintext_len;
    l.segment_bytes = static_cast<uint32_t>(segment_bytes);
    l.segment_count =
        static_cast<uint32_t>(SegmentCount(plaintext_len, segment_bytes));
    uint8_t* h = l.header.data();
    Put32(h, kObjectMagic);
    h[4] = kObjectVersion;
    Put32(h + 8, l.segment_count);
    Put32(h + 12, l.segment_bytes);
    Put64(h + 16, plaintext_len);
    return l;
}

// Slices for every segment, in one pass over `bufs`.
std::vector<std::vector<Buf>> SliceAll(const std::vector<Buf>& bufs,
                                       const ObjectLayout& l) {
    std::vector<std::vector<Buf>> segs(l.segment_count);
    size_t bi = 0, boff = 0;
    for (uint32_t i = 0; i < l.segment_count; ++i) {
        size_t need = l.PlainLength(i);
        while (need > 0 && bi < bufs.size()) {
            const Buf& b = bufs[bi];
            const size_t n = std::min(b.size - boff, need);
            if (n > 0)
                segs[i].push_back(
                    {static_cast<char*>(b.data) + boff, n, b.device});
            boff += n;
            need -= n;
            if (boff == b.size) {
                ++bi;
                boff = 0;
            }
        }
    }
    return segs;
}

size_t Total(const std::vector<Buf>& v) {
    size_t t = 0;
    for (const auto& b : v) t += b.size;
    return t;
}

bool AnyDevice(const std::vector<Buf>& v) {
    for (const auto& b : v)
        if (b.device >= 0 && b.size) return true;
    return false;
}

uint64_t NsSince(std::chrono::steady_clock::time_point t0) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - t0)
            .count());
}

// Records the first error of a job.
struct JobStatus {
    std::atomic<int> error{0};
    void Fail(Error e) {
        int expected = 0;
        error.compare_exchange_strong(expected, static_cast<int>(e));
    }
    Error get() const { return static_cast<Error>(error.load()); }
};

}  // namespace

// ---------------------------------------------------------------- format --

size_t SealedObjectSize(size_t plaintext_len, size_t segment_bytes) {
    return kObjectHeaderSize + plaintext_len +
           SegmentCount(plaintext_len, segment_bytes) * kOverhead;
}

uint64_t ObjectLayout::PlainOffset(uint32_t i) const {
    return version == 1 ? 0 : uint64_t(i) * segment_bytes;
}

size_t ObjectLayout::PlainLength(uint32_t i) const {
    if (version == 1) return plaintext_len;
    const uint64_t off = PlainOffset(i);
    return static_cast<size_t>(
        std::min<uint64_t>(segment_bytes, plaintext_len - off));
}

uint64_t ObjectLayout::SealedOffset(uint32_t i) const {
    if (version == 1) return 0;
    return kObjectHeaderSize + uint64_t(i) * (segment_bytes + kOverhead);
}

bool ParseObject(ConstSpan prefix, size_t sealed_size, ObjectLayout* out) {
    if (!prefix.data || prefix.size < 4 || sealed_size < 4) return false;
    const auto* p = static_cast<const uint8_t*>(prefix.data);
    const uint32_t magic = Get32(p);
    ObjectLayout l;
    if (magic == kMagic) {
        // Version 1: one kv_crypto message; the opener checks its header.
        if (sealed_size < kOverhead) return false;
        l.version = 1;
        l.plaintext_len = sealed_size - kOverhead;
        l.segment_count = 1;
        *out = l;
        return true;
    }
    if (magic != kObjectMagic) return false;
    if (prefix.size < kObjectHeaderSize ||
        sealed_size < kObjectHeaderSize + kOverhead)
        return false;
    std::memcpy(l.header.data(), p, kObjectHeaderSize);
    const uint8_t* h = l.header.data();
    if (h[4] != kObjectVersion || h[5] || h[6] || h[7] || Get64(h + 24) != 0)
        return false;
    l.version = kObjectVersion;
    l.segment_count = Get32(h + 8);
    l.segment_bytes = Get32(h + 12);
    l.plaintext_len = Get64(h + 16);
    if (l.segment_bytes == 0 || l.segment_count == 0 ||
        l.segment_count > kMaxObjectSegments ||
        l.plaintext_len > sealed_size ||
        SegmentCount(l.plaintext_len, l.segment_bytes) != l.segment_count ||
        SealedObjectSize(l.plaintext_len, l.segment_bytes) != sealed_size)
        return false;
    *out = l;
    return true;
}

std::string SegmentAad(const std::string& key, const ObjectLayout& layout,
                       uint32_t index) {
    std::string aad(kSegmentAadLabel, sizeof(kSegmentAadLabel));  // with NUL
    aad.append(reinterpret_cast<const char*>(layout.header.data()),
               kObjectHeaderSize);
    uint8_t idx[4];
    Put32(idx, index);
    aad.append(reinterpret_cast<const char*>(idx), 4);
    aad.append(key);
    return aad;
}

std::string LegacyObjectAad(const std::string& key) {
    std::string aad(kLegacyAadLabel, sizeof(kLegacyAadLabel));  // with NUL
    aad.append(key);
    return aad;
}

// --------------------------------------------------------------- options --

StoreCryptoOptions StoreCryptoOptions::FromEnv(const SecureConfig& cfg) {
    StoreCryptoOptions o;
    o.threads = std::clamp<size_t>(EnvSize("MC_SECURE_STORE_THREADS", o.threads),
                                   1, 256);
    o.segment_bytes =
        std::clamp(EnvSize("MC_SECURE_STORE_SEGMENT_BYTES", o.segment_bytes),
                   kMinSegmentBytes, kMaxSegmentBytes);
    o.segment_bytes = (o.segment_bytes + 63) & ~size_t(63);
    o.plain_region_bytes = cfg.staging_region_bytes;
    o.plain_max_bytes =
        EnvSize("MC_SECURE_STORE_PLAIN_MAX_BYTES", cfg.staging_max_bytes);
    if (const char* v = getenv("MC_SECURE_STORE_NUMA_NODE"); v && *v) {
        const std::string t(v);
        char* end = nullptr;
        const long node = strtol(v, &end, 10);
        if (t == "auto") {
            o.numa_node = StoreCryptoOptions::kNumaAuto;
        } else if (t == "none" || t == "off") {
            o.numa_node = StoreCryptoOptions::kNumaNone;
        } else if (end != v && *end == '\0' && node >= 0 && node < 256) {
            o.numa_node = static_cast<int>(node);
        } else {
            LOG(WARNING) << "secure store: ignoring malformed "
                            "MC_SECURE_STORE_NUMA_NODE="
                         << v << " (auto)";
        }
    }
    o.stats_interval_s = static_cast<int>(std::min<size_t>(
        86400, EnvSize("MC_SECURE_STORE_STATS_INTERVAL_S",
                       static_cast<size_t>(o.stats_interval_s))));
    if (const char* c = getenv("MC_SECURE_STORE_CPUS")) {
        if (!ParseCpuList(c, &o.cpus)) {
            LOG(WARNING) << "secure store: ignoring malformed "
                            "MC_SECURE_STORE_CPUS="
                         << c;
            o.cpus.clear();
        }
    }
    return o;
}

// ---------------------------------------------------------------- stages --

const char* StoreStageName(StoreStage s) {
    switch (s) {
        case StoreStage::kPut: return "put";
        case StoreStage::kD2H: return "d2h";
        case StoreStage::kSeal: return "seal";
        case StoreStage::kPutTransfer: return "put_transfer";
        case StoreStage::kGet: return "get";
        case StoreStage::kGetTransfer: return "get_transfer";
        case StoreStage::kOpen: return "open";
        case StoreStage::kH2D: return "h2d";
        default: return "?";
    }
}

std::string StoreStats::ToString() const {
    const char* names[static_cast<int>(StoreStage::kCount)];
    for (int i = 0; i < static_cast<int>(StoreStage::kCount); ++i)
        names[i] = StoreStageName(static_cast<StoreStage>(i));
    return "node=" + std::to_string(numa_node) +
           FormatStages(stage, names, static_cast<int>(StoreStage::kCount));
}

// ---------------------------------------------------------------- crypto --

ObjectCrypto::ObjectCrypto(const StoreCryptoOptions& options,
                           StageRecorder* stages)
    : opt_(options),
      stages_(stages),
      // Plaintext for device destinations is staged here: page-locked for
      // the copy engine and never registered with the NIC.
      scratch_(std::make_unique<StagingPool>(
          options.plain_region_bytes, options.plain_max_bytes,
          [](void* p, size_t n) { return PinHostMemory(p, n); },
          [](void* p) { return UnpinHostMemory(p); })),
      pool_(std::make_unique<CryptoPool>(std::max<size_t>(1, options.threads),
                                         options.cpus, "mc-store-aead")) {}

ObjectCrypto::~ObjectCrypto() { pool_.reset(); }

void ObjectCrypto::SetHome(int node) {
    if (node < 0) return;
    std::vector<int> cpus = NumaNodeCpus(node);
    scratch_->set_numa_node(node, cpus);
    if (opt_.cpus.empty()) pool_->SetCpus(std::move(cpus), false);
}

void ObjectCrypto::Seal(std::vector<SealJob>& jobs, CryptoTiming* timing) {
    struct Task {
        size_t job;
        uint32_t index;
        std::vector<Buf> in;
        uint8_t* out;
        size_t out_len;
    };
    std::vector<ObjectLayout> layouts(jobs.size());
    std::unique_ptr<JobStatus[]> status(new JobStatus[jobs.size()]);
    std::vector<Task> tasks;
    for (size_t j = 0; j < jobs.size(); ++j) {
        auto& job = jobs[j];
        const size_t plain = Total(job.in);
        layouts[j] = MakeLayout(plain, opt_.segment_bytes);
        const ObjectLayout& l = layouts[j];
        if (!job.out.data || job.out.size != SealedSize(plain)) {
            status[j].Fail(Error::kBufferTooSmall);
            continue;
        }
        auto* out = static_cast<uint8_t*>(job.out.data);
        std::memcpy(out, l.header.data(), kObjectHeaderSize);
        auto slices = SliceAll(job.in, l);
        for (uint32_t i = 0; i < l.segment_count; ++i)
            tasks.push_back({j, i, std::move(slices[i]),
                             out + l.SealedOffset(i),
                             kOverhead + l.PlainLength(i)});
    }
    auto& sealer = SecureContext::Global().sealer(Purpose::kStoreObject);
    Latch latch(tasks.size());
    for (auto& t : tasks) {
        pool_->Run([&, tp = &t] {
            const Task& t = *tp;
            JobStatus& st = status[t.job];
            if (st.get() == Error::kOk) {
                const size_t plain = t.out_len - kOverhead;
                std::vector<ConstSpan> in;
                in.reserve(t.in.size());
                std::vector<DevCopy> copies;
                uint8_t* bounce = nullptr;
                if (AnyDevice(t.in)) {
                    // Device -> pinned host on the copy engine, then seal on
                    // this CPU. Sized for a whole segment, so the buffer is
                    // pinned once per thread, not regrown.
                    bounce = static_cast<uint8_t*>(
                        ThreadBounce(std::max(plain, opt_.segment_bytes)));
                    if (!bounce) st.Fail(Error::kCryptoError);
                }
                size_t off = 0;
                for (const auto& b : t.in) {
                    if (b.device >= 0 && bounce) {
                        copies.push_back({bounce + off, b.data, b.size,
                                          b.device});
                        in.push_back({bounce + off, b.size});
                    } else {
                        in.push_back({b.data, b.size});
                    }
                    off += b.size;
                }
                if (st.get() == Error::kOk && !copies.empty()) {
                    const auto t0 = std::chrono::steady_clock::now();
                    if (!CopyDevice(copies)) st.Fail(Error::kCryptoError);
                    const uint64_t ns = NsSince(t0);
                    if (stages_)
                        stages_->Record(static_cast<size_t>(StoreStage::kD2H),
                                        ns);
                    if (timing) timing->d2h_ns.fetch_add(ns);
                }
                if (st.get() == Error::kOk) {
                    const std::string aad =
                        SegmentAad(*jobs[t.job].key, layouts[t.job], t.index);
                    size_t n = 0;
                    const auto t0 = std::chrono::steady_clock::now();
                    Error e = sealer.Seal(in.data(), in.size(),
                                          {aad.data(), aad.size()},
                                          {t.out, t.out_len}, &n);
                    const uint64_t ns = NsSince(t0);
                    if (stages_)
                        stages_->Record(static_cast<size_t>(StoreStage::kSeal),
                                        ns);
                    if (timing) {
                        timing->seal_ns.fetch_add(ns);
                        AtomicMax(timing->seal_max_ns, ns);
                    }
                    if (e == Error::kOk && n != t.out_len)
                        e = Error::kCryptoError;
                    if (e != Error::kOk) st.Fail(e);
                }
            }
            latch.CountDown();
        });
    }
    latch.Wait();
    for (size_t j = 0; j < jobs.size(); ++j) jobs[j].result = status[j].get();
}

StagingBuffer ObjectCrypto::AllocateScratch(size_t bytes) {
    // Waits for other callers' scratch when the pool is at its cap; gives up
    // if `bytes` can never fit or nothing frees in time.
    if (bytes > opt_.plain_max_bytes) return {};
    const auto deadline = std::chrono::steady_clock::now() + kScratchWait;
    for (;;) {
        StagingBuffer b = scratch_->Allocate(bytes);
        if (b) return b;
        if (std::chrono::steady_clock::now() >= deadline) return {};
        std::unique_lock<std::mutex> lock(scratch_mu_);
        scratch_cv_.wait_for(lock, std::chrono::milliseconds(20));
    }
}

void ObjectCrypto::Open(std::vector<OpenJob>& jobs, CryptoTiming* timing) {
    auto& opener = SecureContext::Global().opener();
    size_t next = 0;
    while (next < jobs.size()) {
        // A wave: as many jobs as pinned scratch allows (all of them when
        // nothing goes to a device).
        std::vector<size_t> wave;
        std::vector<StagingBuffer> scratch;  // parallel to wave
        for (; next < jobs.size(); ++next) {
            auto& job = jobs[next];
            job.result = Error::kOk;
            if (Total(job.out) != job.layout.plaintext_len) {
                job.result = Error::kSizeMismatch;
                continue;
            }
            StagingBuffer s;
            if (AnyDevice(job.out) && job.layout.plaintext_len > 0) {
                s = scratch_->Allocate(job.layout.plaintext_len);
                if (!s && !wave.empty()) break;  // run this wave first
                if (!s) s = AllocateScratch(job.layout.plaintext_len);
                if (!s) {
                    LOG(ERROR) << "secure store: no pinned scratch for "
                               << job.layout.plaintext_len << " bytes";
                    job.result = Error::kBufferTooSmall;
                    continue;
                }
            }
            wave.push_back(next);
            scratch.push_back(std::move(s));
        }
        if (wave.empty()) continue;

        struct Task {
            size_t w;  // index into wave
            uint32_t index;
            std::vector<MutableSpan> out;
        };
        std::vector<Task> tasks;
        std::unique_ptr<JobStatus[]> status(new JobStatus[wave.size()]);
        for (size_t w = 0; w < wave.size(); ++w) {
            const auto& job = jobs[wave[w]];
            const ObjectLayout& l = job.layout;
            std::vector<std::vector<Buf>> slices;
            if (!scratch[w]) slices = SliceAll(job.out, l);
            for (uint32_t i = 0; i < l.segment_count; ++i) {
                Task t{w, i, {}};
                if (scratch[w]) {
                    t.out.push_back(
                        {static_cast<char*>(scratch[w].data()) + l.PlainOffset(i),
                         l.PlainLength(i)});
                } else {
                    for (const auto& b : slices[i])
                        t.out.push_back({b.data, b.size});
                }
                tasks.push_back(std::move(t));
            }
        }
        Latch latch(tasks.size());
        for (auto& t : tasks) {
            pool_->Run([&, tp = &t] {
                const Task& t = *tp;
                JobStatus& st = status[t.w];
                const auto& job = jobs[wave[t.w]];
                const ObjectLayout& l = job.layout;
                if (st.get() == Error::kOk) {
                    const std::string aad =
                        l.version == 1 ? LegacyObjectAad(*job.key)
                                       : SegmentAad(*job.key, l, t.index);
                    const auto* base =
                        static_cast<const uint8_t*>(job.sealed.data);
                    ConstSpan in{base + l.SealedOffset(t.index),
                                 kOverhead + l.PlainLength(t.index)};
                    const auto t0 = std::chrono::steady_clock::now();
                    Error e = opener.Open(in, Purpose::kStoreObject,
                                          {aad.data(), aad.size()},
                                          t.out.data(), t.out.size());
                    const uint64_t ns = NsSince(t0);
                    if (stages_)
                        stages_->Record(static_cast<size_t>(StoreStage::kOpen),
                                        ns);
                    if (timing) {
                        timing->open_ns.fetch_add(ns);
                        AtomicMax(timing->open_max_ns, ns);
                    }
                    if (e != Error::kOk) st.Fail(e);
                }
                latch.CountDown();
            });
        }
        latch.Wait();

        // Every segment of a job verified: only now does its plaintext reach
        // the caller's device memory.
        std::vector<DevCopy> copies;
        std::vector<size_t> copied;  // wave indices with device copies
        for (size_t w = 0; w < wave.size(); ++w) {
            auto& job = jobs[wave[w]];
            const Error e = status[w].get();
            if (e != Error::kOk) {
                LOG(ERROR) << "secure store: key " << *job.key
                           << " failed to open: " << ToString(e);
                job.result = e;
                if (!scratch[w]) {
                    for (const auto& b : job.out)
                        if (b.size) std::memset(b.data, 0, b.size);
                }
                continue;
            }
            if (!scratch[w]) continue;
            const auto* src = static_cast<const char*>(scratch[w].data());
            size_t off = 0;
            bool dev = false;
            for (const auto& b : job.out) {
                if (b.device >= 0) {
                    copies.push_back({b.data, src + off, b.size, b.device});
                    dev = true;
                } else if (b.size) {
                    std::memcpy(b.data, src + off, b.size);
                }
                off += b.size;
            }
            if (dev) copied.push_back(w);
        }
        if (!copies.empty()) {
            const auto t0 = std::chrono::steady_clock::now();
            const bool ok = CopyDevice(copies);
            const uint64_t ns = NsSince(t0);
            if (stages_)
                stages_->Record(static_cast<size_t>(StoreStage::kH2D), ns);
            if (timing) timing->h2d_ns.fetch_add(ns);
            if (!ok)
                for (size_t w : copied)
                    jobs[wave[w]].result = Error::kCryptoError;
        }
        scratch.clear();
        scratch_cv_.notify_all();
    }
}

}  // namespace secure
}  // namespace mooncake
