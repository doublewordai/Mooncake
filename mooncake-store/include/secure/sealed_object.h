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

// Sealed store objects (DW-1288): the stored form of a value in secure mode,
// sealed and opened in parallel segments, from and into host or GPU memory.
//
// Format, version 2 (little-endian):
//
//   object    = header || segment_0 || ... || segment_{n-1}
//   header    = magic "MCSO" (4) | version = 2 (1) | reserved = 0 (3)
//               | segment_count n (4) | segment_bytes (4)
//               | plaintext_len (8) | reserved = 0 (8)          (32 bytes)
//   segment_i = one kv_crypto sealed message (Purpose::kStoreObject) of
//               plaintext bytes [i * segment_bytes,
//                                min((i + 1) * segment_bytes, plaintext_len))
//   AAD_i     = "mooncake-store-object-v2" 0 | header | i (4) | object key
//
// n is max(1, ceil(plaintext_len / segment_bytes)) and the object's size is
// exactly 32 + plaintext_len + n * kOverhead. Every segment authenticates the
// whole header (so the count, sizes and version), its own index and the key:
// segments cannot be reordered, dropped, duplicated or moved between objects,
// and a changed header fails every segment. segment_bytes is the writer's
// choice; readers take it from the header.
//
// Version 1 (read only): the whole value as a single kv_crypto message with
// AAD "mooncake-store-object" 0 | key. It starts with kv_crypto's own magic,
// so the two versions are told apart by their first four bytes.
//
// Opening is all-or-nothing per object: every segment is verified before the
// caller can see any of it. Into host memory, segments are opened in place and
// the caller's buffers are zeroed if any segment fails. Into GPU memory,
// segments are opened into pinned host scratch and copied to the device only
// after all of them verified; on failure the device memory is not touched.

#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "secure/kv_crypto.h"
#include "secure/stage_stats.h"
#include "secure/staging_pool.h"

// Hidden: each module that links this (engine.so, _store.so) keeps its own
// copy of the secure code and its state (SECURE_KV.md, "One copy per module").
#pragma GCC visibility push(hidden)

namespace mooncake {
namespace secure {

class CryptoPool;

inline constexpr uint32_t kObjectMagic = 0x4f53434dU;  // "MCSO"
inline constexpr uint8_t kObjectVersion = 2;
inline constexpr size_t kObjectHeaderSize = 32;
inline constexpr uint32_t kMaxObjectSegments = 1u << 24;

// Size of a version-2 object holding `plaintext_len` bytes in segments of
// `segment_bytes`.
size_t SealedObjectSize(size_t plaintext_len, size_t segment_bytes);

// A parsed object header (a private copy: never re-read from the object).
struct ObjectLayout {
    uint8_t version = 0;  // 1 or 2
    uint64_t plaintext_len = 0;
    uint32_t segment_bytes = 0;  // version 2
    uint32_t segment_count = 0;  // 1 for version 1
    std::array<uint8_t, kObjectHeaderSize> header{};  // version 2, as stored

    // Plaintext offset / length of segment i, and its sealed offset in the
    // object.
    uint64_t PlainOffset(uint32_t i) const;
    size_t PlainLength(uint32_t i) const;
    uint64_t SealedOffset(uint32_t i) const;
};

// Parses the header of a sealed object whose total size is `sealed_size`,
// from `prefix` (its first bytes: at least min(sealed_size, 48)). Checks the
// magic, version, reserved bytes and that the size is exactly what the header
// implies. Authenticates nothing: that happens when the segments are opened.
bool ParseObject(ConstSpan prefix, size_t sealed_size, ObjectLayout* out);

// Associated data of a segment (version 2) and of a version-1 object.
std::string SegmentAad(const std::string& key, const ObjectLayout& layout,
                       uint32_t index);
std::string LegacyObjectAad(const std::string& key);

// Environment (all optional):
//   MC_SECURE_STORE_THREADS          crypto threads (8)
//   MC_SECURE_STORE_SEGMENT_BYTES    plaintext per sealed segment (2 MiB;
//                                    64 KiB .. 1 GiB)
//   MC_SECURE_STORE_CPUS             CPU list the crypto threads are pinned
//                                    to, one CPU each, e.g. "64-71"; unset:
//                                    the home node's CPUs (see below), or not
//                                    pinned if there is no home node
//   MC_SECURE_STORE_PLAIN_MAX_BYTES  cap on pinned plaintext scratch for gets
//                                    into GPU memory (MC_SECURE_STAGING_MAX_BYTES)
//   MC_SECURE_STORE_NUMA_NODE        the client's home NUMA node: "auto"
//                                    (default: the node of the GPU current at
//                                    setup, then of the first buffer
//                                    registered), a node number, or "none".
//                                    The client's segment, local buffer and
//                                    staging are registered as that node's
//                                    memory (so on its NIC) and placed there,
//                                    as are its scratch and crypto threads.
//   MC_SECURE_STORE_STATS_INTERVAL_S at most this often, a call logs the
//                                    cumulative stage timings (60; 0: never).
//                                    Each call's own breakdown is at VLOG(1).
struct StoreCryptoOptions {
    static constexpr int kNumaAuto = -1;
    static constexpr int kNumaNone = -2;
    size_t threads = 8;
    size_t segment_bytes = 2ull << 20;
    std::vector<int> cpus;
    size_t plain_region_bytes = 256ull << 20;
    size_t plain_max_bytes = 4ull << 30;
    int numa_node = kNumaAuto;
    int stats_interval_s = 60;

    static StoreCryptoOptions FromEnv(const SecureConfig& cfg);
};

// Where the time of secure store calls goes (DW-1288). Per call unless noted.
enum class StoreStage : int {
    kPut = 0,      // a put call, whole
    kD2H,          // per segment: device -> pinned host before sealing
    kSeal,         // per segment: sealing
    kPutTransfer,  // the inner client's put of the sealed objects
    kGet,          // a get call, whole
    kGetTransfer,  // the inner client's get of the sealed objects
    kOpen,         // per segment: verifying and decrypting
    kH2D,          // per wave: pinned scratch -> device after verification
    kCount
};
const char* StoreStageName(StoreStage s);

// Cumulative since the client was set up.
struct StoreStats {
    StageStats stage[static_cast<int>(StoreStage::kCount)];
    int numa_node = -1;  // home node in use (-1: none)
    std::string ToString() const;
};

// One call's crypto time (sums over its segments, and the longest segment).
struct CryptoTiming {
    std::atomic<uint64_t> d2h_ns{0}, seal_ns{0}, open_ns{0}, h2d_ns{0};
    std::atomic<uint64_t> seal_max_ns{0}, open_max_ns{0};
};

// A caller buffer and where it lives (device -1: host memory).
struct Buf {
    void* data = nullptr;
    size_t size = 0;
    int device = -1;
};

// Seals and opens store objects on a pool of crypto threads. Thread safe:
// concurrent calls share the pool.
class ObjectCrypto {
   public:
    // `stages` (optional) receives the per-segment and per-wave stages.
    explicit ObjectCrypto(const StoreCryptoOptions& options,
                          StageRecorder* stages = nullptr);
    ~ObjectCrypto();

    // Places scratch regions added from now on, and the crypto threads
    // (unless MC_SECURE_STORE_CPUS pins them), on NUMA node `node`.
    void SetHome(int node);

    size_t segment_bytes() const { return opt_.segment_bytes; }
    size_t SealedSize(size_t plaintext_len) const {
        return SealedObjectSize(plaintext_len, opt_.segment_bytes);
    }

    struct SealJob {
        const std::string* key = nullptr;
        std::vector<Buf> in;  // the value, in order (host or device)
        MutableSpan out;      // exactly SealedSize(total of in) bytes
        Error result = Error::kOk;
    };
    // Seals every job; each job's result is set.
    void Seal(std::vector<SealJob>& jobs, CryptoTiming* timing = nullptr);

    struct OpenJob {
        const std::string* key = nullptr;
        ConstSpan sealed;      // the whole object
        ObjectLayout layout;   // from ParseObject
        std::vector<Buf> out;  // exactly layout.plaintext_len bytes
        Error result = Error::kOk;
    };
    // Opens every job, all-or-nothing per job (see above). kAuthFailed (or
    // another open error) if any segment fails; kBufferTooSmall if no pinned
    // scratch could be had; kCryptoError if a device copy failed after
    // verification (the device may then hold part of the verified value).
    void Open(std::vector<OpenJob>& jobs, CryptoTiming* timing = nullptr);

    // Tests.
    StagingPool& scratch() { return *scratch_; }

   private:
    StagingBuffer AllocateScratch(size_t bytes);

    StoreCryptoOptions opt_;
    StageRecorder* stages_ = nullptr;
    std::unique_ptr<StagingPool> scratch_;
    std::mutex scratch_mu_;
    std::condition_variable scratch_cv_;
    std::unique_ptr<CryptoPool> pool_;  // last: joined first
};

}  // namespace secure
}  // namespace mooncake

#pragma GCC visibility pop
