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

// Stage timings for secure mode (DW-1288): per-stage counters and log2
// histograms, recorded lock-free (a few relaxed atomic adds per sample), for
// the secure push and the sealing store client.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Hidden: each module that links this (engine.so, _store.so) keeps its own
// copy of the secure code and its state (SECURE_KV.md, "One copy per module").
#pragma GCC visibility push(hidden)

namespace mooncake {
namespace secure {

// Bucket b of a stage histogram counts durations in [2^(b-1), 2^b)
// microseconds (bucket 0: under 1 us; the last: everything longer).
constexpr int kStageBuckets = 24;

struct StageStats {
    uint64_t count = 0;
    uint64_t sum_ns = 0;
    uint64_t max_ns = 0;
    uint64_t buckets[kStageBuckets] = {};
    // Upper bound (us) of the bucket holding quantile q (0..1); 0 if empty.
    uint64_t QuantileUpperUs(double q) const;
};

// " name{n=.. mean_us=.. max_us=.. p50_le_us=.. p99_le_us=..}" for each
// stage with samples.
std::string FormatStages(const StageStats* stages, const char* const* names,
                         size_t n);

// Cumulative timings of `n` stages.
class StageRecorder {
   public:
    explicit StageRecorder(size_t n);
    void Record(size_t stage, uint64_t ns);
    // Copies stage i into out[i] for i < n.
    void Snapshot(StageStats* out, size_t n) const;
    // True at most once per `interval_s` (never for 0); the first call only
    // starts the interval. For periodic summaries.
    bool Due(int interval_s);

   private:
    struct Stage {
        std::atomic<uint64_t> count{0}, sum_ns{0}, max_ns{0};
        std::atomic<uint64_t> buckets[kStageBuckets];
        Stage();
    };
    std::unique_ptr<Stage[]> stages_;
    size_t n_;
    std::atomic<int64_t> last_due_s_{0};
};

void AtomicMax(std::atomic<uint64_t>& m, uint64_t v);

}  // namespace secure
}  // namespace mooncake

#pragma GCC visibility pop
