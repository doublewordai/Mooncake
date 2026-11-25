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

#include "secure/stage_stats.h"

#include <algorithm>
#include <chrono>
#include <cstdio>

namespace mooncake {
namespace secure {

void AtomicMax(std::atomic<uint64_t>& m, uint64_t v) {
    uint64_t cur = m.load(std::memory_order_relaxed);
    while (v > cur &&
           !m.compare_exchange_weak(cur, v, std::memory_order_relaxed)) {
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

std::string FormatStages(const StageStats* stages, const char* const* names,
                         size_t n) {
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        const StageStats& st = stages[i];
        if (!st.count) continue;
        char b[160];
        snprintf(b, sizeof(b),
                 " %s{n=%llu mean_us=%.0f max_us=%.0f p50_le_us=%llu "
                 "p99_le_us=%llu}",
                 names[i], static_cast<unsigned long long>(st.count),
                 st.sum_ns / 1e3 / static_cast<double>(st.count),
                 st.max_ns / 1e3,
                 static_cast<unsigned long long>(st.QuantileUpperUs(0.5)),
                 static_cast<unsigned long long>(st.QuantileUpperUs(0.99)));
        out += b;
    }
    return out;
}

StageRecorder::Stage::Stage() {
    for (auto& b : buckets) b.store(0, std::memory_order_relaxed);
}

StageRecorder::StageRecorder(size_t n) : stages_(new Stage[n]), n_(n) {}

void StageRecorder::Record(size_t stage, uint64_t ns) {
    if (stage >= n_) return;
    Stage& st = stages_[stage];
    st.count.fetch_add(1, std::memory_order_relaxed);
    st.sum_ns.fetch_add(ns, std::memory_order_relaxed);
    AtomicMax(st.max_ns, ns);
    const uint64_t us = ns / 1000;
    const int b = us == 0 ? 0
                          : std::min(64 - __builtin_clzll(us), kStageBuckets - 1);
    st.buckets[b].fetch_add(1, std::memory_order_relaxed);
}

void StageRecorder::Snapshot(StageStats* out, size_t n) const {
    for (size_t i = 0; i < n && i < n_; ++i) {
        const Stage& st = stages_[i];
        out[i].count = st.count.load(std::memory_order_relaxed);
        out[i].sum_ns = st.sum_ns.load(std::memory_order_relaxed);
        out[i].max_ns = st.max_ns.load(std::memory_order_relaxed);
        for (int b = 0; b < kStageBuckets; ++b)
            out[i].buckets[b] = st.buckets[b].load(std::memory_order_relaxed);
    }
}

bool StageRecorder::Due(int interval_s) {
    if (interval_s <= 0) return false;
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();
    int64_t last = last_due_s_.load(std::memory_order_relaxed);
    if (last == 0) {
        last_due_s_.compare_exchange_strong(last, now);
        return false;
    }
    return now - last >= interval_s &&
           last_due_s_.compare_exchange_strong(last, now);
}

}  // namespace secure
}  // namespace mooncake
