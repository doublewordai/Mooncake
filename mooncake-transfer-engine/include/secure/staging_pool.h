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

// Engine-owned staging memory for secure mode: the only memory of a process
// (besides store segments) that is registered with the NIC, and so the only
// memory peers can read or write. It only ever holds sealed messages.
//
// Regions are anonymous host mappings (populated up front), registered through
// a caller-supplied function that must register them as ciphertext memory
// (inside a CiphertextRegistrationScope). Allocation is first-fit with
// coalescing, 64-byte aligned, thread safe; new regions are added on demand
// up to a cap.

#pragma once

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

// Hidden: each module that links this (engine.so, _store.so) keeps its own
// copy of the secure code and its state (SECURE_KV.md, "One copy per module").
#pragma GCC visibility push(hidden)

namespace mooncake {
namespace secure {

class StagingPool;

// A block of staging memory; returned to the pool when destroyed.
class StagingBuffer {
   public:
    StagingBuffer() = default;
    ~StagingBuffer();
    StagingBuffer(StagingBuffer&& o) noexcept;
    StagingBuffer& operator=(StagingBuffer&& o) noexcept;
    StagingBuffer(const StagingBuffer&) = delete;
    StagingBuffer& operator=(const StagingBuffer&) = delete;

    void* data() const { return data_; }
    size_t size() const { return size_; }
    explicit operator bool() const { return data_ != nullptr; }

   private:
    friend class StagingPool;
    StagingBuffer(StagingPool* pool, size_t region, size_t offset, void* data,
                  size_t size, size_t reserved)
        : pool_(pool),
          region_(region),
          offset_(offset),
          data_(data),
          size_(size),
          reserved_(reserved) {}
    void Release();

    StagingPool* pool_ = nullptr;
    size_t region_ = 0;
    size_t offset_ = 0;
    void* data_ = nullptr;
    size_t size_ = 0;
    size_t reserved_ = 0;
};

class StagingPool {
   public:
    // Returns 0 on success. Must register the memory as ciphertext memory.
    using RegisterFn = std::function<int(void* addr, size_t length)>;
    using UnregisterFn = std::function<int(void* addr)>;

    StagingPool(size_t region_bytes, size_t max_bytes, RegisterFn reg,
                UnregisterFn unreg);
    ~StagingPool();  // unregisters and unmaps all regions

    // An empty buffer if `bytes` cannot be served (exhausted, over the cap, or
    // registration failed).
    StagingBuffer Allocate(size_t bytes);

    // True if [p, p+n) lies inside one of this pool's regions.
    bool Contains(const void* p, size_t n) const;

    size_t region_bytes() const { return region_bytes_; }
    size_t mapped_bytes() const;
    size_t free_bytes() const;

   private:
    friend class StagingBuffer;
    struct Region {
        void* base = nullptr;
        size_t size = 0;
        std::map<size_t, size_t> free;  // offset -> length
    };
    bool AddRegionLocked(size_t min_bytes);
    void Free(size_t region, size_t offset, size_t reserved);

    const size_t region_bytes_;
    const size_t max_bytes_;
    RegisterFn reg_;
    UnregisterFn unreg_;
    mutable std::mutex mu_;
    std::vector<std::unique_ptr<Region>> regions_;
};

}  // namespace secure
}  // namespace mooncake

#pragma GCC visibility pop
