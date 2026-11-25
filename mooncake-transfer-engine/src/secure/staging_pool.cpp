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

#include "secure/staging_pool.h"

#include <glog/logging.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <thread>

namespace mooncake {
namespace secure {

namespace {
constexpr size_t kAlign = 64;
size_t AlignUp(size_t n, size_t a) { return (n + a - 1) / a * a; }

// Linux mempolicy constants (numaif.h, without linking libnuma).
constexpr int kMpolPreferred = 1;
constexpr unsigned kMpolMfMove = 1u << 1;
constexpr unsigned long kMpolFNode = 1ul << 0;
constexpr unsigned long kMpolFAddr = 1ul << 1;
constexpr int kMaxNodes = 256;

void Populate(void* p, size_t n) {
#ifdef MADV_POPULATE_WRITE
    if (madvise(p, n, MADV_POPULATE_WRITE) == 0) return;
#endif
    const long page = sysconf(_SC_PAGESIZE);
    auto* c = static_cast<volatile char*>(p);
    for (size_t off = 0; off < n; off += static_cast<size_t>(page)) c[off] = 0;
}
}  // namespace

void* MapOnNode(size_t n, int node, const std::vector<int>& cpus) {
    if (node < 0 || node >= kMaxNodes) {
        void* p = mmap(nullptr, n, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        return p == MAP_FAILED ? nullptr : p;
    }
    void* p = mmap(nullptr, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return nullptr;
    unsigned long mask[kMaxNodes / (8 * sizeof(unsigned long))] = {};
    mask[node / (8 * sizeof(unsigned long))] |=
        1ul << (node % (8 * sizeof(unsigned long)));
    const long rc = syscall(SYS_mbind, p, n, kMpolPreferred, mask,
                            static_cast<unsigned long>(kMaxNodes + 1),
                            kMpolMfMove);
    if (rc != 0)
        VLOG(1) << "secure staging: mbind to node " << node
                << " refused (errno " << errno
                << "); placing by first touch";
    if (cpus.empty()) {
        Populate(p, n);
        return p;
    }
    // First touch from the node's own CPUs, without moving the caller.
    std::thread t([&] {
        cpu_set_t set;
        CPU_ZERO(&set);
        for (int c : cpus)
            if (c >= 0 && c < CPU_SETSIZE) CPU_SET(c, &set);
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
        Populate(p, n);
    });
    t.join();
    return p;
}

int NodeOfPage(const void* p) {
    int node = -1;
    if (syscall(SYS_get_mempolicy, &node, nullptr, 0ul, const_cast<void*>(p),
                kMpolFNode | kMpolFAddr) != 0)
        return -1;
    return node;
}

void StagingPool::set_numa_node(int node, std::vector<int> cpus) {
    std::lock_guard<std::mutex> lock(mu_);
    node_ = node;
    node_cpus_ = std::move(cpus);
}

StagingBuffer::~StagingBuffer() { Release(); }

StagingBuffer::StagingBuffer(StagingBuffer&& o) noexcept { *this = std::move(o); }

StagingBuffer& StagingBuffer::operator=(StagingBuffer&& o) noexcept {
    if (this != &o) {
        Release();
        pool_ = o.pool_;
        region_ = o.region_;
        offset_ = o.offset_;
        data_ = o.data_;
        size_ = o.size_;
        reserved_ = o.reserved_;
        o.pool_ = nullptr;
        o.data_ = nullptr;
        o.size_ = 0;
    }
    return *this;
}

void StagingBuffer::Release() {
    if (pool_ && data_) pool_->Free(region_, offset_, reserved_);
    pool_ = nullptr;
    data_ = nullptr;
    size_ = 0;
}

StagingPool::StagingPool(size_t region_bytes, size_t max_bytes, RegisterFn reg,
                         UnregisterFn unreg)
    : region_bytes_(AlignUp(std::max<size_t>(region_bytes, 1 << 20), 4096)),
      max_bytes_(max_bytes),
      reg_(std::move(reg)),
      unreg_(std::move(unreg)) {}

StagingPool::~StagingPool() {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& r : regions_) {
        if (unreg_) unreg_(r->base);
        munmap(r->base, r->size);
    }
}

bool StagingPool::AddRegionLocked(size_t min_bytes) {
    size_t size = std::max(region_bytes_, AlignUp(min_bytes, 4096));
    size_t mapped = 0;
    for (auto& r : regions_) mapped += r->size;
    if (mapped + size > max_bytes_) return false;
    void* p = MapOnNode(size, node_, node_cpus_);
    if (!p) {
        PLOG(ERROR) << "secure staging: mmap of " << size << " bytes failed";
        return false;
    }
    if (reg_ && reg_(p, size) != 0) {
        LOG(ERROR) << "secure staging: registering " << size
                   << " bytes failed";
        munmap(p, size);
        return false;
    }
    auto r = std::make_unique<Region>();
    r->base = p;
    r->size = size;
    r->free[0] = size;
    regions_.push_back(std::move(r));
    LOG(INFO) << "secure staging: added a " << size << "-byte region ("
              << regions_.size() << " regions) on NUMA node " << NodeOfPage(p)
              << " (wanted " << node_ << ")";
    return true;
}

StagingBuffer StagingPool::Allocate(size_t bytes) {
    if (bytes == 0) return {};
    const size_t need = AlignUp(bytes, kAlign);
    std::lock_guard<std::mutex> lock(mu_);
    for (int pass = 0; pass < 2; ++pass) {
        for (size_t ri = 0; ri < regions_.size(); ++ri) {
            auto& fl = regions_[ri]->free;
            for (auto it = fl.begin(); it != fl.end(); ++it) {
                if (it->second < need) continue;
                size_t off = it->first, len = it->second;
                fl.erase(it);
                if (len > need) fl[off + need] = len - need;
                return StagingBuffer(
                    this, ri, off,
                    static_cast<char*>(regions_[ri]->base) + off, bytes, need);
            }
        }
        if (pass == 0 && !AddRegionLocked(need)) break;
    }
    return {};
}

void StagingPool::Free(size_t region, size_t offset, size_t reserved) {
    std::lock_guard<std::mutex> lock(mu_);
    auto& fl = regions_[region]->free;
    auto it = fl.emplace(offset, reserved).first;
    auto next = std::next(it);
    if (next != fl.end() && it->first + it->second == next->first) {
        it->second += next->second;
        fl.erase(next);
    }
    if (it != fl.begin()) {
        auto prev = std::prev(it);
        if (prev->first + prev->second == it->first) {
            prev->second += it->second;
            fl.erase(it);
        }
    }
}

bool StagingPool::Contains(const void* p, size_t n) const {
    auto a = reinterpret_cast<uintptr_t>(p);
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& r : regions_) {
        auto b = reinterpret_cast<uintptr_t>(r->base);
        if (a >= b && n <= r->size && a - b <= r->size - n) return true;
    }
    return false;
}

size_t StagingPool::mapped_bytes() const {
    std::lock_guard<std::mutex> lock(mu_);
    size_t t = 0;
    for (auto& r : regions_) t += r->size;
    return t;
}

size_t StagingPool::free_bytes() const {
    std::lock_guard<std::mutex> lock(mu_);
    size_t t = 0;
    for (auto& r : regions_)
        for (auto& [_, l] : r->free) t += l;
    return t;
}

}  // namespace secure
}  // namespace mooncake
