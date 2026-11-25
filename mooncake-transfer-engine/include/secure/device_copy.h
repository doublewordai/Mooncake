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

// Device <-> host movement for secure mode (DW-1288), shared by the secure
// P->D push and the sealing store client.
//
// The host AEAD backend cannot read device memory, so device sources are
// copied to pinned host memory on the copy engine before sealing, and device
// destinations are written from pinned host memory after opening. Copies are
// queued with cudaMemcpyAsync on a per-thread, per-device non-blocking stream
// and each used stream is synchronised once.
//
// Without CUDA (USE_CUDA undefined) nothing is device memory: DeviceOf is
// always -1, CopyDevice succeeds only on an empty list and pinning is a no-op.

#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <vector>

// Hidden: each module that links this (engine.so, _store.so) keeps its own
// copy of the secure code and its state (SECURE_KV.md, "One copy per module").
#pragma GCC visibility push(hidden)

namespace mooncake {
namespace secure {

// CUDA device that `p` lives on (device or managed memory), or -1 for
// host-accessible memory.
int DeviceOf(const void* p);

// This thread's pinned host bounce buffer, at least `n` bytes (grown on
// demand; plain heap memory if pinning fails). nullptr on failure. Cleansed
// and freed when the thread exits.
void* ThreadBounce(size_t n);

// Cleanses the first `n` bytes (at most its size) of this thread's bounce
// buffer, if it has one.
void CleanseThreadBounce(size_t n);

struct DevCopy {
    void* dst;
    const void* src;
    size_t n;
    int dev;  // the device side's device
};

// Queues every copy on its device's stream (this thread's), then synchronises
// each used stream once. True only if every copy completed.
bool CopyDevice(const std::vector<DevCopy>& copies);

// Page-locks [p, p+n) for the copy engine (cudaHostRegister). 0 on success.
int PinHostMemory(void* p, size_t n);
int UnpinHostMemory(void* p);

// A countdown latch.
class Latch {
   public:
    explicit Latch(size_t n) : n_(n) {}
    void CountDown() {
        std::lock_guard<std::mutex> lock(mu_);
        if (n_ && --n_ == 0) cv_.notify_all();
    }
    void Wait() {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [&] { return n_ == 0; });
    }

   private:
    std::mutex mu_;
    std::condition_variable cv_;
    size_t n_;
};

}  // namespace secure
}  // namespace mooncake

#pragma GCC visibility pop
