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

#include "secure/device_copy.h"

#include <glog/logging.h>
#include <openssl/crypto.h>
#include <sched.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <map>
#include <string>

#include "secure/secure_push.h"
#include "secure/staging_pool.h"

#ifdef USE_CUDA
#include <cuda_runtime.h>
#endif

namespace mooncake {
namespace secure {

namespace {

// Per-thread pinned host bounce buffer and per-device copy streams.
struct Bounce {
    void* host = nullptr;
    size_t size = 0;
    bool pinned = false;
#ifdef USE_CUDA
    std::map<int, cudaStream_t> streams;
#endif
    ~Bounce() { Release(); }
    void Release() {
        if (!host) return;
        OPENSSL_cleanse(host, size);
#ifdef USE_CUDA
        if (pinned) {
            cudaFreeHost(host);
        } else {
            free(host);
        }
#else
        free(host);
#endif
        host = nullptr;
    }
    void* Get(size_t n) {
        if (size >= n) return host;
        Release();
        size = 0;
        pinned = false;
#ifdef USE_CUDA
        if (cudaHostAlloc(&host, n, cudaHostAllocPortable) == cudaSuccess) {
            pinned = true;
        } else {
            cudaGetLastError();
            host = nullptr;
        }
#endif
        if (!host) host = malloc(n);
        if (host) size = n;
        return host;
    }
#ifdef USE_CUDA
    cudaStream_t Stream(int dev) {
        auto it = streams.find(dev);
        if (it != streams.end()) return it->second;
        cudaStream_t s = nullptr;
        cudaSetDevice(dev);
        if (cudaStreamCreateWithFlags(&s, cudaStreamNonBlocking) !=
            cudaSuccess) {
            cudaGetLastError();
            return nullptr;
        }
        streams[dev] = s;
        return s;
    }
#endif
};

thread_local Bounce t_bounce;

}  // namespace

int DeviceOf(const void* p) {
#ifdef USE_CUDA
    cudaPointerAttributes a{};
    if (cudaPointerGetAttributes(&a, p) != cudaSuccess) {
        cudaGetLastError();
        return -1;
    }
    if (a.type == cudaMemoryTypeDevice || a.type == cudaMemoryTypeManaged)
        return a.device;
#else
    (void)p;
#endif
    return -1;
}

int HomeNumaNode(const void* p) {
    if (!p) return -1;
#ifdef USE_CUDA
    const int dev = DeviceOf(p);
    if (dev >= 0) {
        char bus[32] = {};
        if (cudaDeviceGetPCIBusId(bus, sizeof(bus), dev) != cudaSuccess) {
            cudaGetLastError();
            return -1;
        }
        for (char* c = bus; *c; ++c)
            *c = static_cast<char>(std::tolower(static_cast<unsigned char>(*c)));
        int node = -1;
        std::ifstream(std::string("/sys/bus/pci/devices/") + bus +
                      "/numa_node") >>
            node;
        return node;
    }
#endif
    return NodeOfPage(p);
}

std::vector<int> NumaNodeCpus(int node) {
    std::vector<int> out;
    if (node < 0) return out;
    std::string list;
    std::ifstream("/sys/devices/system/node/node" + std::to_string(node) +
                  "/cpulist") >>
        list;
    std::vector<int> all;
    if (list.empty() || !ParseCpuList(list, &all)) return out;
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    // The process's mask (its main thread's), not the calling thread's.
    if (sched_getaffinity(getpid(), sizeof(allowed), &allowed) != 0)
        return out;
    for (int c : all)
        if (c >= 0 && c < CPU_SETSIZE && CPU_ISSET(c, &allowed))
            out.push_back(c);
    return out;
}

void* ThreadBounce(size_t n) { return t_bounce.Get(n); }

void CleanseThreadBounce(size_t n) {
    if (t_bounce.host) OPENSSL_cleanse(t_bounce.host, std::min(n, t_bounce.size));
}

bool CopyDevice(const std::vector<DevCopy>& copies) {
#ifdef USE_CUDA
    if (copies.empty()) return true;
    // The caller may be an application thread: leave its current device as
    // it was.
    int prev = -1;
    if (cudaGetDevice(&prev) != cudaSuccess) {
        cudaGetLastError();
        prev = -1;
    }
    std::vector<int> used;
    bool ok = true;
    for (const auto& c : copies) {
        cudaSetDevice(c.dev);
        cudaStream_t s = t_bounce.Stream(c.dev);
        if (!s || cudaMemcpyAsync(c.dst, c.src, c.n, cudaMemcpyDefault, s) !=
                      cudaSuccess) {
            ok = false;
            break;
        }
        if (std::find(used.begin(), used.end(), c.dev) == used.end())
            used.push_back(c.dev);
    }
    for (int d : used) {
        cudaSetDevice(d);
        if (cudaStreamSynchronize(t_bounce.Stream(d)) != cudaSuccess)
            ok = false;
    }
    if (!ok)
        LOG(ERROR) << "secure: device copy failed: "
                   << cudaGetErrorString(cudaGetLastError());
    if (prev >= 0) cudaSetDevice(prev);
    return ok;
#else
    return copies.empty();
#endif
}

int PinHostMemory(void* p, size_t n) {
#ifdef USE_CUDA
    if (cudaHostRegister(p, n, cudaHostRegisterPortable) != cudaSuccess) {
        LOG(ERROR) << "secure: pinning " << n << " bytes failed: "
                   << cudaGetErrorString(cudaGetLastError());
        return -1;
    }
#else
    (void)p;
    (void)n;
#endif
    return 0;
}

int UnpinHostMemory(void* p) {
#ifdef USE_CUDA
    if (cudaHostUnregister(p) != cudaSuccess) {
        cudaGetLastError();
        return -1;
    }
#else
    (void)p;
#endif
    return 0;
}

}  // namespace secure
}  // namespace mooncake
