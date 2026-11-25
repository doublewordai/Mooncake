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

#include "secure/secure_py_client.h"

#include <glog/logging.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "client_buffer.h"
#include "device/accelerator_registry.h"
#include "secure/device_copy.h"
#include "secure/secure_transport.h"

namespace mooncake {
namespace secure {

namespace {

int Err(ErrorCode e) { return toInt(e); }

using Clock = std::chrono::steady_clock;

uint64_t NsSince(Clock::time_point t0) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - t0)
            .count());
}

std::string Ms(uint64_t ns) {
    char b[32];
    snprintf(b, sizeof(b), "%.2f", ns / 1e6);
    return b;
}

int Refuse(const char *what) {
    LOG(ERROR) << "secure mode: " << what
               << " is not supported (refused, fails closed)";
    return Err(ErrorCode::INVALID_PARAMS);
}

// The store error for a failed seal or open.
int ErrOf(Error e) {
    switch (e) {
        case Error::kOk:
            return 0;
        case Error::kBadHeader:
        case Error::kAuthFailed:
        case Error::kSizeMismatch:
        case Error::kUnknownKeyId:
            return Err(ErrorCode::CHECKSUM_MISMATCH);
        case Error::kBufferTooSmall:
            return Err(ErrorCode::NO_AVAILABLE_HANDLE);
        default:
            return Err(ErrorCode::INTERNAL_ERROR);
    }
}

}  // namespace

bool SecurePyClient::Enabled() { return SecureContext::Global().enabled(); }

StoreStats SecurePyClient::store_stats() const {
    StoreStats st;
    stages_.Snapshot(st.stage, static_cast<size_t>(StoreStage::kCount));
    st.numa_node = home_node_.load();
    return st;
}

void SecurePyClient::MaybeLogStats() {
    if (!stages_.Due(opt_.stats_interval_s)) return;
    LOG(INFO) << "secure store: stage timings since setup: "
              << store_stats().ToString();
}

SecurePyClient::SecurePyClient(std::shared_ptr<PyClient> inner)
    : inner_(std::move(inner)) {}

SecurePyClient::~SecurePyClient() {
    // Staging is registered with the inner client's engine: release it while
    // that engine is still alive.
    crypto_.reset();
    pool_.reset();
}

int SecurePyClient::EnsureReady() {
    auto &ctx = SecureContext::Global();
    if (!ctx.enabled() || ctx.failed()) {
        LOG(ERROR) << "secure mode: not available: " << ctx.reason();
        return Err(ErrorCode::INVALID_PARAMS);
    }
    if (!pool_ || !crypto_ || !client_) return Err(ErrorCode::INVALID_PARAMS);
    return 0;
}

bool SecurePyClient::Classify(const void *p, size_t n, const std::string &key,
                              Buf *out) const {
    out->data = const_cast<void *>(p);
    out->size = n;
    out->device = -1;
    if (n == 0) return true;
    if (!p) {
        LOG(ERROR) << "secure mode: null buffer for key " << key;
        return false;
    }
    // CUDA memory moves through pinned host memory on the copy engine.
    out->device = DeviceOf(p);
    if (out->device >= 0) return true;
    // Other accelerators' memory cannot be read or written by the CPU.
    auto accelerators = device::GetAcceleratorRegistry().RuntimeAccelerators();
    if (accelerators.FindDeviceForPointer(p) != nullptr) {
        LOG(ERROR) << "secure mode: key " << key
                   << " uses non-CUDA device memory, which is not supported";
        return false;
    }
    return true;
}

int SecurePyClient::SetupInner(const std::function<int()> &setup,
                               bool external_engine, bool ssd_offload) {
    std::lock_guard<std::mutex> lock(setup_mu_);
    auto &ctx = SecureContext::Global();
    if (!ctx.enabled() || ctx.failed()) {
        LOG(ERROR) << "secure mode: cannot set up the store: "
                   << (ctx.enabled() ? ctx.reason() : "secure mode is off");
        return Err(ErrorCode::INVALID_PARAMS);
    }
    const char *tent = std::getenv("MC_USE_TENT");
    if (tent && *tent && std::strcmp(tent, "0") != 0)
        return Refuse("the TENT engine (MC_USE_TENT)");
    if (ssd_offload) return Refuse("SSD offload");
    // A caller-supplied engine may already hold plaintext registrations made
    // outside this decorator's control.
    if (external_engine) return Refuse("a caller-supplied transfer engine");
    opt_ = StoreCryptoOptions::FromEnv(ctx.config());
    // Home node: the GPU this rank serves (vLLM sets the device before it
    // sets up the store), until a registered KV buffer says otherwise.
    int node = -1;
    if (opt_.numa_node >= 0)
        node = opt_.numa_node;
    else if (opt_.numa_node == StoreCryptoOptions::kNumaAuto)
        node = CurrentGpuNumaNode();
    home_node_.store(node);
    int rc;
    {
        // The inner client's segments, hot cache and local buffer only ever
        // receive sealed bytes, so they are registered with the NIC (the
        // home node's).
        CiphertextRegistrationScope scope(node);
        rc = setup();
    }
    if (rc != 0) return rc;
    client_ = inner_->client_;
    auto inner = inner_;
    pool_ = std::make_unique<StagingPool>(
        ctx.config().staging_region_bytes, ctx.config().staging_max_bytes,
        [this, inner](void *p, size_t n) {
            CiphertextRegistrationScope scope(home_node_.load());
            return inner->register_buffer(p, n);
        },
        [inner](void *p) { return inner->unregister_buffer(p); });
    crypto_ = std::make_unique<ObjectCrypto>(opt_, &stages_);
    if (node >= 0) {
        pool_->set_numa_node(node, NumaNodeCpus(node));
        crypto_->SetHome(node);
    }
    LOG(INFO) << "secure mode: store client ready (values sealed with "
              << ToString(ctx.config().algorithm) << " in "
              << opt_.segment_bytes << "-byte segments on " << opt_.threads
              << " threads; home NUMA node " << node << ")";
    return 0;
}

int SecurePyClient::setup_real(
    const std::string &local_hostname, const std::string &metadata_server,
    size_t global_segment_size, size_t local_buffer_size,
    const std::string &protocol, const std::string &rdma_devices,
    const std::string &master_server_addr,
    const std::shared_ptr<TransferEngine> &transfer_engine,
    const std::string &ipc_socket_path, bool enable_ssd_offload,
    const std::string &ssd_offload_path, const std::string &tenant_id,
    bool enable_client_http_server, int client_http_port) {
    return SetupInner(
        [&] {
            return inner_->setup_real(
                local_hostname, metadata_server, global_segment_size,
                local_buffer_size, protocol, rdma_devices, master_server_addr,
                transfer_engine, ipc_socket_path, enable_ssd_offload,
                ssd_offload_path, tenant_id, enable_client_http_server,
                client_http_port);
        },
        transfer_engine != nullptr, enable_ssd_offload);
}

int SecurePyClient::setup_dummy(size_t, size_t, const std::string &,
                                const std::string &) {
    return Refuse("the dummy (shared-memory) client");
}

int SecurePyClient::initAll(const std::string &, const std::string &, size_t) {
    return Refuse("initAll (use setup)");
}

uint64_t SecurePyClient::alloc_from_mem_pool(size_t) { return 0; }

// ------------------------------------------------------------------- put --

std::vector<int> SecurePyClient::PutMany(const std::vector<std::string> &keys,
                                         const std::vector<Parts> &values,
                                         const ReplicateConfig &config,
                                         bool upsert) {
    std::vector<int> results(keys.size(), 0);
    if (int rc = EnsureReady()) {
        std::fill(results.begin(), results.end(), rc);
        return results;
    }
    if (values.size() != keys.size()) {
        std::fill(results.begin(), results.end(),
                  Err(ErrorCode::INVALID_PARAMS));
        return results;
    }
    const auto t_call = Clock::now();
    CryptoTiming timing;
    uint64_t transfer_ns = 0, bytes = 0;
    // Where each value lives, decided once per piece.
    std::vector<std::vector<Buf>> bufs(keys.size());
    std::vector<bool> pending(keys.size(), true);
    for (size_t i = 0; i < keys.size(); ++i) {
        for (auto &p : values[i]) {
            Buf b;
            if (!Classify(p.data, p.size, keys[i], &b)) {
                results[i] = Err(ErrorCode::INVALID_PARAMS);
                pending[i] = false;
                break;
            }
            if (b.size) bufs[i].push_back(b);
        }
    }
    size_t i = 0;
    while (i < keys.size()) {
        // Take as many values as staging holds, seal them in parallel, then
        // hand them to the inner client as one batch.
        std::vector<StagingBuffer> held;
        std::vector<ObjectCrypto::SealJob> jobs;
        std::vector<size_t> index;
        for (; i < keys.size(); ++i) {
            if (!pending[i]) continue;
            size_t plain = 0;
            for (auto &b : bufs[i]) plain += b.size;
            const size_t sealed_len = crypto_->SealedSize(plain);
            StagingBuffer buf = pool_->Allocate(sealed_len);
            if (!buf) {
                if (!held.empty()) break;  // flush, then retry this key
                LOG(ERROR) << "secure mode: no staging for " << sealed_len
                           << " bytes (key " << keys[i] << ")";
                results[i] = Err(ErrorCode::NO_AVAILABLE_HANDLE);
                continue;
            }
            ObjectCrypto::SealJob job;
            job.key = &keys[i];
            job.in = std::move(bufs[i]);
            job.out = {buf.data(), sealed_len};
            jobs.push_back(std::move(job));
            index.push_back(i);
            held.push_back(std::move(buf));
        }
        if (jobs.empty()) continue;
        crypto_->Seal(jobs, &timing);
        std::vector<std::string> batch_keys;
        std::vector<void *> ptrs;
        std::vector<size_t> sizes;
        std::vector<size_t> sent;
        for (size_t j = 0; j < jobs.size(); ++j) {
            const size_t k = index[j];
            if (jobs[j].result != Error::kOk) {
                LOG(ERROR) << "secure mode: sealing key " << keys[k]
                           << " failed: " << ToString(jobs[j].result);
                results[k] = Err(ErrorCode::INTERNAL_ERROR);
                continue;
            }
            batch_keys.push_back(keys[k]);
            ptrs.push_back(jobs[j].out.data);
            sizes.push_back(jobs[j].out.size);
            sent.push_back(k);
        }
        if (batch_keys.empty()) continue;
        const auto t0 = Clock::now();
        auto r = upsert
                     ? inner_->batch_upsert_from(batch_keys, ptrs, sizes, config)
                     : inner_->batch_put_from(batch_keys, ptrs, sizes, config);
        transfer_ns += NsSince(t0);
        for (size_t j = 0; j < sent.size(); ++j) {
            results[sent[j]] =
                j < r.size() ? r[j] : Err(ErrorCode::INTERNAL_ERROR);
            if (results[sent[j]] == 0)
                bytes += sizes[j];  // sealed bytes stored
        }
    }
    const uint64_t total = NsSince(t_call);
    stages_.Record(static_cast<size_t>(StoreStage::kPut), total);
    stages_.Record(static_cast<size_t>(StoreStage::kPutTransfer), transfer_ns);
    VLOG(1) << "secure store put: " << keys.size() << " keys, " << bytes
            << " sealed B in " << Ms(total) << " ms; d2h sum "
            << Ms(timing.d2h_ns.load()) << ", seal sum/max "
            << Ms(timing.seal_ns.load()) << "/" << Ms(timing.seal_max_ns.load())
            << ", transfer " << Ms(transfer_ns) << " ms (node "
            << home_node_.load() << ")";
    MaybeLogStats();
    return results;
}

static std::vector<ConstSpan> Span(const void *p, size_t n) {
    return {ConstSpan{p, n}};
}

int SecurePyClient::put(const std::string &key, std::span<const char> value,
                        const ReplicateConfig &config) {
    return PutMany({key}, {Span(value.data(), value.size())}, config, false)[0];
}

int SecurePyClient::put_from(const std::string &key, void *buffer, size_t size,
                             const ReplicateConfig &config) {
    return PutMany({key}, {Span(buffer, size)}, config, false)[0];
}

int SecurePyClient::upsert(const std::string &key, std::span<const char> value,
                           const ReplicateConfig &config) {
    return PutMany({key}, {Span(value.data(), value.size())}, config, true)[0];
}

int SecurePyClient::upsert_from(const std::string &key, void *buffer,
                                size_t size, const ReplicateConfig &config) {
    return PutMany({key}, {Span(buffer, size)}, config, true)[0];
}

static std::vector<std::vector<ConstSpan>> Flat(
    const std::vector<void *> &buffers, const std::vector<size_t> &sizes) {
    std::vector<std::vector<ConstSpan>> v;
    if (buffers.size() != sizes.size()) return v;
    for (size_t i = 0; i < buffers.size(); ++i)
        v.push_back(Span(buffers[i], sizes[i]));
    return v;
}

static std::vector<std::vector<ConstSpan>> Nested(
    const std::vector<std::vector<void *>> &buffers,
    const std::vector<std::vector<size_t>> &sizes) {
    std::vector<std::vector<ConstSpan>> v;
    if (buffers.size() != sizes.size()) return v;
    for (size_t i = 0; i < buffers.size(); ++i) {
        if (buffers[i].size() != sizes[i].size()) return {};
        std::vector<ConstSpan> parts;
        for (size_t j = 0; j < buffers[i].size(); ++j)
            parts.push_back({buffers[i][j], sizes[i][j]});
        v.push_back(std::move(parts));
    }
    return v;
}

static std::vector<std::vector<ConstSpan>> Parts1(
    const std::vector<std::span<const char>> &values) {
    std::vector<ConstSpan> parts;
    for (auto &v : values) parts.push_back({v.data(), v.size()});
    return {parts};
}

std::vector<int> SecurePyClient::batch_put_from(
    const std::vector<std::string> &keys, const std::vector<void *> &buffers,
    const std::vector<size_t> &sizes, const ReplicateConfig &config) {
    return PutMany(keys, Flat(buffers, sizes), config, false);
}

std::vector<int> SecurePyClient::batch_upsert_from(
    const std::vector<std::string> &keys, const std::vector<void *> &buffers,
    const std::vector<size_t> &sizes, const ReplicateConfig &config) {
    return PutMany(keys, Flat(buffers, sizes), config, true);
}

std::vector<int> SecurePyClient::batch_put_from_multi_buffers(
    const std::vector<std::string> &keys,
    const std::vector<std::vector<void *>> &all_buffers,
    const std::vector<std::vector<size_t>> &all_sizes,
    const ReplicateConfig &config) {
    return PutMany(keys, Nested(all_buffers, all_sizes), config, false);
}

std::vector<int> SecurePyClient::batch_upsert_from_multi_buffers(
    const std::vector<std::string> &keys,
    const std::vector<std::vector<void *>> &all_buffers,
    const std::vector<std::vector<size_t>> &all_sizes,
    const ReplicateConfig &config) {
    return PutMany(keys, Nested(all_buffers, all_sizes), config, true);
}

int SecurePyClient::put_parts(const std::string &key,
                              std::vector<std::span<const char>> values,
                              const ReplicateConfig &config) {
    return PutMany({key}, Parts1(values), config, false)[0];
}

int SecurePyClient::upsert_parts(const std::string &key,
                                 std::vector<std::span<const char>> values,
                                 const ReplicateConfig &config) {
    return PutMany({key}, Parts1(values), config, true)[0];
}

static int FirstError(const std::vector<int> &r) {
    for (int x : r)
        if (x != 0) return x;
    return 0;
}

int SecurePyClient::put_batch(const std::vector<std::string> &keys,
                              const std::vector<std::span<const char>> &values,
                              const ReplicateConfig &config) {
    std::vector<std::vector<ConstSpan>> v;
    for (auto &x : values) v.push_back(Span(x.data(), x.size()));
    return FirstError(PutMany(keys, v, config, false));
}

int SecurePyClient::upsert_batch(
    const std::vector<std::string> &keys,
    const std::vector<std::span<const char>> &values,
    const ReplicateConfig &config) {
    std::vector<std::vector<ConstSpan>> v;
    for (auto &x : values) v.push_back(Span(x.data(), x.size()));
    return FirstError(PutMany(keys, v, config, true));
}

int SecurePyClient::put_from_with_metadata(const std::string &, void *, void *,
                                           size_t, size_t,
                                           const ReplicateConfig &) {
    return Refuse("put_from_with_metadata");
}

// ------------------------------------------------------------------- get --

std::vector<int64_t> SecurePyClient::GetMany(
    const std::vector<std::string> &keys, const std::vector<Outs> &outs) {
    std::vector<int64_t> results(keys.size(), 0);
    if (int rc = EnsureReady()) {
        std::fill(results.begin(), results.end(), rc);
        return results;
    }
    if (outs.size() != keys.size()) {
        std::fill(results.begin(), results.end(),
                  Err(ErrorCode::INVALID_PARAMS));
        return results;
    }
    const auto t_call = Clock::now();
    CryptoTiming timing;
    uint64_t transfer_ns = 0;
    auto queries = inner_->batch_query(keys);
    std::vector<uint64_t> sealed_sizes(keys.size(), 0);
    std::vector<std::vector<Buf>> bufs(keys.size());
    std::vector<bool> pending(keys.size(), false);
    std::vector<void *> local_src(keys.size(), nullptr);
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i >= queries.size() || !queries[i]) {
            results[i] = Err(i < queries.size() ? queries[i].error()
                                                : ErrorCode::INTERNAL_ERROR);
            continue;
        }
        const auto &replicas = queries[i]->replicas;
        if (replicas.empty()) {
            results[i] = Err(ErrorCode::INVALID_REPLICA);
            continue;
        }
        const uint64_t sealed = calculate_total_size(replicas.front());
        if (sealed < kOverhead) {
            LOG(ERROR) << "secure mode: key " << keys[i]
                       << " is not a sealed object (size " << sealed << ")";
            results[i] = Err(ErrorCode::CHECKSUM_MISMATCH);
            continue;
        }
        bool ok = true;
        for (auto &o : outs[i]) {
            Buf b;
            if (!Classify(o.data, o.size, keys[i], &b)) {
                ok = false;
                break;
            }
            if (b.size) bufs[i].push_back(b);
        }
        if (!ok) {
            results[i] = Err(ErrorCode::INVALID_PARAMS);
            continue;
        }
        sealed_sizes[i] = sealed;
        pending[i] = true;
        // A replica in this process's own segment is opened where it lies:
        // the segment is NIC-registered ciphertext memory, as staging is, so
        // copying it to staging first (the inner client's single memcpy
        // thread) would only add a pass. Opening verifies every segment as
        // before; the lease is checked after.
        if (client_)
            for (const auto &rep : replicas) {
                if (!rep.is_memory_replica() || !client_->CanUseLocalMemcpy(rep))
                    continue;
                const auto &bd = rep.get_memory_descriptor().buffer_descriptor;
                void *p = reinterpret_cast<void *>(bd.buffer_address_);
                if (bd.size_ == sealed && p && DeviceOf(p) < 0)
                    local_src[i] = p;
                break;
            }
    }

    // Local replicas, all opened at once.
    {
        std::vector<ObjectCrypto::OpenJob> jobs;
        std::vector<size_t> opened;
        for (size_t k = 0; k < keys.size(); ++k) {
            if (!pending[k] || !local_src[k]) continue;
            pending[k] = false;
            ObjectCrypto::OpenJob job;
            if (!ParseObject({local_src[k], sealed_sizes[k]}, sealed_sizes[k],
                             &job.layout)) {
                LOG(ERROR) << "secure mode: key " << keys[k]
                           << " is not a well-formed sealed object";
                results[k] = Err(ErrorCode::CHECKSUM_MISMATCH);
                continue;
            }
            uint64_t plain = job.layout.plaintext_len;
            for (auto &b : bufs[k]) {
                if (plain == 0) break;
                const size_t n =
                    static_cast<size_t>(std::min<uint64_t>(plain, b.size));
                job.out.push_back({b.data, n, b.device});
                plain -= n;
            }
            if (plain != 0) {
                LOG(ERROR) << "secure mode: buffer too small for key "
                           << keys[k]
                           << ": required=" << job.layout.plaintext_len;
                results[k] = Err(ErrorCode::INVALID_PARAMS);
                continue;
            }
            job.key = &keys[k];
            job.sealed = {local_src[k], sealed_sizes[k]};
            jobs.push_back(std::move(job));
            opened.push_back(k);
        }
        if (!jobs.empty()) crypto_->Open(jobs, &timing);
        const auto now = std::chrono::steady_clock::now();
        for (size_t j = 0; j < jobs.size(); ++j) {
            const size_t k = opened[j];
            if (jobs[j].result != Error::kOk) {
                results[k] = ErrOf(jobs[j].result);
            } else if (now >= queries[k]->lease_timeout) {
                // As the inner client: the replica may have been evicted
                // while it was read.
                for (auto &b : jobs[j].out)
                    if (b.device < 0 && b.size) std::memset(b.data, 0, b.size);
                results[k] = Err(ErrorCode::LEASE_EXPIRED);
            } else {
                results[k] = static_cast<int64_t>(jobs[j].layout.plaintext_len);
            }
        }
    }

    size_t i = 0;
    while (i < keys.size()) {
        std::vector<StagingBuffer> held;
        std::vector<std::string> batch_keys;
        std::vector<void *> ptrs;
        std::vector<size_t> sizes;
        std::vector<size_t> index;
        for (; i < keys.size(); ++i) {
            if (!pending[i]) continue;
            StagingBuffer buf = pool_->Allocate(sealed_sizes[i]);
            if (!buf) {
                if (!held.empty()) break;
                results[i] = Err(ErrorCode::NO_AVAILABLE_HANDLE);
                continue;
            }
            batch_keys.push_back(keys[i]);
            ptrs.push_back(buf.data());
            sizes.push_back(sealed_sizes[i]);
            index.push_back(i);
            held.push_back(std::move(buf));
        }
        if (batch_keys.empty()) continue;
        const auto t0 = Clock::now();
        auto r = inner_->batch_get_into(batch_keys, ptrs, sizes);
        transfer_ns += NsSince(t0);
        std::vector<ObjectCrypto::OpenJob> jobs;
        std::vector<size_t> opened;
        for (size_t j = 0; j < index.size(); ++j) {
            const size_t k = index[j];
            const int64_t got = j < r.size() ? r[j] : -1;
            if (got < 0) {
                results[k] = got;
                continue;
            }
            ObjectCrypto::OpenJob job;
            // The header is copied out once; nothing below re-reads it from
            // staging.
            if (static_cast<uint64_t>(got) != sealed_sizes[k] ||
                !ParseObject({held[j].data(), sealed_sizes[k]},
                             sealed_sizes[k], &job.layout)) {
                // Not a sealed object, or it changed size between query and
                // read.
                LOG(ERROR) << "secure mode: key " << keys[k]
                           << " is not a well-formed sealed object";
                results[k] = Err(ErrorCode::CHECKSUM_MISMATCH);
                continue;
            }
            // Open into exactly the plaintext's length of the caller's
            // buffers.
            uint64_t plain = job.layout.plaintext_len;
            for (auto &b : bufs[k]) {
                if (plain == 0) break;
                const size_t n = static_cast<size_t>(
                    std::min<uint64_t>(plain, b.size));
                job.out.push_back({b.data, n, b.device});
                plain -= n;
            }
            if (plain != 0) {
                LOG(ERROR) << "secure mode: buffer too small for key "
                           << keys[k]
                           << ": required=" << job.layout.plaintext_len;
                results[k] = Err(ErrorCode::INVALID_PARAMS);
                continue;
            }
            job.key = &keys[k];
            job.sealed = {held[j].data(), sealed_sizes[k]};
            jobs.push_back(std::move(job));
            opened.push_back(k);
        }
        crypto_->Open(jobs, &timing);
        for (size_t j = 0; j < jobs.size(); ++j) {
            results[opened[j]] =
                jobs[j].result == Error::kOk
                    ? static_cast<int64_t>(jobs[j].layout.plaintext_len)
                    : ErrOf(jobs[j].result);
        }
    }
    const uint64_t total = NsSince(t_call);
    uint64_t bytes = 0;
    for (int64_t r : results)
        if (r > 0) bytes += static_cast<uint64_t>(r);
    stages_.Record(static_cast<size_t>(StoreStage::kGet), total);
    stages_.Record(static_cast<size_t>(StoreStage::kGetTransfer), transfer_ns);
    VLOG(1) << "secure store get: " << keys.size() << " keys, " << bytes
            << " B in " << Ms(total) << " ms; transfer " << Ms(transfer_ns)
            << ", open sum/max " << Ms(timing.open_ns.load()) << "/"
            << Ms(timing.open_max_ns.load()) << ", h2d "
            << Ms(timing.h2d_ns.load()) << " ms (node " << home_node_.load()
            << ")";
    MaybeLogStats();
    return results;
}

int64_t SecurePyClient::get_into(const std::string &key, void *buffer,
                                 size_t size) {
    return GetMany({key}, {{MutableSpan{buffer, size}}})[0];
}

std::vector<int64_t> SecurePyClient::batch_get_into(
    const std::vector<std::string> &keys, const std::vector<void *> &buffers,
    const std::vector<size_t> &sizes) {
    std::vector<Outs> outs;
    if (buffers.size() == sizes.size()) {
        for (size_t i = 0; i < buffers.size(); ++i)
            outs.push_back({MutableSpan{buffers[i], sizes[i]}});
    }
    return GetMany(keys, outs);
}

std::vector<int> SecurePyClient::batch_get_into_multi_buffers(
    const std::vector<std::string> &keys,
    const std::vector<std::vector<void *>> &all_buffers,
    const std::vector<std::vector<size_t>> &all_sizes, bool) {
    std::vector<Outs> outs;
    if (all_buffers.size() == all_sizes.size()) {
        for (size_t i = 0; i < all_buffers.size(); ++i) {
            if (all_buffers[i].size() != all_sizes[i].size()) {
                outs.clear();
                break;
            }
            Outs o;
            for (size_t j = 0; j < all_buffers[i].size(); ++j)
                o.push_back({all_buffers[i][j], all_sizes[i][j]});
            outs.push_back(std::move(o));
        }
    }
    auto r = GetMany(keys, outs);
    return std::vector<int>(r.begin(), r.end());
}

int64_t SecurePyClient::getSize(const std::string &key) {
    if (int rc = EnsureReady()) return rc;
    int64_t s = inner_->getSize(key);
    if (s < 0) return s;
    if (static_cast<uint64_t>(s) < kOverhead)
        return Err(ErrorCode::CHECKSUM_MISMATCH);
    // The plaintext size is in the object's header: read just that. It is
    // not authenticated here (a get authenticates it).
    const size_t n = std::min<size_t>(static_cast<size_t>(s), kHeaderSize);
    StagingBuffer buf = pool_->Allocate(n);
    if (!buf) return Err(ErrorCode::NO_AVAILABLE_HANDLE);
    auto r = inner_->get_into_ranges({buf.data()}, {{key}}, {{{0}}}, {{{0}}},
                                     {{{n}}}, nullptr);
    if (r.size() != 1 || r[0].size() != 1 || r[0][0].size() != 1)
        return Err(ErrorCode::INTERNAL_ERROR);
    if (r[0][0][0] < 0) return r[0][0][0];
    ObjectLayout layout;
    if (static_cast<size_t>(r[0][0][0]) != n ||
        !ParseObject({buf.data(), n}, static_cast<size_t>(s), &layout))
        return Err(ErrorCode::CHECKSUM_MISMATCH);
    return static_cast<int64_t>(layout.plaintext_len);
}

// --------------------------------------------------------------- refused --

std::vector<std::vector<std::vector<int64_t>>> SecurePyClient::get_into_ranges(
    const std::vector<void *> &,
    const std::vector<std::vector<std::string>> &all_keys,
    const std::vector<std::vector<std::vector<size_t>>> &,
    const std::vector<std::vector<std::vector<size_t>>> &,
    const std::vector<std::vector<std::vector<size_t>>> &all_sizes,
    const QueryResultCache *) {
    const int64_t e = Refuse("ranged reads (get_into_ranges)");
    std::vector<std::vector<std::vector<int64_t>>> out(all_keys.size());
    for (size_t b = 0; b < all_keys.size(); ++b) {
        out[b].resize(all_keys[b].size());
        for (size_t k = 0; k < all_keys[b].size(); ++k)
            out[b][k].assign(b < all_sizes.size() && k < all_sizes[b].size()
                                 ? std::max<size_t>(all_sizes[b][k].size(), 1)
                                 : 1,
                             e);
    }
    return out;
}

std::vector<std::vector<std::vector<int64_t>>>
SecurePyClient::get_into_ranges_from_snapshot(
    const std::vector<void *> &buffers,
    const std::vector<std::vector<std::string>> &all_keys,
    const std::vector<std::vector<std::vector<size_t>>> &all_dst_offsets,
    const std::vector<std::vector<std::vector<size_t>>> &all_src_offsets,
    const std::vector<std::vector<std::vector<size_t>>> &all_sizes,
    const QueryResultCache &) {
    return get_into_ranges(buffers, all_keys, all_dst_offsets, all_src_offsets,
                           all_sizes, nullptr);
}

std::shared_ptr<BufferHandle> SecurePyClient::get_buffer(const std::string &) {
    Refuse("get_buffer");
    return nullptr;
}

std::vector<std::shared_ptr<BufferHandle>> SecurePyClient::batch_get_buffer(
    const std::vector<std::string> &keys) {
    Refuse("batch_get_buffer");
    return std::vector<std::shared_ptr<BufferHandle>>(keys.size());
}

std::optional<BufferHandle> SecurePyClient::allocate_client_buffer(size_t) {
    return std::nullopt;
}

int SecurePyClient::register_buffer(void *buffer, size_t) {
    // Caller buffers are only read and written by the CPU here; nothing of
    // theirs is ever registered with the transfer engine. The first one (the
    // KV cache) tells where this client's work belongs: staging, scratch and
    // crypto threads follow it; the segment, registered at setup, stays.
    std::lock_guard<std::mutex> lock(setup_mu_);
    if (opt_.numa_node != StoreCryptoOptions::kNumaAuto || home_from_buffer_ ||
        !pool_ || !crypto_ || !buffer)
        return 0;
    const int node = HomeNumaNode(buffer);
    if (node < 0) return 0;
    home_from_buffer_ = true;
    if (node == home_node_.load()) return 0;
    LOG(INFO) << "secure mode: store client home NUMA node " << node
              << " (from the registered buffer; was " << home_node_.load()
              << ", where its segment stays)";
    home_node_.store(node);
    pool_->set_numa_node(node, NumaNodeCpus(node));
    crypto_->SetHome(node);
    return 0;
}

int SecurePyClient::unregister_buffer(void *) { return 0; }

// -------------------------------------------------------------- forwarded --

std::vector<tl::expected<QueryResult, ErrorCode>> SecurePyClient::batch_query(
    const std::vector<std::string> &keys) {
    return inner_->batch_query(keys);
}
std::string SecurePyClient::get_hostname() const {
    return inner_->get_hostname();
}
int SecurePyClient::remove(const std::string &key, bool force) {
    return inner_->remove(key, force);
}
long SecurePyClient::removeByRegex(const std::string &str, bool force) {
    return inner_->removeByRegex(str, force);
}
long SecurePyClient::removeAll(bool force) { return inner_->removeAll(force); }
std::vector<int> SecurePyClient::batchRemove(
    const std::vector<std::string> &keys, bool force) {
    return inner_->batchRemove(keys, force);
}
int SecurePyClient::isExist(const std::string &key) {
    return inner_->isExist(key);
}
std::vector<int> SecurePyClient::batchIsExist(
    const std::vector<std::string> &keys) {
    return inner_->batchIsExist(keys);
}
int SecurePyClient::probeKey(const std::string &key) {
    return inner_->probeKey(key);
}
std::vector<int> SecurePyClient::batchProbeKey(
    const std::vector<std::string> &keys, const GrantLeasePolicy &policy) {
    return inner_->batchProbeKey(keys, policy);
}
std::map<std::string, std::vector<Replica::Descriptor>>
SecurePyClient::batch_get_replica_desc(const std::vector<std::string> &keys) {
    return inner_->batch_get_replica_desc(keys);
}
std::vector<Replica::Descriptor> SecurePyClient::get_replica_desc(
    const std::string &key) {
    return inner_->get_replica_desc(key);
}
std::vector<std::string> SecurePyClient::batch_replica_clear(
    const std::vector<std::string> &keys, const std::string &segment_name) {
    return inner_->batch_replica_clear(keys, segment_name);
}
int SecurePyClient::tearDownAll() {
    crypto_.reset();
    pool_.reset();
    return inner_->tearDownAll();
}
int SecurePyClient::health_check() { return inner_->health_check(); }
tl::expected<UUID, ErrorCode> SecurePyClient::create_copy_task(
    const std::string &key, const std::vector<std::string> &targets) {
    return inner_->create_copy_task(key, targets);
}
tl::expected<UUID, ErrorCode> SecurePyClient::create_move_task(
    const std::string &key, const std::string &source,
    const std::string &target) {
    return inner_->create_move_task(key, source, target);
}
tl::expected<QueryTaskResponse, ErrorCode> SecurePyClient::query_task(
    const UUID &task_id) {
    return inner_->query_task(task_id);
}

}  // namespace secure
}  // namespace mooncake
