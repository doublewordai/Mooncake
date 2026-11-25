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

// SecurePyClient: a decorator around the store's RealClient used when secure
// mode is on (WITH_SECURE_KV build, MC_SECURE_MODE=1). Built only with
// WITH_SECURE_KV.
//
//  * Put: the value, from host or GPU memory, is sealed into engine staging
//    as a sealed object (secure/sealed_object.h: independently authenticated
//    segments, sealed in parallel; GPU memory reaches the CPU through pinned
//    host memory on the copy engine), and the sealed bytes are what the inner
//    client stores, on whatever path it picks (local memcpy, RDMA, disk).
//    Sizes sent to the master are the sealed sizes.
//  * Get: the sealed object is fetched into staging and every segment is
//    verified before the caller sees any of it; a failure is a per-key
//    CHECKSUM_MISMATCH that leaves a host buffer zeroed and GPU memory
//    untouched.
//  * Everything else that moves object bytes (ranged reads and writes,
//    sessions, get_buffer, put_from_with_metadata, dummy/shm modes, offload)
//    is refused with INVALID_PARAMS: it cannot be authenticated as a whole
//    object, so it fails closed. Metadata calls (exists, remove, replica
//    queries, tasks) are forwarded.
//
// The inner client is set up inside a CiphertextRegistrationScope, so its
// segments, hot cache and local buffer are registered with the NIC: they only
// ever receive sealed bytes because no plaintext reaches the inner client.
// Caller buffers are never registered with the NIC.

#pragma once

#include <functional>
#include <memory>
#include <mutex>

#include "pyclient.h"
#include "secure/kv_crypto.h"
#include "secure/sealed_object.h"
#include "secure/staging_pool.h"

namespace mooncake {
namespace secure {

class SecurePyClient final : public PyClient {
   public:
    // Decorates `inner` (a RealClient that has not been set up yet).
    explicit SecurePyClient(std::shared_ptr<PyClient> inner);
    ~SecurePyClient() override;

    // Secure mode is on for this process (the construction-time switch).
    static bool Enabled();

    // Runs the inner client's setup (`setup`, returning 0 on success) inside a
    // CiphertextRegistrationScope, then readies staging. Refuses a
    // caller-supplied transfer engine (it may hold plaintext registrations),
    // SSD offload and the TENT engine.
    int SetupInner(const std::function<int()> &setup,
                   bool external_engine = false, bool ssd_offload = false);

    int setup_real(const std::string &local_hostname,
                   const std::string &metadata_server,
                   size_t global_segment_size, size_t local_buffer_size,
                   const std::string &protocol,
                   const std::string &rdma_devices,
                   const std::string &master_server_addr,
                   const std::shared_ptr<TransferEngine> &transfer_engine,
                   const std::string &ipc_socket_path, bool enable_ssd_offload,
                   const std::string &ssd_offload_path,
                   const std::string &tenant_id, bool enable_client_http_server,
                   int client_http_port) override;
    int setup_dummy(size_t, size_t, const std::string &,
                    const std::string &) override;
    int initAll(const std::string &protocol, const std::string &device_name,
                size_t mount_segment_size) override;
    uint64_t alloc_from_mem_pool(size_t) override;

    int put(const std::string &key, std::span<const char> value,
            const ReplicateConfig &config) override;
    int register_buffer(void *buffer, size_t size) override;
    int unregister_buffer(void *buffer) override;
    int64_t get_into(const std::string &key, void *buffer,
                     size_t size) override;
    std::vector<std::vector<std::vector<int64_t>>> get_into_ranges(
        const std::vector<void *> &buffers,
        const std::vector<std::vector<std::string>> &all_keys,
        const std::vector<std::vector<std::vector<size_t>>> &all_dst_offsets,
        const std::vector<std::vector<std::vector<size_t>>> &all_src_offsets,
        const std::vector<std::vector<std::vector<size_t>>> &all_sizes,
        const QueryResultCache *query_result_cache) override;
    std::vector<std::vector<std::vector<int64_t>>>
    get_into_ranges_from_snapshot(
        const std::vector<void *> &buffers,
        const std::vector<std::vector<std::string>> &all_keys,
        const std::vector<std::vector<std::vector<size_t>>> &all_dst_offsets,
        const std::vector<std::vector<std::vector<size_t>>> &all_src_offsets,
        const std::vector<std::vector<std::vector<size_t>>> &all_sizes,
        const QueryResultCache &query_result_cache) override;
    using PyClient::get_into_ranges_from_snapshot;
    std::vector<tl::expected<QueryResult, ErrorCode>> batch_query(
        const std::vector<std::string> &keys) override;
    std::vector<int64_t> batch_get_into(
        const std::vector<std::string> &keys,
        const std::vector<void *> &buffers,
        const std::vector<size_t> &sizes) override;
    std::vector<int> batch_get_into_multi_buffers(
        const std::vector<std::string> &keys,
        const std::vector<std::vector<void *>> &all_buffers,
        const std::vector<std::vector<size_t>> &all_sizes,
        bool prefer_same_node) override;
    int put_from(const std::string &key, void *buffer, size_t size,
                 const ReplicateConfig &config) override;
    int put_from_with_metadata(const std::string &key, void *buffer,
                               void *metadata_buffer, size_t size,
                               size_t metadata_size,
                               const ReplicateConfig &config) override;
    std::vector<int> batch_put_from(const std::vector<std::string> &keys,
                                    const std::vector<void *> &buffers,
                                    const std::vector<size_t> &sizes,
                                    const ReplicateConfig &config) override;
    std::vector<int> batch_put_from_multi_buffers(
        const std::vector<std::string> &keys,
        const std::vector<std::vector<void *>> &all_buffers,
        const std::vector<std::vector<size_t>> &all_sizes,
        const ReplicateConfig &config) override;
    std::shared_ptr<BufferHandle> get_buffer(const std::string &key) override;
    std::vector<std::shared_ptr<BufferHandle>> batch_get_buffer(
        const std::vector<std::string> &keys) override;
    int put_parts(const std::string &key,
                  std::vector<std::span<const char>> values,
                  const ReplicateConfig &config) override;
    int put_batch(const std::vector<std::string> &keys,
                  const std::vector<std::span<const char>> &values,
                  const ReplicateConfig &config) override;
    int upsert(const std::string &key, std::span<const char> value,
               const ReplicateConfig &config) override;
    int upsert_from(const std::string &key, void *buffer, size_t size,
                    const ReplicateConfig &config) override;
    std::vector<int> batch_upsert_from(const std::vector<std::string> &keys,
                                       const std::vector<void *> &buffers,
                                       const std::vector<size_t> &sizes,
                                       const ReplicateConfig &config) override;
    std::vector<int> batch_upsert_from_multi_buffers(
        const std::vector<std::string> &keys,
        const std::vector<std::vector<void *>> &all_buffers,
        const std::vector<std::vector<size_t>> &all_sizes,
        const ReplicateConfig &config) override;
    int upsert_parts(const std::string &key,
                     std::vector<std::span<const char>> values,
                     const ReplicateConfig &config) override;
    int upsert_batch(const std::vector<std::string> &keys,
                     const std::vector<std::span<const char>> &values,
                     const ReplicateConfig &config) override;
    std::string get_hostname() const override;
    int remove(const std::string &key, bool force) override;
    long removeByRegex(const std::string &str, bool force) override;
    long removeAll(bool force) override;
    std::vector<int> batchRemove(const std::vector<std::string> &keys,
                                 bool force) override;
    int isExist(const std::string &key) override;
    std::vector<int> batchIsExist(
        const std::vector<std::string> &keys) override;
    int probeKey(const std::string &key) override;
    std::vector<int> batchProbeKey(const std::vector<std::string> &keys,
                                   const GrantLeasePolicy &policy) override;
    int64_t getSize(const std::string &key) override;
    std::map<std::string, std::vector<Replica::Descriptor>>
    batch_get_replica_desc(const std::vector<std::string> &keys) override;
    std::vector<Replica::Descriptor> get_replica_desc(
        const std::string &key) override;
    std::vector<std::string> batch_replica_clear(
        const std::vector<std::string> &keys,
        const std::string &segment_name) override;
    int tearDownAll() override;
    int health_check() override;
    tl::expected<UUID, ErrorCode> create_copy_task(
        const std::string &key,
        const std::vector<std::string> &targets) override;
    tl::expected<UUID, ErrorCode> create_move_task(
        const std::string &key, const std::string &source,
        const std::string &target) override;
    tl::expected<QueryTaskResponse, ErrorCode> query_task(
        const UUID &task_id) override;
    std::optional<BufferHandle> allocate_client_buffer(size_t size) override;

    // For tests and diagnostics.
    StagingPool *staging() const { return pool_.get(); }
    ObjectCrypto *crypto() const { return crypto_.get(); }

   private:
    using Parts = std::vector<ConstSpan>;
    using Outs = std::vector<MutableSpan>;

    // Where the caller's [p, p+n) lives: false (and an error logged) if it
    // cannot be sealed from or opened into (null, or device memory that is
    // not CUDA).
    bool Classify(const void *p, size_t n, const std::string &key,
                  Buf *out) const;

    int EnsureReady();
    std::vector<int> PutMany(const std::vector<std::string> &keys,
                             const std::vector<Parts> &values,
                             const ReplicateConfig &config, bool upsert);
    std::vector<int64_t> GetMany(const std::vector<std::string> &keys,
                                 const std::vector<Outs> &outs);

    std::shared_ptr<PyClient> inner_;
    std::unique_ptr<StagingPool> pool_;
    std::unique_ptr<ObjectCrypto> crypto_;
    std::mutex setup_mu_;
};

}  // namespace secure
}  // namespace mooncake
