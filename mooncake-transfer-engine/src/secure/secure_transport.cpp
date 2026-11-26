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

#include "secure/secure_transport.h"

#include <glog/logging.h>

#include <chrono>
#include <set>
#include <thread>

#include "error.h"
#include "memory_location.h"
#include "secure/device_copy.h"
#include "secure/staging_pool.h"
#include "secure/kv_crypto.h"

namespace mooncake {
namespace secure {

namespace {
thread_local int g_ciphertext_scope_depth = 0;
thread_local int g_ciphertext_home_node = -1;

// Where ciphertext memory registered at `location` should go: "cpu:<home>"
// for host memory registered without a location inside a scope with a home
// node (moved there first), else `location` unchanged.
std::string HomeLocation(void* addr, size_t length,
                         const std::string& location) {
    const int node = CiphertextRegistrationScope::HomeNode();
    if (node < 0 || location != kWildcardLocation || DeviceOf(addr) >= 0)
        return location;
    PlacePagesOnNode(addr, length, node);
    return "cpu:" + std::to_string(node);
}
}  // namespace

CiphertextRegistrationScope::CiphertextRegistrationScope(int home_node)
    : saved_node_(g_ciphertext_home_node) {
    ++g_ciphertext_scope_depth;
    if (home_node >= 0) g_ciphertext_home_node = home_node;
}
CiphertextRegistrationScope::~CiphertextRegistrationScope() {
    --g_ciphertext_scope_depth;
    g_ciphertext_home_node = saved_node_;
}
bool CiphertextRegistrationScope::Active() {
    return g_ciphertext_scope_depth > 0;
}
int CiphertextRegistrationScope::HomeNode() {
    return g_ciphertext_scope_depth > 0 ? g_ciphertext_home_node : -1;
}

SecureTransport::SecureTransport(Transport* inner) : inner_(inner) {}

SecureTransport::~SecureTransport() = default;

int SecureTransport::install(std::string& local_server_name,
                             std::shared_ptr<TransferMetadata> meta,
                             std::shared_ptr<Topology> topo) {
    int rc = Transport::install(local_server_name, meta, topo);
    if (rc) return rc;
    rc = inner_->install(local_server_name, meta, topo);
    if (rc) return rc;
    PushFabric f;
    f.register_ciphertext = [this](void* p, size_t n, int node) {
        // Registered as the node's memory, so on that node's NIC (the one
        // the engine uses for the GPU on that node).
        CiphertextRegistrationScope scope(node);
        return registerLocalMemory(p, n, kWildcardLocation, true, true);
    };
    f.unregister = [this](void* p) { return unregisterLocalMemory(p, true); };
    f.is_local_only = [this](const void* p, size_t n) {
        return IsLocalOnlyMemory(p, n);
    };
    f.begin_ops = [this](const std::vector<TransferRequest>& reqs) {
        return BeginInnerOps(reqs);
    };
    f.wait_ops = [this](void* h, int timeout_ms) {
        return WaitInnerOps(h, timeout_ms);
    };
    f.segment_desc = [this](SegmentID id, bool force) {
        return metadata_->getSegmentDescByID(id, force);
    };
    f.local_name = local_server_name;
    push_ = std::make_unique<SecurePushService>(std::move(f),
                                                PushOptions::FromEnv());
    return 0;
}

const char* SecureTransport::getName() const { return inner_->getName(); }

bool SecureTransport::InRegion(const void* addr, size_t length,
                               bool nic) const {
    const auto a = reinterpret_cast<uintptr_t>(addr);
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = regions_.upper_bound(a);
    if (it == regions_.begin()) return false;
    --it;
    if (it->second.nic != nic) return false;
    const uintptr_t end = it->first + it->second.length;
    return a >= it->first && a < end && length <= end - a;
}

bool SecureTransport::IsCiphertextMemory(const void* addr,
                                         size_t length) const {
    return InRegion(addr, length, true);
}

bool SecureTransport::IsLocalOnlyMemory(const void* addr,
                                        size_t length) const {
    return InRegion(addr, length, false);
}

Status SecureTransport::CheckRequests(const TransferRequest* requests,
                                      size_t count) const {
    for (size_t i = 0; i < count; ++i) {
        const auto& r = requests[i];
        if (!IsCiphertextMemory(r.source, r.length)) {
            LOG(ERROR) << "secure mode: refusing a transfer whose local "
                          "buffer is not engine staging or store segment "
                          "memory (addr="
                       << r.source << " len=" << r.length << ")";
            return Status::InvalidArgument(
                "secure mode: local buffer is not ciphertext memory");
        }
    }
    return Status::OK();
}

Status SecureTransport::submitTransfer(
    BatchID batch_id, const std::vector<TransferRequest>& entries) {
    auto s = CheckRequests(entries.data(), entries.size());
    if (!s.ok()) return s;
    return inner_->submitTransfer(batch_id, entries);
}

Status SecureTransport::SubmitTasks(
    const std::vector<TransferTask*>& task_list, bool group) {
    // Classify first, so a refused batch starts nothing.
    std::vector<TransferTask*> forward, push;
    for (auto* task : task_list) {
        bool cipher = true, pushable = true;
        for (size_t i = 0; i < task->request_count; ++i) {
            const auto& r = task->request[i];
            const bool c = IsCiphertextMemory(r.source, r.length);
            cipher = cipher && c;
            pushable = pushable && !c && r.opcode == TransferRequest::WRITE &&
                       r.target_id == task->request[0].target_id &&
                       IsLocalOnlyMemory(r.source, r.length);
        }
        if (cipher) {
            forward.push_back(task);
        } else if (pushable && push_) {
            push.push_back(task);
        } else {
            const auto& r = task->request[0];
            LOG(ERROR) << "secure mode: refusing a transfer whose local "
                          "buffer is neither ciphertext memory nor a WRITE "
                          "from registered local-only memory (addr="
                       << r.source << " len=" << r.length << " op="
                       << (r.opcode == TransferRequest::WRITE ? "write"
                                                              : "read")
                       << ")";
            return Status::InvalidArgument(
                "secure mode: transfer refused (local buffer is not "
                "ciphertext memory, and not a write from registered memory)");
        }
    }
    Status s = Status::OK();
    if (!push.empty()) s = StartPush(push);
    if (!s.ok() || forward.empty()) return s;
    return group ? inner_->submitTransferTaskGroup(forward)
                 : inner_->submitTransferTask(forward);
}

Status SecureTransport::StartPush(const std::vector<TransferTask*>& tasks) {
    std::map<SegmentID, std::vector<TransferTask*>> by_target;
    for (auto* t : tasks) by_target[t->request[0].target_id].push_back(t);
    Status overall = Status::OK();
    for (auto& [target, group] : by_target) {
        std::vector<PushPiece> pieces;
        std::set<BatchDesc*> batches;
        for (auto* t : group) {
            t->total_bytes = 0;
            for (size_t i = 0; i < t->request_count; ++i) {
                const auto& r = t->request[i];
                pieces.push_back({r.source, r.target_offset, r.length});
                t->total_bytes += r.length;
            }
            // The task completes when the push does; its status is read
            // through push_status_ (MultiTransport polls task.transport_).
            t->transport_ = &push_status_;
            __atomic_store_n(&t->success_slice_count, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&t->failed_slice_count, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&t->transferred_bytes, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&t->slice_count, 1, __ATOMIC_RELEASE);
            batches.insert(&toBatchDesc(t->batch_id));
        }
        // Pin the batches: freeBatchID defers while a pin is held, so the
        // tasks stay valid until the push has published its result.
        for (auto* b : batches)
            b->active_completion_callbacks.fetch_add(1,
                                                     std::memory_order_acq_rel);
        auto done = [group, batches](bool ok) {
            for (auto* t : group) {
                if (ok) {
                    __atomic_store_n(&t->transferred_bytes, t->total_bytes,
                                     __ATOMIC_RELAXED);
                    __atomic_fetch_add(&t->success_slice_count, 1,
                                       __ATOMIC_ACQ_REL);
                } else {
                    __atomic_fetch_add(&t->failed_slice_count, 1,
                                       __ATOMIC_ACQ_REL);
                }
            }
            for (auto* b : batches)
                b->active_completion_callbacks.fetch_sub(
                    1, std::memory_order_acq_rel);
        };
        if (!push_->PushAsync(target, std::move(pieces), done)) {
            done(false);
            overall = Status::Context("secure push could not start");
        }
    }
    return overall;
}

Status SecureTransport::submitTransferTask(
    const std::vector<TransferTask*>& task_list) {
    return SubmitTasks(task_list, false);
}

Status SecureTransport::submitTransferTaskGroup(
    const std::vector<TransferTask*>& task_list) {
    return SubmitTasks(task_list, true);
}

bool SecureTransport::supportsGroupedScatter() const {
    return inner_->supportsGroupedScatter();
}

// Push tasks complete outside the inner transport's completion counters, so
// batches through this decorator are always polled.
bool SecureTransport::supportsBatchCompletionCounter() const { return false; }

Status SecureTransport::PushTaskStatus::submitTransfer(
    BatchID, const std::vector<TransferRequest>&) {
    return Status::NotImplemented("secure push tasks are not submitted here");
}

Status SecureTransport::PushTaskStatus::getTransferStatus(
    BatchID batch_id, size_t task_id, TransferStatus& status) {
    auto& batch_desc = toBatchDesc(batch_id);
    if (task_id >= batch_desc.task_list.size())
        return Status::InvalidArgument("secure push: task id out of range");
    auto& task = batch_desc.task_list[task_id];
    const uint64_t ok =
        __atomic_load_n(&task.success_slice_count, __ATOMIC_ACQUIRE);
    const uint64_t failed =
        __atomic_load_n(&task.failed_slice_count, __ATOMIC_ACQUIRE);
    status.transferred_bytes =
        __atomic_load_n(&task.transferred_bytes, __ATOMIC_RELAXED);
    if (ok + failed == task.slice_count) {
        status.s = failed ? TransferStatusEnum::FAILED
                          : TransferStatusEnum::COMPLETED;
        task.is_finished = true;
    } else {
        status.s = TransferStatusEnum::WAITING;
    }
    return Status::OK();
}

namespace {
struct InnerOps {
    std::vector<Transport::TransferRequest> reqs;
    Transport::BatchDesc* desc = nullptr;
    Status submit = Status::OK();
};
}  // namespace

void* SecureTransport::BeginInnerOps(const std::vector<TransferRequest>& reqs) {
    auto* h = new InnerOps;
    h->reqs = reqs;
    for (const auto& r : h->reqs) {
        if (!IsCiphertextMemory(r.source, r.length)) {
            h->submit = Status::InvalidArgument(
                "secure push: staging op outside ciphertext memory");
            return h;
        }
    }
    auto* d = new BatchDesc();
    d->id = reinterpret_cast<BatchID>(d);
    d->batch_size = h->reqs.size();
    d->context = nullptr;
    d->task_list.resize(h->reqs.size());
    std::vector<TransferTask*> ptrs;
    for (size_t i = 0; i < h->reqs.size(); ++i) {
        auto& t = d->task_list[i];
        t.batch_id = d->id;
        t.transport_ = inner_.get();
        t.request = &h->reqs[i];
        t.request_count = 1;
        ptrs.push_back(&t);
    }
    h->desc = d;
    h->submit = inner_->submitTransferTask(ptrs);
    return h;
}

Status SecureTransport::WaitInnerOps(void* handle, int timeout_ms) {
    std::unique_ptr<InnerOps> h(static_cast<InnerOps*>(handle));
    if (!h->desc) return h->submit;
    auto* d = h->desc;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    bool failed = !h->submit.ok();
    const size_t n = d->task_list.size();
    std::vector<bool> done(n, false);
    size_t remaining = n;
    for (int spins = 0; remaining;) {
        for (size_t i = 0; i < n; ++i) {
            if (done[i]) continue;
            TransferStatus st;
            Status s = inner_->getTransferStatus(d->id, i, st);
            if (!s.ok() || st.s == TransferStatusEnum::FAILED ||
                st.s == TransferStatusEnum::TIMEOUT ||
                st.s == TransferStatusEnum::CANCELED ||
                st.s == TransferStatusEnum::INVALID) {
                failed = true;
            } else if (st.s != TransferStatusEnum::COMPLETED) {
                continue;
            }
            done[i] = true;
            --remaining;
        }
        if (!remaining) break;
        if (std::chrono::steady_clock::now() > deadline) {
            LOG(ERROR) << "secure push: fabric ops timed out after "
                       << timeout_ms << " ms; leaking their batch";
            h.release();  // in-flight slices may still reference it
            return Status::Context("secure push: fabric ops timed out");
        }
        if (++spins < 2000)
            std::this_thread::yield();
        else
            std::this_thread::sleep_for(std::chrono::microseconds(20));
    }
    while (d->active_completion_callbacks.load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() > deadline) {
            h.release();
            return Status::Context("secure push: completion still unwinding");
        }
        std::this_thread::yield();
    }
    delete d;
    return failed ? Status::Context("secure push: fabric ops failed")
                  : Status::OK();
}

Status SecureTransport::getTransferStatus(BatchID batch_id, size_t task_id,
                                          TransferStatus& status) {
    return inner_->getTransferStatus(batch_id, task_id, status);
}

Status SecureTransport::OpenChannel(const std::string& segment_name,
                                    SegmentID sid) {
    return inner_->OpenChannel(segment_name, sid);
}

Status SecureTransport::CheckStatus(SegmentID sid) {
    return inner_->CheckStatus(sid);
}

int SecureTransport::registerLocalMemory(void* addr, size_t length,
                                         const std::string& location,
                                         bool remote_accessible,
                                         bool update_metadata) {
    const bool nic = CiphertextRegistrationScope::Active();
    if (nic) {
        const std::string where = HomeLocation(addr, length, location);
        int rc = inner_->registerLocalMemory(addr, length, where,
                                             remote_accessible,
                                             update_metadata);
        // A node the engine has no NIC entry for: where the memory is.
        if (rc && where != location)
            rc = inner_->registerLocalMemory(addr, length, location,
                                             remote_accessible,
                                             update_metadata);
        if (rc) return rc;
    } else {
        VLOG(1) << "secure mode: " << addr << "+" << length
                << " registered for local use only (not with the NIC)";
    }
    {
        std::unique_lock<std::shared_mutex> lock(mu_);
        regions_[reinterpret_cast<uintptr_t>(addr)] = Region{length, nic};
    }
    if (!nic && EnableReceiver(addr) != 0) {
        std::unique_lock<std::shared_mutex> lock(mu_);
        regions_.erase(reinterpret_cast<uintptr_t>(addr));
        return -1;
    }
    return 0;
}

// Local-only memory can be a push destination, so the first registration of
// it brings up the receive side (staging, control server).
int SecureTransport::EnableReceiver(const void* near) {
    if (!push_) return 0;
    if (push_->EnableReceiver(near) == 0) return 0;
    LOG(ERROR) << "secure mode: cannot start the secure push receiver; "
                  "refusing to register local-only memory";
    return -1;
}

int SecureTransport::unregisterLocalMemory(void* addr, bool update_metadata) {
    bool nic = false;
    {
        std::unique_lock<std::shared_mutex> lock(mu_);
        auto it = regions_.find(reinterpret_cast<uintptr_t>(addr));
        if (it == regions_.end()) return ERR_ADDRESS_NOT_REGISTERED;
        nic = it->second.nic;
        regions_.erase(it);
    }
    return nic ? inner_->unregisterLocalMemory(addr, update_metadata) : 0;
}

int SecureTransport::registerLocalMemoryBatch(
    const std::vector<BufferEntry>& buffer_list, const std::string& location) {
    const bool nic = CiphertextRegistrationScope::Active();
    if (nic) {
        int rc = -1;
        if (CiphertextRegistrationScope::HomeNode() >= 0 &&
            location == kWildcardLocation) {
            // One at a time, each placed on the home node.
            size_t done = 0;
            for (; done < buffer_list.size(); ++done) {
                const auto& b = buffer_list[done];
                const std::string where = HomeLocation(b.addr, b.length, location);
                int r = inner_->registerLocalMemory(b.addr, b.length, where,
                                                    true, true);
                if (r && where != location)
                    r = inner_->registerLocalMemory(b.addr, b.length, location,
                                                    true, true);
                if (r) break;
            }
            rc = done == buffer_list.size() ? 0 : -1;
            if (rc)
                for (size_t i = 0; i < done; ++i)
                    inner_->unregisterLocalMemory(buffer_list[i].addr, true);
        } else {
            rc = inner_->registerLocalMemoryBatch(buffer_list, location);
        }
        if (rc) return rc;
    }
    {
        std::unique_lock<std::shared_mutex> lock(mu_);
        for (const auto& b : buffer_list)
            regions_[reinterpret_cast<uintptr_t>(b.addr)] =
                Region{b.length, nic};
    }
    if (!nic && !buffer_list.empty() &&
        EnableReceiver(buffer_list.front().addr) != 0) {
        std::unique_lock<std::shared_mutex> lock(mu_);
        for (const auto& b : buffer_list)
            regions_.erase(reinterpret_cast<uintptr_t>(b.addr));
        return -1;
    }
    return 0;
}

int SecureTransport::unregisterLocalMemoryBatch(
    const std::vector<void*>& addr_list) {
    std::vector<void*> nic_addrs;
    {
        std::unique_lock<std::shared_mutex> lock(mu_);
        for (void* a : addr_list) {
            auto it = regions_.find(reinterpret_cast<uintptr_t>(a));
            if (it == regions_.end()) continue;
            if (it->second.nic) nic_addrs.push_back(a);
            regions_.erase(it);
        }
    }
    return nic_addrs.empty() ? 0
                             : inner_->unregisterLocalMemoryBatch(nic_addrs);
}

Transport* MaybeWrapTransport(const std::string& proto, Transport* transport) {
    if (!transport) return nullptr;
    auto& ctx = SecureContext::Global();
    if (!ctx.enabled()) return transport;
    if (ctx.failed()) {
        LOG(ERROR) << "secure mode requested but not available ("
                   << ctx.reason() << "); refusing to install transport "
                   << proto;
        delete transport;
        return nullptr;
    }
    LOG(INFO) << "secure mode: transport " << proto
              << " registers only ciphertext memory with the NIC";
    return new SecureTransport(transport);
}

}  // namespace secure
}  // namespace mooncake
