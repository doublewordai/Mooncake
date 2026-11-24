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

#include "error.h"
#include "secure/kv_crypto.h"

namespace mooncake {
namespace secure {

namespace {
thread_local int g_ciphertext_scope_depth = 0;
}

CiphertextRegistrationScope::CiphertextRegistrationScope() {
    ++g_ciphertext_scope_depth;
}
CiphertextRegistrationScope::~CiphertextRegistrationScope() {
    --g_ciphertext_scope_depth;
}
bool CiphertextRegistrationScope::Active() {
    return g_ciphertext_scope_depth > 0;
}

SecureTransport::SecureTransport(Transport* inner) : inner_(inner) {}

SecureTransport::~SecureTransport() = default;

int SecureTransport::install(std::string& local_server_name,
                             std::shared_ptr<TransferMetadata> meta,
                             std::shared_ptr<Topology> topo) {
    int rc = Transport::install(local_server_name, meta, topo);
    if (rc) return rc;
    return inner_->install(local_server_name, meta, topo);
}

const char* SecureTransport::getName() const { return inner_->getName(); }

bool SecureTransport::IsCiphertextMemory(const void* addr,
                                         size_t length) const {
    const auto a = reinterpret_cast<uintptr_t>(addr);
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = regions_.upper_bound(a);
    if (it == regions_.begin()) return false;
    --it;
    if (!it->second.nic) return false;
    const uintptr_t end = it->first + it->second.length;
    return a >= it->first && length <= end - a;
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

Status SecureTransport::submitTransferTask(
    const std::vector<TransferTask*>& task_list) {
    for (auto* task : task_list) {
        auto s = CheckRequests(task->request, task->request_count);
        if (!s.ok()) return s;
    }
    return inner_->submitTransferTask(task_list);
}

Status SecureTransport::submitTransferTaskGroup(
    const std::vector<TransferTask*>& task_list) {
    for (auto* task : task_list) {
        auto s = CheckRequests(task->request, task->request_count);
        if (!s.ok()) return s;
    }
    return inner_->submitTransferTaskGroup(task_list);
}

bool SecureTransport::supportsGroupedScatter() const {
    return inner_->supportsGroupedScatter();
}

bool SecureTransport::supportsBatchCompletionCounter() const {
    return inner_->supportsBatchCompletionCounter();
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
        int rc = inner_->registerLocalMemory(addr, length, location,
                                             remote_accessible,
                                             update_metadata);
        if (rc) return rc;
    } else {
        VLOG(1) << "secure mode: " << addr << "+" << length
                << " registered for local use only (not with the NIC)";
    }
    std::unique_lock<std::shared_mutex> lock(mu_);
    regions_[reinterpret_cast<uintptr_t>(addr)] = Region{length, nic};
    return 0;
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
        int rc = inner_->registerLocalMemoryBatch(buffer_list, location);
        if (rc) return rc;
    }
    std::unique_lock<std::shared_mutex> lock(mu_);
    for (const auto& b : buffer_list)
        regions_[reinterpret_cast<uintptr_t>(b.addr)] = Region{b.length, nic};
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
