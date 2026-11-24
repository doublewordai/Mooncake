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

// SecureTransport: a decorator around any Transport (cxi on Isambard, tcp in
// tests) installed in place of it when secure mode is on (WITH_SECURE_KV build
// and MC_SECURE_MODE=1). It changes two things and forwards everything else:
//
//  * Registration. Memory reaches the inner transport (and so the NIC and the
//    published segment metadata) only when it is registered inside a
//    CiphertextRegistrationScope on the calling thread: engine staging, and
//    the store's segments, which only ever receive sealed bytes. Everything
//    else (a vLLM KV cache, a user's buffer) is recorded as local-only and is
//    invisible to peers.
//  * Submission. A transfer whose local side is not inside NIC-registered
//    (ciphertext) memory is refused, so plaintext cannot be put on the fabric
//    even by a code path that forgot to seal.
//
// Nothing here runs unless secure mode is configured.

#pragma once

#include <map>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

#include "transport/transport.h"

namespace mooncake {
namespace secure {

// While an instance is alive on a thread, memory that thread registers with
// the transfer engine is treated as ciphertext memory and registered with the
// NIC. Nestable.
class CiphertextRegistrationScope {
   public:
    CiphertextRegistrationScope();
    ~CiphertextRegistrationScope();
    CiphertextRegistrationScope(const CiphertextRegistrationScope&) = delete;
    CiphertextRegistrationScope& operator=(const CiphertextRegistrationScope&) =
        delete;
    static bool Active();
};

class SecureTransport final : public Transport {
   public:
    explicit SecureTransport(Transport* inner);  // takes ownership
    ~SecureTransport() override;

    Status submitTransfer(BatchID batch_id,
                          const std::vector<TransferRequest>& entries) override;
    Status submitTransferTask(
        const std::vector<TransferTask*>& task_list) override;
    Status submitTransferTaskGroup(
        const std::vector<TransferTask*>& task_list) override;
    bool supportsGroupedScatter() const override;
    bool supportsBatchCompletionCounter() const override;
    Status getTransferStatus(BatchID batch_id, size_t task_id,
                             TransferStatus& status) override;
    Status OpenChannel(const std::string& segment_name,
                       SegmentID sid) override;
    Status CheckStatus(SegmentID sid) override;

    // True if [addr, addr+length) lies inside one NIC-registered region.
    bool IsCiphertextMemory(const void* addr, size_t length) const;
    Transport* inner() const { return inner_.get(); }

   protected:
    int install(std::string& local_server_name,
                std::shared_ptr<TransferMetadata> meta,
                std::shared_ptr<Topology> topo) override;

   private:
    int registerLocalMemory(void* addr, size_t length,
                            const std::string& location, bool remote_accessible,
                            bool update_metadata) override;
    int unregisterLocalMemory(void* addr, bool update_metadata) override;
    int registerLocalMemoryBatch(const std::vector<BufferEntry>& buffer_list,
                                 const std::string& location) override;
    int unregisterLocalMemoryBatch(
        const std::vector<void*>& addr_list) override;
    const char* getName() const override;

    Status CheckRequests(const TransferRequest* requests, size_t count) const;

    struct Region {
        size_t length;
        bool nic;
    };
    std::unique_ptr<Transport> inner_;
    mutable std::shared_mutex mu_;
    std::map<uintptr_t, Region> regions_;
};

// Called once per transport installation (MultiTransport::installTransport).
// Returns `transport` unchanged unless secure mode is on, in which case it is
// wrapped. Returns nullptr (and deletes `transport`) if secure mode was
// requested but cannot start, so the install fails closed.
Transport* MaybeWrapTransport(const std::string& proto, Transport* transport);

}  // namespace secure
}  // namespace mooncake
