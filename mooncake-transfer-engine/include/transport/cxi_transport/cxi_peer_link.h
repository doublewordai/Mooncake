// Copyright 2024 KVCache.AI
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

#ifndef CXI_PEER_LINK_H
#define CXI_PEER_LINK_H

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <utility>

namespace mooncake {

// The connection state of one CXI peer: the peer's endpoint address and its
// slot in the local address vector.
//
// Either side creates it. Actively, a sender exchanges addresses with the
// peer through the handshake RPC; passively, the peer's handshake reaches
// this process's handshake listener, which records the peer's address and
// replies with ours. Both happen at once when two processes first send to
// each other. The listener serves handshakes one at a time, so the passive
// side must never wait for an active handshake: that handshake may itself be
// waiting for the peer's listener, which is waiting the same way for ours.
// The RPC therefore runs without the state lock. Active handshakes on one
// link are serialized among themselves (only senders wait for them), and a
// passive handshake from a peer whose address is unchanged leaves the slot in
// place, so transfers already posted to it are not cut off.
//
// No libfabric types here, so the protocol is testable without a NIC.
class CxiPeerLink {
   public:
    static constexpr uint64_t kNoSlot = ~0ull;  // FI_ADDR_UNSPEC

    struct AddressVector {
        // Insert `addr` (the peer's endpoint address, as exchanged) and
        // return its slot; 0 on success.
        std::function<int(const std::string& addr, uint64_t& slot)> insert;
        std::function<void(uint64_t slot)> remove;
    };

    explicit CxiPeerLink(AddressVector av) : av_(std::move(av)) {}

    CxiPeerLink(const CxiPeerLink&) = delete;
    CxiPeerLink& operator=(const CxiPeerLink&) = delete;

    // Active side: 0 once connected. `exchange` runs the handshake RPC and
    // sets the peer's address; it is called with no lock held that the
    // passive side takes.
    int connect(const std::function<int(std::string& peer_addr)>& exchange) {
        std::lock_guard<std::mutex> one_at_a_time(handshake_mu_);
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (slot_ != kNoSlot) return 0;
        }
        std::string peer_addr;
        int rc = exchange(peer_addr);
        std::lock_guard<std::mutex> lock(mu_);
        if (rc != 0) {
            // The peer's own handshake may have connected us meanwhile.
            return slot_ != kNoSlot ? 0 : rc;
        }
        return installLocked(peer_addr);
    }

    // Passive side: record the address the peer sent in its handshake.
    int accept(const std::string& peer_addr) {
        std::lock_guard<std::mutex> lock(mu_);
        return installLocked(peer_addr);
    }

    // Remove the peer's slot.
    void disconnect() {
        std::lock_guard<std::mutex> lock(mu_);
        if (slot_ != kNoSlot) av_.remove(slot_);
        slot_ = kNoSlot;
        peer_addr_.clear();
    }

    // Forget the slot without removing it (the address vector is going away).
    void forget() {
        std::lock_guard<std::mutex> lock(mu_);
        slot_ = kNoSlot;
        peer_addr_.clear();
    }

    bool connected() const {
        std::lock_guard<std::mutex> lock(mu_);
        return slot_ != kNoSlot;
    }

    uint64_t slot() const {
        std::lock_guard<std::mutex> lock(mu_);
        return slot_;
    }

   private:
    int installLocked(const std::string& peer_addr) {
        if (peer_addr.empty()) return -1;
        if (slot_ != kNoSlot) {
            if (peer_addr == peer_addr_) return 0;
            // The peer came back with a new endpoint.
            av_.remove(slot_);
            slot_ = kNoSlot;
            peer_addr_.clear();
        }
        uint64_t slot = kNoSlot;
        int rc = av_.insert(peer_addr, slot);
        if (rc != 0) return rc;
        slot_ = slot;
        peer_addr_ = peer_addr;
        return 0;
    }

    AddressVector av_;
    std::mutex handshake_mu_;  // serializes active handshakes on this link
    mutable std::mutex mu_;    // slot_, peer_addr_; never held across an RPC
    uint64_t slot_ = kNoSlot;
    std::string peer_addr_;
};

}  // namespace mooncake

#endif  // CXI_PEER_LINK_H
