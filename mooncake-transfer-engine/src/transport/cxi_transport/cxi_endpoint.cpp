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

#include "transport/cxi_transport/cxi_endpoint.h"

#include <glog/logging.h>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <thread>

#include "config.h"

namespace mooncake {

static_assert(CxiPeerLink::kNoSlot == FI_ADDR_UNSPEC,
              "CxiPeerLink's empty slot must be libfabric's");

CxiEndpoint::CxiEndpoint(CxiContext& context)
    : context_(context),
      link_(CxiPeerLink::AddressVector{
          [&context](const std::string& addr, uint64_t& slot) {
              fi_addr_t fi_addr = FI_ADDR_UNSPEC;
              int rc = context.insertPeerAddr(addr, fi_addr);
              slot = fi_addr;
              return rc;
          },
          [&context](uint64_t slot) { context.removePeerAddr(slot); }}) {}

CxiEndpoint::~CxiEndpoint() { disconnect(); }

std::string CxiEndpoint::peerNicPath() const {
    RWSpinlock::ReadGuard guard(lock_);
    return peer_nic_path_;
}

void CxiEndpoint::setPeerNicPath(const std::string& peer_nic_path) {
    {
        RWSpinlock::WriteGuard guard(lock_);
        if (peer_nic_path_ == peer_nic_path) return;  // No change
        peer_nic_path_ = peer_nic_path;
    }
    if (link_.connected()) {
        LOG(INFO) << "Peer reconnected with new address, re-establishing: "
                  << toString();
        link_.disconnect();
    }
}

// The handshake RPC runs without any lock the passive side takes; see
// CxiPeerLink.
int CxiEndpoint::setupConnectionsByActive() {
    if (link_.connected()) return 0;
    const std::string peer_nic_path = peerNicPath();

    // Loopback: no handshake, the peer is our own endpoint.
    if (context_.nicPath() == peer_nic_path) {
        int rc = link_.connect([this](std::string& peer_addr) {
            peer_addr = context_.localEpAddr();
            return 0;
        });
        if (rc == 0)
            LOG(INFO) << "CXI loopback connection established: " << toString();
        return rc;
    }

    auto peer_server_name = getServerNameFromNicPath(peer_nic_path);
    auto peer_nic_name = getNicNameFromNicPath(peer_nic_path);
    if (peer_server_name.empty() || peer_nic_name.empty()) {
        LOG(ERROR) << "Parse peer CXI nic path failed: " << peer_nic_path;
        return ERR_INVALID_ARGUMENT;
    }

    int rc = link_.connect([&](std::string& peer_addr) {
        // Exchange addresses via the transfer-metadata handshake RPC.
        TransferMetadata::HandShakeDesc local_desc, peer_desc;
        local_desc.local_nic_path = context_.nicPath();
        local_desc.peer_nic_path = peer_nic_path;
        local_desc.cxi_addr = context_.localEpAddr();
        int ret = context_.engine().sendHandshake(peer_server_name,
                                                  local_desc, peer_desc);
        if (ret) return ret;
        if (peer_desc.cxi_addr.empty()) {
            LOG(ERROR) << "Peer did not provide CXI address in handshake";
            return static_cast<int>(ERR_REJECT_HANDSHAKE);
        }
        peer_addr = peer_desc.cxi_addr;
        return 0;
    });
    if (rc == 0)
        VLOG(1) << "CXI connection established: " << toString()
                << " peer_fi_addr=" << link_.slot();
    return rc;
}

int CxiEndpoint::setupConnectionsByPassive(const HandShakeDesc& peer_desc,
                                           HandShakeDesc& local_desc) {
    const std::string peer_nic_path = peerNicPath();
    if (peer_desc.peer_nic_path != context_.nicPath() ||
        peer_desc.local_nic_path != peer_nic_path) {
        local_desc.reply_msg = "CXI nic path inconsistency";
        LOG(ERROR) << "Invalid argument: peer CXI nic path inconsistency"
                   << " peer_nic_path=" << peer_desc.peer_nic_path
                   << " context_.nicPath()=" << context_.nicPath()
                   << " local_nic_path=" << peer_desc.local_nic_path
                   << " peer_nic_path_=" << peer_nic_path;
        return ERR_REJECT_HANDSHAKE;
    }

    if (peer_desc.cxi_addr.empty()) {
        local_desc.reply_msg = "No CXI address provided";
        LOG(ERROR) << "Peer did not provide CXI address";
        return ERR_REJECT_HANDSHAKE;
    }

    // Idempotent for an unchanged peer address: a peer's handshake that
    // crosses ours, or repeats after a timeout, keeps the slot in place.
    int ret = link_.accept(peer_desc.cxi_addr);
    if (ret != 0) {
        local_desc.reply_msg = "Failed to insert peer address";
        return ret;
    }

    local_desc.local_nic_path = context_.nicPath();
    local_desc.peer_nic_path = peer_nic_path;
    local_desc.cxi_addr = context_.localEpAddr();
    // reply_msg empty on success

    VLOG(1) << "CXI connection established (passive): " << toString();
    return 0;
}

const std::string CxiEndpoint::toString() const {
    return "CxiEndpoint[" + context_.nicPath() + " <-> " + peerNicPath() + "]";
}

void CxiEndpoint::disconnect() { link_.disconnect(); }

void CxiEndpoint::markDetachedForTeardown() { link_.forget(); }

int CxiEndpoint::submitPostSend(
    std::vector<Transport::Slice*>& slice_list,
    std::vector<Transport::Slice*>& failed_slice_list) {
    if (!link_.connected()) {
        int ret = setupConnectionsByActive();
        if (ret != 0) {
            for (auto* slice : slice_list) {
                failed_slice_list.push_back(slice);
            }
            slice_list.clear();
            return ret;
        }
    }

    const fi_addr_t peer = link_.slot();
    if (peer == FI_ADDR_UNSPEC) {
        for (auto* slice : slice_list) failed_slice_list.push_back(slice);
        slice_list.clear();
        return ERR_ENDPOINT;
    }

    return context_.submitSlicesOnPeer(peer, slice_list, failed_slice_list);
}

}  // namespace mooncake
