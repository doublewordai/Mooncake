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

// Secure push (DW-1288): a WRITE from local-only memory (a vLLM KV cache) to
// local-only memory on a peer, without either side's plaintext ever being
// registered with the NIC.
//
// Sender                                   Receiver
//   RESERVE(n)  ----- control (TCP) ----->   grants slots of its receive
//               <----------------------- -   staging (NIC-registered)
//   per window of segments (default 2 MiB each):
//     copy device->pinned host, seal (kTransfer) into send staging,
//     fabric WRITE sealed segment ----------> slot
//     COMMIT(window: slot, sealed length,     checks every destination lies
//            destination list per segment)    in its local-only registered
//               ----- control ----------->    memory, opens slot -> dest
//               <---- ACK(window) --------    (verify + decrypt, one pass),
//                                             replies
//   success only after every window's authenticated ACK.
//
// Every control message is sealed with Purpose::kControl under the shared
// key: requests bind the receiver's segment name, replies bind the request's
// header (so a reply cannot be replayed onto another request), and the
// receiver refuses a request whose (key id, salt, counter) it has seen. Data
// segments are sealed with Purpose::kTransfer and bind sender, receiver, a
// fresh random transfer id, the segment index and its destination list, so a
// segment cannot be committed to other destinations, another transfer or
// another receiver.
//
// Discovery never touches fabric-writable memory. A receiver advertises its
// control endpoint (host, port) inside its segment descriptor as it goes out
// over the authenticated P2P handshake (handshake_auth.h); a sender takes the
// endpoint from the descriptor it fetched and asks the receiver for its slot
// layout with a HELLO on the sealed control channel. The receive staging
// holds only slots.
//
// Control server limits: a connection is unauthenticated until its first
// request opens; until then its frame may be at most
// kMaxUnauthenticatedFrameBytes (the largest legitimate first request) and
// must arrive within the handshake timeout. Unauthenticated connections are
// capped in total and per source address, separately from authenticated
// ones; when a cap is full the oldest unauthenticated connection from the
// address holding the most is dropped, so a flood cannot keep a new sender
// out. Authenticated connections close after the idle timeout.
//
// Everything here runs only in secure mode (SecureTransport owns the
// service); with secure mode off none of it is constructed.

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "secure/kv_crypto.h"
#include "secure/staging_pool.h"
#include "transport/transport.h"

namespace mooncake {
namespace secure {

// Environment (all optional):
//   MC_SECURE_P2D_THREADS          seal threads and open threads (4 each)
//   MC_SECURE_P2D_SEGMENT_BYTES    plaintext per sealed segment (2 MiB)
//   MC_SECURE_P2D_WINDOW_SEGMENTS  segments per commit window (8)
//   MC_SECURE_P2D_RX_BYTES         receive staging (256 MiB)
//   MC_SECURE_P2D_TX_BYTES         cap on send staging (1 GiB)
//   MC_SECURE_P2D_CPUS             CPU list the crypto threads are pinned
//                                  to, e.g. "72-79" (GPU-local NUMA node);
//                                  unset: not pinned
//   MC_SECURE_P2D_HOST             address peers use for the control
//                                  endpoint (default: host part of the
//                                  engine's segment name)
//   MC_SECURE_P2D_PORT             control port (default: ephemeral)
//   MC_SECURE_P2D_TIMEOUT_MS       per-step timeout (30000)
//   MC_SECURE_P2D_RX_COPY          1 (default): copy each sealed segment out
//                                  of the remotely writable slot before
//                                  opening it; 0: open in place
//   MC_SECURE_P2D_MAX_CONNS        authenticated control connections (1024)
//   MC_SECURE_P2D_MAX_PREAUTH      unauthenticated control connections (256)
//   MC_SECURE_P2D_MAX_PREAUTH_PER_IP  of those, from one address (64)
//   MC_SECURE_P2D_HANDSHAKE_TIMEOUT_MS  time a new connection has to send
//                                  an authenticated request (5000)
//   MC_SECURE_P2D_IDLE_TIMEOUT_MS  authenticated connection idle (no lease)
//                                  before the receiver closes it (120000);
//                                  senders drop pooled connections idle for
//                                  half of it
struct PushOptions {
    size_t threads = 4;
    size_t segment_bytes = 2ull << 20;
    size_t window_segments = 8;
    size_t rx_bytes = 256ull << 20;
    size_t tx_bytes = 1ull << 30;
    std::vector<int> cpus;
    std::string host;
    int port = 0;
    int timeout_ms = 30000;
    bool rx_copy = true;
    size_t max_conns = 1024;
    size_t max_preauth = 256;
    size_t max_preauth_per_ip = 64;
    int handshake_timeout_ms = 5000;
    int idle_timeout_ms = 120000;

    static PushOptions FromEnv();
};

// The largest frame the control server reads from a connection that has not
// yet sent an authenticated request: a sealed HELLO or RESERVE with a sender
// name of at most 4096 bytes fits.
constexpr size_t kMaxUnauthenticatedFrameBytes = 8192;

// Control server accounting (tests, logs).
struct ControlStats {
    size_t preauth_conns = 0;      // open, not yet authenticated
    size_t auth_conns = 0;         // open, authenticated
    uint64_t refused_conns = 0;    // authenticated over MC_SECURE_P2D_MAX_CONNS
    uint64_t evicted_conns = 0;    // unauthenticated, dropped for a newer one
    uint64_t timed_out_conns = 0;  // handshake or idle timeout
    uint64_t oversized_frames = 0; // length claim over the connection's cap
    size_t preauth_buffer_peak = 0;  // most bytes ever buffered at once for
                                     // unauthenticated frames
};

// Parses "0-3,8,10-11". Returns false on malformed input.
bool ParseCpuList(const std::string& text, std::vector<int>* out);

// Fixed-size worker pool; threads optionally pinned to a CPU list.
class CryptoPool {
   public:
    CryptoPool(size_t threads, const std::vector<int>& cpus,
               const char* name);
    ~CryptoPool();
    void Run(std::function<void()> fn);

   private:
    void Loop(size_t index);
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::function<void()>> queue_;
    bool stop_ = false;
    std::vector<std::thread> threads_;
    std::vector<int> cpus_;
};

// What the service needs from the transport it lives in. Kept as callbacks so
// the service never reaches into transport internals.
struct PushFabric {
    using Request = Transport::TransferRequest;
    // Registers [p, p+n) with the NIC as ciphertext memory. 0 on success.
    std::function<int(void* p, size_t n)> register_ciphertext;
    std::function<int(void* p)> unregister;
    // True if [p, p+n) lies inside one local-only (not NIC) registered region.
    std::function<bool(const void* p, size_t n)> is_local_only;
    // Starts fabric requests whose local side is send staging. Returns an
    // opaque handle (never null) to pass to wait_ops exactly once.
    std::function<void*(const std::vector<Request>& reqs)> begin_ops;
    // Waits for the handle's requests; OK only if every one completed.
    std::function<Status(void* handle, int timeout_ms)> wait_ops;
    // The peer's segment descriptor (force: refetch).
    std::function<std::shared_ptr<TransferMetadata::SegmentDesc>(
        Transport::SegmentID, bool force)>
        segment_desc;
    std::string local_name;  // this engine's segment name
};

// One piece of a push: local source, remote destination.
struct PushPiece {
    const void* src;
    uint64_t dst;
    size_t len;
};

// Test hooks (all optional; never set in production).
struct PushTestHooks {
    // Sender: after a window's sealed segments reached the peer and before
    // its commit is sent. Arguments: peer addresses and sizes of the slots.
    std::function<void(const std::vector<std::pair<uint64_t, size_t>>&)>
        before_commit;
    // Sender: every RESERVE and COMMIT frame a push sends (sealed bytes,
    // without the length); discovery HELLOs are not reported.
    std::function<void(const std::string& frame)> on_frame_sent;
    // Sender: the header of every sealed data segment.
    std::function<void(const SealedInfo& info)> on_segment_sealed;
};

class SecurePushService {
   public:
    SecurePushService(PushFabric fabric, PushOptions options);
    ~SecurePushService();
    SecurePushService(const SecurePushService&) = delete;
    SecurePushService& operator=(const SecurePushService&) = delete;

    // Brings up the receive side (staging, control server) and advertises
    // the control endpoint in this engine's handshake descriptor.
    // Idempotent; 0 on success.
    int EnableReceiver();
    bool receiver_enabled() const;

    // Pushes `pieces` to `target` in the background and calls done(true)
    // only after the peer authenticated every window; done(false) on any
    // failure. Returns false (without calling done) if the push could not
    // be started.
    bool PushAsync(Transport::SegmentID target, std::vector<PushPiece> pieces,
                   std::function<void(bool ok)> done);
    // Blocking form.
    Status Push(Transport::SegmentID target, std::vector<PushPiece> pieces);

    // Tests.
    PushTestHooks& test_hooks() { return hooks_; }
    std::string control_host() const;
    int control_port() const;
    // Sends one raw frame to a control endpoint and returns the raw reply
    // frame (empty if the peer closed the connection or timed out).
    static std::string SendRawFrameForTesting(const std::string& host, int port,
                                              const std::string& frame,
                                              int timeout_ms);
    // Rx statistics for tests.
    uint64_t rejected_requests() const { return rejected_.load(); }
    ControlStats control_stats() const;
    // Forgets every discovered peer and pooled connection, so the next push
    // discovers and connects as a new sender would.
    void ForgetPeersForTesting();

    struct Peer;
    struct Receiver;
    struct Job;

   private:
    friend struct Job;
    std::shared_ptr<Peer> Discover(Transport::SegmentID target, bool force);
    bool RunJob(Job& job);
    bool EnsureSender();

    PushFabric fabric_;
    PushOptions opt_;
    PushTestHooks hooks_;

    std::mutex mu_;
    std::unique_ptr<Receiver> rx_;
    std::unique_ptr<StagingPool> tx_pool_;
    std::unique_ptr<CryptoPool> seal_pool_;
    std::map<Transport::SegmentID, std::shared_ptr<Peer>> peers_;

    std::mutex jobs_mu_;
    std::condition_variable jobs_cv_;
    size_t active_jobs_ = 0;
    bool stopping_ = false;
    std::atomic<uint64_t> rejected_{0};
};

}  // namespace secure
}  // namespace mooncake
