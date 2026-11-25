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
//   (sealing starts as RESERVE is sent: seals go to the sender's own
//   staging and do not depend on the slots granted)
//   per segment, streamed (the first and last few are small, so the pipe
//   fills and drains quickly; the rest are MC_SECURE_P2D_SEGMENT_BYTES):
//     copy device->pinned host, seal (kTransfer) into send staging,
//     fabric WRITE sealed segment ----------> slot (posted as soon as the
//                                             segment is sealed and its
//                                             slot is free)
//     COMMIT(segment: slot, sealed length,    checks every destination lies
//            destination list)                in its local-only registered
//               ----- control ----------->    memory, opens slot -> dest
//               <---- ACK(segment) -------    (verify + decrypt, one pass),
//                                             replies in request order;
//                                             commits are opened in
//                                             parallel, not one at a time
//   success only after every segment's authenticated ACK. A slot is reused
//   only after the ACK of the segment that last held it.
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

// Hidden: each module that links this (engine.so, _store.so) keeps its own
// copy of the secure code and its state (SECURE_KV.md, "One copy per module").
#pragma GCC visibility push(hidden)

namespace mooncake {
namespace secure {

// Environment (all optional):
//   MC_SECURE_P2D_THREADS          seal threads and open threads (4 each)
//   MC_SECURE_P2D_SEGMENT_BYTES    plaintext per sealed segment (2 MiB)
//   MC_SECURE_P2D_WINDOW_SEGMENTS  half the receive slots a push asks for
//                                  (asks for 2x this many) (8)
//   MC_SECURE_P2D_FIRST_SEGMENT_BYTES  plaintext of the first (and last)
//                                  segments of a push; sizes double up to
//                                  MC_SECURE_P2D_SEGMENT_BYTES (256 KiB; 0 or
//                                  at least the segment size: no ramp)
//   MC_SECURE_P2D_RX_BYTES         receive staging (256 MiB)
//   MC_SECURE_P2D_TX_BYTES         cap on send staging (1 GiB)
//   MC_SECURE_P2D_CPUS             CPU list the crypto threads are pinned
//                                  to, one CPU each, e.g. "72-79"; unset:
//                                  the staging node's CPUs (see below), or
//                                  not pinned if there is no staging node
//   MC_SECURE_P2D_NUMA_NODE        NUMA node for send and receive staging
//                                  and the crypto threads: "auto" (default:
//                                  the node of the memory being pushed or
//                                  received into, for GPU memory the node
//                                  its GPU hangs off), a node number, or
//                                  "none" (wherever first touch lands).
//                                  Staging is ciphertext memory, so its node
//                                  also picks the NIC it goes out on.
//   MC_SECURE_P2D_STATS_INTERVAL_S  at most this often, a push logs the
//                                  cumulative stage timings (60; 0: never).
//                                  Each push's own breakdown is at VLOG(1).
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
    size_t first_segment_bytes = 256ull << 10;
    size_t rx_bytes = 256ull << 20;
    size_t tx_bytes = 1ull << 30;
    std::vector<int> cpus;
    static constexpr int kNumaAuto = -1;
    static constexpr int kNumaNone = -2;
    int numa_node = kNumaAuto;
    int stats_interval_s = 60;
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

// How a push of `total` bytes is cut into segments: (offset, length) pairs
// covering [0, total) in order, none longer than `segment_bytes`. The first
// segments are `first_bytes` long, `ramp` of each size, doubling up to
// `segment_bytes`, and the last few halve back down to `first_bytes`, so the
// first write starts after sealing a small segment and the receiver's last
// open is short. `first_bytes` 0 or >= `segment_bytes`: all full-size.
std::vector<std::pair<size_t, size_t>> PlanPushSegments(size_t total,
                                                        size_t segment_bytes,
                                                        size_t first_bytes,
                                                        size_t ramp);

// Parses "0-3,8,10-11". Returns false on malformed input.
bool ParseCpuList(const std::string& text, std::vector<int>* out);

// Where the time of secure pushes goes, stage by stage (DW-1288). Sender
// stages are per segment unless noted; the three waits are the committer's
// (the thread that posts writes and commits in order) and so show which
// stage the pipeline is waiting on.
enum class PushStage : int {
    kD2H = 0,    // sender: device -> pinned host copy of a segment
    kSeal,       // sender: sealing a segment into send staging
    kWrite,      // sender: fabric WRITE, posted -> completion observed
    kCommitRtt,  // sender: COMMIT sent -> its ACK read
    kSealWait,   // sender committer: waiting for the next seal
    kWriteWait,  // sender committer: waiting for a write to complete
    kAckWait,    // sender committer: waiting for an ACK (no free slot)
    kPush,       // sender: a whole push, start -> last ACK (per push)
    kRxCopy,     // receiver: copying a sealed segment out of its slot
    kOpen,       // receiver: verifying and decrypting a segment
    kH2D,        // receiver: pinned host -> device copy of a segment
    kCount
};
const char* PushStageName(PushStage s);

// Bucket b of a stage histogram counts durations in [2^(b-1), 2^b)
// microseconds (bucket 0: under 1 us; the last: everything longer).
constexpr int kStageBuckets = 24;

struct StageStats {
    uint64_t count = 0;
    uint64_t sum_ns = 0;
    uint64_t max_ns = 0;
    uint64_t buckets[kStageBuckets] = {};
    // Upper bound (us) of the bucket holding quantile q (0..1); 0 if empty.
    uint64_t QuantileUpperUs(double q) const;
};

// Cumulative since the service started.
struct PushStats {
    StageStats stage[static_cast<int>(PushStage::kCount)];
    uint64_t pushes = 0;         // completed
    uint64_t failed_pushes = 0;
    uint64_t bytes = 0;          // plaintext bytes of completed pushes
    uint64_t rx_segments = 0;    // segments opened (receiver)
    int numa_node = -1;          // staging node in use (-1: none)
    // One line: per stage count, mean, max and p50/p99 bucket bounds.
    std::string ToString() const;
};

// Fixed-size worker pool; threads optionally pinned to a CPU list: with
// `each`, thread i to cpus[i % size]; otherwise every thread to the whole
// list.
class CryptoPool {
   public:
    CryptoPool(size_t threads, const std::vector<int>& cpus,
               const char* name, bool each = true);
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
    bool each_ = true;
};

// What the service needs from the transport it lives in. Kept as callbacks so
// the service never reaches into transport internals.
struct PushFabric {
    using Request = Transport::TransferRequest;
    // Registers [p, p+n) with the NIC as ciphertext memory, through the NIC
    // of NUMA node `node` (node < 0: the node the memory is on). 0 on
    // success.
    std::function<int(void* p, size_t n, int node)> register_ciphertext;
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
    // Sender: after a commit's sealed segments reached the peer and before
    // the commit is sent. Arguments: peer addresses and sizes of the slots.
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
    // the control endpoint in this engine's handshake descriptor. `near`
    // (optional) is memory pushes will land in; it picks the staging node
    // (MC_SECURE_P2D_NUMA_NODE=auto). Idempotent; 0 on success.
    int EnableReceiver(const void* near = nullptr);
    bool receiver_enabled() const;

    // Pushes `pieces` to `target` in the background and calls done(true)
    // only after the peer authenticated every segment; done(false) on any
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
    // Stage timings (both halves), cumulative.
    PushStats push_stats() const;
    ControlStats control_stats() const;
    // Forgets every discovered peer and pooled connection, so the next push
    // discovers and connects as a new sender would.
    void ForgetPeersForTesting();

    struct Peer;
    struct Receiver;
    struct Job;
    struct Stream;
    struct Telemetry;

   private:
    friend struct Job;
    friend struct Stream;
    std::shared_ptr<Peer> Discover(Transport::SegmentID target, bool force);
    bool RunJob(Job& job);
    bool EnsureSender(const void* near);
    // Logs the cumulative stage timings if MC_SECURE_P2D_STATS_INTERVAL_S
    // passed since the last time.
    void MaybeLogStats();
    // mu_ held. Resolves the staging node (once) from `near` and the
    // options; sets numa_node_ and crypto_cpus_.
    void ResolvePlacementLocked(const void* near);

    PushFabric fabric_;
    PushOptions opt_;
    PushTestHooks hooks_;

    std::mutex mu_;
    std::unique_ptr<Receiver> rx_;
    std::unique_ptr<StagingPool> tx_pool_;
    std::unique_ptr<CryptoPool> seal_pool_;
    std::map<Transport::SegmentID, std::shared_ptr<Peer>> peers_;
    bool placed_ = false;
    int numa_node_ = -1;
    std::vector<int> crypto_cpus_;
    bool crypto_cpus_each_ = true;
    std::unique_ptr<Telemetry> tm_;

    std::mutex jobs_mu_;
    std::condition_variable jobs_cv_;
    size_t active_jobs_ = 0;
    bool stopping_ = false;
    std::atomic<uint64_t> rejected_{0};
};

}  // namespace secure
}  // namespace mooncake

#pragma GCC visibility pop
