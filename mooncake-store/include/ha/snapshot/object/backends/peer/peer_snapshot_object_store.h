#pragma once

// A snapshot object store that needs no shared storage: each master keeps the
// snapshots it holds in a local directory and serves them to the other masters
// of its cluster over coro_rpc (authenticated in secure mode, like the store's
// other RPCs). A master that lacks an object fetches it from a live peer,
// keeps it, and from then on serves it too; every master also prefetches the
// published latest and fallback snapshots in the background, so a published
// snapshot outlives the pod that wrote it. The OpLog is pruned behind a
// snapshot only once enough live masters hold it (RetainedForPruning).
//
// Peers find each other through etcd: each announces its address and the
// snapshots it holds, verified, under PeerSnapshotRegistryPrefix(cluster),
// refreshing the entry periodically; entries not refreshed within the stale
// window are ignored.
//
// Selected with snapshot_object_store_type=peer; configured from the
// environment (PeerSnapshotStoreOptions::FromEnvironment):
//   MOONCAKE_SNAPSHOT_LOCAL_PATH       local directory (as the local backend)
//   MOONCAKE_SNAPSHOT_PEER_ADDRESS     host:port this master serves snapshots
//                                      on and announces (required)
//   MOONCAKE_SNAPSHOT_PEER_BIND        address to listen on (default: the
//                                      host of MOONCAKE_SNAPSHOT_PEER_ADDRESS)
//   MOONCAKE_SNAPSHOT_PEER_MIN_HOLDERS live masters, this one included, that
//                                      must hold a snapshot before the OpLog is
//                                      pruned behind it (default 2)
//   MOONCAKE_SNAPSHOT_PEER_RESET_GRACE_S seconds the cluster must stay
//                                      unrestorable before it is reset to
//                                      empty (default 60; 0 never resets)
//
// The store is a cache, so an unrestorable cluster starts empty rather than
// staying down. It is unrestorable when the OpLog has been pruned (a
// compaction floor exists) and no live master, this one included, holds the
// latest or fallback snapshot. Once that has held continuously for the grace
// period with no leader serving, one master resets it: an etcd transaction,
// fenced on everything it observed (pointers, floor, master view, the
// maintenance lock, the epoch), bumps the cluster's snapshot epoch
// (PeerSnapshotEpochKey) and marks both pointers as reset; it then deletes the
// OpLog batches, the durable prefix, the floor and the pointers, in that
// order, so that a standby restoring at any point in between either fails or
// restores an empty index, never a partial one. Any master finishes a reset
// it finds marked but unfinished. Masters drop their local snapshots when the
// epoch changes.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <ylt/coro_rpc/coro_rpc_server.hpp>

#include "ha/snapshot/object/backends/local/local_file_snapshot_object_store.h"
#include "ha/snapshot/object/snapshot_object_store.h"

namespace mooncake {

class HaKvBackend;

struct PeerSnapshotStoreOptions {
    std::string cluster_id;
    std::string local_path;
    std::string advertise_address;  // host:port
    std::string bind_host;          // empty: the host of advertise_address
    size_t min_holders{2};
    // Background work (prefetch, local GC, announcement) runs every tick.
    std::chrono::milliseconds tick{2000};
    // The registry entry is rewritten when what it says changes, and at least
    // this often otherwise.
    std::chrono::milliseconds announce_every{10000};
    std::chrono::milliseconds peer_stale_after{30000};
    // Zero disables the reset to empty.
    std::chrono::milliseconds reset_grace{60000};
    std::chrono::milliseconds connect_timeout{1000};
    std::chrono::milliseconds request_timeout{10000};
    // Tests drive Tick() themselves.
    bool background{true};

    static PeerSnapshotStoreOptions FromEnvironment(std::string cluster_id);
};

// What a peer answers. Statuses: kOk, kNotFound, kRefused (a key outside the
// snapshot namespace), kError.
struct PeerSnapshotStatResponse {
    int32_t status{0};
    uint64_t size{0};
};

struct PeerSnapshotReadResponse {
    int32_t status{0};
    std::string data;
};

// The RPC service each peer serves. Public for tests.
class PeerSnapshotService {
   public:
    static constexpr int32_t kOk = 0;
    static constexpr int32_t kNotFound = 1;
    static constexpr int32_t kRefused = 2;
    static constexpr int32_t kError = 3;
    static constexpr uint64_t kMaxReadBytes = 4ull << 20;

    PeerSnapshotService(std::filesystem::path base, std::string namespace_prefix)
        : base_(std::move(base)), namespace_prefix_(std::move(namespace_prefix)) {}

    PeerSnapshotStatResponse Stat(std::string key);
    PeerSnapshotReadResponse Read(std::string key, uint64_t offset,
                                  uint64_t length);

    // The file a key names, if the key is inside the snapshot namespace and
    // the path stays inside the base directory.
    std::optional<std::filesystem::path> Resolve(const std::string& key) const;

   private:
    std::filesystem::path base_;
    std::string namespace_prefix_;
};

std::string PeerSnapshotRegistryPrefix(const std::string& cluster_id);
// The cluster's snapshot epoch: absent before the first reset, then 1, 2, ...
std::string PeerSnapshotEpochKey(const std::string& cluster_id);
// What a reset leaves in the latest and fallback pointers until it finishes.
inline constexpr char kPeerSnapshotResetMarker[] = "reset-in-progress";

class PeerSnapshotObjectStore final : public SnapshotObjectStore {
   public:
    PeerSnapshotObjectStore(PeerSnapshotStoreOptions options,
                            HaKvBackend& backend);
    ~PeerSnapshotObjectStore() override;

    PeerSnapshotObjectStore(const PeerSnapshotObjectStore&) = delete;
    PeerSnapshotObjectStore& operator=(const PeerSnapshotObjectStore&) =
        delete;

    tl::expected<void, std::string> UploadBuffer(
        const std::string& key, const std::vector<uint8_t>& buffer) override;
    tl::expected<void, std::string> DownloadBuffer(
        const std::string& key, std::vector<uint8_t>& buffer) override;
    tl::expected<void, std::string> UploadString(
        const std::string& key, const std::string& data) override;
    tl::expected<void, std::string> DownloadString(const std::string& key,
                                                   std::string& data) override;
    tl::expected<void, std::string> DeleteObjectsWithPrefix(
        const std::string& prefix) override;
    tl::expected<void, std::string> ListObjectsWithPrefix(
        const std::string& prefix,
        std::vector<std::string>& object_keys) override;
    tl::expected<SnapshotObjectInspection, std::string> InspectObject(
        const std::string& key) override;
    bool IsNotFoundError(const std::string& error) const override;
    std::string GetConnectionInfo() const override;
    bool RetainedForPruning(const std::string& artifact_prefix) override;

    // One round of background work: prefetch the published snapshots, drop
    // local snapshots older than the fallback, announce. Exposed for tests.
    void Tick();
    // Removes this peer's registry entry and stops serving (as at shutdown).
    void Shutdown();

    // Snapshot ids this master holds, verified against their manifests.
    std::set<std::string> HeldSnapshots() const;
    const std::string& address() const { return options_.advertise_address; }

   private:
    struct Peer {
        std::string address;
        std::set<std::string> held;
    };

    // Fetches `key` from a live peer into the local directory. Returns
    // nullopt on success, else an error (a not-found error if no reachable
    // peer has it and at least one answered).
    std::optional<std::string> FetchFromPeers(const std::string& key);
    std::optional<std::string> FetchFromPeer(const std::string& address,
                                             const std::string& key,
                                             bool& not_found);
    // Makes every artifact of the snapshot a pointer names present and
    // verified locally. True when it is.
    bool EnsureSnapshotLocal(const std::string& pointer_bytes);
    bool EnsureVerified(const std::string& key, uint64_t size, uint32_t crc);
    // Fresh entries other than this master's; entries dead for 10x the stale
    // window (or unreadable) are added to `expired`.
    std::vector<Peer> LivePeers(
        std::vector<std::string>* expired = nullptr) const;
    void Announce(bool force);
    void CollectLocalGarbage(uint64_t keep_from_batch);
    void Loop();
    // The reset to empty (see the file comment).
    void MaybeReset(const std::optional<std::string>& latest,
                    const std::optional<std::string>& fallback);
    void FinishReset();
    bool PeerAnswersFor(const std::string& address, const std::string& key);
    void WipeLocalSnapshots();

    PeerSnapshotStoreOptions options_;
    HaKvBackend& backend_;
    std::string snapshot_root_;
    std::string namespace_prefix_;  // <root>/batch-oplog/
    std::string registry_key_;
    LocalFileSnapshotObjectStore local_;
    std::filesystem::path base_;
    std::unique_ptr<PeerSnapshotService> service_;
    std::unique_ptr<coro_rpc::coro_rpc_server> server_;

    mutable std::mutex mutex_;
    std::set<std::string> verified_;  // snapshot ids, all artifacts verified
    std::string last_announced_;
    std::chrono::steady_clock::time_point last_announce_{};
    std::atomic<uint64_t> fetch_seq_{0};
    std::optional<std::chrono::steady_clock::time_point> unrestorable_since_;
    std::optional<std::string> seen_epoch_;

    std::mutex loop_mutex_;
    std::condition_variable loop_cv_;
    bool stop_{false};
    bool shut_down_{false};
    std::thread worker_;
};

// The standby controller's constructor for this backend: options from the
// environment, peers through the HA backend.
std::unique_ptr<SnapshotObjectStore> CreatePeerSnapshotObjectStore(
    const std::string& cluster_id, HaKvBackend& backend);

}  // namespace mooncake
