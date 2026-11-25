// The peer snapshot object store: masters with no shared storage restore the
// latest snapshot from each other, the OpLog is pruned only behind a snapshot
// enough live masters hold, and (secure build) only authenticated peers can
// fetch. Several masters run in one process, each with its own directory and
// port; the HA backend is an in-memory KV.

#include "ha/snapshot/object/backends/peer/peer_snapshot_object_store.h"

#include <gtest/gtest.h>

#include <async_simple/coro/SyncAwait.h>
#include <ylt/coro_rpc/coro_rpc_client.hpp>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "common/network.h"
#include "crc32c.h"
#include "ha/kv/ha_kv_backend.h"
#include "ha/oplog/oplog_batch_codec.h"
#include "ha/oplog/oplog_batch_types.h"
#include "ha/snapshot/batch_oplog/batch_oplog_pruning_coordinator.h"
#include "ha/snapshot/batch_oplog/batch_oplog_snapshot_provider.h"
#include "ha/snapshot/batch_oplog/codec.h"
#include "ha/snapshot/batch_oplog/metadata.h"
#include "ha/snapshot/snapshot_maintenance_lease.h"
#include "ha_metric_manager.h"
#ifdef MOONCAKE_WITH_SECURE_KV
#include "control_auth.h"
#include "rpc_auth.h"
#endif

namespace mooncake::test {
namespace {

namespace fs = std::filesystem;
const std::string kCluster = "clusterA";
const std::string kOwner = "101";

class MemBackend final : public HaKvBackend {
   public:
    ErrorCode Get(std::string_view key, std::string& value) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = values_.find(std::string(key));
        if (it == values_.end()) return ErrorCode::ETCD_KEY_NOT_EXIST;
        value = it->second;
        return ErrorCode::OK;
    }
    ErrorCode Put(std::string_view key, std::string_view value) override {
        std::lock_guard<std::mutex> lock(mutex_);
        values_[std::string(key)] = std::string(value);
        return ErrorCode::OK;
    }
    ErrorCode Range(std::string_view begin, std::string_view end, size_t limit,
                    std::vector<KvPair>& out) override {
        std::lock_guard<std::mutex> lock(mutex_);
        out.clear();
        for (auto it = values_.lower_bound(std::string(begin));
             it != values_.end() && it->first < end; ++it) {
            if (limit != 0 && out.size() >= limit) break;
            out.push_back({it->first, it->second});
        }
        return ErrorCode::OK;
    }
    ErrorCode DeleteRange(std::string_view begin,
                          std::string_view end) override {
        std::lock_guard<std::mutex> lock(mutex_);
        values_.erase(values_.lower_bound(std::string(begin)),
                      values_.lower_bound(std::string(end)));
        return ErrorCode::OK;
    }
    bool SupportsTxn() const override { return true; }
    ErrorCode Txn(const KvTxn& txn) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& c : txn.compares) {
            auto it = values_.find(c.key);
            if (c.kind == KvCompareKind::kKeyNotExists) {
                if (it != values_.end()) return ErrorCode::ETCD_TRANSACTION_FAIL;
            } else if (c.kind == KvCompareKind::kValueEquals) {
                if (it == values_.end() || it->second != c.expected_value)
                    return ErrorCode::ETCD_TRANSACTION_FAIL;
            }
        }
        for (const auto& put : txn.puts) values_[put.key] = put.value;
        return ErrorCode::OK;
    }
    size_t CountPrefix(const std::string& prefix) {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t n = 0;
        for (const auto& [key, value] : values_) n += key.starts_with(prefix);
        return n;
    }

   private:
    std::mutex mutex_;
    std::map<std::string, std::string> values_;
};

class PeerSnapshotStoreTest : public ::testing::Test {
   protected:
    void SetUp() override {
        HAMetricManager::instance().reset_snapshot_runtime(true);
        char pattern[] = "/tmp/mooncake-peer-snapshot-XXXXXX";
        const char* dir = mkdtemp(pattern);
        ASSERT_NE(nullptr, dir);
        dir_ = dir;
        ports_ = getFreeTcpPorts(8);
        ASSERT_EQ(8u, ports_.size());
        root_ = ha::BuildBatchOpLogSnapshotRoot(kCluster);
        backend_.Put(ha::BuildBatchOpLogSnapshotMaintenanceKey(kCluster),
                     kOwner);
    }
    void TearDown() override {
        masters_.clear();
        fs::remove_all(dir_);
    }

    std::string Address(int i) const {
        return "127.0.0.1:" + std::to_string(ports_[i]);
    }

    // A master's snapshot store on a pod of its own: its own empty directory.
    PeerSnapshotObjectStore& Start(int i, size_t min_holders = 2) {
        PeerSnapshotStoreOptions options;
        options.cluster_id = kCluster;
        options.local_path = dir_ + "/m" + std::to_string(i);
        options.advertise_address = Address(i);
        options.min_holders = min_holders;
        options.background = false;
        options.connect_timeout = std::chrono::milliseconds(500);
        masters_[i] =
            std::make_unique<PeerSnapshotObjectStore>(options, backend_);
        return *masters_[i];
    }
    // The pod goes: its registry entry and server go with it.
    void Stop(int i) { masters_.erase(i); }
    PeerSnapshotObjectStore& M(int i) { return *masters_.at(i); }

    // Batch i (seq i) removes `key` (a no-op for a key that does not exist).
    void AppendBatches(uint64_t from, uint64_t to,
                       const std::map<uint64_t, std::string>& removes = {}) {
        for (uint64_t id = from; id <= to; ++id) {
            OpLogEntry entry;
            entry.sequence_id = id;
            entry.op_type = OpType::REMOVE;
            entry.tenant_id = "default";
            entry.object_key =
                removes.contains(id) ? removes.at(id)
                                     : "noop-" + std::to_string(id);
            OpLogBatchRecord batch;
            batch.batch_id = batch.first_seq = batch.last_seq = id;
            batch.entries = {entry};
            backend_.Put(BuildBatchRecordKey(kCluster, id),
                         EncodeOpLogBatchRecord(batch));
        }
        backend_.Put(BuildDurablePrefixKey(kCluster),
                     EncodeDurablePrefix({.batch_id = to, .last_seq = to}));
    }
    size_t BatchCount() {
        return backend_.CountPrefix(BuildBatchRecordKey(kCluster, 0).substr(
            0, BuildBatchRecordKey(kCluster, 0).rfind('/') + 1));
    }

    // Writes a snapshot of objects key-0..key-(n-1), less `gone`, at `batch`
    // into the store of the master that took it, and publishes it (latest
    // moves to fallback), as the coordinator does.
    std::string Publish(SnapshotObjectStore& store, uint64_t batch, size_t n,
                        const std::vector<std::string>& gone = {}) {
        const std::string id = std::to_string(batch) + "-" + kOwner;
        const auto segments = EncodeBatchOpLogSnapshotSegments({});
        const auto segments_key =
            ha::BuildBatchOpLogSnapshotSegmentsKey(root_, id);
        EXPECT_TRUE(store.UploadBuffer(segments_key, segments));
        std::vector<StandbyObjectEntry> objects;
        for (size_t i = 0; i < n; ++i) {
            const std::string key = "key-" + std::to_string(i);
            if (std::find(gone.begin(), gone.end(), key) != gone.end())
                continue;
            objects.push_back(
                {.tenant_id = "default", .key = key, .metadata = {}});
        }
        const size_t count = objects.size();
        const auto chunk = EncodeBatchOpLogSnapshotObjectChunk(0, objects);
        const auto chunk_key =
            ha::BuildBatchOpLogSnapshotObjectChunkKey(root_, id, 0);
        EXPECT_TRUE(store.UploadBuffer(chunk_key, chunk));

        ha::BatchOpLogSnapshotManifest manifest;
        manifest.snapshot_id = id;
        manifest.last_included_seq = manifest.last_included_batch_id = batch;
        manifest.segments = {
            .key = segments_key,
            .stored_size = segments.size(),
            .crc32c = Crc32cValue(segments.data(), segments.size())};
        manifest.object_chunks.push_back(
            {.chunk_index = 0,
             .key = chunk_key,
             .object_count = count,
             .stored_size = chunk.size(),
             .crc32c = Crc32cValue(chunk.data(), chunk.size())});
        const auto manifest_bytes =
            ha::EncodeBatchOpLogSnapshotManifest(manifest);
        const auto manifest_key =
            ha::BuildBatchOpLogSnapshotManifestKey(root_, id);
        EXPECT_TRUE(store.UploadString(manifest_key, manifest_bytes));

        ha::BatchOpLogSnapshotDescriptor descriptor;
        descriptor.snapshot_id = id;
        descriptor.last_included_seq = descriptor.last_included_batch_id =
            batch;
        descriptor.manifest_key = manifest_key;
        descriptor.manifest_size = manifest_bytes.size();
        descriptor.manifest_crc32c =
            Crc32cValue(manifest_bytes.data(), manifest_bytes.size());
        const auto pointer = ha::EncodeBatchOpLogSnapshotDescriptor(descriptor);
        EXPECT_TRUE(store.UploadString(
            ha::BuildBatchOpLogSnapshotDescriptorKey(root_, id), pointer));

        std::string latest;
        if (backend_.Get(ha::BuildBatchOpLogSnapshotLatestKey(kCluster),
                         latest) == ErrorCode::OK) {
            backend_.Put(ha::BuildBatchOpLogSnapshotFallbackKey(kCluster),
                         latest);
        }
        backend_.Put(ha::BuildBatchOpLogSnapshotLatestKey(kCluster), pointer);
        return id;
    }

    struct Restored {
        tl::expected<BatchOpLogSnapshotRestoreResult, ErrorCode> result;
        std::unique_ptr<StandbyMetadataStore> metadata;
    };
    // What a standby that starts on this master does first.
    Restored Restore(SnapshotObjectStore& store) {
        Restored r{.result = tl::make_unexpected(ErrorCode::INTERNAL_ERROR),
                   .metadata = std::make_unique<StandbyMetadataStore>()};
        StandbySegmentRegistry registry;
        BatchOpLogSnapshotProvider provider(kCluster, backend_, store, root_);
        r.result = provider.RestoreBaseline(*r.metadata, registry);
        return r;
    }

    ErrorCode Prune(SnapshotObjectStore& store) {
        auto lease = SnapshotMaintenanceLease::MakeForTesting(kCluster, kOwner);
        return BatchOpLogPruningCoordinator(backend_, store, kCluster, root_)
            .Run(*lease);
    }
    std::string Floor() {
        std::string floor;
        backend_.Get(ha::BuildBatchOpLogSnapshotCompactionFloorKey(kCluster),
                     floor);
        return floor;
    }

    MemBackend backend_;
    std::string dir_, root_;
    std::vector<int> ports_;
    std::map<int, std::unique_ptr<PeerSnapshotObjectStore>> masters_;
};

// The index a fresh standby restored: snapshot objects minus suffix removals.
void ExpectIndex(const StandbyMetadataStore& metadata, size_t n,
                 const std::vector<std::string>& removed) {
    EXPECT_EQ(n - removed.size(), metadata.GetKeyCount());
    for (const auto& key : removed) EXPECT_FALSE(metadata.Exists("default", key));
    for (size_t i = 0; i < n; ++i) {
        const std::string key = "key-" + std::to_string(i);
        if (std::find(removed.begin(), removed.end(), key) == removed.end()) {
            EXPECT_TRUE(metadata.Exists("default", key)) << key;
        }
    }
}

}  // namespace

TEST_F(PeerSnapshotStoreTest, FreshMasterRestoresPeerSnapshotPlusSuffix) {
    AppendBatches(1, 7, {{6, "key-3"}, {7, "key-4"}});
    auto& a = Start(0);
    const auto id = Publish(a, 5, 100);
    // The OpLog was pruned behind the snapshot: replay alone cannot rebuild.
    backend_.Put(ha::BuildBatchOpLogSnapshotCompactionFloorKey(kCluster), "5");
    backend_.DeleteRange(BuildBatchRecordKey(kCluster, 0),
                         BuildBatchRecordRange(kCluster, 5).begin_key);
    a.Tick();
    EXPECT_TRUE(a.HeldSnapshots().contains(id));

    auto& b = Start(1);
    auto restored = Restore(b);
    ASSERT_TRUE(restored.result) << toString(restored.result.error());
    EXPECT_EQ(5u, restored.result->last_included_batch_id);
    EXPECT_EQ(7u, restored.result->last_applied_batch_id);
    ExpectIndex(*restored.metadata, 100, {"key-3", "key-4"});
    // B now holds it too, so it serves it after A goes.
    b.Tick();
    EXPECT_TRUE(b.HeldSnapshots().contains(id));
}

TEST_F(PeerSnapshotStoreTest, NoReachableHolderAfterPruningFailsClosed) {
    AppendBatches(1, 7);
    {
        auto& a = Start(0);
        Publish(a, 5, 10);
        backend_.Put(ha::BuildBatchOpLogSnapshotCompactionFloorKey(kCluster),
                     "5");
        Stop(0);
    }
    auto& b = Start(1);
    auto restored = Restore(b);
    ASSERT_FALSE(restored.result);
    EXPECT_EQ(ErrorCode::INCOMPLETE_OPLOG_CATCH_UP, restored.result.error());
}

TEST_F(PeerSnapshotStoreTest, PruningWaitsForASecondLiveHolder) {
    AppendBatches(1, 9, {{8, "key-1"}});
    auto& a = Start(0);
    const auto s1 = Publish(a, 5, 20);
    const auto s2 = Publish(a, 7, 20);
    a.Tick();
    // Only the writer holds the fallback: no floor, no deletion.
    ASSERT_EQ(ErrorCode::OK, Prune(a));
    EXPECT_EQ("", Floor());
    EXPECT_EQ(9u, BatchCount());

    auto& b = Start(1);
    b.Tick();  // prefetches latest and fallback, then announces them
    EXPECT_TRUE(b.HeldSnapshots().contains(s1));
    EXPECT_TRUE(b.HeldSnapshots().contains(s2));
    ASSERT_EQ(ErrorCode::OK, Prune(a));
    EXPECT_EQ("5", Floor());
    EXPECT_EQ(4u, BatchCount());  // 6..9

    // Both holders of the newest snapshot go; a fresh master still restores
    // from whichever remains, and nothing it needs was pruned.
    Stop(0);
    auto& c = Start(2);
    auto restored = Restore(c);
    ASSERT_TRUE(restored.result) << toString(restored.result.error());
    EXPECT_EQ(9u, restored.result->last_applied_batch_id);
    ExpectIndex(*restored.metadata, 20, {"key-1"});
}

TEST_F(PeerSnapshotStoreTest, RollingReplacementKeepsSnapshotsReachable) {
    // Three seats, replaced one at a time for several generations; every
    // replacement starts empty. Each generation publishes a newer snapshot
    // from a surviving master and prunes behind the previous one.
    uint64_t batch = 5;
    AppendBatches(1, batch);
    Start(0);
    Start(1);
    Start(2);
    Publish(M(0), batch, 50);
    for (int i : {0, 1, 2}) M(i).Tick();
    std::vector<std::string> removed;
    int next = 3;
    for (int generation = 0; generation < 5; ++generation) {
        const int oldest = masters_.begin()->first;
        Stop(oldest);
        // The cluster moves on while the seat is empty.
        const uint64_t to = batch + 2;
        const std::string victim = "key-" + std::to_string(generation);
        AppendBatches(batch + 1, to, {{to, victim}});
        removed.push_back(victim);
        batch = to;

        auto& fresh = Start(next % 8);
        ++next;
        auto restored = Restore(fresh);
        ASSERT_TRUE(restored.result)
            << "generation " << generation << ": "
            << toString(restored.result.error());
        EXPECT_EQ(batch, restored.result->last_applied_batch_id);
        ExpectIndex(*restored.metadata, 50, removed);

        // A survivor publishes a newer snapshot of what it now has.
        auto& survivor = masters_.begin()->second;
        const auto before = BatchCount();
        Publish(*survivor, batch, 50, removed);
        for (auto& [i, m] : masters_) m->Tick();
        ASSERT_EQ(ErrorCode::OK, Prune(*survivor));
        EXPECT_LT(BatchCount(), before) << "generation " << generation;
    }
}

TEST_F(PeerSnapshotStoreTest, DeadPeerIsSkipped) {
    AppendBatches(1, 6);
    auto& a = Start(0);
    const auto id = Publish(a, 5, 10);
    a.Tick();
    // A fresh registry entry for a master that is gone, announcing the
    // snapshot (so it is tried first).
    backend_.Put(PeerSnapshotRegistryPrefix(kCluster) + "127.0.0.1:1",
                 R"({"address":"127.0.0.1:1","held":[")" + id +
                     R"("],"updated_ms":)" +
                     std::to_string(
                         std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::system_clock::now()
                                 .time_since_epoch())
                             .count()) +
                     "}");
    auto& b = Start(1);
    auto restored = Restore(b);
    ASSERT_TRUE(restored.result) << toString(restored.result.error());
    EXPECT_EQ(10u, restored.metadata->GetKeyCount());
}

TEST_F(PeerSnapshotStoreTest, LongDeadEntriesAreRemoved) {
    const std::string prefix = PeerSnapshotRegistryPrefix(kCluster);
    // Killed an hour ago, never deregistered; dead a moment ago.
    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    backend_.Put(prefix + "10.0.0.1:1",
                 R"({"address":"10.0.0.1:1","held":[],"updated_ms":)" +
                     std::to_string(now_ms - 3600 * 1000) + "}");
    backend_.Put(prefix + "10.0.0.2:1",
                 R"({"address":"10.0.0.2:1","held":[],"updated_ms":)" +
                     std::to_string(now_ms - 1000) + "}");
    auto& a = Start(0);
    a.Tick();
    std::string ignored;
    EXPECT_EQ(ErrorCode::ETCD_KEY_NOT_EXIST,
              backend_.Get(prefix + "10.0.0.1:1", ignored));
    EXPECT_EQ(ErrorCode::OK, backend_.Get(prefix + "10.0.0.2:1", ignored));
    EXPECT_EQ(ErrorCode::OK, backend_.Get(prefix + a.address(), ignored));
    Stop(0);  // a master that stops cleanly leaves at once
    EXPECT_EQ(ErrorCode::ETCD_KEY_NOT_EXIST,
              backend_.Get(prefix + Address(0), ignored));
}

TEST_F(PeerSnapshotStoreTest, ServesOnlyTheSnapshotNamespace) {
    auto& a = Start(0);
    Publish(a, 5, 1);
    std::ofstream(dir_ + "/m0/secret") << "not a snapshot";
    coro_rpc::coro_rpc_client client;
    ASSERT_FALSE(async_simple::coro::syncAwait(
        client.connect("127.0.0.1", std::to_string(ports_[0]))));
    for (const std::string key :
         {std::string("secret"), std::string("/etc/passwd"),
          root_ + "/batch-oplog/../../../secret",
          root_ + "/batch-oplog/5-101/../../../../secret"}) {
        SCOPED_TRACE(key);
        auto stat = async_simple::coro::syncAwait(
            client.call<&PeerSnapshotService::Stat>(key));
        ASSERT_TRUE(stat) << stat.error().msg;
        EXPECT_EQ(PeerSnapshotService::kRefused, stat->status);
        auto read = async_simple::coro::syncAwait(
            client.call<&PeerSnapshotService::Read>(key, uint64_t{0},
                                                    uint64_t{100}));
        ASSERT_TRUE(read) << read.error().msg;
        EXPECT_EQ(PeerSnapshotService::kRefused, read->status);
        EXPECT_TRUE(read->data.empty());
    }
}

#ifdef MOONCAKE_WITH_SECURE_KV
class SecurePeerSnapshotStoreTest : public PeerSnapshotStoreTest {
   protected:
    void SetUp() override {
        control_auth::ConfigureForTesting(true, std::string(40, 'a'));
        PeerSnapshotStoreTest::SetUp();
    }
    void TearDown() override {
        PeerSnapshotStoreTest::TearDown();
        control_auth::ResetForTesting();
    }
};

TEST_F(SecurePeerSnapshotStoreTest, AuthenticatedPeerRestores) {
    AppendBatches(1, 6, {{6, "key-2"}});
    auto& a = Start(0);
    Publish(a, 5, 10);
    a.Tick();
    auto& b = Start(1);
    auto restored = Restore(b);
    ASSERT_TRUE(restored.result) << toString(restored.result.error());
    ExpectIndex(*restored.metadata, 10, {"key-2"});
}

TEST_F(SecurePeerSnapshotStoreTest, UnauthenticatedFetchIsRefused) {
    AppendBatches(1, 6);
    auto& a = Start(0);
    const auto id = Publish(a, 5, 10);
    const std::string key =
        ha::BuildBatchOpLogSnapshotObjectChunkKey(root_, id, 0);
    coro_rpc::coro_rpc_client client;
    ASSERT_FALSE(async_simple::coro::syncAwait(
        client.connect("127.0.0.1", std::to_string(ports_[0]))));
    auto stat = async_simple::coro::syncAwait(
        client.call<&PeerSnapshotService::Stat>(key));
    ASSERT_FALSE(stat);
    EXPECT_EQ(secure::kUnauthenticated,
              static_cast<uint16_t>(stat.error().code.ec));
    auto read = async_simple::coro::syncAwait(
        client.call<&PeerSnapshotService::Read>(key, uint64_t{0},
                                                uint64_t{1} << 20));
    ASSERT_FALSE(read);
    EXPECT_EQ(secure::kUnauthenticated,
              static_cast<uint16_t>(read.error().code.ec));
}

#endif

}  // namespace mooncake::test
