#include "ha/snapshot/object/backends/peer/peer_snapshot_object_store.h"

#include <async_simple/coro/SyncAwait.h>
#include <glog/logging.h>
#include <unistd.h>

#if __has_include(<jsoncpp/json/json.h>)
#include <jsoncpp/json/json.h>
#else
#include <json/json.h>
#endif

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <ylt/coro_rpc/coro_rpc_client.hpp>

#include "crc32c.h"
#include "ha/kv/ha_kv_backend.h"
#include "ha/oplog/oplog_batch_types.h"
#include "ha/oplog/oplog_types.h"
#include "ha/snapshot/batch_oplog/metadata.h"
#include "rpc_registrar.h"

namespace mooncake {
namespace fs = std::filesystem;

namespace {

constexpr char kNotFoundPrefix[] = "File not found: ";
constexpr int64_t kExpireAfterStaleFactor = 10;

int64_t WallMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string Env(const char* name) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
}

bool SplitHostPort(const std::string& address, std::string& host,
                   uint16_t& port) {
    const size_t colon = address.rfind(':');
    if (colon == std::string::npos || colon == 0 ||
        colon + 1 == address.size()) {
        return false;
    }
    host = address.substr(0, colon);
    char* end = nullptr;
    const unsigned long value =
        std::strtoul(address.c_str() + colon + 1, &end, 10);
    if (*end != '\0' || value == 0 || value > 65535) return false;
    port = static_cast<uint16_t>(value);
    return true;
}

// "<root>/batch-oplog/<id>/..." -> "<id>"
std::string SnapshotIdOfKey(const std::string& namespace_prefix,
                            const std::string& key) {
    if (!key.starts_with(namespace_prefix)) return {};
    const size_t end = key.find('/', namespace_prefix.size());
    if (end == std::string::npos) return {};
    return key.substr(namespace_prefix.size(),
                      end - namespace_prefix.size());
}

// "<batch>-<lease>" -> batch
std::optional<uint64_t> BatchOfSnapshotId(const std::string& snapshot_id) {
    const size_t dash = snapshot_id.find('-');
    if (dash == 0 || dash == std::string::npos) return std::nullopt;
    uint64_t batch = 0;
    for (size_t i = 0; i < dash; ++i) {
        const char c = snapshot_id[i];
        if (c < '0' || c > '9') return std::nullopt;
        batch = batch * 10 + static_cast<uint64_t>(c - '0');
    }
    return batch;
}

template <typename T>
async_simple::coro::Lazy<T> Flatten(
    async_simple::coro::Lazy<async_simple::coro::Lazy<T>> outer) {
    auto inner = co_await std::move(outer);
    co_return co_await std::move(inner);
}

template <auto Method, typename... Args>
auto Call(coro_rpc::coro_rpc_client& client, Args&&... args) {
    return async_simple::coro::syncAwait(Flatten(
        RpcSendRequest<Method>(client, std::forward<Args>(args)...)));
}

}  // namespace

std::string PeerSnapshotRegistryPrefix(const std::string& cluster_id) {
    std::string normalized = cluster_id;
    if (!NormalizeAndValidateClusterId(normalized) || normalized.empty()) {
        return {};
    }
    return "mooncake-store/" + normalized + "/snapshot_peers/";
}

std::string PeerSnapshotEpochKey(const std::string& cluster_id) {
    std::string normalized = cluster_id;
    if (!NormalizeAndValidateClusterId(normalized) || normalized.empty()) {
        return {};
    }
    return "mooncake-store/" + normalized + "/snapshot_epoch";
}

PeerSnapshotStoreOptions PeerSnapshotStoreOptions::FromEnvironment(
    std::string cluster_id) {
    PeerSnapshotStoreOptions options;
    options.cluster_id = std::move(cluster_id);
    options.local_path = Env("MOONCAKE_SNAPSHOT_LOCAL_PATH");
    options.advertise_address = Env("MOONCAKE_SNAPSHOT_PEER_ADDRESS");
    options.bind_host = Env("MOONCAKE_SNAPSHOT_PEER_BIND");
    const std::string holders = Env("MOONCAKE_SNAPSHOT_PEER_MIN_HOLDERS");
    if (!holders.empty()) {
        char* end = nullptr;
        const unsigned long value = std::strtoul(holders.c_str(), &end, 10);
        if (*end != '\0' || value == 0) {
            throw std::invalid_argument(
                "MOONCAKE_SNAPSHOT_PEER_MIN_HOLDERS must be a positive "
                "integer");
        }
        options.min_holders = value;
    }
    const std::string grace = Env("MOONCAKE_SNAPSHOT_PEER_RESET_GRACE_S");
    if (!grace.empty()) {
        char* end = nullptr;
        const long value = std::strtol(grace.c_str(), &end, 10);
        if (*end != '\0' || value < 0) {
            throw std::invalid_argument(
                "MOONCAKE_SNAPSHOT_PEER_RESET_GRACE_S must be a non-negative "
                "integer");
        }
        options.reset_grace = std::chrono::seconds(value);
    }
    if (options.local_path.empty()) {
        throw std::invalid_argument(
            "the peer snapshot store needs MOONCAKE_SNAPSHOT_LOCAL_PATH");
    }
    if (options.advertise_address.empty()) {
        throw std::invalid_argument(
            "the peer snapshot store needs MOONCAKE_SNAPSHOT_PEER_ADDRESS "
            "(host:port it serves snapshots on)");
    }
    return options;
}

// ---------------------------------------------------------------- service --

std::optional<fs::path> PeerSnapshotService::Resolve(
    const std::string& key) const {
    if (!key.starts_with(namespace_prefix_) || key.find("..") !=
            std::string::npos || key.find("//") != std::string::npos ||
        key.find('\0') != std::string::npos || key.ends_with('/')) {
        return std::nullopt;
    }
    std::error_code ec;
    const fs::path path = fs::weakly_canonical(base_ / key, ec);
    if (ec) return std::nullopt;
    auto [base_end, ignored] =
        std::mismatch(base_.begin(), base_.end(), path.begin(), path.end());
    (void)ignored;
    if (base_end != base_.end()) return std::nullopt;
    return path;
}

PeerSnapshotStatResponse PeerSnapshotService::Stat(std::string key) {
    const auto path = Resolve(key);
    if (!path) return {.status = kRefused, .size = 0};
    std::error_code ec;
    if (!fs::is_regular_file(*path, ec)) return {.status = kNotFound};
    const uint64_t size = fs::file_size(*path, ec);
    if (ec) return {.status = kError};
    return {.status = kOk, .size = size};
}

PeerSnapshotReadResponse PeerSnapshotService::Read(std::string key,
                                                   uint64_t offset,
                                                   uint64_t length) {
    const auto path = Resolve(key);
    if (!path) return {.status = kRefused};
    std::ifstream file(*path, std::ios::binary);
    if (!file) return {.status = kNotFound};
    PeerSnapshotReadResponse response;
    response.data.resize(std::min(length, kMaxReadBytes));
    file.seekg(static_cast<std::streamoff>(offset));
    if (!file) return {.status = kError};
    file.read(response.data.data(),
              static_cast<std::streamsize>(response.data.size()));
    response.data.resize(static_cast<size_t>(file.gcount()));
    response.status = kOk;
    return response;
}

// ------------------------------------------------------------------ store --

PeerSnapshotObjectStore::PeerSnapshotObjectStore(
    PeerSnapshotStoreOptions options, HaKvBackend& backend)
    : options_(std::move(options)),
      backend_(backend),
      snapshot_root_(ha::BuildBatchOpLogSnapshotRoot(options_.cluster_id)),
      namespace_prefix_(snapshot_root_ + "/batch-oplog/"),
      registry_key_(PeerSnapshotRegistryPrefix(options_.cluster_id) +
                    options_.advertise_address),
      local_(options_.local_path) {
    if (snapshot_root_.empty() ||
        PeerSnapshotRegistryPrefix(options_.cluster_id).empty()) {
        throw std::invalid_argument(
            "the peer snapshot store needs a valid cluster_id");
    }
    std::string host;
    uint16_t port = 0;
    if (!SplitHostPort(options_.advertise_address, host, port)) {
        throw std::invalid_argument("bad peer snapshot address '" +
                                    options_.advertise_address +
                                    "' (want host:port)");
    }
    if (options_.min_holders == 0) options_.min_holders = 1;
    base_ = fs::canonical(options_.local_path);
    service_ = std::make_unique<PeerSnapshotService>(base_, namespace_prefix_);
    const std::string bind =
        options_.bind_host.empty() ? host : options_.bind_host;
    server_ = std::make_unique<coro_rpc::coro_rpc_server>(
        /*thread_num=*/2, port, bind, std::chrono::seconds(0),
        /*tcp_no_delay=*/true);
    RpcRegistrar(*server_)
        .register_handler<&PeerSnapshotService::Stat,
                          &PeerSnapshotService::Read>(service_.get());
    auto started = server_->async_start();
    if (started.hasResult()) {
        throw std::runtime_error("peer snapshot server failed to listen on " +
                                 bind + ":" + std::to_string(port));
    }
    LOG(INFO) << "Peer snapshot store: serving " << base_ << " on " << bind
              << ":" << port << ", announced as "
              << options_.advertise_address << " under " << registry_key_
              << ", min_holders=" << options_.min_holders;
    if (options_.background) {
        worker_ = std::thread(&PeerSnapshotObjectStore::Loop, this);
    }
}

PeerSnapshotObjectStore::~PeerSnapshotObjectStore() { Shutdown(); }

void PeerSnapshotObjectStore::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(loop_mutex_);
        if (shut_down_) return;
        shut_down_ = true;
        stop_ = true;
    }
    loop_cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    // Leave the registry first, so nobody picks this peer while it goes.
    const ErrorCode err =
        backend_.DeleteRange(registry_key_, registry_key_ + '\0');
    if (err != ErrorCode::OK) {
        LOG(WARNING) << "Peer snapshot store: registry entry " << registry_key_
                     << " not removed (" << toString(err)
                     << "); it goes stale";
    }
    if (server_) {
        server_->stop();
        server_.reset();
    }
}

void PeerSnapshotObjectStore::Loop() {
    while (true) {
        {
            // Wait first: the supervisor connects etcd after constructing us.
            std::unique_lock<std::mutex> lock(loop_mutex_);
            loop_cv_.wait_for(lock, options_.tick, [this] { return stop_; });
            if (stop_) return;
        }
        try {
            Tick();
        } catch (const std::exception& e) {
            LOG(WARNING) << "Peer snapshot store tick failed: " << e.what();
        }
    }
}

// --------------------------------------------------- SnapshotObjectStore --

tl::expected<void, std::string> PeerSnapshotObjectStore::UploadBuffer(
    const std::string& key, const std::vector<uint8_t>& buffer) {
    return local_.UploadBuffer(key, buffer);
}

tl::expected<void, std::string> PeerSnapshotObjectStore::UploadString(
    const std::string& key, const std::string& data) {
    return local_.UploadString(key, data);
}

tl::expected<void, std::string> PeerSnapshotObjectStore::DownloadBuffer(
    const std::string& key, std::vector<uint8_t>& buffer) {
    auto result = local_.DownloadBuffer(key, buffer);
    if (result || !local_.IsNotFoundError(result.error())) return result;
    if (auto error = FetchFromPeers(key)) return tl::make_unexpected(*error);
    return local_.DownloadBuffer(key, buffer);
}

tl::expected<void, std::string> PeerSnapshotObjectStore::DownloadString(
    const std::string& key, std::string& data) {
    auto result = local_.DownloadString(key, data);
    if (result || !local_.IsNotFoundError(result.error())) return result;
    if (auto error = FetchFromPeers(key)) return tl::make_unexpected(*error);
    return local_.DownloadString(key, data);
}

tl::expected<SnapshotObjectInspection, std::string>
PeerSnapshotObjectStore::InspectObject(const std::string& key) {
    auto result = local_.InspectObject(key);
    if (result || !local_.IsNotFoundError(result.error())) return result;
    if (auto error = FetchFromPeers(key)) return tl::make_unexpected(*error);
    return local_.InspectObject(key);
}

tl::expected<void, std::string>
PeerSnapshotObjectStore::DeleteObjectsWithPrefix(const std::string& prefix) {
    const std::string id = SnapshotIdOfKey(namespace_prefix_, prefix);
    if (!id.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        verified_.erase(id);
    }
    return local_.DeleteObjectsWithPrefix(prefix);
}

tl::expected<void, std::string> PeerSnapshotObjectStore::ListObjectsWithPrefix(
    const std::string& prefix, std::vector<std::string>& object_keys) {
    // Local only: the caller (snapshot GC) cleans this master's directory.
    return local_.ListObjectsWithPrefix(prefix, object_keys);
}

bool PeerSnapshotObjectStore::IsNotFoundError(const std::string& error) const {
    return local_.IsNotFoundError(error) || error.starts_with(kNotFoundPrefix);
}

std::string PeerSnapshotObjectStore::GetConnectionInfo() const {
    return "PeerSnapshotObjectStore: base_path=" + base_.string() +
           ", address=" + options_.advertise_address;
}

// ------------------------------------------------------------------ peers --

std::vector<PeerSnapshotObjectStore::Peer> PeerSnapshotObjectStore::LivePeers(
    std::vector<std::string>* expired) const {
    std::vector<Peer> peers;
    const std::string prefix = PeerSnapshotRegistryPrefix(options_.cluster_id);
    std::string end = prefix;
    end.back() = static_cast<char>(end.back() + 1);
    std::vector<KvPair> kvs;
    if (backend_.Range(prefix, end, 0, kvs) != ErrorCode::OK) return peers;
    const int64_t now = WallMs();
    for (const auto& kv : kvs) {
        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errors;
        std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
        if (!reader->parse(kv.value.data(), kv.value.data() + kv.value.size(),
                           &root, &errors) ||
            !root.isObject()) {
            if (expired) expired->push_back(kv.key);
            continue;
        }
        const std::string address = root.get("address", "").asString();
        const int64_t updated = root.get("updated_ms", 0).asInt64();
        // A master that died without leaving (SIGKILL, a lost node) leaves
        // its entry behind; anyone may remove it once it is long dead.
        if (expired && now - updated > kExpireAfterStaleFactor *
                                           options_.peer_stale_after.count()) {
            expired->push_back(kv.key);
        }
        if (address.empty() || address == options_.advertise_address ||
            now - updated > options_.peer_stale_after.count()) {
            continue;
        }
        Peer peer{.address = address, .held = {}};
        for (const auto& id : root["held"]) peer.held.insert(id.asString());
        peers.push_back(std::move(peer));
    }
    return peers;
}

std::optional<std::string> PeerSnapshotObjectStore::FetchFromPeer(
    const std::string& address, const std::string& key, bool& not_found) {
    not_found = false;
    coro_rpc::coro_rpc_client client;
    client.get_config().request_timeout_duration = options_.request_timeout;
    auto ec = async_simple::coro::syncAwait(
        client.connect(std::string_view(address), options_.connect_timeout));
    if (ec) return "connect to " + address + " failed: " + std::string(ec.message());

    auto stat = Call<&PeerSnapshotService::Stat>(client, key);
    if (!stat) return "stat at " + address + " failed: " + stat.error().msg;
    const auto st = stat->result();
    if (st.status == PeerSnapshotService::kNotFound) {
        not_found = true;
        return address + " does not have it";
    }
    if (st.status != PeerSnapshotService::kOk) {
        return address + " refused or failed stat (" +
               std::to_string(st.status) + ")";
    }

    const fs::path final_path = base_ / key;
    std::error_code fs_ec;
    fs::create_directories(final_path.parent_path(), fs_ec);
    if (fs_ec) return "mkdir failed: " + fs_ec.message();
    const fs::path tmp =
        final_path.string() + ".fetch-" + std::to_string(::getpid()) + "-" +
        std::to_string(fetch_seq_.fetch_add(1));
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return "cannot write " + tmp.string();
        uint64_t offset = 0;
        while (offset < st.size) {
            const uint64_t want =
                std::min(st.size - offset, PeerSnapshotService::kMaxReadBytes);
            auto read =
                Call<&PeerSnapshotService::Read>(client, key, offset, want);
            if (!read || read->result().status != PeerSnapshotService::kOk ||
                read->result().data.empty()) {
                out.close();
                fs::remove(tmp, fs_ec);
                return "read at " + address + " failed at offset " +
                       std::to_string(offset) +
                       (read ? "" : ": " + read.error().msg);
            }
            const auto& data = read->result().data;
            out.write(data.data(), static_cast<std::streamsize>(data.size()));
            offset += data.size();
        }
        if (!out) {
            out.close();
            fs::remove(tmp, fs_ec);
            return "write of " + tmp.string() + " failed";
        }
    }
    fs::rename(tmp, final_path, fs_ec);
    if (fs_ec) {
        fs::remove(tmp, fs_ec);
        return "rename failed: " + fs_ec.message();
    }
    VLOG(1) << "Peer snapshot store: fetched " << key << " (" << st.size
            << " bytes) from " << address;
    return std::nullopt;
}

bool PeerSnapshotObjectStore::PeerAnswersFor(const std::string& address,
                                             const std::string& key) {
    coro_rpc::coro_rpc_client client;
    client.get_config().request_timeout_duration = options_.connect_timeout;
    if (async_simple::coro::syncAwait(client.connect(
            std::string_view(address), options_.connect_timeout))) {
        return false;
    }
    auto stat = Call<&PeerSnapshotService::Stat>(client, key);
    return stat && stat->result().status == PeerSnapshotService::kOk;
}

std::optional<std::string> PeerSnapshotObjectStore::FetchFromPeers(
    const std::string& key) {
    if (!service_->Resolve(key)) {
        return std::string(kNotFoundPrefix) + key + " (outside the namespace)";
    }
    auto peers = LivePeers();
    const std::string id = SnapshotIdOfKey(namespace_prefix_, key);
    // Peers that announce the snapshot first.
    std::stable_partition(peers.begin(), peers.end(), [&](const Peer& p) {
        return p.held.contains(id);
    });
    bool any_answered = false;
    std::string errors;
    for (const auto& peer : peers) {
        bool not_found = false;
        auto error = FetchFromPeer(peer.address, key, not_found);
        if (!error) return std::nullopt;
        any_answered = any_answered || not_found;
        errors += (errors.empty() ? "" : "; ") + *error;
    }
    if (any_answered || peers.empty()) {
        // Nobody reachable has it (an unreachable peer counts as not having
        // it once someone answered): a missing object, so the caller can
        // fall back to an older snapshot.
        return std::string(kNotFoundPrefix) + key + " (no live peer has it" +
               (errors.empty() ? "" : ": " + errors) + ")";
    }
    LOG(WARNING) << "Peer snapshot store: no peer reachable for " << key
                 << ": " << errors;
    return "peer fetch of " + key + " failed: " + errors;
}

// -------------------------------------------------------------- snapshots --

bool PeerSnapshotObjectStore::EnsureVerified(const std::string& key,
                                             uint64_t size, uint32_t crc) {
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::vector<uint8_t> bytes;
        auto read = DownloadBuffer(key, bytes);  // fetches if missing
        if (!read) return false;
        if (bytes.size() == size &&
            Crc32cValue(bytes.data(), bytes.size()) == crc) {
            return true;
        }
        LOG(WARNING) << "Peer snapshot store: local " << key
                     << " does not match its manifest; refetching";
        std::error_code ec;
        fs::remove(base_ / key, ec);
    }
    return false;
}

bool PeerSnapshotObjectStore::EnsureSnapshotLocal(
    const std::string& pointer_bytes) {
    const auto descriptor = ha::DecodeBatchOpLogSnapshotDescriptor(pointer_bytes);
    if (!descriptor) return false;
    const std::string& id = descriptor->snapshot_id;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (verified_.contains(id)) {
            std::error_code ec;
            if (fs::exists(base_ / descriptor->manifest_key, ec)) return true;
            verified_.erase(id);
        }
    }
    const std::string descriptor_key =
        ha::BuildBatchOpLogSnapshotDescriptorKey(snapshot_root_, id);
    if (descriptor_key.empty() ||
        descriptor->manifest_key !=
            ha::BuildBatchOpLogSnapshotManifestKey(snapshot_root_, id)) {
        return false;
    }
    if (!EnsureVerified(descriptor_key, pointer_bytes.size(),
                        Crc32cValue(pointer_bytes.data(), pointer_bytes.size())) ||
        !EnsureVerified(descriptor->manifest_key, descriptor->manifest_size,
                        descriptor->manifest_crc32c)) {
        return false;
    }
    std::string manifest_bytes;
    if (!local_.DownloadString(descriptor->manifest_key, manifest_bytes)) {
        return false;
    }
    const auto manifest = ha::DecodeBatchOpLogSnapshotManifest(manifest_bytes);
    if (!manifest || manifest->snapshot_id != id) return false;
    if (!EnsureVerified(manifest->segments.key, manifest->segments.stored_size,
                        manifest->segments.crc32c)) {
        return false;
    }
    for (const auto& chunk : manifest->object_chunks) {
        if (!EnsureVerified(chunk.key, chunk.stored_size, chunk.crc32c)) {
            return false;
        }
    }
    if (manifest->weight_metadata &&
        !EnsureVerified(manifest->weight_metadata->key,
                        manifest->weight_metadata->stored_size,
                        manifest->weight_metadata->crc32c)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (verified_.insert(id).second) {
        LOG(INFO) << "Peer snapshot store: holds snapshot " << id
                  << " (batch " << descriptor->last_included_batch_id << ")";
    }
    return true;
}

std::set<std::string> PeerSnapshotObjectStore::HeldSnapshots() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return verified_;
}

bool PeerSnapshotObjectStore::RetainedForPruning(
    const std::string& artifact_prefix) {
    const std::string id = SnapshotIdOfKey(namespace_prefix_, artifact_prefix);
    if (id.empty()) return false;
    // This master: the pruning caller has just validated the snapshot, which
    // fetched anything missing; verify it in full.
    std::string pointer;
    size_t holders = 0;
    if (local_.DownloadString(
            ha::BuildBatchOpLogSnapshotDescriptorKey(snapshot_root_, id),
            pointer) &&
        EnsureSnapshotLocal(pointer)) {
        holders = 1;
    }
    for (const auto& peer : LivePeers()) holders += peer.held.contains(id);
    if (holders < options_.min_holders) {
        LOG(INFO) << "Peer snapshot store: not pruning behind snapshot " << id
                  << " yet: " << holders << " live holder(s), want "
                  << options_.min_holders;
        return false;
    }
    return true;
}

void PeerSnapshotObjectStore::CollectLocalGarbage(uint64_t keep_from_batch) {
    std::vector<std::string> objects;
    if (!local_.ListObjectsWithPrefix(namespace_prefix_, objects)) return;
    std::set<std::string> ids;
    for (const auto& object : objects) {
        const std::string id = SnapshotIdOfKey(namespace_prefix_, object);
        if (!id.empty()) ids.insert(id);
    }
    for (const auto& id : ids) {
        const auto batch = BatchOfSnapshotId(id);
        // Older than the fallback: no pointer names it and none will again.
        // Newer ones may be a candidate being written, or the next latest.
        if (!batch || *batch >= keep_from_batch) continue;
        auto removed = DeleteObjectsWithPrefix(namespace_prefix_ + id + "/");
        if (removed) {
            LOG(INFO) << "Peer snapshot store: dropped superseded snapshot "
                      << id;
        }
    }
}

void PeerSnapshotObjectStore::Announce(bool force) {
    Json::Value root;
    root["address"] = options_.advertise_address;
    Json::Value held(Json::arrayValue);
    for (const auto& id : HeldSnapshots()) held.append(id);
    root["held"] = held;
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    const std::string what = Json::writeString(builder, held);
    const auto now = std::chrono::steady_clock::now();
    if (!force && what == last_announced_ &&
        now - last_announce_ < options_.announce_every) {
        return;
    }
    root["updated_ms"] = Json::Int64(WallMs());
    const ErrorCode err =
        backend_.Put(registry_key_, Json::writeString(builder, root));
    if (err == ErrorCode::OK) {
        last_announced_ = what;
        last_announce_ = now;
    } else {
        LOG(WARNING) << "Peer snapshot store: announce failed: "
                     << toString(err);
    }
}

void PeerSnapshotObjectStore::Tick() {
    // A reset elsewhere made every local snapshot stale.
    std::string epoch;
    const ErrorCode epoch_error =
        backend_.Get(PeerSnapshotEpochKey(options_.cluster_id), epoch);
    if (epoch_error == ErrorCode::OK || epoch_error == ErrorCode::ETCD_KEY_NOT_EXIST) {
        std::optional<std::string> now_epoch;
        if (epoch_error == ErrorCode::OK) now_epoch = epoch;
        if (seen_epoch_ && *seen_epoch_ != now_epoch.value_or("")) {
            LOG(WARNING) << "Peer snapshot store: snapshot epoch changed to "
                         << now_epoch.value_or("(none)")
                         << "; dropping local snapshots";
            WipeLocalSnapshots();
        }
        seen_epoch_ = now_epoch.value_or("");
    }

    std::optional<uint64_t> keep_from;
    std::optional<std::string> raw[2];
    int i = 0;
    for (const auto& key :
         {ha::BuildBatchOpLogSnapshotLatestKey(options_.cluster_id),
          ha::BuildBatchOpLogSnapshotFallbackKey(options_.cluster_id)}) {
        std::string pointer;
        const int slot = i++;
        if (backend_.Get(key, pointer) != ErrorCode::OK) continue;
        raw[slot] = pointer;
        const auto descriptor = ha::DecodeBatchOpLogSnapshotDescriptor(pointer);
        if (!descriptor) continue;
        keep_from = std::min(keep_from.value_or(UINT64_MAX),
                             descriptor->last_included_batch_id);
        if (!EnsureSnapshotLocal(pointer)) {
            LOG(WARNING) << "Peer snapshot store: snapshot "
                         << descriptor->snapshot_id
                         << " is not available locally yet";
        }
    }
    if (keep_from) CollectLocalGarbage(*keep_from);
    Announce(false);
    std::vector<std::string> expired;
    LivePeers(&expired);
    for (const auto& key : expired) {
        if (key != registry_key_ &&
            backend_.DeleteRange(key, key + '\0') == ErrorCode::OK) {
            LOG(INFO) << "Peer snapshot store: removed expired entry " << key;
        }
    }
    MaybeReset(raw[0], raw[1]);
}

void PeerSnapshotObjectStore::WipeLocalSnapshots() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        verified_.clear();
    }
    std::error_code ec;
    fs::remove_all(base_ / namespace_prefix_, ec);
}

void PeerSnapshotObjectStore::FinishReset() {
    const std::string& c = options_.cluster_id;
    const std::string first = BuildBatchRecordKey(c, 0);
    std::string batches = first.substr(0, first.rfind('/') + 1);
    std::string batches_end = batches;
    batches_end.back() = static_cast<char>(batches_end.back() + 1);
    // Batches before the durable prefix, the prefix before the floor, the
    // floor before the pointers: a standby restoring in between sees either a
    // floor it cannot reach (and waits) or nothing at all (and starts empty).
    const std::string floor_key = ha::BuildBatchOpLogSnapshotCompactionFloorKey(c);
    const std::string prefix_key = BuildDurablePrefixKey(c);
    for (const auto& [begin, end] :
         {std::pair{batches, batches_end},
          std::pair{prefix_key, prefix_key + '\0'},
          std::pair{floor_key, floor_key + '\0'}}) {
        const ErrorCode err = backend_.DeleteRange(begin, end);
        if (err != ErrorCode::OK) {
            LOG(ERROR) << "Peer snapshot store: reset of cluster " << c
                       << " stopped deleting at " << begin << " ("
                       << toString(err) << "); a later tick finishes it";
            return;
        }
    }
    for (const auto& key : {ha::BuildBatchOpLogSnapshotLatestKey(c),
                            ha::BuildBatchOpLogSnapshotFallbackKey(c)}) {
        std::string value;
        if (backend_.Get(key, value) == ErrorCode::OK &&
            value == kPeerSnapshotResetMarker) {
            backend_.DeleteRange(key, key + '\0');
        }
    }
    WipeLocalSnapshots();
    LOG(ERROR) << "Peer snapshot store: RESET of cluster " << c
               << " complete: the OpLog and snapshot pointers are gone and "
                  "the next leader starts with an empty index";
}

void PeerSnapshotObjectStore::MaybeReset(
    const std::optional<std::string>& latest,
    const std::optional<std::string>& fallback) {
    if (options_.reset_grace.count() <= 0) return;
    const std::string& c = options_.cluster_id;
    const std::string view_key = "mooncake-store/" + c + "/master_view";
    std::string view;
    const ErrorCode view_error = backend_.Get(view_key, view);
    if (view_error != ErrorCode::OK && view_error != ErrorCode::ETCD_KEY_NOT_EXIST) {
        return;
    }
    const bool view_exists = view_error == ErrorCode::OK;
    // A view that is not a warming marker is a leader serving.
    const bool leader_serving =
        view_exists && !view.starts_with("__mooncake_service_warming__:");
    auto reset_clock = [&](const char* why) {
        if (unrestorable_since_) {
            LOG(WARNING) << "Peer snapshot store: cluster " << c
                         << " no longer pending reset: " << why;
        }
        unrestorable_since_.reset();
    };
    if (leader_serving) return reset_clock("a leader is serving");

    if (latest.value_or("") == kPeerSnapshotResetMarker ||
        fallback.value_or("") == kPeerSnapshotResetMarker) {
        LOG(ERROR) << "Peer snapshot store: finishing an interrupted reset of "
                   << c;
        FinishReset();
        return reset_clock("reset finished");
    }

    std::string floor_value;
    uint64_t floor = 0;
    if (backend_.Get(ha::BuildBatchOpLogSnapshotCompactionFloorKey(c),
                     floor_value) != ErrorCode::OK) {
        return reset_clock("no compaction floor");
    }
    {
        char* end = nullptr;
        floor = std::strtoull(floor_value.c_str(), &end, 10);
        if (floor == 0) return reset_clock("floor is 0");
    }
    // Usable: a pointer at or above the floor that some live master holds.
    const auto peers = LivePeers();
    for (const auto* pointer : {&latest, &fallback}) {
        if (!*pointer) continue;
        const auto d = ha::DecodeBatchOpLogSnapshotDescriptor(**pointer);
        if (!d || d->last_included_batch_id < floor) continue;
        if (HeldSnapshots().contains(d->snapshot_id)) {
            return reset_clock("this master holds a snapshot");
        }
        // A registry entry stays fresh for a while after its master dies:
        // a holder counts only if it answers for the snapshot now.
        const std::string descriptor_key =
            ha::BuildBatchOpLogSnapshotDescriptorKey(snapshot_root_,
                                                     d->snapshot_id);
        for (const auto& peer : peers) {
            if (peer.held.contains(d->snapshot_id) &&
                PeerAnswersFor(peer.address, descriptor_key)) {
                return reset_clock("a live master holds a snapshot");
            }
        }
    }

    const auto now = std::chrono::steady_clock::now();
    if (!unrestorable_since_) {
        unrestorable_since_ = now;
        LOG(ERROR) << "Peer snapshot store: cluster " << c
                   << " cannot be restored: the OpLog is pruned through batch "
                   << floor << " and no live master holds the latest or "
                   << "fallback snapshot. Resetting it to empty in "
                   << options_.reset_grace.count() / 1000
                   << " s unless a holder or a leader appears";
        return;
    }
    if (now - *unrestorable_since_ < options_.reset_grace) return;

    // Fence on everything observed: any change since means someone else moved.
    std::string epoch;
    const ErrorCode epoch_error = backend_.Get(PeerSnapshotEpochKey(c), epoch);
    if (epoch_error != ErrorCode::OK && epoch_error != ErrorCode::ETCD_KEY_NOT_EXIST) {
        return;
    }
    const bool epoch_exists = epoch_error == ErrorCode::OK;
    const uint64_t next_epoch =
        (epoch_exists ? std::strtoull(epoch.c_str(), nullptr, 10) : 0) + 1;
    auto same = [](const std::string& key,
                   const std::optional<std::string>& value) {
        return value ? KvCompare{.key = key,
                                 .kind = KvCompareKind::kValueEquals,
                                 .expected_value = *value}
                     : KvCompare{.key = key,
                                 .kind = KvCompareKind::kKeyNotExists};
    };
    KvTxn txn;
    txn.compares = {
        same(ha::BuildBatchOpLogSnapshotLatestKey(c), latest),
        same(ha::BuildBatchOpLogSnapshotFallbackKey(c), fallback),
        same(ha::BuildBatchOpLogSnapshotCompactionFloorKey(c), floor_value),
        same(view_key, view_exists ? std::optional<std::string>(view)
                                   : std::nullopt),
        same(ha::BuildBatchOpLogSnapshotMaintenanceKey(c), std::nullopt),
        same(PeerSnapshotEpochKey(c),
             epoch_exists ? std::optional<std::string>(epoch) : std::nullopt)};
    txn.puts = {{.key = ha::BuildBatchOpLogSnapshotLatestKey(c),
                 .value = kPeerSnapshotResetMarker},
                {.key = ha::BuildBatchOpLogSnapshotFallbackKey(c),
                 .value = kPeerSnapshotResetMarker},
                {.key = PeerSnapshotEpochKey(c),
                 .value = std::to_string(next_epoch)}};
    const ErrorCode err = backend_.Txn(txn);
    if (err != ErrorCode::OK) {
        LOG(WARNING) << "Peer snapshot store: reset of " << c
                     << " not taken (" << toString(err)
                     << "); the cluster changed or another master reset it";
        unrestorable_since_.reset();
        return;
    }
    seen_epoch_ = std::to_string(next_epoch);
    LOG(ERROR) << "Peer snapshot store: RESETTING cluster " << c
               << " to EMPTY (snapshot epoch " << next_epoch
               << "): unrestorable for "
               << std::chrono::duration_cast<std::chrono::seconds>(
                      now - *unrestorable_since_)
                      .count()
               << " s with the OpLog pruned through batch " << floor
               << " and no live holder of its snapshots. Every cached object "
                  "is forgotten; clients see misses";
    unrestorable_since_.reset();
    FinishReset();
}

std::unique_ptr<SnapshotObjectStore> CreatePeerSnapshotObjectStore(
    const std::string& cluster_id, HaKvBackend& backend) {
    return std::make_unique<PeerSnapshotObjectStore>(
        PeerSnapshotStoreOptions::FromEnvironment(cluster_id), backend);
}

}  // namespace mooncake
