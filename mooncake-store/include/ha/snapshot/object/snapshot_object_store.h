#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <ylt/util/tl/expected.hpp>

namespace mooncake {

// Snapshot object store type enumeration
enum class SnapshotObjectStoreType {
    LOCAL_FILE = 0,  // Local file system
    S3 = 1,          // S3 storage
    PEER = 2         // Local file system, served to and fetched from peers
};

struct SnapshotObjectInspection {
    uint64_t stored_size{0};
    std::optional<uint32_t> crc32c;
};

// Convert string to SnapshotObjectStoreType
inline SnapshotObjectStoreType ParseSnapshotObjectStoreType(
    const std::string& type_str) {
#ifdef HAVE_AWS_SDK
    if (type_str == "s3" || type_str == "S3") {
        return SnapshotObjectStoreType::S3;
    }
#else
    if (type_str == "s3" || type_str == "S3") {
        throw std::invalid_argument(
            "S3 snapshot object store requested but AWS SDK is not "
            "available. Please rebuild with HAVE_AWS_SDK or use the "
            "'local' object store.");
    }
#endif
    if (type_str == "local" || type_str == "LOCAL") {
        return SnapshotObjectStoreType::LOCAL_FILE;
    }
    if (type_str == "peer" || type_str == "PEER") {
        return SnapshotObjectStoreType::PEER;
    }

    // Unknown object store type - fail fast.
    throw std::invalid_argument("Unknown snapshot object store type: '" +
                                type_str + "'");
}

// Convert SnapshotObjectStoreType to string
inline std::string SnapshotObjectStoreTypeToString(
    SnapshotObjectStoreType type) {
    switch (type) {
        case SnapshotObjectStoreType::S3:
            return "s3";
        case SnapshotObjectStoreType::LOCAL_FILE:
            return "local";
        case SnapshotObjectStoreType::PEER:
            return "peer";
        default:
            throw std::invalid_argument("Unknown SnapshotObjectStoreType: " +
                                        std::to_string(static_cast<int>(type)));
    }
}

/**
 * @brief Abstract interface for snapshot object storage
 *
 * Defines a unified storage interface for snapshot objects across
 * different implementations (S3, local file system, etc.)
 */
class SnapshotObjectStore {
   public:
    virtual ~SnapshotObjectStore() = default;

    /**
     * @brief Upload binary data
     * @param key Storage key (path)
     * @param buffer Binary data
     * @return Empty on success, error message on failure
     */
    virtual tl::expected<void, std::string> UploadBuffer(
        const std::string& key, const std::vector<uint8_t>& buffer) = 0;

    /**
     * @brief Download binary data (supports chunked download for large files)
     * @param key Storage key (path)
     * @param buffer Output buffer
     * @return Empty on success, error message on failure
     */
    virtual tl::expected<void, std::string> DownloadBuffer(
        const std::string& key, std::vector<uint8_t>& buffer) = 0;

    /**
     * @brief Upload string data
     * @param key Storage key (path)
     * @param data String data
     * @return Empty on success, error message on failure
     */
    virtual tl::expected<void, std::string> UploadString(
        const std::string& key, const std::string& data) = 0;

    /**
     * @brief Download string data
     * @param key Storage key (path)
     * @param data Output string
     * @return Empty on success, error message on failure
     */
    virtual tl::expected<void, std::string> DownloadString(
        const std::string& key, std::string& data) = 0;

    /**
     * @brief Delete all objects with specified prefix
     * @param prefix Prefix
     * @return Empty on success, error message on failure
     */
    virtual tl::expected<void, std::string> DeleteObjectsWithPrefix(
        const std::string& prefix) = 0;

    /**
     * @brief List all objects with specified prefix
     * @param prefix Prefix
     * @param object_keys Output list of object keys
     * @return Empty on success, error message on failure
     */
    virtual tl::expected<void, std::string> ListObjectsWithPrefix(
        const std::string& prefix, std::vector<std::string>& object_keys) = 0;

    /**
     * @brief Read stored size and an optional backend-verified CRC32C
     */
    virtual tl::expected<SnapshotObjectInspection, std::string> InspectObject(
        const std::string& key) {
        return tl::make_unexpected("Object inspection is not supported: " +
                                   key);
    }

    /**
     * @brief Tell whether an error means the target object is missing
     * @param error Store-specific error string
     * @return true when the error represents a missing object
     */
    virtual bool IsNotFoundError(const std::string& error) const {
        return false;
    }

    /**
     * @brief Whether the OpLog may be pruned behind the snapshot whose
     * artifacts live under `artifact_prefix`, i.e. a standby that starts with
     * no local state can still read it. A store every reader shares always
     * can; a store whose objects live on the masters themselves says so only
     * once enough live masters hold the snapshot.
     */
    virtual bool RetainedForPruning(const std::string& artifact_prefix) {
        (void)artifact_prefix;
        return true;
    }

    /**
     * @brief Get connection/configuration info (for logging)
     * @return Connection info string
     */
    virtual std::string GetConnectionInfo() const = 0;

    /**
     * @brief Factory method: create object store instance by type (PEER
     * needs the HA backend: CreatePeerSnapshotObjectStore)
     * @param type Object store type
     * @return Smart pointer to object store instance
     */
    static std::unique_ptr<SnapshotObjectStore> Create(
        SnapshotObjectStoreType type);
};

}  // namespace mooncake
