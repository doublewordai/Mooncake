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

// Transparent KV encryption ("secure mode") shared by the transfer engine and
// the store.
//
// When secure mode is on, every byte Mooncake puts on the fabric is a sealed
// message: header || ciphertext || tag. The header is authenticated as
// associated data together with caller context (for the store, the object
// key), so a message cannot be moved to another key, purpose or algorithm.
//
// Keys come from files or environment variables (a Kubernetes Secret) and
// never leave the process. Each Sealer derives its own subkey with
// HKDF-SHA256(master key, random 128-bit salt, purpose, algorithm) and uses a
// 64-bit counter as the nonce, so nonces never repeat under one subkey: the
// salt is fresh per Sealer and per fork.
//
// Secure mode is off unless MC_SECURE_MODE is set; with it off nothing in this
// module runs and Mooncake behaves exactly as upstream.

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace mooncake {
namespace secure {

// ---------------------------------------------------------------- format --

inline constexpr uint32_t kMagic = 0x4553434dU;  // "MCSE" little-endian
inline constexpr uint8_t kFormatVersion = 1;
inline constexpr size_t kKeySize = 32;
inline constexpr size_t kSaltSize = 16;
inline constexpr size_t kNonceSize = 12;
inline constexpr size_t kTagSize = 16;
// magic(4) version(1) algorithm(1) purpose(1) flags(1) key_id(4) salt(16)
// nonce(12) plaintext_len(8)
inline constexpr size_t kHeaderSize = 48;
inline constexpr size_t kOverhead = kHeaderSize + kTagSize;

enum class Algorithm : uint8_t {
    kAes256Gcm = 1,
    kChaCha20Poly1305 = 2,
};

// Domain separation: a message sealed for one purpose never opens as another.
enum class Purpose : uint8_t {
    kStoreObject = 1,  // a value in the Mooncake store
    kTransfer = 2,     // a P->D (or any engine-to-engine) data push
    kControl = 3,      // a control message (e.g. commit / ack of a push)
};

enum class Error : int {
    kOk = 0,
    kDisabled,         // secure mode is off
    kNoKey,            // secure mode on, but no key could be loaded
    kBadConfig,        // malformed key or setting
    kUnknownKeyId,     // message sealed under a key we do not hold
    kBadHeader,        // not a sealed message, or wrong version/purpose/size
    kAuthFailed,       // tag did not verify: tampered, wrong key or wrong AAD
    kSizeMismatch,     // output buffers do not match the plaintext length
    kBufferTooSmall,   // sealed output buffer too small
    kUnsupported,      // algorithm or memory the backend cannot handle
    kCryptoError,      // the crypto library failed
    kNonceExhausted,   // counter space used up (practically unreachable)
};

const char* ToString(Error e);
const char* ToString(Algorithm a);

constexpr size_t SealedSize(size_t plaintext_len) {
    return plaintext_len + kOverhead;
}

// Returns false if `sealed_len` cannot be a sealed message.
inline bool PlaintextSize(size_t sealed_len, size_t* plaintext_len) {
    if (sealed_len < kOverhead) return false;
    *plaintext_len = sealed_len - kOverhead;
    return true;
}

struct ConstSpan {
    const void* data = nullptr;
    size_t size = 0;
};

struct MutableSpan {
    void* data = nullptr;
    size_t size = 0;
};

// Parsed, copied-out header of a sealed message.
struct SealedInfo {
    Algorithm algorithm{};
    Purpose purpose{};
    uint8_t flags = 0;
    uint32_t key_id = 0;
    std::array<uint8_t, kSaltSize> salt{};
    std::array<uint8_t, kNonceSize> nonce{};
    uint64_t plaintext_len = 0;
    // The nonce's counter (low 8 bytes, big-endian). Together with
    // (key_id, salt) it identifies the message: a receiver that wants replay
    // protection keeps a per-(key_id, salt) high-water mark or window.
    uint64_t counter() const;
};

// Copies the header out of `sealed` and checks magic, version, sizes and that
// `sealed.size == SealedSize(plaintext_len)`.
Error ParseHeader(ConstSpan sealed, SealedInfo* info);

// ------------------------------------------------------------------ keys --

class MasterKey {
   public:
    MasterKey(uint32_t id, const uint8_t bytes[kKeySize]);
    ~MasterKey();  // zeroizes
    MasterKey(const MasterKey&) = delete;
    MasterKey& operator=(const MasterKey&) = delete;
    uint32_t id() const { return id_; }
    const uint8_t* bytes() const { return bytes_.data(); }

   private:
    uint32_t id_;
    std::array<uint8_t, kKeySize> bytes_;
};

// Key ids are derived from the key (HMAC-SHA256(key, "mooncake key id")), so
// two processes holding the same key agree on its id with no extra setting.
uint32_t DeriveKeyId(const uint8_t key[kKeySize]);

// Parses a key in one of: 32 raw bytes, 64 hex digits, or base64 of 32 bytes
// (surrounding whitespace ignored).
Error ParseKeyMaterial(const std::string& text,
                       std::array<uint8_t, kKeySize>* out);

// The current key (used to seal) plus previous keys (accepted when opening),
// for rotation: roll out new-current + old-previous everywhere, then drop the
// old key once nothing sealed under it is still live.
class KeyRing {
   public:
    // keys[0] is the current key; the rest are accepted for opening only.
    static std::shared_ptr<const KeyRing> FromKeys(
        const std::vector<std::array<uint8_t, kKeySize>>& keys, Error* err);

    const MasterKey& current() const { return *keys_.front(); }
    // nullptr if the id is not held.
    const MasterKey* Find(uint32_t key_id) const;
    size_t size() const { return keys_.size(); }

   private:
    std::vector<std::unique_ptr<MasterKey>> keys_;
};

// --------------------------------------------------------------- config --

// Environment: the switch (MC_SECURE_MODE) and the key variables
// (MC_SECURE_KEY_FILE, MC_SECURE_KEY, MC_SECURE_PREVIOUS_KEY_FILE,
// MC_SECURE_PREVIOUS_KEY) are shared with control-plane authentication and
// documented in src/secure/secure_env.h. The data path's own settings:
//   MC_SECURE_AEAD                 aes-256-gcm (default) | chacha20-poly1305;
//                                  the algorithm this process seals with.
//                                  Opening accepts both.
//   MC_SECURE_STAGING_BYTES        size of each staging region (default 256MiB)
//   MC_SECURE_STAGING_MAX_BYTES    cap on all staging regions (default 4GiB)
struct SecureConfig {
    bool enabled = false;
    // Non-empty when the switch is on but misconfigured (fail closed).
    std::string switch_error;
    std::string key_file;
    std::string key_inline;
    std::string previous_key_file;
    std::string previous_key_inline;
    Algorithm algorithm = Algorithm::kAes256Gcm;
    size_t staging_region_bytes = 256ull << 20;
    size_t staging_max_bytes = 4ull << 30;

    static SecureConfig FromEnv();
};

// Loads the key ring named by `cfg`. On failure returns nullptr, sets *err
// and a reason in *why (never containing key material).
std::shared_ptr<const KeyRing> LoadKeyRing(const SecureConfig& cfg, Error* err,
                                           std::string* why);

// ------------------------------------------------------------- backends --

// One AEAD invocation. The backend reads `in` (a gather list) once and writes
// `out` (a scatter list of the same total length). For Open, if the tag does
// not verify the backend must zero every output span before returning
// kAuthFailed, so no unauthenticated plaintext survives the call.
struct AeadCall {
    Algorithm algorithm{};
    const uint8_t* key = nullptr;    // kKeySize subkey
    const uint8_t* nonce = nullptr;  // kNonceSize
    const ConstSpan* aad = nullptr;  // authenticated, not encrypted
    size_t aad_count = 0;
    const ConstSpan* in = nullptr;
    size_t in_count = 0;
    const MutableSpan* out = nullptr;
    size_t out_count = 0;
    uint8_t* tag_out = nullptr;       // Seal: kTagSize written here
    const uint8_t* tag_in = nullptr;  // Open: expected tag (already copied)
};

// The pluggable AEAD implementation. The host backend (OpenSSL, CPU) is always
// present. A GPU backend (e.g. a fused ChaCha20-Poly1305 kernel, or AES-GCM)
// can be registered with RegisterAeadBackend: it is then preferred for calls
// whose memory it reports it can access, and the wire format is unchanged, so
// a GPU sender and a CPU receiver interoperate as long as both support the
// header's algorithm.
class AeadBackend {
   public:
    virtual ~AeadBackend() = default;
    virtual const char* name() const = 0;
    virtual bool Supports(Algorithm a) const = 0;
    // Whether this backend can read/write [p, p+n) directly (e.g. host memory
    // for the CPU backend; device or host-pinned memory for a GPU backend).
    virtual bool CanAccess(const void* p, size_t n) const = 0;
    virtual Error Seal(const AeadCall& call) = 0;
    virtual Error Open(const AeadCall& call) = 0;
};

// The always-available OpenSSL backend (host memory only).
AeadBackend& HostAeadBackend();

// Registers an additional backend (process-wide, e.g. a CUDA one). Backends
// are tried most-recently-registered first; the host backend is the fallback.
void RegisterAeadBackend(std::shared_ptr<AeadBackend> backend);

// Picks a backend that supports `alg` and can access every span; nullptr if
// none can (the caller must then bounce through host memory).
AeadBackend* SelectAeadBackend(Algorithm alg, const ConstSpan* in,
                               size_t in_count, const MutableSpan* out,
                               size_t out_count);

// ---------------------------------------------------------- seal / open --

// HKDF-SHA256(master, salt, info = "mooncake-secure-v1" | alg | purpose).
Error DeriveSubkey(const MasterKey& master, const uint8_t salt[kSaltSize],
                   Algorithm alg, Purpose purpose,
                   std::array<uint8_t, kKeySize>* out);

// Seals messages for one purpose under the key ring's current key. Thread
// safe. Each instance draws a fresh random salt (and so a fresh subkey) and
// counts nonces from zero; after fork() the child redraws before sealing.
class Sealer {
   public:
    static std::unique_ptr<Sealer> Create(std::shared_ptr<const KeyRing> ring,
                                          Purpose purpose, Algorithm alg,
                                          Error* err);
    ~Sealer();

    // Seals the concatenation of `plaintext` into `out` (contiguous, at least
    // SealedSize(total) bytes). `aad` is caller context bound to the message
    // (e.g. the object key); the same bytes must be given to Open.
    Error Seal(const ConstSpan* plaintext, size_t count, ConstSpan aad,
               MutableSpan out, size_t* sealed_len);

    Purpose purpose() const { return purpose_; }
    Algorithm algorithm() const { return alg_; }
    uint32_t key_id() const;

    // For tests: forces the next Seal to redraw salt and subkey.
    void RotateForTesting();
    // For tests: sets the counter (to exercise exhaustion handling).
    void SetCounterForTesting(uint64_t value);

   private:
    struct State;
    Sealer(std::shared_ptr<const KeyRing> ring, Purpose purpose, Algorithm alg);
    Error Refresh();  // holds mu_

    std::shared_ptr<const KeyRing> ring_;
    Purpose purpose_;
    Algorithm alg_;
    std::mutex mu_;
    std::shared_ptr<State> state_;  // guarded by mu_ for swaps
};

// Opens messages sealed by any Sealer holding a key in the ring. Thread safe;
// caches derived subkeys per (key id, salt, algorithm, purpose).
class Opener {
   public:
    explicit Opener(std::shared_ptr<const KeyRing> ring);
    ~Opener();

    // Copies the header out of `sealed` once, checks `expected` purpose, then
    // decrypts the ciphertext into `out` (scatter list whose total size must
    // equal the plaintext length) in a single pass over the ciphertext and
    // verifies the tag. On any failure all of `out` is zeroed. `info`, if
    // given, receives the parsed header (for replay windows).
    Error Open(ConstSpan sealed, Purpose expected, ConstSpan aad,
               const MutableSpan* out, size_t count,
               SealedInfo* info = nullptr);

   private:
    struct Cache;
    std::shared_ptr<const KeyRing> ring_;
    std::unique_ptr<Cache> cache_;
};

// ------------------------------------------------------- process context --

// The process-wide secure-mode state, built once from SecureConfig::FromEnv().
class SecureContext {
   public:
    // Returns the process context. When secure mode is off, enabled() is
    // false and nothing else is meaningful.
    static SecureContext& Global();

    bool enabled() const { return enabled_; }
    // Secure mode was requested but could not start (e.g. no key). Callers
    // must refuse to run (fail closed).
    bool failed() const { return enabled_ && status_ != Error::kOk; }
    Error status() const { return status_; }
    const std::string& reason() const { return reason_; }
    const SecureConfig& config() const { return config_; }
    std::shared_ptr<const KeyRing> keys() const { return keys_; }

    // Process-shared sealer per purpose (the configured algorithm), and an
    // opener. Valid only when enabled() && !failed().
    Sealer& sealer(Purpose p);
    Opener& opener();

    // Tests: replace the process context (pass nullptr to rebuild from env on
    // next Global()).
    static void ResetForTesting(std::unique_ptr<SecureContext> ctx);
    static std::unique_ptr<SecureContext> CreateForTesting(
        const SecureConfig& cfg,
        std::shared_ptr<const KeyRing> keys /* null: load from cfg */);

   private:
    SecureContext() = default;
    static std::unique_ptr<SecureContext> Build(
        const SecureConfig& cfg, std::shared_ptr<const KeyRing> keys);

    bool enabled_ = false;
    Error status_ = Error::kDisabled;
    std::string reason_;
    SecureConfig config_;
    std::shared_ptr<const KeyRing> keys_;
    std::unique_ptr<Sealer> sealers_[4];
    std::unique_ptr<Opener> opener_;
};

// Shorthand: secure mode is on for this process.
inline bool SecureModeEnabled() { return SecureContext::Global().enabled(); }

}  // namespace secure
}  // namespace mooncake
