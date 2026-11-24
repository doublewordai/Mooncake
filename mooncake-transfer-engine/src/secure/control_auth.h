// Control-plane authentication (secure mode).
//
// Every control-plane message — the transfer engine's P2P handshake, the
// store's coro_rpc requests and the master admin API's privileged routes —
// carries a tag: an HMAC-SHA256, under a key derived from a shared secret,
// over a timestamp, a random nonce, the channel it was made for and the data
// it vouches for. A receiver accepts a tag once, and only within the clock
// skew window. The secret itself never crosses the network.
//
// Built only with -DWITH_SECURE_KV=ON. Even then secure mode is off unless
// MC_CONTROL_AUTH is set, and off, no hook is installed and the wire format is
// upstream's. On, a process without a usable secret fails closed: it makes no
// tags and accepts none.
//
//   MC_CONTROL_AUTH           1/true/on/yes turns secure mode on; 0/false/off/
//                             no or unset leaves it off; any other value turns
//                             it on with a configuration error (fail closed).
//   MC_CONTROL_AUTH_KEY_FILE  path of the shared secret (a mounted Kubernetes
//                             Secret). Trailing whitespace is ignored.
//   MC_CONTROL_AUTH_KEY       the shared secret itself (a secretKeyRef env),
//                             used when no key file is named.
//   MC_CONTROL_AUTH_MAX_SKEW_MS  how far a tag's timestamp may differ from the
//                             receiver's clock (default 30000).
//
// The secret must be at least kMinSecretBytes long.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

namespace mooncake {
namespace control_auth {

// What a tag was made for. A tag made for one domain never verifies in
// another, so a handshake message cannot be replayed as an RPC. Handshake
// requests and responses share a domain (the framing hook does not know the
// direction), so an on-path attacker could reflect a request back to its
// sender as the response; that only hands the sender its own descriptor.
enum class Domain : uint8_t {
    kHandshake = 1,
    kRpcRequest = 3,
};

// magic(4) | timestamp ms, big-endian (8) | nonce (16) | HMAC-SHA256 (32)
constexpr size_t kTagMagicSize = 4;
constexpr size_t kTagNonceSize = 16;
constexpr size_t kTagMacSize = 32;
constexpr size_t kTagSize = kTagMagicSize + 8 + kTagNonceSize + kTagMacSize;
constexpr size_t kMinSecretBytes = 32;
constexpr int64_t kDefaultMaxSkewMs = 30000;

enum class Verdict {
    kOk,
    kNotReady,   // secure mode is on but this process has no usable key
    kMissing,    // no tag
    kMalformed,  // wrong size or magic
    kBadMac,     // wrong key, or the tag or the data it covers was altered
    kStale,      // timestamp outside the skew window
    kReplayed,   // this tag was already accepted
    kOverloaded, // the replay cache is full; refused rather than forgotten
};

const char *VerdictName(Verdict v);

// True when secure mode is on (whether or not the key loaded).
bool Enabled();
// True when secure mode is on and the key loaded: tags can be made and
// checked. Enabled() && !Ready() is a configuration error; callers fail
// closed.
bool Ready();
// Why secure mode is on but not ready; empty otherwise.
std::string ConfigError();

// A tag binding `bound` to `domain`, or an empty string if !Ready().
std::string MakeTag(Domain domain, std::string_view bound);

// Checks a tag. Only a tag with a valid MAC enters the replay cache, so
// forged tags cannot fill it.
Verdict VerifyTag(Domain domain, std::string_view tag, std::string_view bound);

// ---- Key loading and HMAC -------------------------------------------------
// These are the parts to merge with the data-path crypto module: it loads the
// same Kubernetes Secret and derives its own subkeys from it. The control
// plane's key is DeriveKey(secret, "mooncake control-auth v1"), so the two
// never share a key even if they share a secret.

// Reads the secret from MC_CONTROL_AUTH_KEY_FILE, else MC_CONTROL_AUTH_KEY.
// On failure returns nullopt and sets *error.
std::optional<std::string> LoadSecretFromEnvironment(std::string *error);

// HMAC-SHA256 over the concatenation of `parts`.
std::array<uint8_t, 32> HmacSha256(std::string_view key,
                                   std::initializer_list<std::string_view> parts);

// A 32-byte key for one purpose: HMAC-SHA256(secret, label).
std::string DeriveKey(std::string_view secret, std::string_view label);

// ---- Test seams -----------------------------------------------------------
// Replace the environment-derived state. An empty secret with enabled=true
// gives the fail-closed state.
void ConfigureForTesting(bool enabled, std::string secret,
                         int64_t max_skew_ms = kDefaultMaxSkewMs);
// Forget any configuration so the next call re-reads the environment.
void ResetForTesting();
// A tag with a chosen timestamp, for stale-timestamp tests.
std::string MakeTagAtForTesting(Domain domain, std::string_view bound,
                                int64_t timestamp_ms);

}  // namespace control_auth
}  // namespace mooncake
