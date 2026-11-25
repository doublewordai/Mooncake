// The secure-mode switch and key source, shared by both halves of secure mode
// (DW-1288): the data path (kv_crypto) and control-plane authentication
// (control_auth). One switch turns both on and one Kubernetes Secret feeds
// both; each half derives its own subkeys from the keys read here, under its
// own labels, so the halves never share a key.
//
// Built only with -DWITH_SECURE_KV=ON. SECURE_KV.md in this directory has the
// deployment view.
//
//   MC_SECURE_MODE               1/true/on/yes turns secure mode on; 0/false/
//                                off/no or unset leaves it off; any other
//                                value turns it on with a configuration error
//                                (fail closed). MC_CONTROL_AUTH is an alias.
//   MC_SECURE_KEY_FILE           path of the key file (a mounted Secret): 32
//                                raw bytes, or one key per line as 64 hex
//                                digits or base64 of 32 bytes; the first key
//                                is current, later ones are previous keys.
//   MC_SECURE_KEY                one key inline, when no key file is named.
//   MC_SECURE_PREVIOUS_KEY_FILE  more previous keys (same format).
//   MC_SECURE_PREVIOUS_KEY       one previous key inline.
//
// MC_CONTROL_AUTH_KEY_FILE and MC_CONTROL_AUTH_KEY are aliases of
// MC_SECURE_KEY_FILE and MC_SECURE_KEY, read only when neither of those is
// set; their content must be in the key format above.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mooncake {
namespace secure_env {

constexpr size_t kKeySize = 32;
using Key = std::array<uint8_t, kKeySize>;

struct Switch {
    bool enabled = false;
    // Non-empty when the switch is on but misconfigured: callers fail closed.
    std::string error;
};

// Reads MC_SECURE_MODE and its alias MC_CONTROL_AUTH. On if either is on;
// an unrecognised value, or the two set to disagreeing values, is on with an
// error.
Switch ReadSwitch();

struct KeySources {
    std::string key_file;
    std::string key_inline;
    std::string previous_key_file;
    std::string previous_key_inline;
};

// Reads the key variables above, applying the aliases.
KeySources ReadKeySources();

enum class KeyError { kOk, kNoKey, kBadConfig };

// Loads the keys named by `src`, current key first. On failure returns the
// error and a reason in *why (never containing key material); *keys is left
// empty.
KeyError LoadKeys(const KeySources& src, std::vector<Key>* keys,
                  std::string* why);

// Parses one key: 64 hex digits or base64 of 32 bytes, surrounding
// whitespace ignored.
KeyError ParseKeyMaterial(const std::string& text, Key* out);

}  // namespace secure_env
}  // namespace mooncake
