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

#include "secure_env.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace mooncake {
namespace secure_env {

namespace {

std::string EnvStr(const char* name) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
}

std::string Trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

bool ReadFile(const std::string& path, std::string* out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    *out = ss.str();
    return true;
}

// A key file holds either exactly 32 raw bytes, or one encoded key per
// non-empty line ('#' starts a comment line).
KeyError ParseKeyFile(const std::string& content, std::vector<Key>* keys) {
    if (content.size() == kKeySize) {
        Key k;
        std::memcpy(k.data(), content.data(), kKeySize);
        keys->push_back(k);
        return KeyError::kOk;
    }
    std::istringstream lines(content);
    std::string line;
    bool any = false;
    while (std::getline(lines, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        Key k;
        KeyError e = ParseKeyMaterial(line, &k);
        OPENSSL_cleanse(line.data(), line.size());
        if (e != KeyError::kOk) return e;
        keys->push_back(k);
        any = true;
    }
    return any ? KeyError::kOk : KeyError::kNoKey;
}

// 1 on, 0 off, -1 unrecognised; `set` reports whether the variable has a
// non-empty value.
int SwitchValue(const char* name, bool* set) {
    std::string v = EnvStr(name);
    std::transform(v.begin(), v.end(), v.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    *set = !v.empty();
    if (v.empty() || v == "0" || v == "false" || v == "off" || v == "no")
        return 0;
    if (v == "1" || v == "true" || v == "on" || v == "yes") return 1;
    return -1;
}

}  // namespace

Switch ReadSwitch() {
    Switch s;
    bool mode_set = false, alias_set = false;
    const int mode = SwitchValue("MC_SECURE_MODE", &mode_set);
    const int alias = SwitchValue("MC_CONTROL_AUTH", &alias_set);
    if (mode == 0 && alias == 0) return s;
    s.enabled = true;
    if (mode < 0)
        s.error = "MC_SECURE_MODE has an unrecognised value";
    else if (alias < 0)
        s.error = "MC_CONTROL_AUTH has an unrecognised value";
    else if (mode_set && alias_set && mode != alias)
        s.error = "MC_SECURE_MODE and MC_CONTROL_AUTH disagree";
    return s;
}

KeySources ReadKeySources() {
    KeySources s;
    s.key_file = EnvStr("MC_SECURE_KEY_FILE");
    s.key_inline = EnvStr("MC_SECURE_KEY");
    if (s.key_file.empty() && s.key_inline.empty()) {
        s.key_file = EnvStr("MC_CONTROL_AUTH_KEY_FILE");
        s.key_inline = EnvStr("MC_CONTROL_AUTH_KEY");
    }
    s.previous_key_file = EnvStr("MC_SECURE_PREVIOUS_KEY_FILE");
    s.previous_key_inline = EnvStr("MC_SECURE_PREVIOUS_KEY");
    return s;
}

KeyError ParseKeyMaterial(const std::string& text, Key* out) {
    std::string s = Trim(text);
    if (s.size() == 2 * kKeySize &&
        std::all_of(s.begin(), s.end(), [](char c) {
            return std::isxdigit(static_cast<unsigned char>(c));
        })) {
        for (size_t i = 0; i < kKeySize; ++i) {
            unsigned v = 0;
            std::sscanf(s.c_str() + 2 * i, "%2x", &v);
            (*out)[i] = static_cast<uint8_t>(v);
        }
        OPENSSL_cleanse(s.data(), s.size());
        return KeyError::kOk;
    }
    // base64 of 32 bytes is 44 chars with one '=' of padding.
    if (s.size() == 44 && s[43] == '=' && s[42] != '=') {
        uint8_t buf[34];
        int n = EVP_DecodeBlock(buf, reinterpret_cast<const uint8_t*>(s.data()),
                                static_cast<int>(s.size()));
        OPENSSL_cleanse(s.data(), s.size());
        if (n != 33) {
            OPENSSL_cleanse(buf, sizeof(buf));
            return KeyError::kBadConfig;
        }
        std::memcpy(out->data(), buf, kKeySize);
        OPENSSL_cleanse(buf, sizeof(buf));
        return KeyError::kOk;
    }
    OPENSSL_cleanse(s.data(), s.size());
    return KeyError::kBadConfig;
}

KeyError LoadKeys(const KeySources& src, std::vector<Key>* keys,
                  std::string* why) {
    keys->clear();
    auto fail = [&](KeyError e, const std::string& reason) {
        for (auto& k : *keys) OPENSSL_cleanse(k.data(), k.size());
        keys->clear();
        if (why) *why = reason;
        return e;
    };
    if (!src.key_file.empty()) {
        std::string content;
        if (!ReadFile(src.key_file, &content))
            return fail(KeyError::kNoKey,
                        "cannot read MC_SECURE_KEY_FILE " + src.key_file);
        KeyError e = ParseKeyFile(content, keys);
        OPENSSL_cleanse(content.data(), content.size());
        if (e != KeyError::kOk)
            return fail(e, "MC_SECURE_KEY_FILE " + src.key_file +
                               " holds no valid key (want 32 raw bytes, 64 hex "
                               "digits or base64)");
    } else if (!src.key_inline.empty()) {
        Key k;
        if (ParseKeyMaterial(src.key_inline, &k) != KeyError::kOk)
            return fail(KeyError::kBadConfig,
                        "MC_SECURE_KEY is not 64 hex digits or base64 of 32 "
                        "bytes");
        keys->push_back(k);
        OPENSSL_cleanse(k.data(), k.size());
    } else {
        return fail(KeyError::kNoKey,
                    "secure mode needs MC_SECURE_KEY_FILE or MC_SECURE_KEY");
    }
    if (!src.previous_key_file.empty()) {
        std::string content;
        if (!ReadFile(src.previous_key_file, &content))
            return fail(KeyError::kBadConfig,
                        "cannot read MC_SECURE_PREVIOUS_KEY_FILE " +
                            src.previous_key_file);
        KeyError e = ParseKeyFile(content, keys);
        OPENSSL_cleanse(content.data(), content.size());
        if (e != KeyError::kOk)
            return fail(KeyError::kBadConfig,
                        "MC_SECURE_PREVIOUS_KEY_FILE holds an invalid key");
    }
    if (!src.previous_key_inline.empty()) {
        Key k;
        if (ParseKeyMaterial(src.previous_key_inline, &k) != KeyError::kOk)
            return fail(KeyError::kBadConfig,
                        "MC_SECURE_PREVIOUS_KEY is not a valid key");
        keys->push_back(k);
        OPENSSL_cleanse(k.data(), k.size());
    }
    return KeyError::kOk;
}

}  // namespace secure_env
}  // namespace mooncake
