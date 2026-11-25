#include "control_auth.h"

#include "secure_env.h"

#include <glog/logging.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace mooncake {
namespace control_auth {
namespace {

constexpr char kMagic[kTagMagicSize] = {'M', 'C', 'A', '1'};
constexpr std::string_view kKeyLabel = "mooncake control-auth v1";
constexpr std::string_view kMacLabel = "mooncake control-auth tag v1";
constexpr size_t kReplayShards = 16;
constexpr size_t kDefaultReplayCapacity = 1u << 21;  // tags per skew window

struct State {
    bool enabled = false;
    bool ready = false;
    std::string error;
    std::string key;  // derived control-plane key (from the current key)
    // Derived from the previous keys: accepted when verifying, so a key
    // rotation does not cut the control plane.
    std::vector<std::string> previous_keys;
    int64_t max_skew_ms = kDefaultMaxSkewMs;
};

struct NonceKey {
    uint64_t hi, lo;
    bool operator==(const NonceKey &o) const {
        return hi == o.hi && lo == o.lo;
    }
};
struct NonceHash {
    size_t operator()(const NonceKey &k) const { return k.hi ^ (k.lo * 31); }
};

struct ReplayShard {
    std::mutex mu;
    std::unordered_map<NonceKey, int64_t, NonceHash> expiry;  // ms
    int64_t next_prune_ms = 0;
};

struct ReplayCache {
    ReplayShard shards[kReplayShards];
    size_t per_shard_capacity = kDefaultReplayCapacity / kReplayShards;
};

std::mutex g_state_mu;
std::atomic<const State *> g_state{nullptr};
// Never destroyed (used at exit); a function-local static so the hook
// installers, which run during static initialisation, can use it.
ReplayCache &Replay() {
    static ReplayCache *cache = new ReplayCache();
    return *cache;
}

int64_t NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

const State *BuildFromEnvironment() {
    auto *st = new State();
    // One switch and one key source for both halves of secure mode; see
    // secure_env.h.
    const secure_env::Switch sw = secure_env::ReadSwitch();
    if (!sw.enabled) return st;
    st->enabled = true;
    if (!sw.error.empty()) {
        st->error = sw.error;
        LOG(ERROR) << "control-auth: " << st->error
                   << "; secure mode is on and fails closed";
        return st;
    }
    if (const char *skew = std::getenv("MC_CONTROL_AUTH_MAX_SKEW_MS")) {
        char *end = nullptr;
        long long ms = std::strtoll(skew, &end, 10);
        if (end == skew || *end != '\0' || ms < 1000 || ms > 600000) {
            st->error = "MC_CONTROL_AUTH_MAX_SKEW_MS must be 1000..600000";
            LOG(ERROR) << "control-auth: " << st->error;
            return st;
        }
        st->max_skew_ms = ms;
    }
    std::vector<secure_env::Key> keys;
    std::string err;
    if (secure_env::LoadKeys(secure_env::ReadKeySources(), &keys, &err) !=
        secure_env::KeyError::kOk) {
        st->error = err;
        LOG(ERROR) << "control-auth: " << err
                   << "; secure mode is on and fails closed";
        return st;
    }
    for (size_t i = 0; i < keys.size(); ++i) {
        std::string_view k(reinterpret_cast<const char *>(keys[i].data()),
                           keys[i].size());
        if (i == 0)
            st->key = DeriveKey(k, kKeyLabel);
        else
            st->previous_keys.push_back(DeriveKey(k, kKeyLabel));
        OPENSSL_cleanse(keys[i].data(), keys[i].size());
    }
    st->ready = true;
    LOG(INFO) << "control-auth: secure mode on, max skew " << st->max_skew_ms
              << " ms, " << st->previous_keys.size() << " previous key(s)";
    return st;
}

const State &GetState() {
    const State *st = g_state.load(std::memory_order_acquire);
    if (st) return *st;
    std::lock_guard<std::mutex> lock(g_state_mu);
    st = g_state.load(std::memory_order_acquire);
    if (!st) {
        st = BuildFromEnvironment();
        g_state.store(st, std::memory_order_release);
    }
    return *st;
}

// Old states are leaked: another thread may still hold a reference, and
// replacement happens only in tests.
void ReplaceState(const State *st) {
    std::lock_guard<std::mutex> lock(g_state_mu);
    g_state.store(st, std::memory_order_release);
    for (auto &shard : Replay().shards) {
        std::lock_guard<std::mutex> l(shard.mu);
        shard.expiry.clear();
    }
}

void PutBigEndian64(char *out, int64_t v) {
    uint64_t u = static_cast<uint64_t>(v);
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<char>(u & 0xff);
        u >>= 8;
    }
}

int64_t GetBigEndian64(const char *in) {
    uint64_t u = 0;
    for (int i = 0; i < 8; ++i) u = (u << 8) | static_cast<uint8_t>(in[i]);
    return static_cast<int64_t>(u);
}

std::array<uint8_t, 32> TagMac(const std::string &key, Domain domain,
                               std::string_view header,
                               std::string_view bound) {
    const char d = static_cast<char>(domain);
    return HmacSha256(key, {kMacLabel, std::string_view(&d, 1), header, bound});
}

std::string BuildTag(const State &st, Domain domain, std::string_view bound,
                     int64_t ts_ms) {
    std::string tag(kTagSize, '\0');
    memcpy(&tag[0], kMagic, kTagMagicSize);
    PutBigEndian64(&tag[kTagMagicSize], ts_ms);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&tag[kTagMagicSize + 8]),
                   kTagNonceSize) != 1) {
        LOG(ERROR) << "control-auth: RAND_bytes failed";
        return "";
    }
    constexpr size_t header = kTagMagicSize + 8 + kTagNonceSize;
    auto mac = TagMac(st.key, domain, std::string_view(tag.data(), header),
                      bound);
    if (std::all_of(mac.begin(), mac.end(), [](uint8_t b) { return b == 0; }))
        return "";  // HMAC failed
    memcpy(&tag[header], mac.data(), kTagMacSize);
    return tag;
}

// Records the nonce until its timestamp leaves the window. False if seen.
Verdict Remember(const char *nonce, int64_t ts_ms, int64_t now_ms,
                 int64_t skew_ms) {
    NonceKey k;
    memcpy(&k.hi, nonce, 8);
    memcpy(&k.lo, nonce + 8, 8);
    auto &shard = Replay().shards[NonceHash{}(k) % kReplayShards];
    std::lock_guard<std::mutex> lock(shard.mu);
    if (now_ms >= shard.next_prune_ms) {
        for (auto it = shard.expiry.begin(); it != shard.expiry.end();) {
            if (it->second < now_ms)
                it = shard.expiry.erase(it);
            else
                ++it;
        }
        shard.next_prune_ms = now_ms + 1000;
    }
    auto it = shard.expiry.find(k);
    if (it != shard.expiry.end()) return Verdict::kReplayed;
    if (shard.expiry.size() >= Replay().per_shard_capacity)
        return Verdict::kOverloaded;
    shard.expiry.emplace(k, ts_ms + skew_ms);
    return Verdict::kOk;
}

}  // namespace

const char *VerdictName(Verdict v) {
    switch (v) {
        case Verdict::kOk:
            return "ok";
        case Verdict::kNotReady:
            return "secure mode has no usable key";
        case Verdict::kMissing:
            return "missing tag";
        case Verdict::kMalformed:
            return "malformed tag";
        case Verdict::kBadMac:
            return "bad MAC";
        case Verdict::kStale:
            return "timestamp outside skew window";
        case Verdict::kReplayed:
            return "replayed tag";
        case Verdict::kOverloaded:
            return "replay cache full";
    }
    return "unknown";
}

bool Enabled() { return GetState().enabled; }
bool Ready() { return GetState().ready; }
std::string ConfigError() {
    const State &st = GetState();
    return st.enabled && !st.ready ? st.error : std::string();
}

std::string MakeTag(Domain domain, std::string_view bound) {
    const State &st = GetState();
    if (!st.ready) return "";
    return BuildTag(st, domain, bound, NowMs());
}

std::string MakeTagAtForTesting(Domain domain, std::string_view bound,
                                int64_t timestamp_ms) {
    const State &st = GetState();
    if (!st.ready) return "";
    return BuildTag(st, domain, bound, timestamp_ms);
}

Verdict VerifyTag(Domain domain, std::string_view tag, std::string_view bound) {
    const State &st = GetState();
    if (!st.ready) return Verdict::kNotReady;
    if (tag.empty()) return Verdict::kMissing;
    if (tag.size() != kTagSize || memcmp(tag.data(), kMagic, kTagMagicSize))
        return Verdict::kMalformed;
    constexpr size_t header = kTagMagicSize + 8 + kTagNonceSize;
    auto mac_ok = [&](const std::string &key) {
        auto mac = TagMac(key, domain, tag.substr(0, header), bound);
        return CRYPTO_memcmp(mac.data(), tag.data() + header, kTagMacSize) ==
               0;
    };
    bool ok = mac_ok(st.key);
    for (size_t i = 0; !ok && i < st.previous_keys.size(); ++i)
        ok = mac_ok(st.previous_keys[i]);
    if (!ok) return Verdict::kBadMac;
    const int64_t ts = GetBigEndian64(tag.data() + kTagMagicSize);
    const int64_t now = NowMs();
    if (ts < now - st.max_skew_ms || ts > now + st.max_skew_ms)
        return Verdict::kStale;
    return Remember(tag.data() + kTagMagicSize + 8, ts, now, st.max_skew_ms);
}

std::array<uint8_t, 32> HmacSha256(
    std::string_view key, std::initializer_list<std::string_view> parts) {
    std::array<uint8_t, 32> out{};
    size_t total = 0;
    for (auto p : parts) total += p.size();
    std::vector<unsigned char> buf;
    buf.reserve(total);
    for (auto p : parts) buf.insert(buf.end(), p.begin(), p.end());
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              buf.data(), buf.size(), out.data(), &len) ||
        len != out.size()) {
        LOG(ERROR) << "control-auth: HMAC failed";
        out.fill(0);
    }
    return out;
}

std::string DeriveKey(std::string_view secret, std::string_view label) {
    auto k = HmacSha256(secret, {label});
    return std::string(reinterpret_cast<const char *>(k.data()), k.size());
}

void ConfigureForTesting(bool enabled, std::string secret,
                         int64_t max_skew_ms) {
    auto *st = new State();
    st->enabled = enabled;
    st->max_skew_ms = max_skew_ms;
    if (enabled) {
        if (secret.size() >= kMinSecretBytes) {
            st->key = DeriveKey(secret, kKeyLabel);
            st->ready = true;
        } else {
            st->error = "test: no usable secret";
        }
    }
    ReplaceState(st);
}

void ResetForTesting() { ReplaceState(nullptr); }

}  // namespace control_auth
}  // namespace mooncake
