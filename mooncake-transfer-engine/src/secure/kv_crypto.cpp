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

#include "secure/kv_crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <pthread.h>

#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unordered_map>

#include <glog/logging.h>

namespace mooncake {
namespace secure {

namespace {

constexpr char kHkdfLabel[] = "mooncake-secure-v1";
constexpr char kKeyIdLabel[] = "mooncake key id";
constexpr size_t kMaxChunk = 1u << 30;  // EVP lengths are int
// Redraw the subkey long before the 64-bit counter could wrap.
constexpr uint64_t kCounterLimit = 1ull << 62;

std::atomic<uint64_t> g_fork_generation{0};

void OnForkChild() {
    g_fork_generation.fetch_add(1, std::memory_order_relaxed);
}

void InstallForkHandler() {
    static std::once_flag once;
    std::call_once(once, [] { pthread_atfork(nullptr, nullptr, OnForkChild); });
}

void PutLe32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
void PutLe64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
uint32_t GetLe32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[i]) << (8 * i);
    return v;
}
uint64_t GetLe64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

bool ValidAlgorithm(uint8_t a) {
    return a == static_cast<uint8_t>(Algorithm::kAes256Gcm) ||
           a == static_cast<uint8_t>(Algorithm::kChaCha20Poly1305);
}
bool ValidPurpose(uint8_t p) { return p >= 1 && p <= 3; }

const EVP_CIPHER* CipherFor(Algorithm a) {
    switch (a) {
        case Algorithm::kAes256Gcm:
            return EVP_aes_256_gcm();
        case Algorithm::kChaCha20Poly1305:
            return EVP_chacha20_poly1305();
    }
    return nullptr;
}

void EncodeHeader(const SealedInfo& h, uint8_t out[kHeaderSize]) {
    PutLe32(out, kMagic);
    out[4] = kFormatVersion;
    out[5] = static_cast<uint8_t>(h.algorithm);
    out[6] = static_cast<uint8_t>(h.purpose);
    out[7] = h.flags;
    PutLe32(out + 8, h.key_id);
    std::memcpy(out + 12, h.salt.data(), kSaltSize);
    std::memcpy(out + 28, h.nonce.data(), kNonceSize);
    PutLe64(out + 40, h.plaintext_len);
}

size_t TotalSize(const ConstSpan* s, size_t n) {
    size_t t = 0;
    for (size_t i = 0; i < n; ++i) t += s[i].size;
    return t;
}
size_t TotalSize(const MutableSpan* s, size_t n) {
    size_t t = 0;
    for (size_t i = 0; i < n; ++i) t += s[i].size;
    return t;
}

void ZeroSpans(const MutableSpan* out, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (out[i].data && out[i].size) OPENSSL_cleanse(out[i].data, out[i].size);
    }
}

struct CtxDeleter {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};

EVP_CIPHER_CTX* ThreadCtx() {
    thread_local std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter> ctx(
        EVP_CIPHER_CTX_new());
    if (ctx) EVP_CIPHER_CTX_reset(ctx.get());
    return ctx.get();
}

// Streams `in` (gather) through EVP_{En,De}cryptUpdate into `out` (scatter).
// Each input byte is read exactly once.
template <typename UpdateFn>
bool StreamUpdate(EVP_CIPHER_CTX* ctx, UpdateFn update, const ConstSpan* in,
                  size_t in_count, const MutableSpan* out, size_t out_count) {
    size_t ii = 0, io = 0, oi = 0, oo = 0;
    while (ii < in_count && oi < out_count) {
        if (io == in[ii].size) {
            ++ii;
            io = 0;
            continue;
        }
        if (oo == out[oi].size) {
            ++oi;
            oo = 0;
            continue;
        }
        size_t n = std::min({in[ii].size - io, out[oi].size - oo, kMaxChunk});
        int outl = 0;
        if (update(ctx, static_cast<uint8_t*>(out[oi].data) + oo, &outl,
                   static_cast<const uint8_t*>(in[ii].data) + io,
                   static_cast<int>(n)) != 1 ||
            static_cast<size_t>(outl) != n) {
            return false;
        }
        io += n;
        oo += n;
    }
    return true;
}

class OpenSslBackend final : public AeadBackend {
   public:
    const char* name() const override { return "openssl-host"; }
    bool Supports(Algorithm a) const override { return CipherFor(a) != nullptr; }
    bool CanAccess(const void*, size_t) const override {
        // The host backend dereferences pointers on the CPU. Device memory is
        // the caller's to bounce; SelectAeadBackend consults the registered
        // device backends first and callers check device pointers themselves.
        return true;
    }

    Error Seal(const AeadCall& c) override {
        EVP_CIPHER_CTX* ctx = ThreadCtx();
        const EVP_CIPHER* cipher = CipherFor(c.algorithm);
        if (!ctx || !cipher) return Error::kCryptoError;
        if (TotalSize(c.in, c.in_count) != TotalSize(c.out, c.out_count))
            return Error::kSizeMismatch;
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, kNonceSize,
                                nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, c.key, c.nonce) != 1)
            return Error::kCryptoError;
        int outl = 0;
        for (size_t i = 0; i < c.aad_count; ++i) {
            if (c.aad[i].size == 0) continue;
            if (EVP_EncryptUpdate(
                    ctx, nullptr, &outl,
                    static_cast<const uint8_t*>(c.aad[i].data),
                    static_cast<int>(c.aad[i].size)) != 1)
                return Error::kCryptoError;
        }
        if (!StreamUpdate(ctx, EVP_EncryptUpdate, c.in, c.in_count, c.out,
                          c.out_count))
            return Error::kCryptoError;
        uint8_t tail[32];
        if (EVP_EncryptFinal_ex(ctx, tail, &outl) != 1 || outl != 0)
            return Error::kCryptoError;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, kTagSize,
                                c.tag_out) != 1)
            return Error::kCryptoError;
        return Error::kOk;
    }

    Error Open(const AeadCall& c) override {
        Error e = OpenInner(c);
        if (e != Error::kOk) ZeroSpans(c.out, c.out_count);
        return e;
    }

   private:
    Error OpenInner(const AeadCall& c) {
        EVP_CIPHER_CTX* ctx = ThreadCtx();
        const EVP_CIPHER* cipher = CipherFor(c.algorithm);
        if (!ctx || !cipher) return Error::kCryptoError;
        if (TotalSize(c.in, c.in_count) != TotalSize(c.out, c.out_count))
            return Error::kSizeMismatch;
        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, kNonceSize,
                                nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, c.key, c.nonce) != 1)
            return Error::kCryptoError;
        int outl = 0;
        for (size_t i = 0; i < c.aad_count; ++i) {
            if (c.aad[i].size == 0) continue;
            if (EVP_DecryptUpdate(
                    ctx, nullptr, &outl,
                    static_cast<const uint8_t*>(c.aad[i].data),
                    static_cast<int>(c.aad[i].size)) != 1)
                return Error::kCryptoError;
        }
        if (!StreamUpdate(ctx, EVP_DecryptUpdate, c.in, c.in_count, c.out,
                          c.out_count))
            return Error::kCryptoError;
        uint8_t tag[kTagSize];
        std::memcpy(tag, c.tag_in, kTagSize);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, kTagSize, tag) !=
            1)
            return Error::kCryptoError;
        uint8_t tail[32];
        if (EVP_DecryptFinal_ex(ctx, tail, &outl) <= 0) return Error::kAuthFailed;
        return Error::kOk;
    }
};

std::mutex g_backends_mu;
std::vector<std::shared_ptr<AeadBackend>>& Backends() {
    static auto* v = new std::vector<std::shared_ptr<AeadBackend>>();
    return *v;
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
// non-empty line.
Error ParseKeyFile(const std::string& content,
                   std::vector<std::array<uint8_t, kKeySize>>* keys) {
    if (content.size() == kKeySize) {
        std::array<uint8_t, kKeySize> k;
        std::memcpy(k.data(), content.data(), kKeySize);
        keys->push_back(k);
        return Error::kOk;
    }
    std::istringstream lines(content);
    std::string line;
    bool any = false;
    while (std::getline(lines, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        std::array<uint8_t, kKeySize> k;
        Error e = ParseKeyMaterial(line, &k);
        OPENSSL_cleanse(line.data(), line.size());
        if (e != Error::kOk) return e;
        keys->push_back(k);
        any = true;
    }
    return any ? Error::kOk : Error::kNoKey;
}

bool EnvTrue(const char* name) {
    const char* v = std::getenv(name);
    if (!v) return false;
    std::string s(v);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s == "1" || s == "true" || s == "on" || s == "yes";
}

std::string EnvStr(const char* name) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
}

size_t EnvSize(const char* name, size_t dflt) {
    const char* v = std::getenv(name);
    if (!v || !*v) return dflt;
    char* end = nullptr;
    unsigned long long x = std::strtoull(v, &end, 10);
    if (end == v) return dflt;
    return static_cast<size_t>(x);
}

}  // namespace

const char* ToString(Error e) {
    switch (e) {
        case Error::kOk:
            return "ok";
        case Error::kDisabled:
            return "secure mode disabled";
        case Error::kNoKey:
            return "no key";
        case Error::kBadConfig:
            return "bad secure-mode config";
        case Error::kUnknownKeyId:
            return "unknown key id";
        case Error::kBadHeader:
            return "bad sealed header";
        case Error::kAuthFailed:
            return "authentication failed";
        case Error::kSizeMismatch:
            return "size mismatch";
        case Error::kBufferTooSmall:
            return "buffer too small";
        case Error::kUnsupported:
            return "unsupported";
        case Error::kCryptoError:
            return "crypto library error";
        case Error::kNonceExhausted:
            return "nonce space exhausted";
    }
    return "unknown";
}

const char* ToString(Algorithm a) {
    switch (a) {
        case Algorithm::kAes256Gcm:
            return "aes-256-gcm";
        case Algorithm::kChaCha20Poly1305:
            return "chacha20-poly1305";
    }
    return "unknown";
}

uint64_t SealedInfo::counter() const {
    uint64_t v = 0;
    for (size_t i = 4; i < kNonceSize; ++i) v = (v << 8) | nonce[i];
    return v;
}

Error ParseHeader(ConstSpan sealed, SealedInfo* info) {
    if (!sealed.data || sealed.size < kOverhead) return Error::kBadHeader;
    uint8_t h[kHeaderSize];
    std::memcpy(h, sealed.data, kHeaderSize);  // read once
    if (GetLe32(h) != kMagic || h[4] != kFormatVersion || !ValidAlgorithm(h[5]) ||
        !ValidPurpose(h[6]) || h[7] != 0)
        return Error::kBadHeader;
    SealedInfo out;
    out.algorithm = static_cast<Algorithm>(h[5]);
    out.purpose = static_cast<Purpose>(h[6]);
    out.flags = h[7];
    out.key_id = GetLe32(h + 8);
    std::memcpy(out.salt.data(), h + 12, kSaltSize);
    std::memcpy(out.nonce.data(), h + 28, kNonceSize);
    out.plaintext_len = GetLe64(h + 40);
    if (out.plaintext_len > sealed.size ||
        SealedSize(out.plaintext_len) != sealed.size)
        return Error::kBadHeader;
    *info = out;
    return Error::kOk;
}

// ------------------------------------------------------------------ keys --

MasterKey::MasterKey(uint32_t id, const uint8_t bytes[kKeySize]) : id_(id) {
    std::memcpy(bytes_.data(), bytes, kKeySize);
}

MasterKey::~MasterKey() { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }

uint32_t DeriveKeyId(const uint8_t key[kKeySize]) {
    uint8_t mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key, kKeySize,
         reinterpret_cast<const uint8_t*>(kKeyIdLabel), sizeof(kKeyIdLabel) - 1,
         mac, &len);
    return GetLe32(mac);
}

Error ParseKeyMaterial(const std::string& text,
                       std::array<uint8_t, kKeySize>* out) {
    std::string s = Trim(text);
    if (s.size() == 2 * kKeySize &&
        std::all_of(s.begin(), s.end(),
                    [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); })) {
        for (size_t i = 0; i < kKeySize; ++i) {
            unsigned v = 0;
            std::sscanf(s.c_str() + 2 * i, "%2x", &v);
            (*out)[i] = static_cast<uint8_t>(v);
        }
        OPENSSL_cleanse(s.data(), s.size());
        return Error::kOk;
    }
    // base64 of 32 bytes is 44 chars with one '=' of padding.
    if (s.size() == 44 && s[43] == '=' && s[42] != '=') {
        uint8_t buf[34];
        int n = EVP_DecodeBlock(buf, reinterpret_cast<const uint8_t*>(s.data()),
                                static_cast<int>(s.size()));
        OPENSSL_cleanse(s.data(), s.size());
        if (n != 33) {
            OPENSSL_cleanse(buf, sizeof(buf));
            return Error::kBadConfig;
        }
        std::memcpy(out->data(), buf, kKeySize);
        OPENSSL_cleanse(buf, sizeof(buf));
        return Error::kOk;
    }
    OPENSSL_cleanse(s.data(), s.size());
    return Error::kBadConfig;
}

std::shared_ptr<const KeyRing> KeyRing::FromKeys(
    const std::vector<std::array<uint8_t, kKeySize>>& keys, Error* err) {
    if (keys.empty()) {
        if (err) *err = Error::kNoKey;
        return nullptr;
    }
    auto ring = std::shared_ptr<KeyRing>(new KeyRing());
    for (const auto& k : keys) {
        uint32_t id = DeriveKeyId(k.data());
        if (ring->Find(id)) continue;  // duplicate key listed twice
        ring->keys_.push_back(std::make_unique<MasterKey>(id, k.data()));
    }
    if (err) *err = Error::kOk;
    return ring;
}

const MasterKey* KeyRing::Find(uint32_t key_id) const {
    for (const auto& k : keys_)
        if (k->id() == key_id) return k.get();
    return nullptr;
}

SecureConfig SecureConfig::FromEnv() {
    SecureConfig c;
    c.enabled = EnvTrue("MC_SECURE_MODE");
    c.key_file = EnvStr("MC_SECURE_KEY_FILE");
    c.key_inline = EnvStr("MC_SECURE_KEY");
    c.previous_key_file = EnvStr("MC_SECURE_PREVIOUS_KEY_FILE");
    c.previous_key_inline = EnvStr("MC_SECURE_PREVIOUS_KEY");
    std::string alg = EnvStr("MC_SECURE_AEAD");
    std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);
    if (alg == "chacha20-poly1305" || alg == "chacha20poly1305")
        c.algorithm = Algorithm::kChaCha20Poly1305;
    c.staging_region_bytes =
        EnvSize("MC_SECURE_STAGING_BYTES", c.staging_region_bytes);
    c.staging_max_bytes =
        EnvSize("MC_SECURE_STAGING_MAX_BYTES", c.staging_max_bytes);
    return c;
}

std::shared_ptr<const KeyRing> LoadKeyRing(const SecureConfig& cfg, Error* err,
                                           std::string* why) {
    std::vector<std::array<uint8_t, kKeySize>> keys;
    auto fail = [&](Error e, const std::string& reason) {
        for (auto& k : keys) OPENSSL_cleanse(k.data(), k.size());
        if (err) *err = e;
        if (why) *why = reason;
        return std::shared_ptr<const KeyRing>();
    };
    if (!cfg.key_file.empty()) {
        std::string content;
        if (!ReadFile(cfg.key_file, &content))
            return fail(Error::kNoKey, "cannot read MC_SECURE_KEY_FILE " +
                                           cfg.key_file);
        Error e = ParseKeyFile(content, &keys);
        OPENSSL_cleanse(content.data(), content.size());
        if (e != Error::kOk)
            return fail(e, "MC_SECURE_KEY_FILE " + cfg.key_file +
                               " holds no valid key (want 32 raw bytes, 64 hex "
                               "digits or base64)");
    } else if (!cfg.key_inline.empty()) {
        std::array<uint8_t, kKeySize> k;
        if (ParseKeyMaterial(cfg.key_inline, &k) != Error::kOk)
            return fail(Error::kBadConfig,
                        "MC_SECURE_KEY is not 64 hex digits or base64 of 32 "
                        "bytes");
        keys.push_back(k);
    } else {
        return fail(Error::kNoKey,
                    "secure mode needs MC_SECURE_KEY_FILE or MC_SECURE_KEY");
    }
    if (!cfg.previous_key_file.empty()) {
        std::string content;
        if (!ReadFile(cfg.previous_key_file, &content))
            return fail(Error::kBadConfig,
                        "cannot read MC_SECURE_PREVIOUS_KEY_FILE " +
                            cfg.previous_key_file);
        Error e = ParseKeyFile(content, &keys);
        OPENSSL_cleanse(content.data(), content.size());
        if (e != Error::kOk)
            return fail(Error::kBadConfig,
                        "MC_SECURE_PREVIOUS_KEY_FILE holds an invalid key");
    }
    if (!cfg.previous_key_inline.empty()) {
        std::array<uint8_t, kKeySize> k;
        if (ParseKeyMaterial(cfg.previous_key_inline, &k) != Error::kOk)
            return fail(Error::kBadConfig,
                        "MC_SECURE_PREVIOUS_KEY is not a valid key");
        keys.push_back(k);
    }
    auto ring = KeyRing::FromKeys(keys, err);
    for (auto& k : keys) OPENSSL_cleanse(k.data(), k.size());
    return ring;
}

// ------------------------------------------------------------- backends --

AeadBackend& HostAeadBackend() {
    static OpenSslBackend* b = new OpenSslBackend();
    return *b;
}

void RegisterAeadBackend(std::shared_ptr<AeadBackend> backend) {
    std::lock_guard<std::mutex> lock(g_backends_mu);
    Backends().push_back(std::move(backend));
}

AeadBackend* SelectAeadBackend(Algorithm alg, const ConstSpan* in,
                               size_t in_count, const MutableSpan* out,
                               size_t out_count) {
    {
        std::lock_guard<std::mutex> lock(g_backends_mu);
        auto& v = Backends();
        for (auto it = v.rbegin(); it != v.rend(); ++it) {
            AeadBackend* b = it->get();
            if (!b->Supports(alg)) continue;
            bool ok = true;
            for (size_t i = 0; ok && i < in_count; ++i)
                ok = b->CanAccess(in[i].data, in[i].size);
            for (size_t i = 0; ok && i < out_count; ++i)
                ok = b->CanAccess(out[i].data, out[i].size);
            if (ok) return b;
        }
    }
    return &HostAeadBackend();
}

Error DeriveSubkey(const MasterKey& master, const uint8_t salt[kSaltSize],
                   Algorithm alg, Purpose purpose,
                   std::array<uint8_t, kKeySize>* out) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return Error::kCryptoError;
    // label (without its NUL) | algorithm | purpose: every byte defined.
    uint8_t info[sizeof(kHkdfLabel) + 1];
    std::memcpy(info, kHkdfLabel, sizeof(kHkdfLabel) - 1);
    info[sizeof(kHkdfLabel) - 1] = static_cast<uint8_t>(alg);
    info[sizeof(kHkdfLabel)] = static_cast<uint8_t>(purpose);
    size_t outlen = kKeySize;
    bool ok = EVP_PKEY_derive_init(pctx) > 0 &&
              EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, kSaltSize) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_key(pctx, master.bytes(), kKeySize) > 0 &&
              EVP_PKEY_CTX_add1_hkdf_info(pctx, info, sizeof(info)) > 0 &&
              EVP_PKEY_derive(pctx, out->data(), &outlen) > 0 &&
              outlen == kKeySize;
    EVP_PKEY_CTX_free(pctx);
    return ok ? Error::kOk : Error::kCryptoError;
}

// ---------------------------------------------------------------- Sealer --

struct Sealer::State {
    uint32_t key_id = 0;
    std::array<uint8_t, kSaltSize> salt{};
    std::array<uint8_t, kKeySize> subkey{};
    std::atomic<uint64_t> counter{0};
    uint64_t fork_generation = 0;
    ~State() { OPENSSL_cleanse(subkey.data(), subkey.size()); }
};

Sealer::Sealer(std::shared_ptr<const KeyRing> ring, Purpose purpose,
               Algorithm alg)
    : ring_(std::move(ring)), purpose_(purpose), alg_(alg) {}

Sealer::~Sealer() = default;

std::unique_ptr<Sealer> Sealer::Create(std::shared_ptr<const KeyRing> ring,
                                       Purpose purpose, Algorithm alg,
                                       Error* err) {
    InstallForkHandler();
    if (!ring) {
        if (err) *err = Error::kNoKey;
        return nullptr;
    }
    if (!ValidPurpose(static_cast<uint8_t>(purpose)) ||
        !HostAeadBackend().Supports(alg)) {
        if (err) *err = Error::kUnsupported;
        return nullptr;
    }
    std::unique_ptr<Sealer> s(new Sealer(std::move(ring), purpose, alg));
    std::lock_guard<std::mutex> lock(s->mu_);
    Error e = s->Refresh();
    if (err) *err = e;
    if (e != Error::kOk) return nullptr;
    return s;
}

Error Sealer::Refresh() {
    auto st = std::make_shared<State>();
    const MasterKey& master = ring_->current();
    st->key_id = master.id();
    if (RAND_bytes(st->salt.data(), kSaltSize) != 1) return Error::kCryptoError;
    Error e = DeriveSubkey(master, st->salt.data(), alg_, purpose_, &st->subkey);
    if (e != Error::kOk) return e;
    st->fork_generation = g_fork_generation.load(std::memory_order_relaxed);
    state_ = std::move(st);
    return Error::kOk;
}

uint32_t Sealer::key_id() const { return ring_->current().id(); }

void Sealer::RotateForTesting() {
    std::lock_guard<std::mutex> lock(mu_);
    Refresh();
}

void Sealer::SetCounterForTesting(uint64_t value) {
    std::lock_guard<std::mutex> lock(mu_);
    state_->counter.store(value);
}

Error Sealer::Seal(const ConstSpan* plaintext, size_t count, ConstSpan aad,
                   MutableSpan out, size_t* sealed_len) {
    const size_t pt_len = TotalSize(plaintext, count);
    const size_t need = SealedSize(pt_len);
    if (!out.data || out.size < need) return Error::kBufferTooSmall;

    std::shared_ptr<State> st;
    uint64_t counter = 0;
    for (int attempt = 0;; ++attempt) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (state_->fork_generation !=
                    g_fork_generation.load(std::memory_order_relaxed) ||
                state_->counter.load(std::memory_order_relaxed) >=
                    kCounterLimit) {
                Error e = Refresh();
                if (e != Error::kOk) return e;
            }
            st = state_;
        }
        counter = st->counter.fetch_add(1, std::memory_order_relaxed);
        if (counter < kCounterLimit) break;
        if (attempt > 2) return Error::kNonceExhausted;
    }

    SealedInfo h;
    h.algorithm = alg_;
    h.purpose = purpose_;
    h.key_id = st->key_id;
    h.salt = st->salt;
    h.nonce.fill(0);
    for (int i = 0; i < 8; ++i)
        h.nonce[kNonceSize - 1 - i] = static_cast<uint8_t>(counter >> (8 * i));
    h.plaintext_len = pt_len;

    uint8_t* base = static_cast<uint8_t*>(out.data);
    uint8_t header[kHeaderSize];
    EncodeHeader(h, header);

    ConstSpan aads[2] = {{header, kHeaderSize}, aad};
    MutableSpan ct = {base + kHeaderSize, pt_len};
    uint8_t tag[kTagSize];
    AeadCall call;
    call.algorithm = alg_;
    call.key = st->subkey.data();
    call.nonce = h.nonce.data();
    call.aad = aads;
    call.aad_count = 2;
    call.in = plaintext;
    call.in_count = count;
    call.out = &ct;
    call.out_count = 1;
    call.tag_out = tag;
    AeadBackend* backend = SelectAeadBackend(alg_, plaintext, count, &ct, 1);
    Error e = backend->Seal(call);
    if (e != Error::kOk) return e;
    std::memcpy(base, header, kHeaderSize);
    std::memcpy(base + kHeaderSize + pt_len, tag, kTagSize);
    if (sealed_len) *sealed_len = need;
    return Error::kOk;
}

// ---------------------------------------------------------------- Opener --

struct Opener::Cache {
    std::mutex mu;
    std::unordered_map<std::string, std::array<uint8_t, kKeySize>> subkeys;
    ~Cache() {
        for (auto& [_, k] : subkeys) OPENSSL_cleanse(k.data(), k.size());
    }
};

Opener::Opener(std::shared_ptr<const KeyRing> ring)
    : ring_(std::move(ring)), cache_(std::make_unique<Cache>()) {}

Opener::~Opener() = default;

Error Opener::Open(ConstSpan sealed, Purpose expected, ConstSpan aad,
                   const MutableSpan* out, size_t count, SealedInfo* info_out) {
    auto fail = [&](Error e) {
        ZeroSpans(out, count);
        return e;
    };
    if (!sealed.data || sealed.size < kOverhead) return fail(Error::kBadHeader);
    // Copy the header and tag out of the (possibly remotely writable) buffer
    // before using them, so each is read exactly once.
    uint8_t header[kHeaderSize];
    std::memcpy(header, sealed.data, kHeaderSize);
    SealedInfo h;
    Error e = ParseHeader({header, kHeaderSize + kTagSize +
                                       (sealed.size - kOverhead)},
                          &h);
    // ParseHeader reads the first kHeaderSize bytes of its argument; pass a
    // view whose size is the sealed size but whose data is our private copy.
    if (e != Error::kOk) return fail(e);
    if (h.purpose != expected) return fail(Error::kBadHeader);
    if (TotalSize(out, count) != h.plaintext_len)
        return fail(Error::kSizeMismatch);
    const MasterKey* master = ring_->Find(h.key_id);
    if (!master) return fail(Error::kUnknownKeyId);

    std::array<uint8_t, kKeySize> subkey;
    {
        std::string cache_key(reinterpret_cast<const char*>(header + 5), 1);
        cache_key.append(reinterpret_cast<const char*>(header + 6), 1);
        cache_key.append(reinterpret_cast<const char*>(header + 8), 4);
        cache_key.append(reinterpret_cast<const char*>(h.salt.data()),
                         kSaltSize);
        std::lock_guard<std::mutex> lock(cache_->mu);
        auto it = cache_->subkeys.find(cache_key);
        if (it != cache_->subkeys.end()) {
            subkey = it->second;
        } else {
            e = DeriveSubkey(*master, h.salt.data(), h.algorithm, h.purpose,
                             &subkey);
            if (e != Error::kOk) return fail(e);
            if (cache_->subkeys.size() >= 4096) {
                for (auto& [_, k] : cache_->subkeys)
                    OPENSSL_cleanse(k.data(), k.size());
                cache_->subkeys.clear();
            }
            cache_->subkeys.emplace(std::move(cache_key), subkey);
        }
    }

    uint8_t tag[kTagSize];
    std::memcpy(tag, static_cast<const uint8_t*>(sealed.data) + kHeaderSize +
                         h.plaintext_len,
                kTagSize);
    ConstSpan aads[2] = {{header, kHeaderSize}, aad};
    ConstSpan ct = {static_cast<const uint8_t*>(sealed.data) + kHeaderSize,
                    static_cast<size_t>(h.plaintext_len)};
    AeadCall call;
    call.algorithm = h.algorithm;
    call.key = subkey.data();
    call.nonce = h.nonce.data();
    call.aad = aads;
    call.aad_count = 2;
    call.in = &ct;
    call.in_count = 1;
    call.out = out;
    call.out_count = count;
    call.tag_in = tag;
    AeadBackend* backend = SelectAeadBackend(h.algorithm, &ct, 1, out, count);
    e = backend->Open(call);
    OPENSSL_cleanse(subkey.data(), subkey.size());
    if (e != Error::kOk) return fail(e);
    if (info_out) *info_out = h;
    return Error::kOk;
}

// ------------------------------------------------------- process context --

namespace {
std::mutex g_ctx_mu;
std::atomic<SecureContext*> g_ctx{nullptr};
// Contexts replaced in tests are kept alive: other threads may still hold
// references obtained from Global().
std::vector<std::unique_ptr<SecureContext>>& RetiredContexts() {
    static auto* v = new std::vector<std::unique_ptr<SecureContext>>();
    return *v;
}
}  // namespace

std::unique_ptr<SecureContext> SecureContext::Build(
    const SecureConfig& cfg, std::shared_ptr<const KeyRing> keys) {
    std::unique_ptr<SecureContext> ctx(new SecureContext());
    ctx->config_ = cfg;
    ctx->enabled_ = cfg.enabled;
    if (!cfg.enabled) {
        ctx->status_ = Error::kDisabled;
        return ctx;
    }
    Error e = Error::kOk;
    std::string why;
    if (!keys) keys = LoadKeyRing(cfg, &e, &why);
    if (!keys) {
        ctx->status_ = e == Error::kOk ? Error::kNoKey : e;
        ctx->reason_ = why;
        LOG(ERROR) << "Mooncake secure mode requested but cannot start: "
                   << why;
        return ctx;
    }
    ctx->keys_ = keys;
    for (uint8_t p = 1; p <= 3; ++p) {
        ctx->sealers_[p] =
            Sealer::Create(keys, static_cast<Purpose>(p), cfg.algorithm, &e);
        if (!ctx->sealers_[p]) {
            ctx->status_ = e;
            ctx->reason_ = std::string("cannot create sealer: ") + ToString(e);
            return ctx;
        }
    }
    ctx->opener_ = std::make_unique<Opener>(keys);
    ctx->status_ = Error::kOk;
    LOG(INFO) << "Mooncake secure mode on: aead=" << ToString(cfg.algorithm)
              << " current_key_id=" << std::hex << keys->current().id()
              << std::dec << " keys=" << keys->size();
    return ctx;
}

SecureContext& SecureContext::Global() {
    SecureContext* c = g_ctx.load(std::memory_order_acquire);
    if (c) return *c;
    std::lock_guard<std::mutex> lock(g_ctx_mu);
    c = g_ctx.load(std::memory_order_relaxed);
    if (!c) {
        auto built = Build(SecureConfig::FromEnv(), nullptr);
        c = built.get();
        RetiredContexts().push_back(std::move(built));
        g_ctx.store(c, std::memory_order_release);
    }
    return *c;
}

Sealer& SecureContext::sealer(Purpose p) {
    return *sealers_[static_cast<uint8_t>(p)];
}

Opener& SecureContext::opener() { return *opener_; }

void SecureContext::ResetForTesting(std::unique_ptr<SecureContext> ctx) {
    std::lock_guard<std::mutex> lock(g_ctx_mu);
    SecureContext* c = ctx.get();
    if (ctx) RetiredContexts().push_back(std::move(ctx));
    g_ctx.store(c, std::memory_order_release);
}

std::unique_ptr<SecureContext> SecureContext::CreateForTesting(
    const SecureConfig& cfg, std::shared_ptr<const KeyRing> keys) {
    return Build(cfg, std::move(keys));
}

}  // namespace secure
}  // namespace mooncake
