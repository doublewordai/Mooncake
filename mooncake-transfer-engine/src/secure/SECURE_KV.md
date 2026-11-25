# Secure KV mode (WITH_SECURE_KV)

Secure mode keeps KV-cache plaintext off the fabric and authenticates the
control plane, for deployments (Isambard) where the network between nodes is
not trusted. It has two halves that share one switch and one key:

- **Data path** (`kv_crypto`, `secure_transport`, `secure_push`, the store's
  `SecurePyClient`): every byte that leaves a process over the transfer engine
  or the store is sealed with an AEAD and verified before use.
- **Control plane** (`control_auth`, `handshake_auth`, the store's
  `rpc_auth`): every P2P handshake message and every store coro_rpc request
  carries an HMAC tag (an RPC's covers its route key and arguments);
  untagged, forged, stale or replayed messages are refused.

The code lives in `src/secure/` directories (and `include/secure/`) and is
compiled only with `-DWITH_SECURE_KV=ON` (needs OpenSSL libcrypto). With the
option off (the default) none of it is built and the wire formats are
upstream's.

## Switching it on

| Variable | Meaning |
| --- | --- |
| `MC_SECURE_MODE` | `1`/`true`/`on`/`yes` turns both halves on. Unset, empty or `0`/`false`/`off`/`no`: off. Any other value: on, with a configuration error (fails closed). `MC_CONTROL_AUTH` is an alias; if both are set they must agree. |
| `MC_SECURE_KEY_FILE` | Path of the key file, normally a mounted Kubernetes Secret. |
| `MC_SECURE_KEY` | One key inline (e.g. a `secretKeyRef` env), used only when no key file is named. |
| `MC_SECURE_PREVIOUS_KEY_FILE`, `MC_SECURE_PREVIOUS_KEY` | Previous keys, accepted for opening/verifying only. |

`MC_CONTROL_AUTH_KEY_FILE` / `MC_CONTROL_AUTH_KEY` are read as aliases of
`MC_SECURE_KEY_FILE` / `MC_SECURE_KEY` when neither of those is set.
The authoritative list, with parsing rules, is
[`secure_env.h`](secure_env.h); tunables specific to one half are in
[`include/secure/kv_crypto.h`](../../include/secure/kv_crypto.h),
[`include/secure/secure_push.h`](../../include/secure/secure_push.h)
(`MC_SECURE_P2D_*`),
[`mooncake-store/include/secure/sealed_object.h`](../../../mooncake-store/include/secure/sealed_object.h)
(`MC_SECURE_STORE_*`: store crypto threads, segment size, CPU pinning,
plaintext scratch cap) and [`control_auth.h`](control_auth.h). These tune the
halves only; none switches secure mode or names a key.

A binary built **without** `WITH_SECURE_KV` refuses to start (exit 78, a
message on stderr) if `MC_SECURE_MODE` or `MC_CONTROL_AUTH` asks for secure
mode, so a wrong image cannot silently run in plaintext
([`mooncake-common/include/secure_mode_guard.h`](../../../mooncake-common/include/secure_mode_guard.h)).

## The key file

One Secret serves every process (prefill, decode, store clients, master).
The file holds either exactly 32 raw bytes, or one key per line as 64 hex
digits or base64 of 32 bytes (`#` lines are comments). The first key is
current; later lines are previous keys. Generate one with
`openssl rand -hex 32`.

```yaml
env:
- {name: MC_SECURE_MODE, value: "1"}
- {name: MC_SECURE_KEY_FILE, value: /etc/mooncake-secure/key}
volumeMounts:
- {name: mooncake-secure, mountPath: /etc/mooncake-secure, readOnly: true}
volumes:
- name: mooncake-secure
  secret: {secretName: mooncake-secure-kv, items: [{key: key, path: key}]}
```

Each half derives its own keys from the shared key and never uses it
directly: the data path through HKDF-SHA256 with its own labels (per purpose,
plus a key id), the control plane as HMAC-SHA256(key,
`"mooncake control-auth v1"`). The labels differ, so the halves never share a
key.

Rotation: put the new key on the first line and the old one after it (or in
`MC_SECURE_PREVIOUS_KEY_FILE`), roll that out everywhere, then drop the old
key. Both halves seal/tag with the current key and accept current or
previous. Keys are read once per process, on first use: restart pods to
pick up a changed Secret.

## Fail-closed behaviour

Secure mode switched on but unusable (unreadable or malformed key, bad switch
value) never falls back to plaintext: the transfer engine refuses to install
transports, servers that would serve RPC abort, and the control plane makes
and accepts no tags.

## One copy per module

The Python modules `engine.so` (vLLM's P2P connector) and `_store*.so` (its
store connector) each link the transfer engine and the secure code
statically, and a prefill worker loads both. Secure mode keeps process-wide
state (the key ring and sealers, control-auth's key and replay cache, the
handshake framing hook and the push endpoints it carries), so every secure
symbol, and the hook in `common.h`, has hidden visibility: each module keeps
its own copy, used only by the transfer engines that module creates. Default
visibility would let the dynamic linker merge some of that state across
modules (an `inline` variable becomes `STB_GNU_UNIQUE`, one per process) or
bind one module's calls to the other's, and a handshake read through one
module's hook would record a peer's push endpoint where the other module's
sender never looks. Each copy reads the same switch and key, and its seals
use their own random salts, so two copies interoperate like two processes.
For the same reason a secure build needs `BUILD_SHARED_LIBS=OFF`.
[`tests/check_module_isolation.py`](tests/check_module_isolation.py) checks
a secure build's modules export no secure symbol;
[`tests/two_module_p2d_test.py`](tests/two_module_p2d_test.py) pushes from a
process that has loaded both.

## Secure push discovery and control limits

A sender finds a receiver's push control endpoint in the receiver's segment
descriptor, which travels only over the authenticated handshake, and gets its
slot layout over the sealed control channel; nothing about discovery is kept
in NIC-registered (fabric-writable) memory. The control server bounds what an
unauthenticated connection can cost (frame size, time, count per source and
in total) separately from authenticated ones. Both are described, with their
`MC_SECURE_P2D_*` limits, in
[`include/secure/secure_push.h`](../../include/secure/secure_push.h).

## What secure mode refuses

- Metadata other than `P2PHANDSHAKE` (etcd, redis, HTTP): the engine aborts at
  start, since only the P2P handshake is authenticated.
- The master's HTTP metadata server.
- TENT (it does not go through the secure transport).
- Transfers whose local side is not registered memory, and READs into
  local-only (plaintext) memory. Plaintext memory (a vLLM KV cache, a user
  buffer) is never registered with the NIC; a WRITE from it becomes a secure
  push that completes only after the peer has verified and decrypted it.
- In the store's Python client, every call that moves object bytes and cannot
  be authenticated as a whole object: ranged reads/writes, sessions,
  `get_buffer` (and so the bytes-returning `get`), `put_from_with_metadata`,
  dummy/shm modes, offload. These return `INVALID_PARAMS`; use
  `put_from`/`get_into` and their batch forms. Metadata calls are forwarded.
- Store entry points that do not go through that decorator: the store C API
  (and so the Rust and Go bindings over it) creates no client, the standalone
  `mooncake_client` exits 78, and a `RealClient` set up anywhere but inside
  the decorator refuses setup
  ([`mooncake-store/include/secure/entry_guard.h`](../../../mooncake-store/include/secure/entry_guard.h)).
- Store RPCs and handshakes without a valid, fresh, unreplayed tag (answered
  with code 401 / dropped).

The master's admin and metrics HTTP server (`--metrics_port`: `/metrics`,
key and segment queries, `remove_all`, drain jobs, tenant quotas) is not
authenticated, so in secure mode it binds to loopback only, in the master, the
HA supervisor and the embedded master alike; `MC_SECURE_ADMIN_BIND` names
another address. Reach it from inside the pod (`kubectl exec`, or a process
beside the master) or with `kubectl port-forward`, which needs no sidecar
([`mooncake-store/src/secure/rpc_auth.h`](../../../mooncake-store/src/secure/rpc_auth.h)).
