#!/usr/bin/env python3
"""Secure push from a process that has loaded both Mooncake modules (DW-1288).

A vLLM prefill worker loads mooncake.engine (its P2P connector pushes KV to
the decode) and mooncake.store (its store connector); a decode worker loads
only mooncake.engine. Each module links the transfer engine and the secure
code statically, so this checks that the two copies in one process do not
mix (SECURE_KV.md, "One copy per module"): with them mixed, the prefill's
handshake read through the store module's hook and its push found "no secure
receiver" on the decode.

  two_module_p2d_test.py --master HOST:PORT [--gpu] [--order engine-first|store-first]

Runs a decode process (engine only) and a prefill process (engine and store:
two store clients and one transfer engine, created in --order) and checks,
with secure mode as the environment sets it (MC_SECURE_MODE,
MC_SECURE_KEY_FILE):
  - P->D pushes land intact;
  - D->P pushes (the decode pushing into the prefill's engine) land intact;
  - store puts and gets between the prefill's two store clients succeed and
    read back intact while the pushes run;
  - the prefill has both modules mapped and the decode only the engine.
Needs a running mooncake_master in the same mode. Synthetic data only. Prints
"P ..." lines; exits 0 only if every check passed.
"""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time


def log(role, *a):
    print("P", role, *a, flush=True)


def parse_size(s):
    m = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
    return int(float(s[:-1]) * m[s[-1]]) if s[-1] in m else int(s)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Buf:
    """A GPU (torch) or host (numpy) buffer with a pointer and range digests."""

    def __init__(self, n, gpu, seed=None):
        self.n, self.gpu = n, gpu
        if gpu:
            import torch
            if seed is None:
                self.t = torch.zeros(n, dtype=torch.uint8, device="cuda")
            else:
                g = torch.Generator(device="cuda").manual_seed(seed)
                self.t = torch.randint(0, 256, (n,), dtype=torch.uint8,
                                       device="cuda", generator=g)
            torch.cuda.synchronize()
            self.ptr = self.t.data_ptr()
        else:
            import numpy as np
            if seed is None:
                self.t = np.zeros(n, dtype=np.uint8)
            else:
                self.t = np.random.default_rng(seed).integers(
                    0, 256, n, dtype=np.uint8)
            self.ptr = self.t.ctypes.data

    def digest(self, ranges):
        if self.gpu:
            import torch
            torch.cuda.synchronize()
        h = hashlib.sha256()
        for off, ln in ranges:
            a = self.t[off:off + ln]
            h.update((a.cpu().numpy() if self.gpu else a).tobytes())
        return h.hexdigest()

    def clear(self):
        if self.gpu:
            import torch
            self.t.zero_()
            torch.cuda.synchronize()
        else:
            self.t[:] = 0


def layout(size, piece, seed):
    """KV-like scattered pieces: (src offset, dst offset, length), dst shuffled."""
    import random
    n = size // piece
    order = list(range(n))
    random.Random(seed).shuffle(order)
    return [(i * piece, order[i] * piece, piece) for i in range(n)]


def module_maps():
    with open("/proc/self/maps") as f:
        paths = {line.split()[-1] for line in f if "/" in line}
    base = {os.path.basename(p) for p in paths}
    return {"engine": any(b.startswith("engine") and b.endswith(".so") for b in base),
            "store": any(b.startswith("_store") and b.endswith(".so") for b in base)}


def send_json(c, obj):
    c.sendall((json.dumps(obj) + "\n").encode())


def recv_json(f):
    line = f.readline()
    if not line:
        raise EOFError
    return json.loads(line)


def make_engine(ip, proto):
    from mooncake.engine import TransferEngine
    te = TransferEngine()
    rc = te.initialize(ip, "P2PHANDSHAKE", proto, "")
    if rc != 0:
        raise SystemExit(f"initialize rc={rc}")
    return te


def push(te, session, src_ptr, dst_ptr, lay, iters):
    srcs = [src_ptr + s for s, _, _ in lay]
    dsts = [dst_ptr + d for _, d, _ in lay]
    lens = [n for _, _, n in lay]
    rcs = []
    for _ in range(iters):
        rcs.append(te.batch_transfer_sync_write(session, srcs, dsts, lens))
    return rcs


# ------------------------------------------------------------------ decode --

def decode_main(a):
    te = make_engine(a.ip, a.proto)
    dst = Buf(a.bytes, a.gpu)
    src = Buf(a.bytes, a.gpu, seed=2)
    rc = te.batch_register_memory([dst.ptr, src.ptr], [dst.n, src.n])
    session = f"{a.ip}:{te.get_rpc_port()}"
    log("decode", f"engine up session={session} register rc={rc}")
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", a.ctl_port))
    s.listen(1)
    c, _ = s.accept()
    f = c.makefile("r")
    send_json(c, {"session": session, "dst": dst.ptr})
    while True:
        try:
            m = recv_json(f)
        except EOFError:
            break
        op = m["op"]
        if op == "digest":
            send_json(c, {"digest": dst.digest(m["ranges"])})
        elif op == "clear":
            dst.clear()
            send_json(c, {"ok": True})
        elif op == "push":
            lay = [tuple(x) for x in m["layout"]]
            rcs = push(te, m["session"], src.ptr, m["dst"], lay, m["iters"])
            send_json(c, {"rcs": rcs,
                          "digest": src.digest([(s_, n) for s_, _, n in lay])})
        elif op == "maps":
            send_json(c, module_maps())
        elif op == "exit":
            send_json(c, {"ok": True})
            break
    log("decode", "done")


# ----------------------------------------------------------------- prefill --

def prefill_main(a):
    # vLLM imports both connectors' modules before creating anything.
    import mooncake.engine  # noqa: F401
    from mooncake.store import MooncakeDistributedStore, ReplicateConfig

    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        log("prefill", f"CHECK {name} ok={int(bool(ok))} {detail}")

    def make_stores():
        out = []
        for i, port in enumerate(a.store_ports):
            st = MooncakeDistributedStore()
            rc = st.setup(f"{a.ip}:{port}", "P2PHANDSHAKE", 256 << 20,
                          64 << 20, a.proto, "", a.master)
            check(f"store[{i}] setup", rc == 0, f"rc={rc}")
            out.append(st)
        return out

    # Each TransferMetadata a module creates installs that module's hook; the
    # one created last decided, for every module, before the fix.
    if a.order == "engine-first":
        te = make_engine(a.ip, a.proto)
        stores = make_stores()
    else:
        stores = make_stores()
        te = make_engine(a.ip, a.proto)
    maps = module_maps()
    check("prefill maps both modules", maps["engine"] and maps["store"], f"{maps}")

    src = Buf(a.bytes, a.gpu, seed=1)
    dst = Buf(a.bytes, a.gpu)
    rc = te.batch_register_memory([src.ptr, dst.ptr], [src.n, dst.n])
    check("engine register", rc == 0, f"rc={rc}")
    session = f"{a.ip}:{te.get_rpc_port()}"

    c = None
    for _ in range(300):
        try:
            c = socket.create_connection(("127.0.0.1", a.ctl_port), timeout=600)
            break
        except OSError:
            time.sleep(0.2)
    f = c.makefile("r")
    info = recv_json(f)

    # Store traffic between the two clients for as long as the pushes run.
    sbuf = Buf(a.store_bytes, a.gpu, seed=3)
    rbuf = Buf(a.store_bytes, a.gpu)
    want = sbuf.digest([(0, sbuf.n)])
    stop = threading.Event()
    push_window = {"start": None, "end": None}
    store_ops = []  # (end time, ok, detail)

    def store_loop():
        w, r = stores
        cfg = ReplicateConfig()
        cfg.preferred_segment = f"{a.ip}:{a.store_ports[0]}"
        i = 0
        while not stop.is_set():
            key = f"two-module-{os.getpid()}-{i}"
            i += 1
            prc = w.put_from(key, sbuf.ptr, sbuf.n, cfg)
            rbuf.clear()
            got = r.get_into(key, rbuf.ptr, rbuf.n)
            # force: the get just leased the object, and leased objects
            # would otherwise fill the segment.
            rrc = w.remove(key, True)
            ok = (prc == 0 and got == rbuf.n and rrc == 0 and
                  rbuf.digest([(0, rbuf.n)]) == want)
            store_ops.append((time.time(), ok, f"put={prc} get={got} remove={rrc}"))

    th = threading.Thread(target=store_loop, daemon=True)
    th.start()
    time.sleep(1.0)

    lay = layout(a.push_bytes, a.piece, 1288)
    push_window["start"] = time.time()
    # P -> D: the prefill's engine pushes into the decode.
    t0 = time.time()
    rcs = push(te, info["session"], src.ptr, info["dst"], lay, a.iters)
    dt = time.time() - t0
    send_json(c, {"op": "digest", "ranges": [(d, n) for _, d, n in lay]})
    got = recv_json(f)["digest"]
    check("push P->D", all(r == 0 for r in rcs) and
          got == src.digest([(s_, n) for s_, _, n in lay]),
          f"rcs={rcs} {a.iters}x{a.push_bytes >> 20}MiB in {dt:.2f}s")
    # D -> P: the decode pushes into the prefill's engine.
    t0 = time.time()
    send_json(c, {"op": "push", "session": session, "dst": dst.ptr,
                  "layout": lay, "iters": a.iters})
    rep = recv_json(f)
    dt = time.time() - t0
    check("push D->P", all(r == 0 for r in rep["rcs"]) and
          rep["digest"] == dst.digest([(d, n) for _, d, n in lay]),
          f"rcs={rep['rcs']} in {dt:.2f}s")
    push_window["end"] = time.time()
    time.sleep(0.5)
    stop.set()
    th.join(timeout=120)

    during = [op for op in store_ops
              if push_window["start"] <= op[0] <= push_window["end"]]
    bad = [op for op in store_ops if not op[1]]
    check("store put/get while pushing",
          len(during) > 0 and not bad and not th.is_alive(),
          f"ops={len(store_ops)} during_pushes={len(during)} failed={len(bad)} "
          f"{bad[0][2] if bad else ''}")

    send_json(c, {"op": "maps"})
    dmaps = recv_json(f)
    check("decode maps only the engine", dmaps["engine"] and not dmaps["store"],
          f"{dmaps}")
    send_json(c, {"op": "exit"})
    recv_json(f)
    for st in stores:
        st.close()
    verdict = "PASS" if all(checks) else "FAIL"
    log("prefill", f"VERDICT {verdict} order={a.order} "
        f"secure={os.environ.get('MC_SECURE_MODE', '')!r} gpu={a.gpu}")
    sys.exit(0 if all(checks) else 1)


# ------------------------------------------------------------------ driver --

def main():
    p = argparse.ArgumentParser()
    p.add_argument("role", nargs="?", default="driver",
                   choices=["driver", "decode", "prefill"])
    p.add_argument("--master", required=True)
    p.add_argument("--ip", default="127.0.0.1")
    p.add_argument("--proto", default="tcp")
    p.add_argument("--gpu", action="store_true")
    p.add_argument("--order", default="engine-first",
                   choices=["engine-first", "store-first"])
    p.add_argument("--bytes", type=parse_size, default=parse_size("64M"))
    p.add_argument("--push-bytes", type=parse_size, default=parse_size("32M"))
    p.add_argument("--store-bytes", type=parse_size, default=parse_size("4M"))
    p.add_argument("--piece", type=parse_size, default=parse_size("256K"))
    p.add_argument("--iters", type=int, default=5)
    p.add_argument("--ctl-port", type=int, default=0)
    p.add_argument("--store-ports", type=int, nargs=2, default=None)
    p.add_argument("--timeout", type=int, default=600)
    a = p.parse_args()
    if a.role == "decode":
        return decode_main(a)
    if a.role == "prefill":
        return prefill_main(a)

    ctl = str(free_port())
    common = [sys.executable, os.path.abspath(__file__), "--master", a.master,
              "--ip", a.ip, "--proto", a.proto, "--order", a.order,
              "--bytes", str(a.bytes), "--push-bytes", str(a.push_bytes),
              "--store-bytes", str(a.store_bytes), "--piece", str(a.piece),
              "--iters", str(a.iters), "--ctl-port", ctl] + (["--gpu"] if a.gpu else [])
    dec = subprocess.Popen(common[:2] + ["decode"] + common[2:])
    pre = subprocess.Popen(common[:2] + ["prefill"] + common[2:] +
                           ["--store-ports", str(free_port()), str(free_port())])
    try:
        prc = pre.wait(timeout=a.timeout)
    except subprocess.TimeoutExpired:
        pre.kill()
        prc = -9
        log("driver", "prefill timed out")
    try:
        drc = dec.wait(timeout=60)
    except subprocess.TimeoutExpired:
        dec.kill()
        drc = -9
    log("driver", f"RESULT order={a.order} prefill_rc={prc} decode_rc={drc}")
    sys.exit(0 if prc == 0 and drc == 0 else 1)


if __name__ == "__main__":
    main()
