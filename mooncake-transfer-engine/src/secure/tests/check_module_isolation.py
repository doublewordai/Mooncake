#!/usr/bin/env python3
"""Checks that built Mooncake modules export no secure-mode symbol (DW-1288).

  check_module_isolation.py MODULE.so [MODULE.so ...]

engine.so and _store*.so each link the secure code statically, and one
process can load both (SECURE_KV.md, "One copy per module"). A secure symbol
in a module's dynamic symbol table can be merged with the other module's
(STB_GNU_UNIQUE, as an inline variable such as the handshake framing hook
gets by default) or bind the other module's calls, so that one module's
transfer engine runs on the other's state. Refused, listed, exit status 1:
  - any secure-mode entity (function, variable, vtable, typeinfo, guard), and
    the handshake framing hook;
  - any GNU-unique or data symbol whose name mentions a secure-mode type,
    such as a static of a foreign template instantiated over one.
Code of foreign templates instantiated over secure types (std::, coro_rpc::)
is stateless and identical in both modules, and is allowed.
Needs binutils' nm.
"""
import re
import subprocess
import sys

NS = r"mooncake::(secure|control_auth|secure_env)::"
OWN = re.compile(
    r"^((typeinfo( name)?|vtable|VTT|construction vtable|guard variable) for )?"
    r"(" + NS + r"|mooncake::g_handshake_framing_hook)")
MENTIONS = re.compile(NS + r"|mooncake::g_handshake_framing_hook")
DATA = set("uBbDdGgSs")


def exported(path):
    out = subprocess.run(["nm", "-D", "--defined-only", "-C", path],
                         check=True, capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3:
            yield parts[1], parts[2]


def refused(kind, name):
    if OWN.search(name):
        return True
    return kind in DATA and bool(MENTIONS.search(name))


def main(paths):
    bad = 0
    for path in paths:
        syms = list(exported(path))
        hits = [(t, n) for t, n in syms if refused(t, n)]
        allowed = sum(1 for t, n in syms if MENTIONS.search(n)) - len(hits)
        unique = sum(1 for t, _ in hits if t == "u")
        print(f"{path}: {len(hits)} refused secure symbols ({unique} GNU-unique); "
              f"{allowed} foreign template instantiations over secure types allowed")
        for t, n in hits[:50]:
            print(f"  {t} {n[:200]}")
        bad += len(hits)
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
