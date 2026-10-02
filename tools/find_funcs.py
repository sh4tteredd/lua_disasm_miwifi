#!/usr/bin/env python3
"""Map global handler names to nested prototype indices.

LuCI controllers define handlers as globals in the chunk root, e.g.::

    CLOSURE R4 proto[187]
    SETGLOBAL R4 "getIcon"

This walks the root prototype and prints ``name = proto[index]`` pairs.

Usage::

    python3 find_funcs.py xqsystem.lua
    python3 find_funcs.py xqsystem.lua getIcon uploadPlug
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fate import parse_file  # noqa: E402


def find(path):
    root, _used, _total = parse_file(path)
    last_closure = {}
    result = {}
    for ins in root.code:
        op = ins & 0x3F
        A = (ins >> 6) & 0xFF
        Bx = (ins >> 14) & 0x3FFFF          # Bx is 18 bits in Lua 5.1
        if op == 1:            # CLOSURE
            last_closure[A] = Bx
        elif op == 40:         # SETGLOBAL
            if Bx < len(root.k) and isinstance(root.k[Bx], str) and A in last_closure:
                result[root.k[Bx]] = last_closure[A]
    return result


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    mapping = find(sys.argv[1])
    names = sys.argv[2:] or sorted(mapping)
    for name in names:
        if name in mapping:
            print("%s = proto[%d]" % (name, mapping[name]))


if __name__ == "__main__":
    main()
