"""Normalise a Fate chunk into stock Lua 5.1 bytecode.

This decrypts all strings, remaps the custom constant tags to stock 5.1 tags,
reorders the prototype fields / tail sections into stock order and emits the
stock 12-byte header.  The result can be fed to a standard Lua 5.1 decompiler
(``unluac``, ``luadec``) or to a stock ``luac -l``.

Note: the custom opcode table is *not* remapped (the bytecode operand layout is
preserved).  Stock tooling will parse the structure but may reject the custom
opcodes -- this module is provided for tooling interop, not full round-tripping.
"""
from __future__ import annotations

import struct

from .bytecode import Reader, Proto, load_proto

STOCK_HEADER = bytes([
    0x1b, 0x4c, 0x75, 0x61,          # ESC "Lua"
    0x51, 0x00, 0x01,                # version 5.1, format 0, little-endian
    0x04, 0x04, 0x04, 0x08, 0x00,    # sizeof int/size_t/Instr, lua_Number, integral
])


class _Writer:
    def __init__(self):
        self.b = bytearray()

    def u8(self, v):
        self.b.append(v & 0xFF)

    def u32(self, v):
        self.b += struct.pack("<I", v & 0xFFFFFFFF)

    def dbl(self, v):
        self.b += struct.pack("<d", v)

    def raw(self, x):
        self.b += x

    def string(self, s):
        if s is None:
            self.u32(0)
            return
        raw = s.encode("latin1") + b"\x00"
        self.u32(len(raw))
        self.raw(raw)


def _dump_const(w, k):
    if k is None:
        w.u8(0)                                  # LUA_TNIL
    elif isinstance(k, bool):
        w.u8(1)
        w.u8(1 if k else 0)                      # LUA_TBOOLEAN
    elif isinstance(k, int):
        w.u8(3)
        w.dbl(float(k))                          # stock has no integer type
    elif isinstance(k, float):
        w.u8(3)
        w.dbl(k)                                 # LUA_TNUMBER
    elif isinstance(k, str):
        w.u8(4)
        w.string(k)                              # LUA_TSTRING
    else:
        raise ValueError("bad constant %r" % (k,))


def _dump_proto(w, f: Proto):
    w.string(f.source)
    w.u32(f.linedefined)
    w.u32(f.lastlinedefined)
    w.u8(f.c1)   # nups
    w.u8(f.c2)   # numparams
    w.u8(f.c3)   # is_vararg
    w.u8(f.c4)   # maxstacksize

    w.u32(len(f.code))
    for ins in f.code:
        w.u32(ins)

    w.u32(len(f.k))
    for k in f.k:
        _dump_const(w, k)

    # stock order: constants -> protos -> debug
    w.u32(len(f.protos))
    for p in f.protos:
        _dump_proto(w, p)

    w.u32(len(f.lineinfo))
    for li in f.lineinfo:
        w.u32(li)

    w.u32(len(f.locvars))
    for name, startpc, endpc in f.locvars:
        w.string(name)
        w.u32(startpc)
        w.u32(endpc)

    w.u32(len(f.upvals))
    for uv in f.upvals:
        w.string(uv)


def to_stock(data: bytes) -> bytes:
    """Convert raw Fate chunk bytes to raw stock Lua 5.1 chunk bytes."""
    r = Reader(data)
    root = load_proto(r)
    w = _Writer()
    w.raw(STOCK_HEADER)
    _dump_proto(w, root)
    return bytes(w.b)


def to_stock_file(src: str, dst: str) -> int:
    with open(src, "rb") as fh:
        out = to_stock(fh.read())
    with open(dst, "wb") as fh:
        fh.write(out)
    return len(out)
