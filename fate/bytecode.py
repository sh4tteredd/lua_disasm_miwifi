"""Parser + disassembler for Xiaomi 'Fate' Lua bytecode.

Container / prototype layout recovered from ``liblua.so.5.1.5`` (``LoadFunction``)::

    header : 16 bytes
             1b "Fate/Z" 1b 51 00 01 04 04 04 08 04
    proto  : char, source(LoadString), char, linedefined(i32), char,
             lastlinedefined(i32), char, sizecode(i32), code[sizecode],
             sizek(i32), consts[sizek], protos, lineinfo, locvars, upvalues
    string : u32 len + len obfuscated bytes  (see :mod:`fate.crypto`)
    consts : tag byte + payload
             3 = nil, 4 = boolean(u8), 6 = number(f64), 7 = string, 12 = int(i32)

The opcode table is *not* stock Lua 5.1; it was recovered by differential
compilation against the firmware's own ``luac`` (see ``tests/`` and
``docs/FORMAT.md``).  Names in :data:`OPS` therefore describe the semantics of
each numeric opcode, not the (stale) names printed by the vendor ``luac -l``.
"""
from __future__ import annotations

import struct

from .crypto import decode

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TAG_NIL = 3
TAG_BOOLEAN = 4
TAG_NUMBER = 6
TAG_STRING = 7
TAG_INT = 12

MAGIC = b"\x1bFate/Z\x1b"
HEADER_LEN = 16
MAX_SBx = 131071

#: numeric opcode -> (mnemonic, operand mode)
OPS_RAW = {
    1:  ("CLOSURE",  "ABx"),
    2:  ("UNARY",    "ABC"),   # NOT / UNM / LEN (subtype in an operand)
    3:  ("LT",       "ABC"),
    4:  ("OP4",      "ABC"),
    5:  ("GT",       "ABC"),
    6:  ("LOADK",    "ABx"),
    7:  ("SETLIST",  "ABC"),
    8:  ("RETURN",   "ABC"),
    9:  ("TEST",     "ABC"),
    10: ("TFORLOOP", "ABC"),
    11: ("FORPREP",  "AsBx"),
    12: ("SUB",      "ABC"),
    13: ("TAILCALL", "ABC"),
    14: ("DIV",      "ABC"),
    15: ("SELF",     "ABC"),
    16: ("CALL",     "ABC"),
    17: ("SETTABLE", "ABC"),
    18: ("GETUPVAL", "ABC"),
    19: ("EQ",       "ABC"),
    20: ("NE",       "ABC"),
    21: ("CONCAT",   "ABC"),
    22: ("LE",       "ABC"),
    23: ("OP23",     "ABC"),
    24: ("LOADBOOL", "ABC"),
    25: ("MOD",      "ABC"),
    26: ("FORLOOP",  "AsBx"),
    27: ("GETTABLE", "ABC"),
    28: ("NEWTABLE", "ABC"),
    29: ("OP29",     "ABC"),
    30: ("VARARG",   "ABC"),
    31: ("JMP",      "sBx"),
    32: ("OP32",     "ABC"),
    33: ("POW",      "ABC"),
    34: ("MUL",      "ABC"),
    35: ("OP35",     "ABC"),
    36: ("MOVE",     "ABC"),
    37: ("ADD",      "ABC"),
    38: ("GETGLOBAL","ABx"),
    39: ("SETUPVAL", "ABC"),
    40: ("SETGLOBAL","ABx"),
}
OPS = [OPS_RAW.get(i, ("OP%d" % i, "ABC")) for i in range(64)]


class FateError(Exception):
    """Raised when a chunk is not valid Fate bytecode."""


# ---------------------------------------------------------------------------
# Reader / model
# ---------------------------------------------------------------------------
class Reader:
    """Little-endian byte reader with the primitive loaders used by undump."""

    def __init__(self, data: bytes, pos: int = HEADER_LEN):
        self.b = data
        self.p = pos

    def u8(self) -> int:
        v = self.b[self.p]
        self.p += 1
        return v

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.b, self.p)[0]
        self.p += 4
        return v

    def i32(self) -> int:
        v = struct.unpack_from("<i", self.b, self.p)[0]
        self.p += 4
        return v

    def dbl(self) -> float:
        v = struct.unpack_from("<d", self.b, self.p)[0]
        self.p += 8
        return v

    def string(self):
        """LoadString: ``u32 len`` + ``len`` obfuscated bytes (0 means NULL)."""
        n = self.u32()
        if n == 0:
            return None
        raw = self.b[self.p:self.p + n]
        self.p += n
        return decode(raw)[:-1].decode("latin1")


class Proto:
    """A parsed function prototype (one entry in the proto tree)."""

    __slots__ = (
        "c1", "source", "c2", "linedefined", "c3", "lastlinedefined", "c4",
        "code", "k", "protos", "lineinfo", "locvars", "upvals",
    )

    def __repr__(self):
        return "<Proto %s:%s-%s code=%d k=%d protos=%d>" % (
            self.source, self.linedefined, self.lastlinedefined,
            len(self.code), len(self.k), len(self.protos),
        )


def load_proto(r: Reader, psource=None) -> Proto:
    """Recursively parse one prototype (and its nested functions)."""
    f = Proto()
    f.c1 = r.u8()
    f.source = r.string()
    if f.source is None:
        f.source = psource
    f.c2 = r.u8()
    f.linedefined = r.i32()
    f.c3 = r.u8()
    f.lastlinedefined = r.i32()
    f.c4 = r.u8()

    n = r.i32()
    f.code = [r.u32() for _ in range(n)]

    nk = r.i32()
    f.k = []
    for _ in range(nk):
        t = r.u8()
        if t == TAG_NIL:
            f.k.append(None)
        elif t == TAG_BOOLEAN:
            f.k.append(bool(r.u8()))
        elif t == TAG_NUMBER:
            f.k.append(r.dbl())
        elif t == TAG_INT:
            f.k.append(r.i32())
        elif t == TAG_STRING:
            f.k.append(r.string())
        else:
            raise FateError("unknown constant tag %d at 0x%x" % (t, r.p - 1))

    # In this dialect the nested functions come before the debug tables.
    np = r.i32()
    f.protos = [load_proto(r, f.source) for _ in range(np)]

    n = r.i32()
    f.lineinfo = [r.i32() for _ in range(n)]

    nlv = r.i32()
    f.locvars = []
    for _ in range(nlv):
        name = r.string()
        startpc = r.i32()
        endpc = r.i32()
        f.locvars.append((name, startpc, endpc))

    nup = r.i32()
    f.upvals = [r.string() for _ in range(nup)]
    return f


def parse_bytes(data: bytes):
    """Parse a Fate chunk from memory.

    Returns ``(root_proto, bytes_consumed, total_len)``.
    """
    if not data.startswith(MAGIC):
        raise FateError("not a Fate chunk (bad signature)")
    r = Reader(data)
    root = load_proto(r)
    return root, r.p, len(data)


def parse_file(path: str):
    """Parse a Fate chunk from disk (same tuple as :func:`parse_bytes`)."""
    with open(path, "rb") as fh:
        return parse_bytes(fh.read())


# ---------------------------------------------------------------------------
# Disassembler
# ---------------------------------------------------------------------------
def _rk(f: Proto, x: int) -> str:
    """Render an RK operand: a register or a constant."""
    if x & 0x100:
        i = x & 0xff
        if i < len(f.k):
            v = f.k[i]
            return '"%s"' % v if isinstance(v, str) else repr(v)
        return "K?%d" % i
    return "R%d" % x


def disasm(f: Proto, depth: int = 0, out=None):
    """Return a list of text lines disassembling ``f`` and its children."""
    out = [] if out is None else out
    ind = "  " * depth
    out.append(
        "%sfunction <%s:%d-%d> upvals=%d nparams=%d vararg=%d stack=%d"
        % (ind, f.source, f.linedefined, f.lastlinedefined,
           f.c1, f.c2, f.c3, f.c4)
    )
    for i, ins in enumerate(f.code):
        op = ins & 0x3f
        A = (ins >> 6) & 0xff
        C = (ins >> 14) & 0x1ff
        B = (ins >> 23) & 0x1ff
        Bx = (ins >> 14) & 0x3ffff          # Bx is 18 bits in Lua 5.1
        sBx = Bx - MAX_SBx
        name, mode = OPS[op]
        s = ""
        if mode == "ABC":
            s = "%s %d %d %d" % (name, A, B, C)
            if name == "GETTABLE":
                s += "   ; R%d=%s[%s]" % (A, _rk(f, B), _rk(f, C))
            elif name == "SETTABLE":
                s += "   ; %s[%s]=%s" % (_rk(f, A), _rk(f, B), _rk(f, C))
            elif name == "SELF":
                s += "   ; R%d=%s; R%d=%s[%s]" % (A + 1, _rk(f, B), A, _rk(f, B), _rk(f, C))
            elif name == "CONCAT":
                s += "   ; R%d=R%d..R%d" % (A, B, C)
            elif name in ("ADD", "SUB", "MUL", "DIV", "MOD", "POW"):
                s += "   ; R%d=%s %s %s" % (A, _rk(f, B), name, _rk(f, C))
            elif name == "CALL":
                s += "   ; R%d..=R%d(R%d..R%d)" % (A, A, A + 1, A + B - 1)
            elif name == "TAILCALL":
                s += "   ; return R%d(R%d..R%d)" % (A, A + 1, A + B - 1)
            elif name == "RETURN":
                s += "   ; return R%d..R%d" % (A, A + B - 2)
            elif name == "LOADBOOL":
                s += "   ; R%d=%d pcskip=%d" % (A, B, C)
            elif name in ("EQ", "LT", "LE", "NE", "GT"):
                s += "   ; if (%s %s %s) ~= %d" % (_rk(f, B), name, _rk(f, C), A)
            elif name == "TEST":
                s += "   ; if R%d ~= %d" % (A, C)
            elif name == "VARARG":
                s += "   ; R%d.. = vararg(%d)" % (A, B - 1)
            elif name == "SETLIST":
                s += "   ; R%d[%d*FPF+i] = R%d.." % (A, C, A + 1)
        elif mode == "ABx":
            s = "%s %d %d" % (name, A, Bx)
            if name in ("LOADK", "GETGLOBAL", "SETGLOBAL") and Bx < len(f.k):
                s += "   ; %r" % (f.k[Bx],)
            elif name == "CLOSURE":
                s += "   ; proto[%d]" % Bx
        elif mode == "sBx":
            s = "%s %d   ; -> %d" % (name, sBx, i + 1 + sBx)
        elif mode == "AsBx":
            s = "%s %d %d   ; -> %d" % (name, A, sBx, i + 1 + sBx)
        out.append("%s  [%4d] %s" % (ind, i, s))
    for j, p in enumerate(f.protos):
        out.append("%s  -- nested proto[%d]" % (ind, j))
        disasm(p, depth + 1, out)
    return out


def iter_protos(f: Proto, path=()):
    """Yield ``(path_tuple, proto)`` for the whole proto tree (depth-first)."""
    yield path, f
    for i, child in enumerate(f.protos):
        yield from iter_protos(child, path + (i,))
