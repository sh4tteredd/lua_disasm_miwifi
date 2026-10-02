"""fate -- parser, decoder and disassembler for Xiaomi 'Fate' Lua bytecode.

Xiaomi/Redmi routers (e.g. RD23 / AX3000T) ship their LuCI controllers as a
custom Lua 5.1 bytecode dialect with the signature ``\\x1bFate/Z\\x1b``, a
length-keyed XOR on every string constant, and a non-stock opcode table.

This package recovers all of that so the files can be read statically.
"""

from .crypto import key_for, decode, extract_strings
from .bytecode import (
    Reader,
    Proto,
    load_proto,
    parse_bytes,
    parse_file,
    disasm,
    OPS,
)

__version__ = "1.0.0"
__all__ = [
    "key_for", "decode", "extract_strings",
    "Reader", "Proto", "load_proto", "parse_bytes", "parse_file",
    "disasm", "OPS",
]
