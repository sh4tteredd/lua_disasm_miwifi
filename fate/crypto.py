"""String de-obfuscation for the Xiaomi 'Fate' Lua dialect.

Recovered from ``liblua.so.5.1.5`` ``LoadString`` @ ``0x14028``::

    key = (len * 0x0d + 0x37) & 0xff
    plaintext[i] = stored[i] ^ key          # len includes the trailing NUL

Every string body is framed in the bytecode as::

    0x07 <u32 little-endian len> <len obfuscated bytes>

The trailing NUL is part of the payload, so a correctly framed string always
decrypts to a value whose last byte is ``0x00``.
"""
from __future__ import annotations

import struct

MUL = 0x0D
ADD = 0x37


def key_for(length: int) -> int:
    """Return the single-byte XOR key for a string of the given stored length."""
    return ((length & 0xFFFFFFFF) * MUL + ADD) & 0xFF


def decode(buf: bytes) -> bytes:
    """Decrypt a raw stored string body (including its trailing NUL)."""
    k = key_for(len(buf))
    return bytes(b ^ k for b in buf)


def encode(text: bytes) -> bytes:
    """Inverse of :func:`decode` (handy for tests / re-packing)."""
    return decode(text)  # XOR is an involution for a fixed length


def extract_strings(data: bytes):
    """Scan a whole Fate chunk and return ``(offset, length, plaintext)`` tuples.

    Framing is validated by requiring the decrypted terminator to be NUL, which
    makes false positives on arbitrary bytecode extremely unlikely.
    """
    out = []
    i = 0
    n = len(data)
    while i < n - 5:
        if data[i] == 0x07:
            size = struct.unpack_from("<I", data, i + 1)[0]
            if 1 <= size <= 0x10000 and i + 5 + size <= n:
                raw = data[i + 5:i + 5 + size]
                if raw[-1] ^ key_for(size) == 0:
                    out.append((i, size, decode(raw)))
                    i += 5 + size
                    continue
        i += 1
    return out
