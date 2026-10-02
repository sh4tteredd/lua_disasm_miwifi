#!/usr/bin/env python3
"""Split a Xiaomi HDR1 firmware container into its named sections.

Container layout (little-endian):

    entry = 16-byte header + 32-byte name + data
    header fields: u16 magic(0xBABE), u16 pad, u32 0xffffffff,
                   u32 size, u32 0x0000ffff
    name: NUL-terminated, padded to 32 bytes

Usage::

    python3 hdr1_parse.py miwifi_rd23_all_0904d_1.0.104_INT.bin extracted
"""
import os
import struct
import sys


def parse(path, outdir):
    data = open(path, "rb").read()
    if data[:4] != b"HDR1":
        raise SystemExit("not an HDR1 container")

    os.makedirs(outdir, exist_ok=True)
    off = 0x90  # first entry offset in known RD23 images
    idx = 0
    while off + 0x30 <= len(data):
        magic, _pad, _ffff, size, _ffff2 = struct.unpack_from("<HHI I I", data, off)
        name = data[off + 0x10: off + 0x30].split(b"\x00", 1)[0].decode("utf-8", "replace")
        if magic != 0xBABE:
            print("stop at 0x%x: magic=0x%04x name=%r" % (off, magic, name))
            break
        doff = off + 0x30
        print("[%d] off=0x%06x size=0x%08x name=%r" % (idx, off, size, name))
        if size == 0 or doff + size > len(data):
            print("   size out of range, stopping")
            break
        with open(os.path.join(outdir, name), "wb") as fh:
            fh.write(data[doff: doff + size])
        off = doff + size
        idx += 1
    print("done, next off = 0x%x, file len = 0x%x" % (off, len(data)))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    parse(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "extracted")
