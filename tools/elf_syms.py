#!/usr/bin/env python3
"""Minimal ELF64 dynamic-symbol dumper for stripped shared libraries.

Some Xiaomi binaries (e.g. ``liblua.so.5.1.5``) have had their section headers
stripped, so ``nm``/``readelf`` cannot list symbols.  This walks the program
headers and the ``PT_DYNAMIC`` segment directly.

Usage::

    python3 elf_syms.py liblua.so.5.1.5 | grep lua_load
"""
import struct
import sys


def dump(path):
    d = open(path, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
    e_phnum = struct.unpack_from("<H", d, 0x38)[0]

    segs = []
    dyn = None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        t = struct.unpack_from("<I", d, o)[0]
        off, va, _pa, fsz, _msz = struct.unpack_from("<QQQQQ", d, o + 8)
        if t == 1:
            segs.append((off, va, fsz))
        if t == 2:
            dyn = (off, fsz)

    def v2o(v):
        for off, va, fsz in segs:
            if va <= v < va + fsz:
                return off + (v - va)
        return None

    tags = {}
    o, fsz = dyn
    j = o
    while j < o + fsz:
        tag, val = struct.unpack_from("<QQ", d, j)
        if tag == 0:
            break
        tags[tag] = val
        j += 16

    symtab = tags.get(6)
    strtab = tags.get(5)
    syment = tags.get(11, 24)

    nsym = None
    if 4 in tags:                      # DT_HASH -> nchain == symbol count
        nbucket, nchain, *_ = struct.unpack_from("<II", d, v2o(tags[4]))
        nsym = nchain

    so = v2o(strtab)
    symo = v2o(symtab)
    print("nsym=%s syment=%s" % (nsym, syment))
    if not nsym:
        return
    for i in range(nsym):
        no = symo + i * syment
        st_name, st_info, _other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", d, no)
        if st_name == 0:
            continue
        s = so + st_name
        e = s
        while d[e] != 0:
            e += 1
        name = d[s:e].decode("latin1")
        if name:
            print("%08x %7d %02x %5d %s" % (st_value, st_size, st_info, st_shndx, name))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    dump(sys.argv[1])
