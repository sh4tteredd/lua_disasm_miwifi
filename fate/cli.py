"""Command line interface: ``fate`` (or ``python -m fate``)."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .bytecode import MAGIC, parse_file, disasm, iter_protos
from .crypto import extract_strings


def _walk_fate(root):
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith(".lua"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "rb") as fh:
                    if fh.read(len(MAGIC)) == MAGIC:
                        yield p
            except OSError:
                continue


def _cmd_info(args):
    root, used, total = parse_file(args.file)
    print("file          :", args.file)
    print("signature     :", MAGIC)
    print("parsed bytes  :", used, "/", total)
    protos = sum(1 for _ in iter_protos(root))
    consts = sum(len(p.k) for _, p in iter_protos(root))
    code = sum(len(p.code) for _, p in iter_protos(root))
    print("prototypes    :", protos)
    print("instructions  :", code)
    print("constants     :", consts)
    print("root source   :", root.source)
    return 0


def _cmd_strings(args):
    if os.path.isdir(args.path):
        n = 0
        for p in _walk_fate(args.path):
            with open(p, "rb") as fh:
                data = fh.read()
            out = os.path.join(args.out, os.path.relpath(p, args.path) + ".txt")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w") as fh:
                for off, size, pt in extract_strings(data):
                    fh.write("%08x len=%5d %r\n" % (off, size, pt[:-1].decode("latin1")))
            n += 1
        print("decoded %d file(s) -> %s" % (n, args.out))
    else:
        with open(args.path, "rb") as fh:
            data = fh.read()
        for off, size, pt in extract_strings(data):
            print("%08x len=%5d %r" % (off, size, pt[:-1].decode("latin1")))
    return 0


def _cmd_disasm(args):
    root, used, total = parse_file(args.file)
    if args.strict and used != total:
        sys.stderr.write("warning: parsed %d/%d bytes\n" % (used, total))
    print("\n".join(disasm(root)))
    return 0


def _cmd_proto(args):
    root, _used, _total = parse_file(args.file)
    node = root
    try:
        for part in args.index.split("."):
            node = node.protos[int(part)]
    except (ValueError, IndexError):
        sys.stderr.write("error: no nested prototype at path %r\n" % args.index)
        return 1
    print("\n".join(disasm(node)))
    return 0


def _cmd_dump(args):
    n = 0
    for p in _walk_fate(args.path):
        root, _u, _t = parse_file(p)
        rel = os.path.relpath(p, args.path)
        with open(p, "rb") as fh:
            data = fh.read()
        sout = os.path.join(args.out, rel + ".strings.txt")
        aout = os.path.join(args.out, rel + ".asm")
        os.makedirs(os.path.dirname(sout), exist_ok=True)
        with open(sout, "w") as fh:
            for off, size, pt in extract_strings(data):
                fh.write("%08x len=%5d %r\n" % (off, size, pt[:-1].decode("latin1")))
        with open(aout, "w") as fh:
            fh.write("\n".join(disasm(root)) + "\n")
        n += 1
        if n % 50 == 0:
            print("... %d" % n, flush=True)
    print("dumped %d file(s) -> %s" % (n, args.out))
    return 0


def _cmd_to_luac(args):
    from .luac import to_stock
    with open(args.file, "rb") as fh:
        data = fh.read()
    out = to_stock(data)
    with open(args.out, "wb") as fh:
        fh.write(out)
    print("%s -> %s (%d bytes)" % (args.file, args.out, len(out)))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="fate",
        description="Parse, decode and disassemble Xiaomi 'Fate' Lua bytecode.",
    )
    ap.add_argument("--version", action="version", version="fate %s" % __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="summarise a chunk")
    p.add_argument("file")
    p.set_defaults(func=_cmd_info)

    p = sub.add_parser("strings", help="decrypt string constants (file or dir)")
    p.add_argument("path")
    p.add_argument("-o", "--out", default="strings_out", help="output dir for directories")
    p.set_defaults(func=_cmd_strings)

    p = sub.add_parser("disasm", help="disassemble a chunk")
    p.add_argument("file")
    p.add_argument("--strict", action="store_true", help="warn if not fully parsed")
    p.set_defaults(func=_cmd_disasm)

    p = sub.add_parser("proto", help="disassemble one nested function by index path")
    p.add_argument("file")
    p.add_argument("index", help="e.g. 187 or 0.3.2")
    p.set_defaults(func=_cmd_proto)

    p = sub.add_parser("dump", help="recursively dump strings + disassembly")
    p.add_argument("path")
    p.add_argument("out")
    p.set_defaults(func=_cmd_dump)

    p = sub.add_parser("to-luac", help="normalise a chunk to stock Lua 5.1 bytecode")
    p.add_argument("file")
    p.add_argument("out")
    p.set_defaults(func=_cmd_to_luac)

    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
