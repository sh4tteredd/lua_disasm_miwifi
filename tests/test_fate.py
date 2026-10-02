"""Tests for the Fate parser / decoder / disassembler.

Run with::

    python3 -m pytest tests/            # if pytest is available
    python3 tests/test_fate.py          # otherwise (plain unittest)

Fixtures under ``tests/fixtures`` were produced with the vendor ``luac`` from
tiny known programs (the matching ``.lua`` source is included), so the expected
opcodes below are ground truth for the opcode table.
"""
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from fate import parse_file, extract_strings, key_for, decode  # noqa: E402
from fate.crypto import encode  # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def _root(name):
    proto, used, total = parse_file(os.path.join(FIX, name))
    assert used == total, "%s parsed %d/%d" % (name, used, total)
    return proto


class TestCrypto(unittest.TestCase):
    def test_key_is_length_based(self):
        # len 17 -> (17*13 + 0x37) & 0xff == 0x14, the "checkMobileAccel" key.
        self.assertEqual(key_for(17), 0x14)
        self.assertEqual(key_for(15), 0xFA)  # "setMobileAccel"

    def test_roundtrip(self):
        for n in range(1, 64):
            raw = bytes(range(n))
            self.assertEqual(encode(decode(raw)), raw)


class TestParser(unittest.TestCase):
    def test_all_fixtures_parse_to_eof(self):
        for fn in sorted(os.listdir(FIX)):
            if fn.endswith(".luac"):
                _root(fn)  # asserts used == total inside

    def test_loadk_constants(self):
        proto = _root("loadk.luac")
        self.assertIn("s", proto.k)

    def test_getglobal_constant(self):
        self.assertIn("g", _root("getglobal.luac").k)

    def test_gettable_constant(self):
        self.assertIn("x", _root("gettable.luac").k)

    def test_opcode_map_loadk(self):
        # source: local a = "s" return a
        ops = [i & 0x3F for i in _root("loadk.luac").code]
        self.assertEqual(ops[:3], [6, 8, 8])  # LOADK, RETURN, RETURN

    def test_opcode_map_getglobal_call(self):
        # source: g()   ->  GETGLOBAL, CALL, RETURN
        ops = [i & 0x3F for i in _root("getglobal.luac").code]
        self.assertEqual(ops[:3], [38, 16, 8])

    def test_opcode_map_arithmetic(self):
        # source: local a=1 local b=2 local c=a+b return c
        ops = [i & 0x3F for i in _root("add.luac").code]
        self.assertIn(37, ops)  # ADD

    def test_string_extraction(self):
        with open(os.path.join(FIX, "gettable.luac"), "rb") as fh:
            data = fh.read()
        texts = {pt[:-1].decode("latin1") for _o, _s, pt in extract_strings(data)}
        self.assertIn("x", texts)


class TestDisasm(unittest.TestCase):
    def test_disasm_mentions_known_constant(self):
        from fate import disasm
        text = "\n".join(disasm(_root("getglobal.luac")))
        self.assertIn("GETGLOBAL", text)
        self.assertIn("'g'", text)


class TestCli(unittest.TestCase):
    def test_info_runs(self):
        from fate.cli import main
        self.assertEqual(main(["info", os.path.join(FIX, "loadk.luac")]), 0)

    def test_proto_runs(self):
        from fate.cli import main
        # closure.luac defines one nested function (proto[0]).
        self.assertEqual(main(["proto", os.path.join(FIX, "closure.luac"), "0"]), 0)

    def test_proto_bad_index(self):
        from fate.cli import main
        self.assertEqual(main(["proto", os.path.join(FIX, "loadk.luac"), "9"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
