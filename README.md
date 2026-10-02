# lua_disasm_miwifi

**Parser, string decoder and disassembler for the Xiaomi “Fate” Lua bytecode
used by MiWiFi / Redmi router firmware.**

Xiaomi ships the LuCI web controllers on its routers as a custom Lua 5.1
bytecode dialect: a `\x1bFate/Z\x1b` signature, an XOR-obfuscated string table,
and a non-stock opcode table. Stock tools (`luac -l`, `unluac`, `luadec`)
cannot read it. This project recovers the format and makes the firmware
readable.

> Verified against `miwifi_rd23_all_0904d_1.0.104_INT.bin` (Redmi AX3000T INT,
> MT7981): **all 205 `.lua` files parse to EOF exactly**.

```
$ fate disasm controller.lua
function <None:2-10> upvals=0 nparams=0 vararg=0 stack=3
  [   0] GETGLOBAL 0 0   ; 'node'
  [   1] LOADK 1 1   ; 'api'
  [   2] CALL 0 2 2   ; R0..=R0(R1..R1)
  [   3] GETGLOBAL 1 3   ; 'firstchild'
  [   4] CALL 1 1 2   ; R1..=R1(R2..R1)
  [   5] SETTABLE 0 258 1   ; R0["target"]=R1
  ...
```

## Features

- **Container parser** — full prototype tree (code, constants, debug info).
- **String decoder** — recovers every string constant (`key = len*0x0d+0x37`).
- **Opcode table** — the real semantics of all 40 used opcodes, recovered by
  differential compilation.
- **Disassembler** — annotated listings (constants resolved, call/table ops
  labelled, jump targets computed).
- **Normaliser** — converts a Fate chunk back to stock Lua 5.1 bytecode for
  interop with other tooling.
- **Helpers** — HDR1 firmware splitter, ELF dynamic-symbol dumper,
  handler→prototype index mapper.
- **Pure standard library** — no dependencies.

## Install

Nothing to install; Python 3.8+ is enough:

```bash
git clone https://github.com/sh4tteredd/lua_disasm_miwifi lua_disasm_miwifi
cd lua_disasm_miwifi
python3 bin/fate --help
```

Optionally install the `fate` entry point:

```bash
pip install -e .
fate --help
```

## Quick start

```bash
# summarise a chunk
fate info /path/to/xqsystem.lua

# decrypt every string constant
fate strings /path/to/xqsystem.lua

# full disassembly (nested functions included)
fate disasm /path/to/xqsystem.lua > xqsystem.asm

# just one nested function, by index path
fate proto /path/to/xqsystem.lua 187

# recursively dump a whole firmware rootfs (strings + disassembly)
fate dump extracted/rootfs out/

# convert one file to stock Lua 5.1 bytecode
fate to-luac /path/to/xqsystem.lua xqsystem.stock.luac
```

## Library

```python
from fate import parse_file, extract_strings, disasm, decode, key_for

root, used, total = parse_file("xqsystem.lua")
print(used, total, root.source, len(root.protos))

# walk the prototype tree
from fate import iter_protos
for path, proto in iter_protos(root):
    if "get_icon" in proto.k:
        print("found in proto", path)

# decrypt a single stored string body
plaintext = decode(raw_bytes)          # includes the trailing NUL
```

## Repository layout

```
lua_disasm_miwifi/
├── fate/                 # the package
│   ├── crypto.py         # string de-obfuscation
│   ├── bytecode.py       # parser + disassembler + opcode table
│   ├── luac.py           # normalise to stock Lua 5.1
│   └── cli.py            # `fate` command line
├── bin/fate              # source-checkout launcher
├── tools/
│   ├── hdr1_parse.py     # split a Xiaomi HDR1 firmware container
│   ├── find_funcs.py     # global handler name -> proto index
│   └── elf_syms.py       # dynamic symbols for stripped ELFs
├── docs/FORMAT.md        # the bytecode specification
├── examples/             # sample disassembly / string dumps
├── tests/                # unittest suite + vendor-compiled fixtures
└── pyproject.toml
```

## Tools

The `tools/` folder holds three standalone, dependency-free helpers. They are
not part of the installed `fate` command; run them straight from a source
checkout with `python3 tools/<script>.py` (Python 3.8+).

### `hdr1_parse.py` — split a firmware container

```bash
python3 tools/hdr1_parse.py miwifi_rd23_all_0904d_1.0.104_INT.bin extracted
```

Xiaomi router firmware downloads are usually an `HDR1` container holding several
named sections (kernel, rootfs, …). This script walks that container and writes
each section out as its own file, so you can get at `rootfs` in one step.

Layout it assumes (little-endian): the first entry starts at offset `0x90`, and
each entry is a 16-byte header followed by a 32-byte NUL-padded name and the
data:

```
header : u16 magic (0xBABE), u16 pad, u32 0xffffffff, u32 size, u32 0x0000ffff
name   : NUL-terminated, padded to 32 bytes
data   : `size` bytes
```

For every entry it prints the index, offset, size and name, then writes the
payload to `<outdir>/<name>` (default output directory is `extracted`). It stops
cleanly if the magic is wrong, the size is zero, or the payload would run past
EOF — handy when the trailing layout differs between models.

### `find_funcs.py` — handler name to prototype index

```bash
python3 tools/find_funcs.py xqsystem.lua                 # list every handler
python3 tools/find_funcs.py xqsystem.lua getIcon uploadPlug
```

LuCI controllers define their handlers as globals in the chunk root, e.g.
`CLOSURE R4 proto[187]` immediately followed by `SETGLOBAL R4 "getIcon"`. This
script walks the root prototype's code, remembers the prototype index (`Bx`)
held by each register on a `CLOSURE` (opcode `1`), and pairs it with the string
constant used by the following `SETGLOBAL` (opcode `40`). The result is a
`name = proto[index]` map. Pass handler names to filter the output, or omit them
to print every mapping sorted by name. The printed index is the one to feed to
`fate proto`.

### `elf_syms.py` — dynamic symbols from stripped ELFs

```bash
python3 tools/elf_syms.py liblua.so.5.1.5 | grep lua_load
```

`liblua.so.5.1.5` on these routers has its section headers stripped, so
`nm`/`readelf` cannot list its symbols. This script reads the program headers
instead and walks the `PT_DYNAMIC` segment directly: it collects the `PT_LOAD`
segments to translate virtual addresses back to file offsets, then reads the
dynamic tags for the symbol table (`DT_SYMTAB`), string table (`DT_STRTAB`),
symbol entry size (`DT_SYMENT`) and symbol count (from `DT_HASH`). Each symbol
is printed as `value size info shndx name`, which is enough to locate routines
like `LoadString` for further disassembly.

## Format in one screen

```
header : 1b "Fate/Z" 1b  51 00 01 04 04 04 08 04            (16 bytes)
proto  : char, source, char, linedefined(i32), char,
         lastlinedefined(i32), char, sizecode(i32), code[],
         sizek(i32), consts[], protos[], lineinfo[], locvars[], upvalues[]
string : u32 len + len obfuscated bytes       (len includes the NUL)
cipher : plaintext[i] = stored[i] ^ ((len*0x0d + 0x37) & 0xff)
consts : tag 3=nil 4=bool 6=number(f64) 7=string 12=int(i32)
```

See **[docs/FORMAT.md](docs/FORMAT.md)** for the full opcode table and operand
encoding.

## How the format was recovered

1. Located the custom undump/`LoadString` in `liblua.so.5.1.5` by scanning for
   the `Fate/Z` signature reference.
2. Read the decoder loop (`0x14028`): a length-keyed XOR, verified against known
   constants.
3. Recovered the prototype layout by parsing to EOF across all files.
4. Recovered the **opcode table** by compiling single-construct snippets
   (`local a = b`, `t.x = 1`, `f()`, `if …`, `for …`, …) with the firmware's
   own `luac` and correlating the emitted opcode numbers — see
   `tests/fixtures/` (sources + compiled output).

## Limitations

- The `UNARY` opcode combines `NOT`/`UNM`/`LEN`; the subtype is not yet decoded
  in the listing (opcodes `4`, `23`, `29`, `32`, `35` are unused/unseen).
- `to-luac` preserves the custom opcodes, so stock decompilers may still reject
  a converted file; it is intended for structural interop.
- Tested only against Xiaomi MT7981 `RD23` 1.0.104; other models may use a
  different opcode permutation.

## Responsible use

This is a static-analysis tool for firmware you are authorised to examine
(security research, CTFs, repair, interoperability). It ships no firmware and
does not contact any device. Do not use it to attack equipment you do not own
or have permission to test.

## License

MIT — see [LICENSE](LICENSE).
