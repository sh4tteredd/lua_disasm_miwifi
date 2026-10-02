# The Xiaomi "Fate" Lua format

Reverse engineered from `liblua.so.5.1.5` (undump/`LoadString`/`LoadFunction`)
and validated against the vendor `luac`. All 205 `.lua` files in RD23 firmware
1.0.104 parse to EOF with this specification.

## 1. File header (16 bytes)

```
1b 46 61 74 65 2f 5a 1b    ; ESC "Fate/Z" ESC  (replaces ESC "Lua")
51 00 01 04 04 04 08 04    ; version 0x51, format 0, little-endian,
                           ; sizeof(int)=4 sizeof(size_t)=4
                           ; sizeof(Instruction)=4 sizeof(lua_Number)=8
```

The stock signature (`ESC "Lua"`, 4 bytes) is replaced by an 8-byte one, so the
header is 16 bytes instead of 12.

## 2. Prototype

Unlike stock Lua 5.1, the scalar fields are interleaved with a source string:

```
char                      ; c1  (upvalues, in practice)
LoadString                ; source name (may be NULL -> inherits parent)
char                      ; c2  (numparams)
i32                       ; linedefined
char                      ; c3  (is_vararg)
i32                       ; lastlinedefined
char                      ; c4  (maxstacksize)
i32 sizecode ; code[sizecode] (u32 each)
i32 sizek    ; constants[sizek]
protos                    ; i32 count, then that many nested prototypes
lineinfo                  ; i32 count, then i32 each
locvars                   ; i32 count, then {LoadString name, i32 startpc, i32 endpc}
upvalues                  ; i32 count, then LoadString names
```

Note the tail order: **nested prototypes come before the debug tables**.

## 3. Strings

A string is stored as a 1-byte tag `0x07` (in the constant table) or directly
as `u32 len` (for source / debug names), followed by `len` obfuscated bytes.
`len` includes the trailing NUL.

```
key = (len * 0x0d + 0x37) & 0xff
plaintext[i] = stored[i] ^ key
```

## 4. Constants

| tag | type | payload |
|----:|------|---------|
| 3 | nil | none |
| 4 | boolean | u8 |
| 6 | number | f64 (little-endian) |
| 7 | string | `u32 len` + obfuscated bytes |
| 12 | integer | i32 |

## 5. Opcode table

The numeric opcode space is custom; the vendor binary's `luaP_opnames` array is
stale (so `luac -l` prints misleading names such as `MOD` for `CALL`). The table
below was recovered by differential compilation of single-construct snippets
with the firmware's own `luac`.

| op | name | mode | stock Lua 5.1 equivalent |
|---:|------|------|--------------------------|
| 1 | CLOSURE | ABx | CLOSURE |
| 2 | UNARY | ABC | NOT / UNM / LEN (combined) |
| 3 | LT | ABC | LT |
| 4 | ? | ABC | (unseen) |
| 5 | GT | ABC | (GT) |
| 6 | LOADK | ABx | LOADK |
| 7 | SETLIST | ABC | SETLIST |
| 8 | RETURN | ABC | RETURN |
| 9 | TEST | ABC | TEST |
| 10 | TFORLOOP | ABC | TFORLOOP |
| 11 | FORPREP | AsBx | FORPREP |
| 12 | SUB | ABC | SUB |
| 13 | TAILCALL | ABC | TAILCALL |
| 14 | DIV | ABC | DIV |
| 15 | SELF | ABC | SELF |
| 16 | CALL | ABC | CALL |
| 17 | SETTABLE | ABC | SETTABLE |
| 18 | GETUPVAL | ABC | GETUPVAL |
| 19 | EQ | ABC | EQ |
| 20 | NE | ABC | (NE) |
| 21 | CONCAT | ABC | CONCAT |
| 22 | LE | ABC | LE |
| 24 | LOADBOOL | ABC | LOADBOOL |
| 25 | MOD | ABC | MOD |
| 26 | FORLOOP | AsBx | FORLOOP |
| 27 | GETTABLE | ABC | GETTABLE |
| 28 | NEWTABLE | ABC | NEWTABLE |
| 30 | VARARG | ABC | VARARG |
| 31 | JMP | sBx | JMP |
| 33 | POW | ABC | POW |
| 34 | MUL | ABC | MUL |
| 36 | MOVE | ABC | MOVE |
| 37 | ADD | ABC | ADD |
| 38 | GETGLOBAL | ABx | GETGLOBAL |
| 39 | SETUPVAL | ABC | SETUPVAL |
| 40 | SETGLOBAL | ABx | SETGLOBAL |

Operand packing is the stock Lua 5.1 layout: `op` bits 0-5, `A` bits 6-13,
`C` bits 14-22, `B` bits 23-31, `Bx = B | C<<9`, `sBx = Bx - 131071`.
RK operands use bit 8 (`0x100`) as the constant flag.
