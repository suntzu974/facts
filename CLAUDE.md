# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`facts` is a small Rust CLI that talks to **MIFARE Classic 1K** cards through an
**ACR122U** PC/SC reader. It speaks raw APDUs directly via the `pcsc` crate —
there is intentionally no `libnfc` abstraction. The whole tool is a single file
(`src/main.rs`, ~310 lines) and is meant to double as a readable reference for
the ACR122U + MIFARE Classic APDU protocol.

## Build & run

```bash
cargo build --release           # binary: ./target/release/facts
cargo run --release -- <args>   # iterate without retyping the path
```

System prerequisites (the `pcsc` crate links against `libpcsclite`):

```bash
sudo dnf install -y pkgconf pcsc-lite-devel pcsc-lite   # Fedora
sudo systemctl enable --now pcscd
```

The ACR122U must be plugged in and `pcscd` running before any subcommand other
than `list` can succeed.

There is no test suite — `cargo test` will pass trivially because no tests are
defined. All verification is done end-to-end against a physical card.

## Architecture

Single binary, single file. The flow is always:

1. `PcscContext::establish` → `connect(reader_index)` returns a `Card`.
2. For any block I/O: `parse_key` → `authenticate(block, key, kind)` → `read_block` / `write_block`.
3. Every APDU goes through `transmit()`, which enforces `SW = 9000` and strips
   the status word before returning the payload. Treat non-`9000` as a hard
   error — don't add silent retries.

The MIFARE Classic 1K layout the code assumes: 64 blocks of 16 bytes, grouped
in 16 sectors of 4 blocks. Block `N % 4 == 3` is a **sector trailer** (keys A/B
+ access bits) — `NdefText` skips these and `Dump` will hit them. Never write
to a trailer without knowing exactly what you're putting there; the sector can
be permanently locked.

### APDU reference (used throughout `transmit()` calls)

| Operation          | APDU                                    |
|--------------------|-----------------------------------------|
| Get UID            | `FF CA 00 00 00`                        |
| Load Auth Key      | `FF 82 00 00 06 <K1..K6>`               |
| Authenticate Block | `FF 86 00 00 05 01 00 <BLK> <KT> 00`    |
| Read Binary (16B)  | `FF B0 00 <BLK> 10`                     |
| Update Binary      | `FF D6 00 <BLK> 10 <D1..D16>`           |

`KT` = `0x60` for key A, `0x61` for key B.

### NDEF Text decoding (`decode_ndef_text`)

`NdefText` reads blocks 4..63 (skipping trailers), concatenates them into a
buffer, and stops as soon as a `0xFE` terminator byte appears. Then
`decode_ndef_text` walks the TLV stream:

- Skip Null TLVs (`0x00`), find NDEF Message TLV (`0x03`), bail on `0xFE` or
  unknown tag before `0x03`.
- Length is 1 byte, or 3 bytes when the first length byte is `0xFF`.
- Parse the first record's header for TNF/SR/IL flags, then type-length,
  payload-length (1B if SR, else 4B BE), optional id-length, type field, id,
  payload.
- Only `TNF == 0x01` with type `"T"` is accepted; UTF-16 (status bit 0x80) is
  rejected. The returned `(lang, text)` come from the language-code prefix and
  the rest of the payload as UTF-8.

If you extend it to URI / other record types, branch on `tnf` + `type_field`
after the header parse — the header parser itself is record-type-agnostic.

## Key conventions

- **Default key is `FFFFFFFFFFFF` with type A.** For NFC-formatted cards
  (NDEF), the data sectors typically authenticate with **key B** of the same
  value — pass `--key-type b`. If a `read`/`dump` fails with `SW != 9000` on
  the auth step, that's the first thing to try.
- All hex inputs to `write` are bare (no `0x`, no spaces) and must be exactly
  32 characters = 16 bytes. The CLI rejects anything else.
- `Dump` deliberately swallows per-block errors and prints `ERREUR (...)` so
  you can see which sectors don't auth with the supplied key — preserve this
  behavior if you refactor.

## Writing NDEF Text manually

A Text record for NFC-formatted MIFARE Classic 1K starts at block 4. The TLV
shape is:

```
03 LL                        NDEF Message TLV, LL = record length
D1 01 PL 54                  SR record, type "T", payload PL bytes
02 <lang1> <lang2>           status (UTF-8 + 2-char lang)
<utf-8 text...>
FE                           terminator
```

Write block-by-block with `write <block> <hex>`; pad the last block and zero
any subsequent block that might contain stale data past `FE`. See `readme.md`
for a concrete walkthrough writing "bonjour le monde".
