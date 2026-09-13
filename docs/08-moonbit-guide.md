# 08 — MoonBit Implementation Guide

Practical notes for building this in MoonBit: toolchain, project files, the async socket API,
and language gotchas. **The MoonBit toolchain is not installed on this machine** — installing
it is the implementer's first step. Where an API detail below is version-sensitive, verify it
with `moon info` / `moon doc` against your installed version before relying on it; MoonBit and
`moonbitlang/x` move fast.

## 1. Toolchain setup

Install (official installer):

```
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash
# adds ~/.moon/bin to PATH; open a new shell or:
export PATH="$HOME/.moon/bin:$PATH"
moon version          # sanity check: prints moon + moonc versions
moon update           # refresh the mooncakes registry index
```

Pin the toolchain version you used in the repo README (e.g. record `moon version` output) so
another agent reproduces the same behavior. There is no per-repo toolchain pin file today;
document it in prose.

**Version in use (2026-09-14):** `moon 0.1.20260904`, `moonc v0.10.12`, `moonbitlang/x@0.5.5`,
`moonbitlang/async@0.21.3`. Note: `moon add` / `moon update` write to `~/.moon`, so they fail
inside a write-restricted sandbox; run them unsandboxed.

Core commands:

| Command | Use |
|---|---|
| `moon new <name>` | scaffold a module (or hand-write `moon.mod`) |
| `moon check` | type-check without building (fast feedback loop) |
| `moon build --target native` | build; native is required for real sockets |
| `moon test` | run all `_test.mbt` / inline tests |
| `moon test -p shutendohg/toy-ssh/crypto` | run one package's tests |
| `moon test --target-dir _build_x` | use a separate build dir (parallel agents must not share `_build`) |
| `moon run src/bin/client --target native -- <args>` | run a binary |
| `moon fmt` | format |
| `moon info` | regenerate `.mbti` interface files (inspect a dep's public API) |
| `moon add moonbitlang/x` | add a dependency |

## 2. Project files

The current toolchain (`moon 0.1.2026xxxx`, feature flags `rr_moon_mod,rr_moon_pkg`) uses
**non-JSON** `moon.mod` and `moon.pkg` files. This is what `moon new` generates today; the
older `moon.mod.json` / `moon.pkg.json` forms are not used in this repo.

`moon.mod` (module root; `source = "src"` makes packages live under `src/`):

```
name = "shutendohg/toy-ssh"
version = "0.1.0"
source = "src"
preferred_target = "native"

import {
  "moonbitlang/x@0.5.5",
  "moonbitlang/async@0.21.3",
}
```

(`moon add moonbitlang/x` fills the `import` block with the resolved version.)

Per-package config is a `moon.pkg` in the package directory (an empty file is valid). A
library package importing x/crypto and our wire package, with an alias:

```
import {
  "moonbitlang/x/crypto" @xcrypto,
  "moonbitlang/x/codec/base64",
  "shutendohg/toy-ssh/wire",
}
```

Test-only imports go in a second block: `import { "moonbitlang/core/test" } for "test"`.

A **binary** package (`src/bin/client`) is declared with `pkgtype(kind: "executable")` (this
is what `moon new` emits for `cmd/main/moon.pkg`); confirm the native-only target key with a
freshly generated project or `moon new`'s output before relying on it.

Imports are referenced in code by the **last path segment as `@segment`** (e.g.
`moonbitlang/async/socket` → `@socket`, `shutendohg/toy-ssh/wire` → `@wire`), or by the
alias given after the import string. Blackbox tests (`*_test.mbt`) refer to their own package
by that same `@segment` name (e.g. `@crypto.x25519(...)` inside `src/crypto/*_test.mbt`).
Test-only imports go in a second block: `import { "moonbitlang/core/encoding/hex" } for "test"`.

## 3. The async socket API (`moonbitlang/async`)

Verified against the current `socket/pkg.generated.mbti`. Real sockets need the native backend; the library supports macOS (kqueue) and Linux (epoll).

Program entry and structured concurrency:

```moonbit
// A minimal echo server (from the async repo's examples), for shape:
async fn main {
  @socket.TcpServer(@socket.Addr::parse("127.0.0.1:2222"))
    .run_forever(fn(conn, _peer) {
      conn.write_reader(conn)     // echo
    })
}
```

Key types/functions (signatures abbreviated; check `.mbti` for exact optionals):

```
// Addresses
@socket.Addr::parse(String) -> Addr           // "127.0.0.1:2222"
@socket.Addr::new(UInt, Int) -> Addr
async @socket.Addr::resolve(String, port~ : Int) -> Addr

// Server
async @socket.TcpServer(Addr, reuse_addr? : Bool) -> TcpServer      // constructor is async
async TcpServer::accept(Self) -> (Tcp, Addr)
async TcpServer::run_forever(Self, async (Tcp, Addr) -> Unit) -> Unit
TcpServer::close(Self) -> Unit

// Client / connection
async @socket.Tcp::connect(Addr) -> Tcp
async @socket.Tcp::connect_to_host(StringView, port~ : Int) -> Tcp
Tcp::close(Self) -> Unit
// Tcp implements @io.Reader and @io.Writer:
async Tcp::read(Self, FixedArray[Byte], offset? : Int, max_len? : Int) -> Int
async Tcp::read_exactly(Self, Int) -> Bytes        // convenient for fixed-size reads
async Tcp::write(Self, &@io.Data) -> Unit          // Bytes implements Data
```

Concurrency rule (from the library docs): **at most one task may read and one may write a
given socket at a time.** For the toy, the simplest safe loop is a single task doing
read → step state machine → write. If the server must push stdout while reading stdin
concurrently, use `with_task_group` to run one reader task and one writer task, with the
writer as the sole owner of `Tcp::write`. See the async repo's `examples/tcp_ping_pong` and
`examples/tcp_echo_server` for working patterns (`moon run -C examples examples/<name>`).

Reading whole SSH packets: read the (encrypted) 4-byte length first, decrypt it to learn the
body size, then `read_exactly(body_len + 16)` for body+tag. `read` may return fewer bytes than
requested, so buffer; `read_exactly` is the convenient primitive.

Child processes for exec/shell: use the `moonbitlang/async` `process` package (see its
`.mbti` via `moon info`; the HTTP-server pearl uses `@process` to spawn). Wire the child's
stdin/stdout/stderr to the channel's DATA/EXTENDED_DATA.

## 4. BigInt notes

`moonbitlang/core`'s `BigInt` backs Poly1305, X25519, and Ed25519 field arithmetic (toy:
clarity over speed). Confirm the exact API with `moon doc` / `.mbti`, but you will need:
arbitrary-precision `+ - *`, `%` (mod), `/`, comparison, `pow`/modular exponentiation (or
implement square-and-multiply yourself with `%`), and conversion **to/from big-endian and
little-endian byte arrays**.

- If a direct `mod_pow(base, exp, modulus)` isn't available, write square-and-multiply over
  `BigInt` — you need it for field inversion (`x^(p-2) mod p`) and Ed25519 sqrt (`x^((p+3)/8)`).
- Watch endianness: X25519/Ed25519 encode integers **little-endian**; SSH `mpint` is
  **big-endian two's-complement**. Write explicit `le_bytes ↔ BigInt` and `be_bytes ↔ BigInt`
  helpers and unit-test them against known vectors, because mixing them up is the most common
  bug in curve code.
- BigInt is not constant-time; that's acceptable here (see [00](00-overview.md) disclaimer).

## 5. Bytes / performance gotchas

- MoonBit `Bytes` is immutable; `FixedArray[Byte]` is mutable. Use `FixedArray[Byte]` for
  cipher scratch buffers and hash state, `Bytes`/`BytesView` for finished/read-only data.
- `BytesView` avoids copies for slicing — prefer it in codec readers.
- Integer widths: if you ever hand-roll a 64-bit-word hash, use `UInt64` wrapping arithmetic
  and unsigned shifts — no sign extension. (SHA-512 is reused from `moonbitlang/x`, so this
  only matters for stretch work.)
- `String` indexing (`s[i]`) yields a UTF-16 code unit (`UInt16`); use `s.to_array()` for
  `Array[Char]` or iterate with `for c in s`. `Bytes::from_fixedarray` is deprecated in favour
  of `Bytes::from_array(ArrayView[Byte])`.
- Endianness helpers: SHA is **big-endian**; SSH wire is **big-endian**; X25519/Ed25519 encode
  integers **little-endian** (see §4). Centralize these conversions and test each.

## 6. Testing in MoonBit

- Tests are `test { ... }` blocks or `_test.mbt` files. `inspect(value, content="...")` is the
  snapshot-style assertion; `assert_eq(a, b)` for equality. Use `moon test` to run.
- For the crypto vectors, use `@hex.encode` / `@hex.decode` from
  `moonbitlang/core/encoding/hex` (test-only import) and assert
  `inspect(@hex.encode(...), content="ddaf35...")` — copy the hex straight from
  [03-crypto-spec.md](03-crypto-spec.md).
- **`test "panic ..."` is not enforced on the native target** (verified 2026-09-14: a
  `panic`-prefixed test whose body does nothing *passes*). Do not use it to pin `abort`
  paths; make peer-facing rejections `raise` instead and test the error value.
- For sans-IO protocol tests, no async is needed — the state machines are synchronous, so
  those tests run on any backend. Only `net/` and the binaries require `--target native`.

## 7. Common pitfalls checklist (SSH-specific, MoonBit-flavored)

- [ ] `mpint(K)`: added the leading `0x00` when the top bit is set? (kex hash breaks otherwise)
- [ ] Exchange hash `I_C`/`I_S`: used the **full KEXINIT payload** including the message byte
      and trailing reserved uint32, not just the name-lists?
- [ ] Chacha key split: `K_2 = key[0..32]` (content), `K_1 = key[32..64]` (length)?
- [ ] Record nonce = **12 bytes = 8 zeros || `uint32_be(seqnum)`** (IETF ChaCha), not a random
      IV and not a little-endian seqnum? (This is the #1 cipher interop bug — see doc 03 §2.)
- [ ] Payload counter starts at **1**, Poly1305 key from counter **0**?
- [ ] Sequence numbers reset to 0 **after NEWKEYS** under strict kex?
- [ ] Publickey signed blob: `string(session_id)` prepended, request bytes **without** the
      final signature field?
- [ ] Ed25519 private field is 64 bytes (`seed||A`); you feed only the 32-byte **seed** to
      sign?
- [ ] Server refuses `pty-req` and the interop `ssh` command uses `-T`?
- [ ] Native target for anything touching sockets/processes?
