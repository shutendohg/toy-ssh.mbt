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
document it in prose. The installer takes a version argument (`unix.sh <version>` or
`MOONBIT_INSTALL_VERSION`), but the versioned download URLs returned 403 for every path
format tried on 2026-09-14, so CI (`.github/workflows/ci.yml`) installs `latest` instead.

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
  "moonbitlang/core/encoding/base64",
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

### Toolchain quirks observed (moon 0.1.20260904 / moonc v0.10.12)

- `moon test -p <pkg>` works but `moon check -p <pkg>` treats the argument as a directory;
  use `moon check src/<pkg>`.
- Bare `moon fmt` formats the whole module; while parallel agents edit one package, run
  `moon fmt src/<pkg>` (or the files) and give each agent its own `--target-dir _build_<x>`.
- Deprecated and their replacements: `try?` → `try … catch {} noraise {}`; `derive(Show)` →
  `derive(Debug)` + `debug_inspect`; `Bytes::from_fixedarray` → `Bytes::from_iter(a.iter())`;
  `StringBuilder::new` → `StringBuilder()`; `@buffer.Buffer(size_hint~)` is a constructor
  call; `@sys.get_cli_args()` → `@env.args()` (index 0 is the program name on native).
- A `catch` arm cannot carry a type annotation. A `pub struct` may not expose a `priv` type
  in its fields (use a `pub` enum with no `pub(all)` to keep it opaque).
- `async fn main` needs `raise` when the body calls raising async functions:
  `async fn main raise { … }`. `moonbitlang/async` must be imported by any package that
  declares `async fn main` or `async test`; a test-only import goes in the `for "test"` block.
- `Array::sort` on `String` orders by length first, so do not pin sorted string lists in
  tests; assert membership instead.
- Socket tests (`net/`) fail inside a write-restricted sandbox with
  `TcpServer::new(): Operation not permitted`; run them unsandboxed. macOS has no `timeout`
  command, so bound `ssh` with `-o ConnectTimeout` instead.

More quirks found in M3:

- **`method` is a reserved word.** docs/01's suggested `Request(user, service, method)` does
  not compile; `auth` uses `auth_method`. `sealed` is reserved too.
- `moonbitlang/core/strconv` is **empty** in this toolchain — there is no library integer
  parser, so the client parses its `-p` port by hand.
- `@sys.exit(n)` returns `Unit`, not a bottom type, so it cannot stand where a value is
  expected. A generic helper whose body ends in `abort` works:
  `fn[T] usage_error(msg : String) -> T { println(msg); @sys.exit(2); abort(msg) }`.
- `println` goes through C stdio and is **fully buffered when standard output is a file or a
  pipe** — a long-running server writes nothing until it exits. Write diagnostics to
  standard error through `@stdio.stderr.write` (`net.log` does this), which also frees
  standard output for a remote command's own output.
- **`@ascii.encode` calls `panic()` on any code unit above 0x7f**, and a panic is not
  catchable — it aborts the process, so `run_forever(allow_failure=true)` cannot contain it.
  Never hand it peer-controlled text (a user name, a banner, a DISCONNECT description, a host
  name): use `@utf8.encode`. Reserve `@ascii.encode` for constants such as the SSH
  identification string.
- Deprecations seen: `Map::new()` → `Map([])`, `Map::size` → `length`, `ArrayView::to_array`
  → `to_owned`, `StringView::to_string` → `to_owned`. `String::trim` takes `char_set~`
  (`line.trim(char_set=" \t\r\n")`), not a positional argument.
- A lambda passed where a concrete function type is expected may still need its parameter
  annotated (`(k_s : Bytes) => …`) or inference fails with "Type _/0 has no method
  op_as_view".
- A synchronous callback held by a sans-IO layer (the transport's `accept_host_key`) cannot
  log through an async writer. Queue the lines and drain them from the async side.

More quirks found in M4:

- A connection with a child process needs **two tasks** (`moonbitlang/async` allows one
  reader and one writer per socket): the socket reader dispatching events, and a writer that
  owns every `write`. Wake the writer with a **semaphore**, not a condition variable —
  `Semaphore::release` before `acquire` still counts, so a wake-up cannot be lost and the
  writer cannot park with bytes queued. Wait on the writer task before the read loop returns,
  or the caller closes the socket with the last packet unsent.
- A task whose read never ends (this process's standard input on a terminal) must be spawned
  with `spawn_bg(no_wait=true, …)`, or the task group waits for it forever. The converse also
  bites: a task group waits for a spawned child process, so cancel the child when the peer
  disconnects or the connection's socket stays open as long as the command runs.
- `@semaphore.Semaphore::release` **aborts** once its value reaches the size it was built
  with. If the consumer can exit (a writer task that breaks on a socket error), stop
  releasing — otherwise a connection error turns into a process-wide crash.
- `@process.spawn` puts the waiter in the group you pass, and `read_from_process()` /
  `write_to_process()` give you the pipe ends. A write to a child that already exited fails
  with a catchable error rather than a signal, so swallow it: a peer that keeps sending
  standard input after the command finished is normal.
- `@stdio.stdout.write` / `@stdio.stderr.write` take bytes and go straight to the fd, which is
  what a remote command's output needs — never route it through a `String`.

More quirks found in M6:

- **`&` binds looser than `==`.** `(x >> b) & 1 == 1` parses as `(x >> b) & (1 == 1)` and fails
  to compile with an Int/Bool mismatch. Write `((x >> b) & 1) == 1`. `moon fmt` will add those
  clarifying parentheses to the *broken* parse, so the formatted source shows you what the
  compiler thought you meant.
- **A `grep` that finds nothing does not prove an edit landed** — the pattern may simply no
  longer match because something else rewrote the line. Assert that a scripted replacement
  actually matched, rather than inferring it from a silent grep.
- `moon test -f <file>` is **not** a per-file filter; it reports "no test entry found". To time
  one file's tests, empty it and compare.

## 7. Common pitfalls checklist (SSH-specific, MoonBit-flavored)

- [ ] `mpint(K)`: added the leading `0x00` when the top bit is set? (kex hash breaks otherwise)
- [ ] Exchange hash `I_C`/`I_S`: used the **full KEXINIT payload** including the message byte
      and trailing reserved uint32, not just the name-lists?
- [ ] Chacha key split: `K_2 = key[0..32]` (content), `K_1 = key[32..64]` (length)?
- [ ] Record nonce = **12 bytes = 8 zeros || `uint32_be(seqnum)`** (IETF ChaCha), not a random
      IV and not a little-endian seqnum? (This is the #1 cipher interop bug — see doc 03 §2.)
- [ ] Payload counter starts at **1**, Poly1305 key from counter **0**?
- [ ] Sequence numbers reset to 0 **after NEWKEYS** under strict kex?
- [ ] Channel data, EOF, CLOSE and `exit-status` queued in **one ordered stream**, with
      WINDOW_ADJUST and request replies on a separate lane that data cannot block?
- [ ] Channel payload sized so the **whole message** fits the peer's `maximum_packet_size`?
- [ ] Publickey signed blob: `string(session_id)` prepended, request bytes **without** the
      final signature field?
- [ ] Ed25519 private field is 64 bytes (`seed||A`); you feed only the 32-byte **seed** to
      sign?
- [ ] Server refuses `pty-req` and the interop `ssh` command uses `-T`?
- [ ] Native target for anything touching sockets/processes?

## Two coroutines must not write one handle

`@stdio.stderr.write` from two tasks at once panics inside the async runtime's IO worker
(`IoHandle::write_via_worker`), and a panic is not catchable — the process dies. This is the
same one-reader / one-writer rule that applies to sockets and pipes, but it is easy to miss
for logging, because logging looks like a side effect rather than IO.

It first appeared when `direct-tcpip` started doing its outbound connect in its own task
(M5): eight concurrent `ssh -L` connections meant eight tasks logging at once, and the server
died. `net.log` now takes a one-permit semaphore around the write.

## C FFI (the pty, M5)

The whole recipe: a `.c` file next to the MoonBit sources, listed in `moon.pkg` as
`options("native-stub": ["pty_stub.c"])`, and declarations of the form

```moonbit
#borrow(buf)
extern "C" fn pty_slave_name_ffi(fd : Int, buf : FixedArray[Byte], len : Int) -> Int = "toy_ssh_pty_slave_name"
```

`#borrow` (or `#owned`) is **required** on every pointer parameter — without it `moon check`
fails rather than warns. `FixedArray[Byte]` arrives as `uint8_t*`, `FixedArray[Int]` as
`int32_t*`, and plain `Int` as `int32_t`, which is enough for an out-parameter without any
memory management crossing the boundary.

Keep the C side as small as the thing that has no MoonBit equivalent. For the pty that is
`grantpt` / `unlockpt` / `ptsname`, the `TIOCSWINSZ` ioctl, and one `open` — the master is
opened as `/dev/ptmx` through `@fs.open`, so the async runtime owns the handle and reads it
like any other file.

### `O_NOCTTY`, and who is allowed to open a terminal

Opening a terminal **without** `O_NOCTTY` makes it the controlling terminal of a process that
is a session leader with none yet — which is how a daemonized server starts. A peer could
then send signals to the server itself by typing them. The library's `open` adds only
`O_CLOEXEC` (`internal/event_loop/fs.c`), and the public file API has no flag for this, so:

- our own slave handle is opened by the C stub with `O_RDWR | O_NOCTTY`;
- the **child** opens the terminal for its three standard streams, in a `sh` wrapper that
  redirects and then `exec`s the real command. `@process.redirect_from_file` /
  `redirect_to_file` look like the natural fit, but they open the path in the *calling*
  process — so they would put the terminal back in the parent, without `O_NOCTTY`, and undo
  the point of the stub. In the child the open is harmless: the child is not a session
  leader. Everything the wrapper needs travels in the environment, never in the script text.

### The descriptor dance around a pty

Three things that each cost a debugging round:

1. **A master with no slave attached fails reads immediately** (EIO on macOS) instead of
   waiting. So the pty holds its own slave descriptor open from the moment it is created:
   without it, a pump started before the child would fall straight out of its loop.
2. **Closing the master does not interrupt a read already in flight.** A pump blocked on it
   stays blocked for the life of the process. Closing the *slave* is what wakes a master
   reader, because that is the end-of-file the kernel reports.
3. **Reap the child before dropping our slave handle.** Dropping it right after `spawn`
   races the child's own open of the slave — for that moment the master has no slave, and
   (1) applies. So `Child::wait` on a pty session waits for the process, *then* releases the
   slave, *then* joins the pump. That is the exact opposite of the pipe case, where the
   pumps are joined first so that no output is lost.

### The client's own terminal (M5, client half)

Three things that are not about the pty at all, but about the terminal the client is
already sitting on:

1. **There is no SIGWINCH.** `moonbitlang/async`'s `signal` package exposes only the
   cancellation signals (SIGINT, SIGTERM, SIGHUP, SIGBREAK), so a resize has nowhere to
   arrive. A C handler would not help on its own: it can do nothing async-signal-unsafe, so
   it could only set a flag that MoonBit then has to poll — and the library says it may
   change the signal mask, so the handler is not even guaranteed to run. Polling
   `TIOCGWINSZ` on a timer is one ioctl and has neither problem.
2. **A raw terminal does not turn `\n` into a carriage return and a line feed.**
   `cfmakeraw` clears `ONLCR`, so every diagnostic written while the client mirrors a remote
   terminal stair-steps down the screen unless it ends its lines with `\r\n`. `net.log` asks
   `terminal_is_raw()` and picks the ending.
3. **`@sys.exit` does not run `defer`.** A client that exits with the remote command's
   status has to restore the terminal itself before calling it; the `defer` only covers the
   paths that leave by raising. Getting this wrong leaves the user's shell with no echo,
   which looks like the terminal broke rather than like a bug in the client.
