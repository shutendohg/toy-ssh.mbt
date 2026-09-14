# 01 — Architecture

## Guiding principle: sans-IO protocol core

Every protocol layer (transport, auth, connection) is a **pure state machine**:

- It **never** calls a socket, timer, or the OS.
- Its inputs are: bytes received from the peer, and API calls from the application
  (e.g. "run this command", "authenticate as user X").
- Its outputs are: bytes to send to the peer, and **events** for the application
  (e.g. "authentication succeeded", "channel data arrived", "peer closed channel").

Only `net/` performs IO, by pumping bytes between a socket and the state machine.

Why this matters for implementers:

- The **entire protocol can be tested without sockets** — connect a client state machine
  to a server state machine in memory and feed each other's output as input. This is the
  primary correctness harness (see [07-verification-plan.md](07-verification-plan.md)).
- Async is confined to one small package. The protocol code is ordinary synchronous MoonBit.
- Debugging is deterministic: given the same byte stream, the state machine always does the
  same thing.

## Package layout

```
toy-ssh.mbt/
├── moon.mod.json                 # module = "toy-ssh" (or username/toy-ssh)
├── src/
│   ├── wire/                     # SSH wire-type codec (no SSH semantics)
│   ├── crypto/                   # self-built primitives (see 03)
│   ├── keys/                     # openssh-key-v1, authorized_keys, known_hosts
│   ├── transport/                # version exchange, packets, kex, key derivation, AEAD
│   ├── auth/                     # userauth client + server state machines
│   ├── connection/               # channels, session, exec/shell
│   ├── net/                      # moonbitlang/async adapter (the only IO)
│   └── bin/
│       ├── client/               # `is-main` executable: toy ssh
│       └── server/               # `is-main` executable: toy sshd
└── docs/                         # these documents
```

Dependency direction (a package may only import things to its left):

```
wire  →  crypto  →  keys  →  transport  →  auth  →  connection  →  net  →  bin
```

`crypto` reuses `moonbitlang/x/crypto` for SHA-256 and HMAC, and `keys` uses
`moonbitlang/core/encoding/base64`
for base64; everything else in `crypto` is ours. `keys` depends on `crypto` (Ed25519) and
`wire` (blob encoding). Nothing above `net` is imported by protocol layers.

## The state-machine contract

Each protocol layer follows the same shape. Concretely (names are a proposal — implementers
may refine, but keep the sans-IO property):

```moonbit
// Bytes the layer wants written to the peer, and events for the app, are
// returned/queued rather than performed. No IO here.

pub struct Transport {
  // negotiated state, cipher state, sequence numbers, buffers, ...
}

pub enum Role { Client; Server }

pub enum TransportEvent {
  NeedMoreData                     // not enough bytes buffered yet
  Established(session_id : Bytes)  // NEWKEYS done both ways
  Packet(payload : Bytes)          // a decrypted, post-KEX packet for the next layer
  Disconnect(code : UInt, msg : String)
}

// Feed raw bytes received from the peer; drains 0..n events.
pub fn Transport::on_received(self : Transport, data : BytesView) -> Array[TransportEvent]

// App/next-layer asks to send a payload; layer frames+encrypts into outgoing buffer.
pub fn Transport::send_packet(self : Transport, payload : BytesView) -> Unit

// Bytes the layer has queued to write to the peer. net/ drains this.
pub fn Transport::take_outgoing(self : Transport) -> Bytes
```

`auth` and `connection` layer sit **on top of** transport: they consume
`TransportEvent::Packet(payload)`, parse the message by its first byte (message number), and
produce payloads they hand back to `Transport::send_packet`. Model this as either nested
state machines or a single `Connection` that owns a `Transport`, an `Auth`, and channel
state. Either is fine; keep each layer's logic separable and independently testable.

### Suggested event vocabulary for higher layers

```moonbit
pub enum AuthEvent {
  Banner(String)
  Success
  Failure(methods : Array[String], partial : Bool)
  // server side:
  Request(user : String, service : String, method : AuthMethod)
}

pub enum ConnEvent {
  ChannelOpened(id : UInt)
  ChannelData(id : UInt, data : Bytes)
  ChannelExtData(id : UInt, data : Bytes)   // stderr (data_type_code 1)
  ExitStatus(id : UInt, code : UInt)
  ChannelEof(id : UInt)
  ChannelClosed(id : UInt)
  // server side:
  ExecRequest(id : UInt, command : String)
  ShellRequest(id : UInt)
}
```

## The IO adapter (`net/`)

`net/` is a thin async loop. Pseudocode of the read/write pump (see
[08-moonbit-guide.md](08-moonbit-guide.md) for the real `moonbitlang/async` API):

```
loop:
  bytes = conn.read(buf)              # async; from moonbitlang/async socket
  for event in machine.on_received(bytes):
      handle event (app logic)
  out = machine.take_outgoing()
  if out is non-empty: conn.write(out)   # async
```

`moonbitlang/async` requires **at most one task reading and one task writing** a socket at a
time. The simplest safe design: a single task that alternates read → step → write. If you
need concurrent app-initiated sends (e.g. server pushing stdout while reading stdin), use one
reader task and one writer task with a queue between the app and `take_outgoing`, guarded so
only the writer task touches the socket's write side.

## Error handling policy

- Protocol layers signal fatal protocol errors by returning a `Disconnect` event carrying an
  `SSH_DISCONNECT_*` reason code; they do **not** raise for peer-caused errors. Reserve
  MoonBit `raise` for programmer errors / truly exceptional local failures (e.g. malformed
  input to a codec that should never happen after validation).
- `wire` decoders `raise` on truncated/invalid input; callers convert that into a
  `Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, ...)`.
- On any fatal condition, send `SSH_MSG_DISCONNECT` (if a cipher is established, encrypt it),
  then close. Never continue after an authentication or MAC/tag failure.
- **Rekey is out of scope:** if `SSH_MSG_KEXINIT` arrives after the first key exchange
  completed, disconnect with `SSH_DISCONNECT_PROTOCOL_ERROR` and a clear message.

## Logging policy

- One leveled logger, controlled by a `-v/-vv/-vvv` flag on the binaries, mirroring OpenSSH.
- **Never log secrets** (private keys, shared secret K, derived keys, passwords). Logging the
  *exchange hash* H and *session id* is fine and useful for interop debugging.
- Trace level may hex-dump packet payloads (post-decrypt) — gate it behind `-vvv` and a
  compile-time-ish flag, and document that it leaks plaintext to the log.
- Recommended trace points for interop bring-up: version strings exchanged, negotiated
  algorithms, each `SSH_MSG_*` sent/received by name+number, computed H (hex), and channel
  open/close/exit-status. These map directly onto what `ssh -vvv` prints, which makes
  side-by-side debugging tractable.

## Concurrency model summary

- Protocol logic: synchronous, single-threaded, deterministic.
- `net/`: async, `native` backend, kqueue/epoll under the hood.
- Server accepts connections with `TcpServer::run_forever` or a manual `accept` loop; each
  connection runs its own state machine. A `session` channel's exec/shell may spawn a child
  process — use `moonbitlang/async`'s `process` package for that (see M4 in
  [06-milestones.md](06-milestones.md)).
