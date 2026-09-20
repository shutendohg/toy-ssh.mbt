# 04 — Authentication & Connection Specification

Implements RFC 4252 (userauth) and RFC 4254 (connection: channels, session, exec/shell).
These layers sit on top of an established, encrypted transport
([02](02-transport-spec.md)) and exchange **payloads** (the decrypted packet bodies).

## Part A — User authentication (RFC 4252)

### Entry

After NEWKEYS, the client sends `SSH_MSG_SERVICE_REQUEST("ssh-userauth")`; the server replies
`SSH_MSG_SERVICE_ACCEPT`. Then the client drives authentication.

### Message numbers

| # | Name |
|---|---|
| 50 | `SSH_MSG_USERAUTH_REQUEST` |
| 51 | `SSH_MSG_USERAUTH_FAILURE` |
| 52 | `SSH_MSG_USERAUTH_SUCCESS` |
| 53 | `SSH_MSG_USERAUTH_BANNER` |
| 60 | `SSH_MSG_USERAUTH_PK_OK` (publickey; context-specific reuse of 60) |

### `SSH_MSG_USERAUTH_REQUEST` common prefix

```
byte      50
string    user_name        # UTF-8
string    service_name     # always "ssh-connection"
string    method_name      # "none" | "password" | "publickey"
... method-specific fields ...
```

The `"none"` method is used by the client as a probe: the server replies
`SSH_MSG_USERAUTH_FAILURE` with the list of methods that can continue. Our client MAY send
`none` first to learn methods, or just attempt `publickey`/`password` directly.

### `SSH_MSG_USERAUTH_FAILURE`

```
byte      51
name-list authentications_that_can_continue   # e.g. "publickey,password"
boolean   partial_success                       # false for us
```

Our server: after too many failures (say 6) or on unknown user, keep replying FAILURE; the
client gives up and disconnects. We never set `partial_success`.

### `SSH_MSG_USERAUTH_SUCCESS`

```
byte      52
```

Sent once. After this, the userauth layer is done and the connection layer (Part B) takes
over on the same encrypted channel. **After success, ignore any further userauth messages.**

### Method: `password` (RFC 4252 §8)

```
byte      50
string    user_name
string    "ssh-connection"
string    "password"
boolean   FALSE
string    plaintext_password   # UTF-8
```

(The `TRUE` variant for password change is not supported — reply FAILURE.)

Server: compare against a configured user/password table (plaintext in a config file is fine
for a toy; document it as insecure). Constant-time comparison not required (toy).

> **Interop note:** OpenSSH `sshd` run as non-root generally cannot do PAM/password auth
> against system accounts. So password auth is verified only (a) toy client ↔ toy server, and
> (b) OpenSSH `ssh` ↔ toy server. Toy client ↔ OpenSSH `sshd` interop uses **publickey**.
> See [07-verification-plan.md](07-verification-plan.md).

### Method: `publickey` (RFC 4252 §7)

Two-phase. **Query phase** (optional, `boolean = FALSE`, no signature): client asks whether a
key would be acceptable.

```
byte      50
string    user_name
string    "ssh-connection"
string    "publickey"
boolean   FALSE
string    public_key_algorithm_name    # "ssh-ed25519"
string    public_key_blob              # ssh-ed25519 blob (see 02 §5)
```

Server replies `SSH_MSG_USERAUTH_PK_OK` (60) echoing algorithm + blob if the key is in the
user's `authorized_keys`; otherwise FAILURE. **The client must check that the reply echoes
the algorithm and blob it offered** — signing whatever a server sends back would let it
choose part of what the client's key signs.

```
byte      60
string    public_key_algorithm_name
string    public_key_blob
```

**Authentication phase** (`boolean = TRUE`, with signature):

```
byte      50
string    user_name
string    "ssh-connection"
string    "publickey"
boolean   TRUE
string    public_key_algorithm_name    # "ssh-ed25519"
string    public_key_blob
string    signature                    # ssh-ed25519 signature blob
```

**The signature is computed over this exact byte sequence** (RFC 4252 §7):

```
string    session_id          # the transport session_id (H of first kex), as a string
byte      50                  # SSH_MSG_USERAUTH_REQUEST
string    user_name
string    "ssh-connection"
string    "publickey"
boolean   TRUE
string    "ssh-ed25519"
string    public_key_blob
```

i.e. `session_id` prepended (as an SSH `string`) to the exact request payload up to and
including the public key blob, but **without** the trailing signature field. The client signs
that blob with the private key; the server rebuilds the same blob and verifies with
`ed25519_verify` against the blob's embedded public key **and** confirms the key is
authorized. Getting the signed-data layout wrong is the #1 publickey interop bug — assert it
with a fixture in tests.

### Auth state machines

- **Client:** `Start → (optional none probe) → send publickey(sig) or password → recv
  SUCCESS|FAILURE → Authenticated | Retry | GiveUp`.
- **Server:** `AwaitRequest → validate method → SUCCESS|FAILURE → (on success) Authenticated`.
  Track the authenticated user name; the connection layer needs it for exec.

Emit `AuthEvent` values (see [01](01-architecture.md)) so the binary can print banners and
progress.

---

## Part B — Connection protocol (RFC 4254)

Only the `session` channel type is supported, carrying `exec` and `shell`. The server runs
either on a PTY (when the peer asks) or on plain pipes, and our client asks for either.

### Message numbers

| # | Name |
|---|---|
| 80 | `SSH_MSG_GLOBAL_REQUEST` |
| 81 | `SSH_MSG_REQUEST_SUCCESS` |
| 82 | `SSH_MSG_REQUEST_FAILURE` |
| 90 | `SSH_MSG_CHANNEL_OPEN` |
| 91 | `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` |
| 92 | `SSH_MSG_CHANNEL_OPEN_FAILURE` |
| 93 | `SSH_MSG_CHANNEL_WINDOW_ADJUST` |
| 94 | `SSH_MSG_CHANNEL_DATA` |
| 95 | `SSH_MSG_CHANNEL_EXTENDED_DATA` |
| 96 | `SSH_MSG_CHANNEL_EOF` |
| 97 | `SSH_MSG_CHANNEL_CLOSE` |
| 98 | `SSH_MSG_CHANNEL_REQUEST` |
| 99 | `SSH_MSG_CHANNEL_SUCCESS` |
| 100 | `SSH_MSG_CHANNEL_FAILURE` |

`SSH_MSG_GLOBAL_REQUEST`: we don't originate any. On receive (e.g. OpenSSH sends
`hostkeys-00@openssh.com`), if `want_reply` is true reply `REQUEST_FAILURE`; otherwise ignore.

### Opening a session channel

Client → server:

```
byte      90  SSH_MSG_CHANNEL_OPEN
string    "session"
uint32    sender_channel        # client's channel id
uint32    initial_window_size   # e.g. 2*1024*1024
uint32    maximum_packet_size   # e.g. 32768
```

Server → client on accept:

```
byte      91  SSH_MSG_CHANNEL_OPEN_CONFIRMATION
uint32    recipient_channel     # client's id (echoed)
uint32    sender_channel        # server's channel id
uint32    initial_window_size
uint32    maximum_packet_size
```

Or `SSH_MSG_CHANNEL_OPEN_FAILURE (92)` with `uint32 reason || string description || string
lang`. Reason codes: `ADMINISTRATIVELY_PROHIBITED=1`, `CONNECT_FAILED=2`,
`UNKNOWN_CHANNEL_TYPE=3`, `RESOURCE_SHORTAGE=4`.

Each side maps its own channel-id space; **address the peer by its `recipient_channel`** in
every subsequent message.

### Channel requests: exec / shell

Client → server after the channel is open:

```
byte      98  SSH_MSG_CHANNEL_REQUEST
uint32    recipient_channel     # server's channel id
string    "exec"                # or "shell"
boolean   want_reply            # typically TRUE
string    command               # only for "exec"; absent for "shell"
```

Server replies `SSH_MSG_CHANNEL_SUCCESS (99)` or `SSH_MSG_CHANNEL_FAILURE (100)` if
`want_reply`. On success the server spawns the process (exec: run `command` via the shell;
shell: run the login shell without a PTY) and pipes stdio.

**PTY (`pty-req`)**: the server honours it — see [`pty-req` and `window-change`](#pty-req-and-window-change-m5)
below, and our client sends one under the same rule OpenSSH uses: a shell started from a
terminal gets one, a command or a redirected standard input does not, and `-t` / `-T` force
the decision either way. OpenSSH `ssh` behaves the same, so `ssh -T` selects the non-PTY
shell explicitly and `ssh host command` never asks.

### Data flow & flow control

- `SSH_MSG_CHANNEL_DATA (94)`: `uint32 recipient_channel || string data`. Carries stdin
  (client→server) and stdout (server→client).
- `SSH_MSG_CHANNEL_EXTENDED_DATA (95)`: `uint32 recipient_channel || uint32 data_type_code ||
  string data`. `data_type_code = 1` (`SSH_EXTENDED_DATA_STDERR`) carries stderr.
- **Message ordering:** `CHANNEL_DATA`, `CHANNEL_EOF`, `CHANNEL_CLOSE` and the `exit-status`
  request form **one ordered stream**. Queue them together: an EOF that overtakes data still
  waiting for window credit makes the peer reject the data that follows (it arrived "after
  EOF"). `CHANNEL_WINDOW_ADJUST` and request replies must **not** be in that queue — a
  window grant stuck behind our own blocked data deadlocks both sides, each waiting for the
  other's window.
- **Windowing:** each side may send at most `window` bytes of channel data before the peer
  replenishes it. Sending `len` bytes of DATA decrements the peer's window you track by `len`.
  When you (as receiver) have consumed data, send `SSH_MSG_CHANNEL_WINDOW_ADJUST (93)`
  (`uint32 recipient_channel || uint32 bytes_to_add`) to grant more. A simple correct policy:
  start with a 2 MiB window and send a WINDOW_ADJUST of the consumed amount whenever the
  remaining window drops below half. Never send DATA that exceeds the peer's advertised window
  or `maximum_packet_size` — and note that `maximum_packet_size` caps the **whole message**,
  so subtract the header (9 bytes for DATA, 13 for EXTENDED_DATA) from the payload you put in
  one message. Also cap it yourself: the transport rejects an SSH packet over 35000 bytes
  (doc 02 §2), so a peer advertising a 4 GiB `maximum_packet_size` must not be able to turn a
  megabyte of output into one message. Keep the whole connection message at or below the
  32768 you advertise.
- **A channel-addressed message needs a channel.** Refuse `CHANNEL_REQUEST`, `CHANNEL_DATA`,
  `CHANNEL_WINDOW_ADJUST`, `CHANNEL_EOF` and `CHANNEL_CLOSE` that arrive before
  `CHANNEL_OPEN`, rather than treating channel 0 as implicitly present. For the same reason,
  **encode a queued message when you send it, not when you queue it**: the peer's
  `recipient_channel` is unknown until it confirms the channel, and the client can reach end
  of its own standard input before that. (Addressing everything to 0 appears to work against
  OpenSSH only because `sshd` numbers the first session channel 0.)

### Closing & exit status

Typical teardown (server side, after the process exits):

1. Flush remaining stdout/stderr as DATA/EXTENDED_DATA. **Wait for both output pumps to
   reach end of file first.** A child is reaped the moment it exits while its pipes may still
   hold unread bytes, so reporting the status on the process's exit alone races the tail of
   its own output out of the channel.
2. Send the exit status as a channel request (no reply):
   ```
   byte      98  SSH_MSG_CHANNEL_REQUEST
   uint32    recipient_channel
   string    "exit-status"
   boolean   FALSE
   uint32    exit_code
   ```
   (Optionally `"exit-signal"` if killed by a signal — out of scope; `exit-status` suffices.)
3. Send `SSH_MSG_CHANNEL_EOF (96)`, then `SSH_MSG_CHANNEL_CLOSE (97)`.
4. Each side sends CLOSE once and, after sending and receiving CLOSE, frees the channel.

Client: on receiving `exit-status`, record the code; on CHANNEL_CLOSE, tear down and exit the
process with that code (like `ssh`). EOF means "no more data this direction" but the channel
stays open until both CLOSEs.

### Connection state machine (per channel)

```
Opening → Open → (exec/shell request) → Running
   → peer EOF / our EOF → Closing (CLOSE sent & received) → Closed
```

Track per channel: local id, remote id, send window (peer→me credit I hold), recv window
(credit I've granted the peer), and whether EOF/CLOSE sent/received. Refuse a second
`exec`/`shell` on the same channel.

### Minimal shell semantics

"Simple shell" = spawn the user's shell (`$SHELL` or `/bin/sh`) with no PTY, wire
stdin/stdout/stderr to the channel, and report its exit code. No line editing, no job
control, no terminal modes. This is enough to run `ssh -T toyserver` and type commands, and to
run `ssh toyserver 'uname -a'` via exec. A peer that asks for a terminal first gets the PTY
path instead. Process spawning uses `moonbitlang/async`'s
`process` package (see [08](08-moonbit-guide.md)).

### `direct-tcpip` port forwarding (M5, server side)

`ssh -L <lport>:<host>:<port>` opens **one channel per accepted local connection**, so this
is the milestone where the server stops having a single hard-wired channel and keeps a table
of them. The CHANNEL_OPEN carries four extra fields after the usual ones (RFC 4254 §7.2):

```
string  host to connect
uint32  port to connect
string  originator IP address
uint32  originator port
```

The originator is informational; we do not act on it. Rules we follow:

- **Off by default.** `direct-tcpip` is refused with
  `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED` unless the server was started with
  `--allow-tcp-forwarding`. A toy server that dials anywhere an authenticated peer names is a
  relay into whatever network it sits in; OpenSSH's `AllowTcpForwarding no` exists for the
  same reason.
- **Confirm only after the connect succeeds.** The channel is held unconfirmed while the TCP
  connection is attempted; a refused or unreachable target becomes
  `SSH_OPEN_CONNECT_FAILED`, not a channel that opens and immediately closes.
- **A malformed target is a protocol error**, not a polite refusal: a channel whose
  parameters we cannot read is one we must not open.
- **The connect happens off the connection's read loop.** The event handler runs on the task
  that reads the socket, so dialling out there would freeze every other channel for as long
  as the connect takes — up to the OS timeout for an address that silently drops packets.
- **Writes to the target are still on that loop**, so a target that stops reading long
  enough to fill its socket buffer does stall the connection. Fixing that needs a per-forward
  writer task; `Child::write_stdin` has the same shape. Toy limitation.
- **The read pump stops while a window's worth of output is already queued**, so a fast
  target and a slow peer do not put the whole transfer in memory.
- **No half-close.** `moonbitlang/async` exposes no socket shutdown, so a peer's CHANNEL_EOF
  cannot become a FIN on the forwarded socket; the target sees the close only when the
  channel closes. A protocol that waits for a half-close (HTTP/1.0 with no length) will hang.
- **Channel ids are never reused**, so a stale message naming a closed channel is rejected
  rather than landing on a new one.
- Channel requests (`exec`, `shell`, `pty-req`) on a forwarded channel are refused: it
  carries bytes, not commands.

The client side (`-L` on the toy client) is **not** implemented; the toy client still opens
exactly one `session` channel.

### `pty-req` and `window-change` (M5)

`ssh` without `-T` asks for a terminal before it asks for a shell, and a session that runs on
one behaves like a login: a prompt, line editing, and programs that check `isatty`.

```
string  TERM
uint32  width (characters)     uint32  height (rows)
uint32  width (pixels)         uint32  height (pixels)
string  encoded terminal modes
```

`window-change` carries the same four numbers and never asks for a reply.

What we do:

- **`pty-req` is accepted only on a session channel, and only before `exec` or `shell`.**
  RFC 4254 §6.2 puts it first, and honouring a late one would mean re-parenting a running
  process onto a terminal. A late one gets CHANNEL_FAILURE.
- The terminal is allocated when the request arrives and handed to the command when it
  starts; `TERM` is passed through to the child's environment, and the window size is applied
  with `TIOCSWINSZ` then re-applied on every `window-change`.
- **A pty merges stdout and stderr**, so a pty session sends no `EXTENDED_DATA`.
- **The terminal modes string is accepted and ignored.** We pass the size to the kernel and
  leave `ECHO`, `ICANON` and the rest at their defaults, which is what a normal terminal
  gives. A client asking for raw mode does not get it — toy limitation.
- **The child is not a session leader with this pty as its controlling terminal.** That needs
  `setsid` + `TIOCSCTTY` between fork and exec, which the process API does not expose, so a
  shell reports "no job control". Everything else (prompt, editing, `tty`, signals typed as
  characters reaching the foreground process) works.
- **The server never opens the terminal without `O_NOCTTY`.** Its own slave handle goes
  through the C stub with that flag, and the child attaches to the terminal itself (a `sh`
  wrapper redirects and `exec`s), because the library's redirect helpers open the path in the
  *calling* process. Otherwise the pty a peer asked for could become the controlling terminal
  of a daemonized server, and a typed `^C` would reach the server's own process group.
- **One `pty-req` per session.** It starts nothing, so nothing else would stop a peer from
  repeating it, and each one costs a real pseudo-terminal; a second is refused.
- **A peer's CHANNEL_EOF cannot close the command's input**: closing the master would take
  the terminal away from a command still using it, and a pty has no half-close. The command
  learns about it when the session ends — the same limitation forwarding has.

The ordering around the pty's own descriptors is the part that is easy to get wrong, and it
is recorded in [08-moonbit-guide.md](08-moonbit-guide.md).

#### The client's half

Asking for a terminal is what makes an interactive session work at all: a shell decides
whether it is interactive from `isatty`, so without `pty-req` it starts, reads its input as
a script and prints no prompt.

- **`pty-req` goes out before `exec` or `shell`, and the command is not requested until the
  server has granted it.** A `CHANNEL_FAILURE` for the terminal ends the connection rather
  than falling back to pipes: the local terminal is already raw by then, and a session that
  silently is not what was asked for is worse than one that stops.
- **The local terminal goes into raw mode** (`cfmakeraw`) for the life of the session, so
  echo, line editing and the signal characters all belong to the remote end and `^C`
  travels as a byte. Every path out of the client puts the settings back; a client that
  exits raw leaves the user's shell with no echo.
- **Resizes are polled, not signalled.** `moonbitlang/async` routes only the cancellation
  signals, so SIGWINCH has nowhere to arrive; a C handler would still have to be polled to
  reach async code, and the runtime reserves the right to change the signal mask. The
  client re-reads `TIOCGWINSZ` five times a second and sends `window-change` when it moved.
  `window-change` goes out ahead of queued standard input, because a resize that waits for
  window credit arrives after the program has already redrawn at the old size.
- **The modes string is empty** (`TTY_OP_END` alone). Our terminal is raw, so telling the
  remote end to copy that would turn its echo and line editing off — exactly what we want
  it to be doing.
- **A raw terminal has no local way out.** `^C`, `^\` and `^Z` all travel as bytes, and we
  have neither OpenSSH's `~.` escape sequence nor a keepalive, so a peer that stops
  answering after the shell starts hangs the session until it is killed from another
  terminal. Left as a toy limitation: an escape sequence means scanning the input stream
  for it, which is a second state machine on the hot path. `-T` avoids it entirely.
