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
user's `authorized_keys`; otherwise FAILURE.

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

Only the `session` channel type is supported, carrying `exec` and a non-PTY `shell`.

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

**PTY (`pty-req`) is out of scope** — if the client sends `pty-req` (our client won't), the
server replies `CHANNEL_FAILURE`. Document that OpenSSH `ssh` allocates a PTY by default for
interactive shells, so **to test toy-server shell with OpenSSH the user must pass `ssh -T`**
(disable PTY). For `exec` (`ssh host command`), OpenSSH does not request a PTY by default, so
that path is clean.

### Data flow & flow control

- `SSH_MSG_CHANNEL_DATA (94)`: `uint32 recipient_channel || string data`. Carries stdin
  (client→server) and stdout (server→client).
- `SSH_MSG_CHANNEL_EXTENDED_DATA (95)`: `uint32 recipient_channel || uint32 data_type_code ||
  string data`. `data_type_code = 1` (`SSH_EXTENDED_DATA_STDERR`) carries stderr.
- **Windowing:** each side may send at most `window` bytes of channel data before the peer
  replenishes it. Sending `len` bytes of DATA decrements the peer's window you track by `len`.
  When you (as receiver) have consumed data, send `SSH_MSG_CHANNEL_WINDOW_ADJUST (93)`
  (`uint32 recipient_channel || uint32 bytes_to_add`) to grant more. A simple correct policy:
  start with a 2 MiB window and send a WINDOW_ADJUST of the consumed amount whenever the
  remaining window drops below half. Never send DATA that exceeds the peer's advertised window
  or `maximum_packet_size`.

### Closing & exit status

Typical teardown (server side, after the process exits):

1. Flush remaining stdout/stderr as DATA/EXTENDED_DATA.
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
run `ssh toyserver 'uname -a'` via exec. Process spawning uses `moonbitlang/async`'s
`process` package (see [08](08-moonbit-guide.md)).
