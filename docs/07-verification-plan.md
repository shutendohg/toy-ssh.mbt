# 07 — Verification Plan

Three layers of testing, from cheapest/most-deterministic to most-realistic:

1. **Unit** — RFC test vectors and codec round-trips (`moon test`).
2. **Protocol** — sans-IO client↔server state machines wired in memory, no sockets.
3. **Interop** — the toy binaries against the OpenSSH `ssh`/`sshd` shipped with macOS.

A change isn't "done" for its milestone until the relevant layer passes (see
[06-milestones.md](06-milestones.md) acceptance criteria).

---

## Layer 1 — Unit tests (`moon test`)

- Every crypto primitive asserts the **exact hex vectors** embedded in
  [03-crypto-spec.md](03-crypto-spec.md). Paste the hex directly; decode with
  `moonbitlang/core/encoding/hex` imported `for "test"`.
- `wire/` codec: byte-exact fixtures for each type, especially `mpint` edge cases and
  name-list ordering.
- Transport: padding math, KEXINIT round-trip, key-derivation against a pinned fixture,
  record encrypt/decrypt round-trip with seqnum progression.
- `keys/`: parse an `ssh-keygen`-generated fixture, re-derive the public key from the seed,
  assert equality; reject an encrypted key with a clear error.

Run: `moon test` (all packages) or `moon test -p toy-ssh/crypto` (one package). Native backend
where async is involved: `moon test --target native`.

---

## Layer 2 — Protocol (sans-IO in-memory interop)

Because the protocol layers are sans-IO ([01](01-architecture.md)), you can connect a client
and a server directly and pump bytes between them with no network:

```
loop until both idle / handshake complete:
    c_out = client.take_outgoing()
    if c_out: server.on_received(c_out)  → collect server events
    s_out = server.take_outgoing()
    if s_out: client.on_received(s_out)  → collect client events
```

Assertions per milestone:
- **M2:** both reach `Established`; `client.session_id == server.session_id`; an encrypted
  echo payload survives a round trip.
- **M3:** password/publickey success and the three failure cases; publickey signed-blob
  fixture.
- **M4:** exec round trip — stdout via DATA, stderr via EXTENDED_DATA, `exit-status`, dual
  CLOSE.

This layer catches nearly all protocol-logic bugs deterministically and is where most test
effort should go. It also lets you fuzz: feed truncated/garbage bytes into `on_received` and
assert the machine emits a `Disconnect` event instead of crashing.

---

## Layer 3 — OpenSSH interoperability

Uses the system OpenSSH on macOS (`/usr/bin/ssh`, `/usr/bin/sshd`, `ssh-keygen`). Check
versions first: `ssh -V`. All of this runs unprivileged (no root) on high ports.

Run long-lived / interactive processes under **tmux** (see the `tmux-runner` skill): start the
toy server or `sshd -ddd` detached, drive `ssh` with `send-keys`, observe with `capture-pane`,
keep full logs in files. Do **not** try to do this with single blocking `Bash` calls.

### 3a. Fixtures (generate once)

```
mkdir -p ./interop && cd ./interop
ssh-keygen -t ed25519 -N '' -f ./host_ed25519      -C toy-host    # toy server host key
ssh-keygen -t ed25519 -N '' -f ./client_ed25519    -C toy-client  # toy client user key
ssh-keygen -t ed25519 -N '' -f ./sshd_host_ed25519 -C real-host   # real sshd host key
```

### 3b. OpenSSH `ssh`  →  toy server  (validates toy server)

Start the toy server (tmux, detached) listening on e.g. `127.0.0.1:2222`, host key
`host_ed25519`, with `client_ed25519.pub` in the user's `authorized_keys`, and a password
entry for password tests.

Publickey:
```
ssh -vvv -T -p 2222 \
    -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile=./interop/known_hosts \
    -o IdentitiesOnly=yes \
    -i ./interop/client_ed25519 \
    user@127.0.0.1 'uname -a; exit 3'
```
Expected: prints `uname` output; `ssh` exits 3. In `-vvv` you should see
`kex: algorithm: curve25519-sha256`, `kex: host key algorithm: ssh-ed25519`,
`cipher: chacha20-poly1305@openssh.com`, `Authenticated to 127.0.0.1`, and the channel
exec. `-T` disables the client's PTY request (our server refuses `pty-req`).

Password (interactive prompt; drive it via tmux `send-keys`):
```
ssh -vvv -T -p 2222 -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o UserKnownHostsFile=./interop/known_hosts -o StrictHostKeyChecking=accept-new \
    user@127.0.0.1 'echo hello; exit 3'
```

Pin algorithms explicitly if a future OpenSSH default drifts:
`-o KexAlgorithms=curve25519-sha256 -o HostKeyAlgorithms=ssh-ed25519 -o Ciphers=chacha20-poly1305@openssh.com`.

### 3c. Toy client  →  OpenSSH `sshd`  (validates toy client)

Run a throwaway unprivileged `sshd` in the foreground under tmux:

Minimal `interop/sshd_config`:
```
Port 2200
ListenAddress 127.0.0.1
HostKey <ABS_PATH>/interop/sshd_host_ed25519
PidFile <ABS_PATH>/interop/sshd.pid
LogLevel DEBUG3
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile <ABS_PATH>/interop/authorized_keys
Subsystem sftp internal-sftp
KexAlgorithms curve25519-sha256
HostKeyAlgorithms ssh-ed25519
Ciphers chacha20-poly1305@openssh.com
```
Put `client_ed25519.pub` into `interop/authorized_keys`. Start it (absolute path to sshd
required):
```
/usr/sbin/sshd -ddd -f <ABS_PATH>/interop/sshd_config
```
`-ddd` keeps it in the foreground, single-connection, very verbose. Then the toy client:
```
toyssh -vvv -i ./interop/client_ed25519 \
    --known-hosts ./interop/toy_known_hosts \
    -p 2200 $(whoami)@127.0.0.1 'uname -a'
```
Expected: `sshd -ddd` logs `Accepted publickey for ...`, the command runs, output returns,
exit code propagates. **Note:** unprivileged `sshd` can't switch users, so log in as
**your own** username (`$(whoami)`), and it can't do system password auth — that's why toy
client ↔ real sshd interop is **publickey-only** (password interop is covered by 3b instead).

### 3d. Reading the debug output

- `ssh -vvv`: look for `SSH2_MSG_KEXINIT`, `expecting SSH2_MSG_KEX_ECDH_REPLY`,
  `rekey after ... blocks`, `Server host key: ssh-ed25519 SHA256:...`, `Authenticated to`,
  and per-channel `debug1: client_input_channel_req ... exit-status`. A hang right after
  `SSH2_MSG_KEX_ECDH_REPLY` usually means a bad exchange hash or signature. A
  `Corrupted MAC on input` means the AEAD tag/keying is wrong (check K_1/K_2 split, nonce =
  seqnum, counter 0 vs 1). `incorrect signature` at userauth means the signed-blob layout is
  wrong (doc 04 Part A).
- `sshd -ddd`: mirrors the above from the server side; `Accepted publickey` / `Postponed
  publickey` / `Authentication refused` tell you where auth failed.
- If kex fails immediately with `no matching key exchange method`, your KEXINIT name-lists are
  wrong or strict-kex markers are malformed.

---

## Toolchain / environment for verification

- MoonBit toolchain must be installed (it currently is **not** on this machine). Setup and
  exact commands are in [08-moonbit-guide.md](08-moonbit-guide.md). At minimum:
  `moon version`, `moon build --target native`, `moon test`.
- `moonbitlang/async` supports **native (macOS kqueue) and Linux (epoll)** only for real
  sockets — so build/run the binaries with `--target native`.
- Everything else (OpenSSH) ships with macOS; verify with `ssh -V` and `sshd -?`/`which sshd`
  (`/usr/sbin/sshd`).

## Suggested CI-ish smoke script

Steps 1–2 run in GitHub Actions (`.github/workflows/ci.yml`, ubuntu + macOS) on every push to
`main` and every pull request. Steps 3–4 need a live `sshd` and stay manual.

1. `moon fmt --check && moon check` (types) → `moon test --target native` (units + protocol).
2. Build both binaries `--target native`.
3. Run 3b publickey demo and assert exit code 3 + expected stdout.
4. Run 3c publickey demo and assert `Accepted publickey` appears in the sshd log.

Only after all three layers pass for a milestone do you mark it done in
`.claude/plans/WIP.md` and move on.
