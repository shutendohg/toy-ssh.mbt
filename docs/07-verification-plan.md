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

Since M3 the server loads an `openssh-key-v1` file, so the host key is stable across runs:

```
server --listen 127.0.0.1:2222 \
       --host-key ./interop/host_ed25519 \
       --authorized-keys user:./interop/toy_authorized_keys \
       --passwords ./interop/toy_passwords
```

`--authorized-keys` is `USER:FILE` and may be repeated: a key authorizes only the account it
is configured for, so the same key presented as another user name is refused (verified —
`ssh attacker@…` gets "Permission denied" while `ssh user@…` succeeds). `--passwords` takes
plaintext `user:password` lines (`user:hunter2`), and an empty password is refused at
startup. Both are insecure by construction, toy only. `--host-seed-hex <64 hex>` still
exists as an alternative to a key file; with it, **pin the seed across runs**, because a
fresh random seed per start makes `ssh` reject the second connection with "REMOTE HOST
IDENTIFICATION HAS CHANGED" once `accept-new` has recorded the first key.

Server diagnostics go to **standard error**, unbuffered, so `2>&1` into a log file shows
progress while the server is still running (`println` is fully buffered to a file and would
show nothing until exit).

Driving the password prompt without a TTY: OpenSSH reads the password from `SSH_ASKPASS`
when `SSH_ASKPASS_REQUIRE=force` and `DISPLAY` are set, which avoids needing tmux for the
password case:

```
printf '#!/bin/sh\necho hunter2\n' > interop/askpass.sh && chmod +x interop/askpass.sh
SSH_ASKPASS=$PWD/interop/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
  ssh -T -p 2222 -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 \
      -o UserKnownHostsFile=./interop/known_hosts -o StrictHostKeyChecking=accept-new \
      user@127.0.0.1 true
```

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
client -i ./interop/client_ed25519 \
    --known-hosts ./interop/toy_known_hosts \
    -p 2200 $(whoami)@127.0.0.1            # 'uname -a' is M4
```

The client trusts an unknown host key on first use and appends it to the known_hosts file
(insecure; `--strict-host-key-checking` refuses instead). A **changed** host key is always
refused, printing both fingerprints. Verified by hand at M3: first connection records the
key, the second reports it matches, and rewriting the stored key makes the client refuse
with exit status 1.
Expected: `sshd -ddd` logs `Accepted publickey for ...`, the command runs, output returns,
exit code propagates. **Note:** unprivileged `sshd` can't switch users, so log in as
**your own** username (`$(whoami)`), and it can't do system password auth — that's why toy
client ↔ real sshd interop is **publickey-only** (password interop is covered by 3b instead).

### 3e. Post-quantum hybrid key exchange (M6)

Force `mlkem768x25519-sha256` on each side in turn, so neither the fallback to
`curve25519-sha256` nor a silent downgrade can pass for success.

**OpenSSH `ssh` → toy server.** Start the toy server as in §3b, then:

```
ssh -vv -T -p 2222 -o KexAlgorithms=mlkem768x25519-sha256 \
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=./interop/known_hosts \
    -o IdentitiesOnly=yes -i ./interop/client_ed25519 \
    user@127.0.0.1 'echo pq; exit 3'
```

Expected: `debug1: kex: algorithm: mlkem768x25519-sha256`, NEWKEYS both ways,
`Authenticated to ...`, `pq` on stdout and `ssh` exiting 3. Run the same command with
`-o KexAlgorithms=curve25519-sha256` as well: both methods must work, since we advertise
both.

**Toy client → OpenSSH `sshd`.** Put `KexAlgorithms mlkem768x25519-sha256` in
`interop/sshd_config` (restricting it to the hybrid, so a fallback cannot hide a failure),
start `sshd -ddd` as in §3c, then:

```
client -p 2200 -i ./interop/client_ed25519 \
       --known-hosts ./interop/toy_known_hosts $(whoami)@127.0.0.1 'echo both; exit 6'
```

Expected: `sshd` logs `debug1: kex: algorithm: mlkem768x25519-sha256` and
`Accepted publickey for ...`, the command output arrives and the client exits 6.

Verified 2026-09-16 against OpenSSH_10.2p1 in both directions, with the classical exchange
re-checked in the same run.

### 3f. The `aes128-ctr` + `hmac-sha2-256` suite (M5)

Force the second suite on each side in turn, the same way §3e forces the hybrid kex, so a
silent fallback to the AEAD cannot pass for success.

**OpenSSH `ssh` → toy server.** Start the toy server as in §3b, then:

```
ssh -vv -T -p 2222 -c aes128-ctr -m hmac-sha2-256 \
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=./interop/m5_kh \
    -o IdentitiesOnly=yes -i ./interop/client_ed25519 \
    user@127.0.0.1 'echo ctr-hello; exit 3'
```

Expected: `debug1: kex: client->server cipher: aes128-ctr MAC: hmac-sha2-256` (and the same
for server->client), the output on stdout, `ssh` exiting 3. Repeat with a bulk command
(`seq 1 20000`) and compare a checksum: a counter that restarted per packet still passes a
one-packet test.

**Toy client → OpenSSH `sshd`.** Copy `interop/sshd_config` with `Ciphers aes128-ctr` and
`MACs hmac-sha2-256`, start `sshd -ddd` on it as in §3c, then pass `-c aes128-ctr` to the toy
client (without it the client offers the AEAD first and gets it):

```
client -p 2200 -c aes128-ctr -i ./interop/client_ed25519 \
       --known-hosts ./interop/m5_toy_kh $(whoami)@127.0.0.1 'uname -s; exit 6'
```

Expected: `sshd` logs the `aes128-ctr` / `hmac-sha2-256` pair and `Accepted publickey`, the
output arrives, the client exits 6.

Verified 2026-09-19 against OpenSSH_10.2p1 in both directions: `echo` + exit 3, 20000 lines
byte-identical (`md5` matched) with stderr kept separate and exit 7, `uname -s` + exit 6 from
the toy client. The default suite was re-checked in the same run, both ways (exit 4 / exit 5).

### 3g. `direct-tcpip` forwarding (M5)

Needs a third party: something to forward *to*. A `python3 -m http.server` in the interop
directory does, because the fetched bytes can be compared with the file on disk.

```
python3 -m http.server 8899 --bind 127.0.0.1        # the target
server --listen 127.0.0.1:2224 --host-key ./interop/host_ed25519 \
       --authorized-keys user:./interop/toy_authorized_keys --allow-tcp-forwarding
ssh -N -L 9099:127.0.0.1:8899 -p 2224 -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile=./interop/fwd_kh -o IdentitiesOnly=yes \
    -i ./interop/client_ed25519 user@127.0.0.1
```

Then fetch `http://127.0.0.1:9099/<file>` and compare it byte for byte with
`interop/<file>`. Four more cases matter, because each exercises a different path:

1. **Several connections at once** (eight parallel fetches, one of them a ~100 KB file):
   this is what the channel table and per-channel windows are for.
2. **A dead target** (`-L 9100:127.0.0.1:1`): the server logs the failed connect, the peer
   sees `open failed: connect failed`, and the SSH connection survives.
3. **Forwarding not enabled** (start the server without `--allow-tcp-forwarding`): `ssh`
   prints `open failed: administratively prohibited: tcp forwarding is not enabled on this
   server`, and again the connection survives.
4. **A session alongside a forward** (`ssh -T -L ... user@host 'sleep 2; echo both; exit 3'`,
   fetching through the tunnel while the command runs): both channels must work at once.

Verified 2026-09-19 against OpenSSH_10.2p1: the fetched file was identical, eight concurrent
fetches all returned the right sizes with the big file's `md5` matching, the dead target and
the disabled server both failed the way they should with the connection intact, and the
session channel returned `both` and exit 3 while the tunnel was in use.

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
