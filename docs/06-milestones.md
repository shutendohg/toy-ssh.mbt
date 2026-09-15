# 06 — Milestones

Each milestone has: **deliverable**, **acceptance criteria** (how you know it's done), and
**TDD order** (the Red→Green sequence). Follow `development-style` (explore → Red → Green →
Refactor). M0 and M1 are independent and can be built in parallel; M2 depends on both.

Dependency graph:

```
M0 (scaffold + wire + plaintext packet + version) ─┐
                                                     ├─► M2 (kex + encrypted transport) ─► M3 (userauth) ─► M4 (connection: exec/shell)
M1 (crypto primitives) ─────────────────────────────┘
                                                                                            M5 (stretch) hangs off M4
```

---

## M0 — Project scaffold, wire codec, plaintext packets, version exchange

**Deliverable:** a buildable `toy-ssh` module; `wire/` codec; plaintext binary-packet
encode/decode; version-string exchange. No crypto, no sockets yet (feed bytes directly).

**Acceptance criteria:**
- `moon test` passes for `wire/` and `transport/` (plaintext parts).
- Round-trip: encode a payload into a plaintext packet, decode it back, get the same payload,
  with correct padding rules (multiple of 8, ≥4 padding bytes).
- Version-line builder produces `SSH-2.0-toyssh_0.1\r\n`; parser extracts a peer version and
  skips pre-banner lines; rejects lines >255 bytes.
- KEXINIT payload encode/decode round-trips, including name-lists.

**TDD order:**
1. `wire/`: `byte/boolean/uint32/uint64/string/mpint/name-list` reader+writer. Red with
   fixed byte fixtures (e.g. `mpint 0x00 → ""`, `mpint 0x80 → 00 80`, `uint32 1 → 00 00 00 01`).
2. Plaintext packet: padding computation tests (payload lengths 0,1,5,6,7,8 → check total is
   multiple of 8 and padding ≥4), then encode/decode round-trip.
3. Version exchange: build/parse, CRLF handling, pre-banner skip, length cap.
4. KEXINIT struct ↔ payload round-trip.

---

## M1 — Crypto primitives (parallel with M0)

**Deliverable:** `crypto/` with the three self-built primitives — Poly1305, X25519,
Ed25519 — all passing the vectors in [03-crypto-spec.md](03-crypto-spec.md). SHA-256, SHA-512,
HMAC, base64, **and ChaCha20** are wired in from `moonbitlang/x`; the SSH-specific ChaCha nonce
plumbing lands in M2 (record layer), not here.

**Acceptance criteria:** every embedded test vector in doc 03 passes:
- SHA-512 (reused): smoke test against the 3 digests in doc 03 §1.
- Poly1305: RFC 8439 §2.5.2 tag.
- X25519: §5.2 two scalarmults, §5.2 iterated (1 and 1000), §6.1 DH triple.
- Ed25519: §7.1 TEST 1/2/3/SHA(abc) — public-key derivation, sign, verify, plus a negative
  verify test.
- ChaCha20 (reused): a smoke test that `@crypto.ChaCha::chacha20` reproduces RFC 8439 §2.4.2
  ciphertext, confirming the library and your `transform`/counter usage before M2 relies on it.

**TDD order (each primitive is its own Red→Green cycle):**
1. Poly1305 (uses BigInt). 2. X25519 (field ops → ladder → vectors).
3. Ed25519 (point ops → decompression/sqrt → sign/verify; SHA-512 from `moonbitlang/x`).
   Plus the SHA-512 and ChaCha20 reuse smoke tests above.

> Ed25519 is the hardest; budget accordingly. If X25519 field arithmetic (`add/sub/mul/inv`
> mod 2^255−19) is factored cleanly, Ed25519 can reuse the same field module.

---

## M2 — Key exchange & encrypted transport

**Status: done (2026-09-14).** Acceptance 1–3 verified: in-memory self-interop (identical
`session_id`, encrypted traffic both ways), pinned `H` fixture, and OpenSSH_10.2p1 interop in
both directions up to `SSH2_MSG_SERVICE_ACCEPT` with strict KEX ordering.

**Deliverable:** full `curve25519-sha256` kex, key derivation, NEWKEYS, strict-kex, and the
`chacha20-poly1305@openssh.com` record layer. Transport reaches "Established" and can send/
receive encrypted packets. `net/` async adapter added so the binaries can actually connect.

**Acceptance criteria:**
1. **In-memory self-interop:** a client `Transport` and server `Transport` driven against each
   other (no sockets) complete kex, both reach `Established` with **identical `session_id`**,
   and can exchange an encrypted `SSH_MSG_IGNORE`/echo payload that decrypts correctly with
   correct Poly1305 tags and sequence numbers.
2. **Exchange-hash fixture:** a known `(V_C,V_S,I_C,I_S,K_S,Q_C,Q_S,K)` set hashes to a
   pinned `H` (generate the fixture once from your own implementation, then guard against
   regressions; optionally cross-check one against OpenSSH debug output).
3. **OpenSSH interop, both directions, kex only:**
   - Toy client connects to OpenSSH `sshd` (non-root, high port) and reaches the point where
     `sshd -ddd` logs a completed kex / expects userauth. Toy client sees SERVICE_ACCEPT
     fail-free up to userauth.
   - OpenSSH `ssh -vvv` connects to the toy server and logs
     "kex: ... curve25519-sha256 ... expecting SSH2_MSG_KEX_ECDH_REPLY" then completes NEWKEYS
     and proceeds to userauth.
   (Full login is M3; here we only require kex+NEWKEYS to succeed.)

**TDD order:**
1. KEXINIT negotiation logic (pick algorithm; detect strict-kex; reject mismatches).
2. Kex math wiring: `Q_C/Q_S` generation, shared `K`, `mpint(K)`, exchange hash `H`,
   server signs, client verifies — as a **sans-IO unit test** with fixed ephemeral keys.
3. Key derivation (`A`–`F`, 64-byte C/D). Assert derived keys against a pinned fixture.
4. Record layer: encrypt/decrypt one packet (K_1/K_2 split, 12-byte IETF nonce from seqnum,
   counter 0/1, tag),
   round-trip test; then multi-packet with incrementing seqnum and post-NEWKEYS reset.
5. Wire in `net/` and do the OpenSSH interop bring-up (see [07](07-verification-plan.md)).

---

## M3 — User authentication

**Status: done (2026-09-15).** All three acceptance criteria verified: in-memory
client/server for password and publickey (success and every failure path), the publickey
signed-data blob pinned byte-exactly, and OpenSSH_10.2p1 interop in both directions
(`ssh` → toy server with publickey and with password, plus a refused wrong password; toy
client → `sshd -ddd` with publickey, logging `Accepted publickey`).

**Deliverable:** `auth/` client+server for `password` and `publickey`, plus `keys/` parsing
(`openssh-key-v1`, `authorized_keys`).

**Acceptance criteria:**
1. In-memory: toy client authenticates to toy server via `password` (correct → SUCCESS, wrong
   → FAILURE) and via `publickey` (authorized key → SUCCESS; unauthorized → FAILURE; tampered
   signature → FAILURE).
2. Publickey **signed-data blob** matches a pinned fixture (guards the #1 interop bug).
3. OpenSSH interop:
   - OpenSSH `ssh -vvv` authenticates to the toy server with **publickey** (key in the toy
     server's `authorized_keys`) → reaches "Authenticated".
   - OpenSSH `ssh` authenticates to the toy server with **password** → success.
   - Toy client authenticates to OpenSSH `sshd` with **publickey** (toy pubkey in the sshd
     user's `authorized_keys`) → sshd logs "Accepted publickey".

**TDD order:** service request/accept → USERAUTH_REQUEST parsing → password path → key-file
parsing (`keys/` unit tests with an `ssh-keygen`-generated fixture) → publickey query phase →
publickey signature build+verify → OpenSSH interop.

---

## M4 — Connection layer: exec + simple shell (the end-to-end goal)

**Status: done (2026-09-16).** All four acceptance criteria verified against
OpenSSH_10.2p1: `ssh -T … 'echo hello; exit 3'` prints `hello` and exits 3; a piped
`pwd`/`echo`/`exit 5` runs through the non-PTY shell and exits 5; the toy client runs a
command on a real `sshd` and exits with its status; and the in-memory client/server exec
round trip covers stdout, stderr, `exit-status` and the dual CLOSE.

**Deliverable:** `connection/` with one `session` channel supporting `exec` and non-PTY
`shell`, wired through `net/` and `moonbitlang/async`'s `process` for child processes. Both
binaries fully functional.

**Acceptance criteria (the headline demos):**
1. **Toy client → OpenSSH sshd:** `toyssh user@localhost -p <port> 'uname -a'` prints the
   real output and exits with the command's exit code.
2. **OpenSSH ssh → toy server:** `ssh -T -p <port> user@localhost 'echo hello; exit 3'` prints
   `hello` and `ssh` exits with code 3 (exit-status propagated).
3. **Interactive-ish shell:** `ssh -T -p <port> user@localhost` then typing `pwd`/`ls`/`exit`
   works (non-PTY, no line editing) against the toy server.
4. In-memory client↔server exec test: run `echo`, capture stdout via CHANNEL_DATA, capture
   stderr via EXTENDED_DATA, receive `exit-status`, both CLOSE, channel freed.

**TDD order:** channel open/confirm (sans-IO) → window accounting → CHANNEL_REQUEST exec
success/failure → data/extended-data plumbing → exit-status + EOF + CLOSE teardown → spawn
real process in `net/` → OpenSSH interop demos.

---

## M5 — Stretch goals (optional; not required for "done")

Pick any, each independent of the others:
- **PTY:** honor `pty-req` (terminal modes, window size), allocate a pseudo-terminal for
  `shell`. Enables `ssh` interactive without `-T`.
- **`diffie-hellman-group14-sha256` + `rsa-sha2-256`:** a second kex + host-key suite using
  `mpint` modexp (BigInt). Exercises the negotiation code with >1 real option.
- **`aes128-ctr` + `hmac-sha2-256`:** a classic encrypt-then-MAC cipher suite (needs AES; the
  MAC reuses `moonbitlang/x/crypto` HMAC). Exercises the non-AEAD packet path (real MAC keys,
  separate MAC field).
- **`direct-tcpip` port forwarding:** a second channel type.

Each stretch item should come with its own acceptance test and, where an OpenSSH-comparable
path exists, an interop check (e.g. force `ssh -o KexAlgorithms=diffie-hellman-group14-sha256`).
