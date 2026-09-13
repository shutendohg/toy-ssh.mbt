# 00 — Overview

## What this project is

`toy-ssh.mbt` is an **experimental, educational** SSH client and server written in
[MoonBit](https://www.moonbitlang.com/). The goal is learning two things at once:

1. The MoonBit language and its `native` backend + async ecosystem.
2. The SSH transport / authentication / connection protocols, implemented from the RFCs.

It is a *toy*. It is written for reading and stepping through, not for protecting anything.

## Non-goals / security disclaimer

> **DO NOT USE THIS FOR ANYTHING REAL.** This code is deliberately simple and makes
> choices no production SSH implementation may make.

Explicit non-goals (state these in code comments and READMEs too):

- **No constant-time guarantees.** Field arithmetic (X25519, Ed25519), Poly1305, and
  MAC/tag comparison are written for clarity, not to resist timing side channels.
- **No protection of key material in memory** (no zeroization, no mlock).
- **No rekeying.** If a peer initiates a second key exchange (`SSH_MSG_KEXINIT` after the
  first `NEWKEYS`), we log it and **close the connection** rather than implement rekey.
- **No compression, no SFTP/scp subsystem, no agent forwarding, no X11 forwarding.**
- **One algorithm suite only** (see below). No negotiation fallbacks, no legacy ciphers.
- **Encrypted private keys are not supported** — only unencrypted `openssh-key-v1` keys
  (`cipher="none"`, `kdf="none"`).

## Scope (what it *does* do)

- SSH-2 transport layer: version exchange, binary packet protocol, key exchange, encryption.
- User authentication: `password` and `publickey` methods.
- Connection layer: a single `session` channel supporting **remote command exec** and a
  **minimal non-PTY shell**.
- Both roles: a **client** (`ssh`-like) and a **server** (`sshd`-like).
- **Interoperability with OpenSSH** in both directions is the acceptance bar
  (see [07-verification-plan.md](07-verification-plan.md)).

Stretch goals (not required for "done"; see [06-milestones.md](06-milestones.md) M5):
PTY allocation, `diffie-hellman-group14-sha256` + `rsa`, `aes128-ctr` + `hmac-sha2-256`,
TCP port forwarding.

## The one algorithm suite

To keep the surface minimal we support exactly one of everything. All four are current
OpenSSH defaults, so no special flags are needed for interop (see verification plan).

| Role | Algorithm | Reference |
|---|---|---|
| Key exchange | `curve25519-sha256` (== `curve25519-sha256@libssh.org`) | RFC 8731, RFC 7748 |
| Host key / signature | `ssh-ed25519` | RFC 8032, RFC 8709 |
| Cipher (both directions) | `chacha20-poly1305@openssh.com` (AEAD) | OpenSSH `PROTOCOL.chacha20poly1305`, RFC 8439 |
| MAC | *(none — implicit in the AEAD)* | — |
| Compression | `none` | — |
| Strict KEX extension | `kex-strict-c-v00@openssh.com` / `kex-strict-s-v00@openssh.com` | OpenSSH `PROTOCOL` |

`ext-info-c` / `ext-info-s` (RFC 8308) are **advertised-but-ignored**: we send no
`SSH_MSG_EXT_INFO` and treat any received one as a no-op.

## How the pieces fit

```
                       ┌─────────────────────────────────────────┐
   bin/client  ─────►  │  connection  (channels, session, exec)   │
   bin/server  ─────►  │  auth        (userauth password/pubkey)  │   sans-IO
                       │  transport   (version, packets, kex, enc)│   state machines
                       └───────────────┬─────────────────────────┘
                                       │ bytes in / bytes out
                       ┌───────────────┴──────────┐
                       │  net (moonbitlang/async)  │  ← the only layer that does IO
                       └───────────────┬──────────┘
                                       │ TCP
                                  OpenSSH / peer
        wire  = SSH type codec used by every layer above
        crypto/keys = primitives + key file parsing used by transport/auth
```

The protocol layers are **sans-IO**: pure state machines that consume and produce bytes
and emit events. Only `net/` touches sockets. Rationale and interfaces are in
[01-architecture.md](01-architecture.md); this is what lets the whole protocol be tested
in-memory with no sockets.

## Reading list (read in this order before implementing)

Protocol:
- **RFC 4251** — SSH architecture & terminology (`name`, `mpint`, `string`, `name-list`).
- **RFC 4253** — Transport layer: version string, binary packet, KEXINIT, KEX, key
  derivation (§7.2 is the key-derivation formula), `SSH_MSG_*` numbers.
- **RFC 4252** — Authentication protocol (`SSH_MSG_USERAUTH_*`, signature blob layout).
- **RFC 4254** — Connection protocol (channels, `session`, `exec`, `shell`, `exit-status`).
- **RFC 4250** — Assigned numbers (message number registry).
- **RFC 8731** — `curve25519-sha256` key exchange method.
- **RFC 8709** — Ed25519/Ed448 host keys for SSH (`ssh-ed25519` blob + signature format).
- **RFC 8308** — `ext-info` / strict-kex context (we only need to recognize it).
- **OpenSSH `PROTOCOL`** and **`PROTOCOL.chacha20poly1305`** and **`PROTOCOL.key`**
  (in the openssh-portable source tree) — the `@openssh.com` extensions, the AEAD cipher,
  and the `openssh-key-v1` private-key container.

Crypto primitives:
- **RFC 7748** — X25519 (Montgomery ladder). §5.2/§6.1 test vectors. *(self-built)*
- **RFC 8032** — Ed25519 (edwards25519, SHA-512). §7.1 test vectors. *(self-built)*
- **RFC 8439** — ChaCha20 and Poly1305. §2.3–2.6 test vectors. Poly1305 is self-built;
  **ChaCha20 is reused** from `moonbitlang/x/crypto` (its IETF variant drives the
  `@openssh.com` cipher correctly — see [03-crypto-spec.md](03-crypto-spec.md) §2).

## Document map

| Doc | Purpose |
|---|---|
| [00-overview.md](00-overview.md) | This file. Goals, suite, reading list. |
| [01-architecture.md](01-architecture.md) | Package layout, sans-IO design, state-machine API shape. |
| [02-transport-spec.md](02-transport-spec.md) | Version exchange, packets, KEX, key derivation, AEAD framing. |
| [03-crypto-spec.md](03-crypto-spec.md) | The 3 self-built primitives + reused SHA-2/ChaCha20 + embedded RFC test vectors. |
| [04-auth-connection-spec.md](04-auth-connection-spec.md) | userauth + channels + exec/shell. |
| [05-key-formats.md](05-key-formats.md) | `openssh-key-v1`, `authorized_keys`, `known_hosts`/TOFU. |
| [06-milestones.md](06-milestones.md) | M0–M5, acceptance criteria, TDD order, dependencies. |
| [07-verification-plan.md](07-verification-plan.md) | 3-layer test strategy + OpenSSH interop harness. |
| [08-moonbit-guide.md](08-moonbit-guide.md) | Toolchain, `moon` commands, async socket API, gotchas. |

Implementing agents: also read the repo-root `CLAUDE.md` for working rules (TDD, English,
progress tracking).
