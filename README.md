# toy-ssh.mbt

An **experimental, educational** SSH-2 client and server written in
[MoonBit](https://www.moonbitlang.com/), implemented from the RFCs and verified against
OpenSSH in both directions.

Algorithms: `ssh-ed25519` host keys; `mlkem768x25519-sha256` (preferred) or
`curve25519-sha256` key exchange; `chacha20-poly1305@openssh.com` (preferred) or `aes128-ctr`
+ `hmac-sha2-256` for the record layer; no compression; strict kex; no rekeying.

> **DO NOT USE THIS FOR ANYTHING REAL.** This is a toy for learning MoonBit and the SSH
> protocol. The crypto is not constant-time, key material is not protected in memory, there
> is no rekeying, and nothing here has been reviewed for security. See
> [`docs/00-overview.md`](docs/00-overview.md) for the full list of non-goals.

## Status

| Milestone | State |
|---|---|
| M0 — wire codec, plaintext packets, version exchange, KEXINIT | done |
| M1 — Poly1305, X25519, Ed25519 (self-built, RFC vectors) | done |
| M2 — key exchange + encrypted transport (OpenSSH interop, kex only) | done |
| M3 — user authentication (`publickey` + `password`, OpenSSH interop) | done |
| M4 — session channel: `exec` + `shell` | done |
| M5 — stretch: `aes128-ctr` + `hmac-sha2-256` | done |
| M5 — stretch: `direct-tcpip` forwarding (server side) | done |
| M5 — stretch: PTY sessions (`pty-req`, `window-change`) | done |
| M5 — stretch: `diffie-hellman-group14-sha256` + `rsa-sha2-256` | dropped |
| M6 — post-quantum hybrid kex `mlkem768x25519-sha256` | done |

M6 was built before M5, because the hybrid exchange is what most needed a real negotiation
seam. The M5 items are independent stretch goals; the dropped one would have exercised that
same seam, which the two algorithm items above already do. Client-side `-L` is not
implemented either: forwarding works when a peer asks the **server** for it, which is what
`ssh -L` does.

## What it does

- A client (`ssh`-like) and a server (`sshd`-like), speaking to each other and to OpenSSH.
- `publickey` and `password` authentication; unencrypted `openssh-key-v1` keys,
  `authorized_keys` and `known_hosts` (trust on first use, a changed key is always refused).
- `exec` and `shell` on a session channel, with a pseudo-terminal when the peer asks for one
  — so `ssh host` without `-T` gets a prompt, line editing and a matching `TERM`. The client
  asks for one under the same rule: an interactive shell gets a terminal, `-t` and `-T` force
  it either way, and resizes are passed on.
- `direct-tcpip` forwarding on the server, **off** unless started with
  `--allow-tcp-forwarding`; with it on, an authenticated peer can make the server connect
  anywhere it can reach.

Deliberately absent: rekeying, compression, SFTP/scp, agent and X11 forwarding, encrypted
private keys, terminal modes (a pty runs with the kernel's defaults), and job control in a
pty session. The reasons are in [`docs/00-overview.md`](docs/00-overview.md) and
[`docs/04-auth-connection-spec.md`](docs/04-auth-connection-spec.md).

## Layout

```
src/wire       SSH wire types (RFC 4251 §5)
src/crypto     Poly1305, X25519, Ed25519 (self-built); SHA-2 / HMAC / ChaCha20 from moonbitlang/x
src/transport  version exchange, packets, kex, record layer   (sans-IO)
src/auth       userauth client + server                        (sans-IO)
src/connection channels, exec / shell / forwarding             (sans-IO)
src/net        the only package that touches sockets, processes and the pty
               (moonbitlang/async, plus this project's single C stub)
src/bin        client and server executables
docs/          design and specification documents
```

The protocol layers are pure state machines; only `src/net` performs IO. This keeps the
entire protocol testable in memory (client and server state machines fed each other's output).

## Building and testing

Toolchain in use: `moon 0.1.20260904` / `moonc v0.10.12` (see `docs/08-moonbit-guide.md`).

```
export PATH="$HOME/.moon/bin:$PATH"
moon test        # unit + protocol tests (RFC vectors, byte-exact fixtures)
moon check       # type-check
```

Two tests need a loopback socket and `/dev/ptmx`, so they fail inside a sandbox that denies
those and pass outside it. The OpenSSH interop runs are manual; the recipes, and what each
one proves, are in [`docs/07-verification-plan.md`](docs/07-verification-plan.md).

## Documents

Start with [`docs/00-overview.md`](docs/00-overview.md); the reading order for implementers
is in [`CLAUDE.md`](CLAUDE.md).

## License

MIT.
