# toy-ssh.mbt

An **experimental, educational** SSH-2 client and server written in
[MoonBit](https://www.moonbitlang.com/), implemented from the RFCs with one fixed algorithm
suite (`ssh-ed25519` / `chacha20-poly1305@openssh.com`, with either
`mlkem768x25519-sha256` or `curve25519-sha256` for key exchange) and verified against OpenSSH
in both directions.

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
| M4 — session channel: `exec` + non-PTY `shell` | done |
| M6 — post-quantum hybrid kex `mlkem768x25519-sha256` | done |

## Layout

```
src/wire       SSH wire types (RFC 4251 §5)
src/crypto     Poly1305, X25519, Ed25519 (self-built); SHA-2 / HMAC / ChaCha20 from moonbitlang/x
src/transport  version exchange, packets, kex, record layer   (sans-IO)
src/auth       userauth client + server                        (sans-IO)
src/connection channels, exec / shell                          (sans-IO)
src/net        the only package that touches sockets (moonbitlang/async)
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

## Documents

Start with [`docs/00-overview.md`](docs/00-overview.md); the reading order for implementers
is in [`CLAUDE.md`](CLAUDE.md).

## License

MIT.
