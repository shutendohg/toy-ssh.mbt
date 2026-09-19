# toy-ssh.mbt — implementing-agent entry point

An experimental, educational SSH client + server in MoonBit. **Toy. Never use for real
security.** The full design lives in `docs/`; this file is the working contract for whoever
implements it.

## Read the docs in this order before writing code

1. `docs/00-overview.md` — goals, non-goals, the single algorithm suite, RFC reading list.
2. `docs/01-architecture.md` — package layout, sans-IO state-machine design.
3. `docs/08-moonbit-guide.md` — toolchain, project files, async socket API, gotchas.
4. `docs/06-milestones.md` — M0–M5 with acceptance criteria and TDD order. **Work milestone
   by milestone in this order** (M0 ∥ M1 → M2 → M3 → M4; M5 optional).
5. Per-area specs, pulled in as each milestone needs them:
   `docs/03-crypto-spec.md` (M1), `docs/02-transport-spec.md` (M0/M2),
   `docs/04-auth-connection-spec.md` (M3/M4), `docs/05-key-formats.md` (M3),
   `docs/07-verification-plan.md` (every milestone's "done" bar).

## Working rules

- **TDD, always.** Explore → Red → Green → Refactor (follow the `development-style` skill).
  For crypto, the Red test is the RFC vector transcribed in `docs/03`. For protocol logic, the
  Red test is a sans-IO client↔server or a byte-exact fixture. Do not write a layer before its
  test.
- **Sans-IO discipline.** `transport`/`auth`/`connection` must not touch sockets, the clock,
  or the OS. Only `net/` does IO. This is what makes the whole thing testable in memory —
  don't break it for convenience.
- **A milestone is "done"** only when its acceptance criteria in `docs/06` pass at the test
  layers named in `docs/07` (unit + protocol, and interop where the milestone lists it).
- **English everywhere in the repo**: source comments, commit messages, PR/issue text,
  `README`, and all of `docs/`. (Japanese is allowed only in `.claude/plans/` working notes.)
- **Progress tracking**: keep `.claude/plans/WIP.md` current — update it when you start/finish
  a milestone or hit a blocker, per the `planning-workflow` skill. `.claude/plans/INDEX.md`
  lists the plan docs.
- **Verification uses tmux** for the OpenSSH interop (long-lived server, interactive `ssh`):
  use the `tmux-runner` skill, not one-shot blocking commands. Details in `docs/07`.
- **Before pushing**: run `/code-review` and `/security-review` (the latter mostly to sanity
  the toy's own disclaimers — this is not production crypto and should not be represented as
  such).

## Scope reminders (don't accidentally expand)

- Two cipher suites: `chacha20-poly1305@openssh.com` (preferred) and `aes128-ctr` +
  `hmac-sha2-256` (M5). Kex is `mlkem768x25519-sha256` (preferred, M6) or
  `curve25519-sha256`; host key `ssh-ed25519`; no compression; strict-kex on.
- `exec` + `shell` on a `session` channel, with a PTY when the peer asks (M5). No SFTP.
  Server-side `direct-tcpip` forwarding exists but is off unless `--allow-tcp-forwarding`
  is given; the client has no `-L`.
- Unencrypted `openssh-key-v1` keys only.
- **No rekey**: on a post-handshake `KEXINIT`, disconnect.
- Everything else is `docs/06` M5 stretch, explicitly optional.

## Layout

```
src/wire  src/crypto  src/keys  src/transport  src/auth  src/connection  src/net
src/bin/client  src/bin/server        docs/  .claude/plans/
```

Dependency direction: `wire → crypto → keys → transport → auth → connection → net → bin`.
Reuse `moonbitlang/x/crypto` (SHA-256, SHA-512, HMAC, ChaCha20) and `moonbitlang/core/encoding/base64`;
build the other three primitives by hand — Poly1305, X25519, Ed25519 (`docs/03`). IO via
`moonbitlang/async` (native backend, macOS and Linux).

Toolchain and config format actually in use (verified 2026-09-14, see `docs/08` §1–§2):
`moon 0.1.20260904`, non-JSON `moon.mod` / `moon.pkg` files, module name `shutendohg/toy-ssh`.
