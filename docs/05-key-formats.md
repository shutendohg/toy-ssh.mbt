# 05 — Key Formats

Covers the on-disk formats the toy needs: the `openssh-key-v1` private key container
(unencrypted only), `authorized_keys` lines, and `known_hosts` / TOFU. Everything is
Ed25519-only. `keys/` depends on `crypto` (Ed25519) and `wire` (blob codec) and reuses
`moonbitlang/core/encoding/base64`. (`moonbitlang/x/codec/base64` also exists, but core's
`decode(s, ignore_whitespace?)` swallows the PEM line wrapping and its
`encode(b, padding?)` covers both the padded form used in key lines and the unpadded form
used in fingerprints, so core is the better fit here.)

## 1. Public key line (`.pub` / `authorized_keys` entry)

Single line, space-separated ASCII:

```
ssh-ed25519 <base64-of-blob> [comment]
```

The base64 decodes to the `ssh-ed25519` public key blob (see [02](02-transport-spec.md) §5):

```
string  "ssh-ed25519"
string  key            # 32-byte Ed25519 public key A
```

Parsing an `authorized_keys` file: read line by line, skip blank lines and lines starting with
`#`, ignore any options prefix we don't support (a toy may reject lines with options), split
into `type / base64 / comment`, require `type == "ssh-ed25519"`, base64-decode, parse the
blob, keep the 32-byte `A`. A key is "authorized" for a user if its 32-byte `A` matches any
entry in that user's file. Compare the raw 32 bytes, not the base64 text.

## 2. Private key: `openssh-key-v1` (unencrypted only)

Authoritative source: OpenSSH `PROTOCOL.key`. Base64 body between the PEM guard lines:

```
-----BEGIN OPENSSH PRIVATE KEY-----
<base64, 70-char-wrapped>
-----END OPENSSH PRIVATE KEY-----
```

Strip the guard lines and newlines, base64-decode, then parse this binary structure:

```
byte[15]  AUTH_MAGIC          # "openssh-key-v1\0"  (the string plus a NUL byte, 15 bytes)
string    ciphername          # "none"  (we only support unencrypted)
string    kdfname             # "none"
string    kdfoptions          # empty string
uint32    number_of_keys      # 1
string    publickey_blob      # the ssh-ed25519 public blob (as in §1)
string    encrypted_section   # for cipher "none", this is plaintext; see below
```

`encrypted_section` (when `ciphername == "none"`, it is not actually encrypted):

```
uint32    checkint1           # random
uint32    checkint2           # MUST equal checkint1 (integrity sanity check)
                              # then, for each of number_of_keys:
string    privatekey_type     # "ssh-ed25519"
string    public_key          # 32-byte A (again)
string    private_key         # 64 bytes: seed(32) || public A(32)  -- see note
string    comment
byte[n]   padding             # 1,2,3,... until section length is a multiple of block size
```

Notes and traps:

- **AUTH_MAGIC is 15 bytes**: the ASCII `openssh-key-v1` (14 chars) **plus a trailing `\0`**.
- **Block size for padding when `cipher == "none"` is 8.** Validate the padding bytes are
  `1,2,3,…` — reject otherwise (cheap corruption check).
- **Ed25519 `private_key` field is 64 bytes**: `seed (32) || public_key A (32)`. RFC 8032's
  "secret key" is the 32-byte *seed*; take the first 32 bytes as the seed you feed to
  `Ed25519KeyPair::from_seed`. Verify the embedded `A` equals `ed25519_public_key(seed)` — if not, the file
  is corrupt or you sliced wrong.
- If `ciphername != "none"` or `kdfname != "none"`, **fail with a clear "encrypted keys not
  supported; re-generate with `-N ''` or decrypt first"** message. Do not attempt bcrypt-pbkdf.

Generating a compatible test key (implementers, in verification):

```
ssh-keygen -t ed25519 -N '' -f ./id_ed25519_toy -C toy
```

This yields an unencrypted `openssh-key-v1` private key and matching `.pub`. Use it as a
fixture in `keys/` tests: parse it, re-derive the public key from the seed, assert it matches
the `.pub`.

## 3. `known_hosts` and TOFU (client side)

The toy client must decide whether to trust a server's Ed25519 host key `K_S`.

Format (one host key per line, subset of OpenSSH's):

```
<host>[,<host>...] ssh-ed25519 <base64-blob>
```

where `<host>` is `hostname` or `[hostname]:port` for non-22 ports. We do **not** implement
hashed hostnames (`|1|...`) — plain host patterns only.

**Trust-on-first-use policy:**

1. Look up the connection's host (and port) in `~/.ssh/known_hosts` (or a toy-specific file,
   e.g. `./toy_known_hosts` — make the path a CLI flag).
2. If an entry exists for this host:
   - key matches → proceed.
   - key differs → **abort loudly** ("REMOTE HOST IDENTIFICATION HAS CHANGED"), like OpenSSH.
     Never silently accept.
3. If no entry exists → print the key's fingerprint (SHA-256 of the blob, base64, OpenSSH
   style `SHA256:...`) and, per a CLI flag, either auto-accept-and-append (default for the toy,
   document it as insecure) or prompt. Append the new line to the known_hosts file.

Fingerprint: `SHA256:` + base64(no padding) of `sha256(public_key_blob)`. Reuse the SHA-256
from `moonbitlang/x/crypto` and base64 from `moonbitlang/core/encoding/base64`
(`encode(blob, padding=false)`).

## 4. Server host key & user db (server side)

- The server loads its Ed25519 host private key from an `openssh-key-v1` file (path via CLI
  flag), parses it per §2, and uses the seed for signing the exchange hash.
- For `publickey` auth, the server loads each user's `authorized_keys` (path via flag or a
  simple `user -> file` config). For `password` auth, a config file maps `user -> password`
  (plaintext; documented insecure, toy only).
- Generate the server host key in verification with the same `ssh-keygen` command as above.
