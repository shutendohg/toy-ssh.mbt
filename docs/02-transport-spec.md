# 02 — Transport Layer Specification

Implements RFC 4253 (transport), RFC 8731 (curve25519-sha256 kex), RFC 8709 (ssh-ed25519),
and OpenSSH `PROTOCOL.chacha20poly1305`. Read those alongside this doc; this file specifies
the *exact* choices for our one suite and points out the traps.

All multi-byte integers on the SSH wire are **big-endian**. The wire-type codec lives in
`wire/` and is specified in the "Wire types" section immediately below; every layer uses it.

## Wire types (`wire/`)

RFC 4251 §5. Implement a `Reader` (cursor over `BytesView`) and a `Writer` (growable buffer):

| Type | Encoding |
|---|---|
| `byte` | 1 byte |
| `boolean` | 1 byte, 0 = false, nonzero = true (write as 0/1) |
| `uint32` | 4 bytes big-endian |
| `uint64` | 8 bytes big-endian |
| `string` | `uint32` length prefix, then that many raw bytes (may be binary) |
| `mpint` | `string` holding a two's-complement big-endian integer; positive numbers whose high bit is set get a leading `0x00`; zero is the empty string; no leading zero bytes otherwise |
| `name-list` | `string` holding comma-separated ASCII names, no spaces, order significant |

`mpint` matters only for the stretch-goal RSA/DH; for our suite, curve25519 public keys and
Ed25519 signatures travel as fixed-length `string`s, not `mpint`. Implement `mpint` anyway;
it's small and the tests are cheap.

Reader must `raise` on short reads. Writer should expose `write_string`, `write_uint32`,
`write_name_list`, etc., and `to_bytes()`.

## 1. Version exchange

RFC 4253 §4.2. Before any binary packets, each side sends an identification line:

```
SSH-2.0-<softwareversion>[ <comments>]\r\n
```

- Our banner: `SSH-2.0-toyssh_0.1` (ASCII, no spaces unless adding comments).
- Terminated by **CR LF**. Max 255 bytes including CR LF.
- The server MAY send extra lines *before* its version line; a client MUST tolerate and skip
  lines not starting with `SSH-`. Our server sends only the version line. Our client must
  skip pre-banner lines (OpenSSH servers sometimes send none, but be safe).
- **Save both raw version strings without CR LF** — they feed the exchange hash `H` as
  `V_C` (client) and `V_S` (server).

## 2. Binary packet protocol

RFC 4253 §6. **Before encryption is enabled**, a packet is:

```
uint32   packet_length          # length of (padding_length + payload + padding), NOT itself
byte     padding_length
byte[n1] payload                 # n1 = packet_length - padding_length - 1
byte[n2] random padding          # n2 = padding_length
                                 # (no MAC before NEWKEYS)
```

Padding rule (RFC 4253 §6): the concatenation `packet_length || padding_length || payload ||
padding` — i.e. **including the 4-byte `packet_length` field** — must be a multiple of the
cipher block size or 8, whichever is larger (**8** for the initial no-cipher state), and there
must be **at least 4 bytes** of padding. Compute:

```
min_align = 8   # max(8, cipher_block_size)
size_wo_pad = 4 (packet_length) + 1 (padding_length byte) + payload_len
pad = min_align - (size_wo_pad % min_align)
if pad < 4: pad += min_align
packet_length = 1 + payload_len + pad
```

> The `chacha20-poly1305@openssh.com` cipher (§7) uses a **different** rule: it excludes the
> 4-byte length field from the alignment, because that field is encrypted separately. Do not
> reuse this §2 formula there.

Padding bytes SHOULD be random. Max packet size we accept: 35000 bytes of payload
(RFC 4253 minimum guarantee is 32768 payload / 35000 total — reject larger).

**After encryption** with `chacha20-poly1305@openssh.com`, framing changes — see §7 below.

## 3. Algorithm negotiation (KEXINIT)

RFC 4253 §7.1. Immediately after version exchange, each side sends `SSH_MSG_KEXINIT` (20):

```
byte         SSH_MSG_KEXINIT (20)
byte[16]     cookie (random)
name-list    kex_algorithms
name-list    server_host_key_algorithms
name-list    encryption_algorithms_client_to_server
name-list    encryption_algorithms_server_to_client
name-list    mac_algorithms_client_to_server
name-list    mac_algorithms_server_to_client
name-list    compression_algorithms_client_to_server
name-list    compression_algorithms_server_to_client
name-list    languages_client_to_server        # empty
name-list    languages_server_to_client        # empty
boolean      first_kex_packet_follows           # false for us
uint32       0  (reserved)
```

Our advertised lists:

| list | client sends | server sends |
|---|---|---|
| kex_algorithms | `curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-c-v00@openssh.com` | `curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-s-v00@openssh.com` |
| server_host_key_algorithms | `ssh-ed25519` | `ssh-ed25519` |
| encryption_* (both) | `chacha20-poly1305@openssh.com` | `chacha20-poly1305@openssh.com` |
| mac_* (both) | `none`* | `none`* |
| compression_* (both) | `none` | `none` |
| languages_* | *(empty)* | *(empty)* |

\* Because the cipher is AEAD, the MAC list is effectively ignored by the peer for this
cipher. Sending an empty MAC list works with OpenSSH for AEAD ciphers. To be safe and match
OpenSSH's own KEXINIT, you MAY send `hmac-sha2-256` in the MAC lists even though it is never
used with the AEAD cipher; document whichever you pick. **Recommendation:** send an empty MAC
name-list — OpenSSH accepts it for AEAD ciphers and it makes the "MAC is implicit" intent
explicit in the code.

**The strict-kex pseudo-algorithm** (`kex-strict-c-v00@openssh.com` from the client,
`kex-strict-s-v00@openssh.com` from the server) is added to our kex list. If **both** sides
advertise their respective marker, strict KEX is in effect:

- The very first packet each side sends MUST be `SSH_MSG_KEXINIT`. If anything precedes it,
  abort.
- No "extra" messages (`SSH_MSG_IGNORE`, `SSH_MSG_DEBUG`, unexpected `SSH_MSG_UNIMPLEMENTED`)
  are permitted during the initial key exchange; if received, abort the connection.
- **The packet sequence numbers are reset to 0 immediately after sending/receiving
  `SSH_MSG_NEWKEYS`** (they are NOT reset at connection start; the KEXINIT and KEXDH packets
  count normally starting from 0, then after NEWKEYS the counters restart at 0). Modern
  OpenSSH enables this by default, so implement it.

### Negotiation rule (RFC 4253 §7.1)

For each direction, the chosen algorithm is the **client's first-preference name that the
server also supports**. With a single-item suite this is trivial: verify the peer's list
contains our one algorithm for each slot; if not, disconnect
(`SSH_DISCONNECT_KEY_EXCHANGE_FAILED`). Ignore the strict-kex marker when picking the actual
kex algorithm (it is not a real kex method).

## 4. Key exchange: `curve25519-sha256`

RFC 8731 (which builds on RFC 5656 message flow). Uses X25519 (RFC 7748) and SHA-256.

**Client** generates an ephemeral X25519 keypair `(c_sk, Q_C)` where `Q_C = X25519(c_sk, 9)`
(32 bytes), and sends:

```
byte      SSH_MSG_KEX_ECDH_INIT (30)
string    Q_C        # 32-byte client ephemeral public key
```

**Server** generates `(s_sk, Q_S)`, computes the shared secret, builds and signs the exchange
hash, and replies:

```
byte      SSH_MSG_KEX_ECDH_REPLY (31)
string    K_S        # server public host key blob (ssh-ed25519, see below)
string    Q_S        # 32-byte server ephemeral public key
string    signature  # server's ssh-ed25519 signature over H (see below)
```

Shared secret:

```
K_raw = X25519(own_sk, peer_Q)      # 32 bytes
```

**Crucial `mpint` step:** `K` is then treated as an `mpint`. Interpret the 32-byte `K_raw`
as a big-endian unsigned integer and **encode it as an `mpint`** (add a leading `0x00` if the
top bit of byte 0 is set) when feeding it into `H` and into key derivation. This is a classic
interop bug — X25519 gives raw bytes but SSH hashes it as `mpint`.

If `K_raw` is all zeros (peer sent a low-order point), abort
(`SSH_DISCONNECT_KEY_EXCHANGE_FAILED`).

### Exchange hash `H`

```
H = SHA256( string(V_C) || string(V_S) || string(I_C) || string(I_S)
            || string(K_S) || string(Q_C) || string(Q_S) || mpint(K) )
```

where each `string(x)` is the wire `string` encoding (uint32 length + bytes):

- `V_C`, `V_S` — the version strings **without** trailing CR LF.
- `I_C`, `I_S` — the **entire payload** of each side's `SSH_MSG_KEXINIT` (starting at the
  message-number byte 20, through the reserved uint32; i.e. the packet payload, not including
  packet_length/padding).
- `K_S` — the server host key blob (§5).
- `Q_C`, `Q_S` — the 32-byte ephemeral public keys.
- `K` — the shared secret as `mpint` (see above).

The hash algorithm is SHA-256 because the kex name ends in `-sha256`.

### `session_id`

`H` from the **first** key exchange is the `session_id`. It never changes (we don't rekey).
It is used in signatures during userauth (see [04](04-auth-connection-spec.md)).

### Server signature

The server signs `H` (the 32-byte SHA-256 output, as-is) with its Ed25519 host private key.
The `signature` field is the `ssh-ed25519` signature blob (§5). The client verifies it
against `K_S` and MUST also check `K_S` against `known_hosts`/TOFU
(see [05](05-key-formats.md)).

## 5. Ed25519 host key & signature blobs (RFC 8709)

Public key blob (`K_S`):

```
string    "ssh-ed25519"
string    key           # 32-byte Ed25519 public key A
```

Signature blob:

```
string    "ssh-ed25519"
string    signature     # 64-byte raw Ed25519 signature
```

## 6. Key derivation & NEWKEYS

After the client verifies the signature, both sides derive keys (RFC 4253 §7.2). Both send:

```
byte    SSH_MSG_NEWKEYS (21)
```

Sending `NEWKEYS` means "everything I send after this is encrypted with the new keys."
Under strict KEX, reset send/recv sequence numbers to 0 right here.

### Derivation formula

Let `HASH = SHA-256`, `K` = shared secret as `mpint`, `H` = exchange hash, `session_id` = `H`.
For each key, letter `X` is a single ASCII char:

```
K1 = HASH(K || H || X || session_id)
K2 = HASH(K || H || K1)
K3 = HASH(K || H || K1 || K2)
...
key = K1 || K2 || K3 || ...   (truncate to needed length)
```

The letters:

| X | Purpose |
|---|---|
| `'A'` | Initial IV client→server |
| `'B'` | Initial IV server→client |
| `'C'` | Encryption key client→server |
| `'D'` | Encryption key server→client |
| `'E'` | Integrity (MAC) key client→server |
| `'F'` | Integrity (MAC) key server→client |

For `chacha20-poly1305@openssh.com`:

- The cipher needs **64 bytes** of key per direction (see §7). So `C` and `D` each need 64
  bytes → two HASH iterations each (32 + 32).
- IVs (`A`,`B`) and MAC keys (`E`,`F`) are **not used** (the AEAD derives its nonce from the
  sequence number and its Poly1305 key from the stream). Derive them or not — they're unused.

Client uses `C`/`E` keys to **send** and `D`/`F` to **receive**; server is the mirror.

## 7. `chacha20-poly1305@openssh.com` packet format

This replaces the RFC 4253 §6 framing once NEWKEYS is active. Authoritative source: OpenSSH
`PROTOCOL.chacha20poly1305`; the crypto details of ChaCha20/Poly1305 are in
[03-crypto-spec.md](03-crypto-spec.md). **Drive `moonbitlang/x/crypto`'s IETF ChaCha20 with
the 12-byte SSH nonce built below** — [03](03-crypto-spec.md) §2 explains why the IETF variant
interoperates (it is keystream-identical to OpenSSH's original variant for our sequence
numbers, and is what Go's `x/crypto/ssh` uses).

### Two keys from the 64-byte key material

The 64-byte per-direction key `K_enc` splits into two 32-byte ChaCha20 keys. **Byte order
matters and is a classic bug:**

```
K_2 (content/payload key) = K_enc[0..32]     # first 32 bytes
K_1 (length key)          = K_enc[32..64]    # second 32 bytes
```

(This matches Go's `x/crypto/ssh`: `contentKey = key[:32]`, `lengthKey = key[32:]`.)

### Nonce

The IETF ChaCha20 nonce for both K_1 and K_2 operations is **12 bytes**:

```
nonce = 0x00 * 8  ||  uint32_be(seqnum)      # 8 zero bytes, then the 4-byte big-endian seqnum
```

`seqnum` is the packet sequence number of the packet being sent/received. **Do not** encode it
little-endian or map it any other way — see the nonce trap in [03](03-crypto-spec.md) §2. (A
self-built original-variant ChaCha20 would instead take the 8-byte big-endian uint64 seqnum as
its nonce; both produce the same keystream for seqnum < 2³².)

### Sending a packet

Given `payload` and current send `seqnum`:

1. **Build the unencrypted packet body** with padding. **Unlike RFC 4253 §2, the 4-byte
   length field is excluded from the alignment** (it is encrypted separately in step 2). Body
   = `padding_length(byte) || payload || padding`, aligned so that
   `1 + len(payload) + len(padding)` is a multiple of **8** (block size for alignment), with a
   minimum of **4** padding bytes:
   ```
   size_wo_pad = 1 + payload_len          # NOTE: no +4 here (differs from §2)
   pad = 8 - (size_wo_pad % 8); if pad < 4: pad += 8
   ```
   Let `packet_length = 1 + len(payload) + len(padding)`.
2. **Encrypt the length field**: `enc_len = ChaCha20(key=K_1, nonce=nonce, counter=0)`
   XOR `uint32_be(packet_length)` → 4 ciphertext bytes.
3. **Derive Poly1305 key**: run `ChaCha20(key=K_2, nonce=nonce, counter=0)` and take the
   **first 32 bytes** of keystream as `poly_key`. (Counter 0 block; the first 32 bytes.)
4. **Encrypt the body**: `enc_body = ChaCha20(key=K_2, nonce=nonce, counter=1)` XOR body.
   Note the counter **starts at 1** for the body (counter 0 was consumed conceptually by the
   Poly1305 key; with the original 64-bit-counter ChaCha20 you simply set the block counter to
   1 before encrypting the body).
5. **Compute the tag**: `tag = Poly1305(poly_key, enc_len || enc_body)` (16 bytes) — over the
   ciphertext of *both* the length field and the body.
6. Wire bytes = `enc_len (4) || enc_body || tag (16)`.
7. Increment `seqnum`.

### Receiving a packet

1. Read 4 bytes. Decrypt with `ChaCha20(K_1, nonce, counter=0)` to get `packet_length`.
   Sanity-check the length (≤ 35000, and `enc_body` length = `packet_length`); abort if absurd.
2. Read `packet_length + 16` more bytes (`enc_body || tag`).
3. Recompute `poly_key` = first 32 bytes of `ChaCha20(K_2, nonce, counter=0)`.
4. Verify `tag == Poly1305(poly_key, enc_len || enc_body)`. **On mismatch, abort the
   connection** (`SSH_DISCONNECT_MAC_ERROR`). Use a comparison that is not obviously
   short-circuit (toy: constant-time not required, but don't reveal position; a simple XOR-accumulate compare is enough).
5. Decrypt body: `ChaCha20(K_2, nonce, counter=1)` XOR `enc_body`.
6. Parse `padding_length`, slice out `payload`, discard padding.
7. Increment recv `seqnum`. Hand `payload` to the next layer.

> The Poly1305 tag is computed over **ciphertext** (encrypt-then-MAC style, but integrated),
> and the length field is authenticated. Do not authenticate plaintext.

## 8. Message number reference

Transport-layer numbers we use (RFC 4250 §4.1.2, RFC 4253):

| # | Name | Direction |
|---|---|---|
| 1 | `SSH_MSG_DISCONNECT` | both |
| 2 | `SSH_MSG_IGNORE` | both (we don't send; must skip on receive except during strict kex) |
| 3 | `SSH_MSG_UNIMPLEMENTED` | both |
| 4 | `SSH_MSG_DEBUG` | both (skip on receive) |
| 5 | `SSH_MSG_SERVICE_REQUEST` | client→server |
| 6 | `SSH_MSG_SERVICE_ACCEPT` | server→client |
| 7 | `SSH_MSG_EXT_INFO` | both (RFC 8308; we ignore) |
| 20 | `SSH_MSG_KEXINIT` | both |
| 21 | `SSH_MSG_NEWKEYS` | both |
| 30 | `SSH_MSG_KEX_ECDH_INIT` | client→server |
| 31 | `SSH_MSG_KEX_ECDH_REPLY` | server→client |

`SSH_MSG_DISCONNECT` payload: `byte(1) || uint32 reason_code || string description || string language_tag(empty)`.

Reason codes we use: `PROTOCOL_ERROR=2`, `KEY_EXCHANGE_FAILED=3`, `MAC_ERROR=5`,
`SERVICE_NOT_AVAILABLE=7`, `NO_MORE_AUTH_METHODS_AVAILABLE=14` (see RFC 4250 §4.2.2).

### Service request flow

After NEWKEYS, the client sends `SSH_MSG_SERVICE_REQUEST` with `string "ssh-userauth"`; the
server replies `SSH_MSG_SERVICE_ACCEPT` with the same service name. Then userauth begins
([04](04-auth-connection-spec.md)). The connection protocol later uses service
`"ssh-connection"` but that service is implicitly available after successful auth — no second
service request is needed.
