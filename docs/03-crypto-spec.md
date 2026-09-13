# 03 — Crypto Primitives Specification

Three primitives are implemented by hand in `src/crypto/` (Poly1305, X25519, Ed25519).
SHA-256, **SHA-512**, HMAC, base64, **and ChaCha20** are **reused** from existing MoonBit
libraries. (SHA-512 was originally planned as self-built because `moonbitlang/x/crypto` used
to stop at SHA-256; version 0.5.5 ships `sha512`, so the reason for building it disappeared.) Everything here is for *learning* and is **not** constant-time or otherwise
hardened (see the disclaimer in [00](00-overview.md)).

Every primitive below ships with a MoonBit `_test.mbt` that checks the **exact hex test
vectors transcribed in this document**. Implement Red (write the failing vector test) →
Green (make it pass) → Refactor. Do not proceed to the transport layer until all vectors pass.

## Reused, not built

| Need | Library | Interface (from `pkg.generated.mbti`) |
|---|---|---|
| SHA-256 | `moonbitlang/x/crypto` | `sha256(data) -> FixedArray[Byte]` (32 bytes); streaming `SHA256::new()`, `update(self, data)`, `finalize(self)` |
| SHA-512 | `moonbitlang/x/crypto` (≥0.5.5) | `sha512(data) -> FixedArray[Byte]` (64 bytes); streaming `SHA512::new()`, `update`, `finalize` |
| HMAC | `moonbitlang/x/crypto` | `hmac(hasher, key, message) -> FixedArray[Byte]` (generic over `CryptoHasher`) |
| base64 | `moonbitlang/x/codec/base64` | encode/decode for `authorized_keys` / key files |
| ChaCha20 | `moonbitlang/x/crypto` | `ChaCha::chacha20(key, nonce, counter?) -> Self`, `transform(self, data, out, offset?)` — IETF variant (see §2 for how to drive it as the SSH cipher) |

> Verify these signatures against the actual installed version with `moon info` before coding
> — `moonbitlang/x` is explicitly experimental and "may change frequently."

## Common helpers

- Represent byte strings as `Bytes` / `FixedArray[Byte]` / `BytesView`. Prefer `BytesView`
  for read-only spans.
- Use `moonbitlang/core/encoding/hex` (`@hex.decode` / `@hex.encode`, imported `for "test"`)
  so the embedded vectors below can be pasted directly into tests. Do not hand-roll hex.
- Little-endian vs big-endian is called out per primitive — this is where bugs hide.

---

## 1. SHA-512 — reuse `moonbitlang/x/crypto`

Ed25519 (RFC 8032) uses SHA-512 internally. `moonbitlang/x/crypto` ≥0.5.5 provides
`sha512(data) -> FixedArray[Byte]` (64 bytes) and a streaming `SHA512` hasher, so **we do not
build it**. A smoke test pins the library against the vectors below (`src/crypto/reused_test.mbt`)
so that a future library change cannot silently break Ed25519.

### Test vectors (hex digests)

| Input | SHA-512 |
|---|---|
| `""` (empty) | `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e` |
| `"abc"` | `ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f` |
| `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"` | `204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445` |

(The `"abc"` digest is also usable as the RFC 8032 "TEST SHA(abc)" message — see Ed25519.)

---

## 2. ChaCha20 — reuse `moonbitlang/x/crypto` (IETF variant)

**We do not build ChaCha20.** The `chacha20-poly1305@openssh.com` cipher can be driven
entirely with the **IETF ChaCha20** (RFC 8439: 96-bit nonce, 32-bit counter) that
`moonbitlang/x/crypto` already provides. This is exactly what Go's production
`golang.org/x/crypto/ssh` does, and it interoperates with OpenSSH.

Why the IETF variant works even though OpenSSH's own code uses the "original" ChaCha20
(64-bit counter, 64-bit nonce): the two layouts produce the **identical keystream** as long as
you build the SSH nonce correctly and the packet sequence number stays below 2³² — which it
always does here, because we never rekey and connections are short. (For the record: OpenSSH
puts the counter in state words 12–13 and the 8-byte nonce in 14–15; the IETF layout puts a
32-bit counter in word 12 and the 12-byte nonce in 13–15. With the SSH nonce below, words
12–15 come out bit-for-bit equal in both.)

### Driving it as the SSH cipher

Build a **12-byte IETF nonce** from the packet sequence number:

```
nonce = 0x00 * 8  ||  uint32_be(seqnum)      # 8 zero bytes, then the 4-byte big-endian seqnum
```

Then, for a given packet (see [02](02-transport-spec.md) §7 for the full framing):

- **Length field** (4 bytes): `ChaCha::chacha20(K_1, nonce, counter=0)`, `transform` the
  4 length bytes.
- **Poly1305 key**: `ChaCha::chacha20(K_2, nonce, counter=0)`, `transform` 32 zero bytes → the
  32-byte Poly1305 key (the first 32 bytes of the counter-0 keystream block).
- **Payload**: `ChaCha::chacha20(K_2, nonce, counter=1)`, `transform` the packet body.

`transform(self, input, output, offset?)` XORs the keystream into `input`. To get raw
keystream (for the Poly1305 key), transform a zero-filled buffer.

> **The nonce trap:** do *not* pass the sequence number as a little-endian integer or map it
> naively into nonce bytes. It must be the **8 zero bytes then the 4-byte big-endian seqnum**,
> exactly as above. Getting this wrong yields `Corrupted MAC on input` from OpenSSH and is the
> single most likely interop bug in the whole cipher.

### Fallback: self-built ChaCha20

Only if the library's ChaCha API can't be driven as above (wrong nonce width, no settable
counter, etc.): implement ChaCha20 yourself. Either variant interoperates for seqnum < 2³².
Implement the pure block function first — `chacha20_block(key, w12, w13, w14, w15) -> [64]byte`
(constant `"expand 32-byte k"`, key in words 4–11 little-endian, 20 rounds = 10 double-rounds
of quarter-rounds) — then layer streaming on top. Validate with RFC 8439 §2.3.2: with key
bytes `00 01 … 1f` and state words `w12=0x00000001, w13=0x09000000, w14=0x4a000000, w15=0`,
the block is:

```
10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e
```

For the fallback, the same nonce rule applies: place `uint32_be(seqnum)` into the low nonce
word(s) so that state word 15 = byte-swapped seqnum and words 13–14 = 0. **Regardless of
path, the only proof the wiring is right is an end-to-end round trip against OpenSSH (M2).**

---

## 3. Poly1305 (RFC 8439 §2.5)

One-time authenticator. Key is 32 bytes = `r` (16 bytes, clamped) || `s` (16 bytes). Compute
`(((sum of 16-byte message chunks as little-endian ints, each with a high 1-bit appended) * r)
mod (2^130 − 5)) + s`, take the low 128 bits as the 16-byte tag. Use MoonBit `BigInt` for the
mod-2^130−5 arithmetic (toy: performance irrelevant).

Clamping `r`: clear bits — `r &= 0x0ffffffc0ffffffc0ffffffc0fffffff` (byte-wise: clear top 4
bits of bytes 3,7,11,15 and clear bottom 2 bits of bytes 4,8,12).

Suggested API:

```moonbit
pub fn poly1305(key : BytesView /*32*/, msg : BytesView) -> FixedArray[Byte]  // 16 bytes
```

### Test vector (RFC 8439 §2.5.2)

```
key (32 bytes):
  85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8
  01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b
message = "Cryptographic Forum Research Group"   (ASCII, 34 bytes)
tag:
  a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9
```

(For reference, clamped `r = 0x806d5400e52447c036d555408bed685`, `s = 0x1bf54941aff6bf4afdb20dfb8a800301`; the tag is `(acc·r mod p) + s`.)

---

## 4. X25519 (RFC 7748)

Montgomery-ladder scalar multiplication on Curve25519 over GF(2^255 − 19). Implement:

```moonbit
pub fn x25519(scalar : BytesView /*32*/, u : BytesView /*32*/) -> FixedArray[Byte]?  // 32
pub fn x25519_base(scalar : BytesView) -> FixedArray[Byte]   // u = 9
```

`x25519` returns `None` when the peer's `u` is not 32 bytes or when the result is all-zero
(a low-order point; RFC 7748 §6.1). The transport treats `None` as a key-exchange failure.
The `scalar` is ours, so a wrong length there is a programmer error and aborts.

Key steps (RFC 7748 §5):

1. **Decode scalar** (`decodeScalar25519`): copy 32 bytes little-endian, then clamp:
   `k[0] &= 248; k[31] &= 127; k[31] |= 64`.
2. **Decode u-coordinate**: little-endian, mask the high bit of the last byte
   (`u[31] &= 127`).
3. Run the constant-`a24 = 121665` Montgomery ladder (255 bits, high→low), conditional swap
   per bit. Field arithmetic mod `p = 2^255 − 19`.
4. Encode the result little-endian (32 bytes).

Field arithmetic: implement with `BigInt` for clarity (toy). `add`, `sub` (add p if
negative), `mul` then reduce mod p, and `inv` = `pow(x, p−2)` via square-and-multiply for the
final `x/z`.

### Test vectors (RFC 7748 §5.2 and §6.1)

Single scalarmult (§5.2):

| scalar | u | X25519(scalar,u) |
|---|---|---|
| `a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4` | `e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c` | `c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552` |
| `4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d` | `e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493` | `95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957` |

Iterated test (§5.2): starting `k = u = 09000000...00` (the byte `09` then 31 zeros), set
`k = X25519(k, u)` then shift `u = old k`. Results:

| iterations | result |
|---|---|
| 1 | `422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079` |
| 1000 | `684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51` |

(The 1M-iteration test is optional — slow with BigInt; the 1000-iteration one is enough.)

Diffie–Hellman (§6.1), which is exactly the SSH kex shape:

```
Alice private a  = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
Alice public  KA = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a   (= x25519_base(a))
Bob   private b  = 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
Bob   public  KB = de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f   (= x25519_base(b))
shared K         = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
                   (= x25519(a, KB) = x25519(b, KA))
```

---

## 5. Ed25519 (RFC 8032)

Signature over the twisted Edwards curve edwards25519 (birationally equivalent to
Curve25519), using SHA-512. Implement sign, verify, and public-key derivation:

```moonbit
pub fn ed25519_public_key(secret : BytesView /*32*/) -> FixedArray[Byte]        // 32-byte A
pub fn ed25519_sign(secret : BytesView /*32*/, msg : BytesView) -> FixedArray[Byte]  // 64
pub fn ed25519_verify(public : BytesView /*32*/, msg : BytesView, sig : BytesView /*64*/) -> Bool
```

Algorithm (RFC 8032 §5.1), all little-endian, curve constant `d = -121665/121666`,
`L = 2^252 + 27742317777372353535851937790883648493` (group order):

- **Key expansion:** `h = SHA512(secret)` (64 bytes). Clamp `h[0..32]` like X25519
  (`&=248`, `[31]&=127`, `[31]|=64`) → scalar `s`. `A = s·B` (base point `B`), encode to 32
  bytes (point compression: y-coord little-endian, top bit = sign of x). The "prefix" is
  `h[32..64]`.
- **Sign:** `r = SHA512(prefix || msg) mod L`; `R = r·B` (32 bytes); `k = SHA512(R || A ||
  msg) mod L`; `S = (r + k·s) mod L`. Signature = `R (32) || S (32, little-endian)`.
- **Verify:** decode `R`, `S`, `A`; check `S < L`; `k = SHA512(R || A || msg) mod L`; accept
  iff `S·B == R + k·A` (use the equivalent `[8S]B == [8]R + [8](k·A)` cofactor form or the
  plain one — RFC 8032 §5.1.7 allows either; plain is fine for a toy). Reject malformed
  points.

Point arithmetic: implement Edwards addition/doubling on `(x,y)` with `BigInt` mod p, or use
extended coordinates for fewer inversions. Point **decompression** requires a modular square
root: `x = ±sqrt((y²−1)/(d·y²+1))`, computed via `pow(_, (p+3)/8)` with the ±sqrt(−1)
correction (RFC 8032 §5.1.3). Get this right — it's the subtle part.

### Test vectors (RFC 8032 §7.1)

Each secret key is the 32-byte seed; public key is derived from it.

**TEST 1 — empty message**
```
secret    9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
public    d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
message   (empty)
signature e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
```

**TEST 2 — one byte `0x72`**
```
secret    4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
public    3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
message   72
signature 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
```

**TEST 3 — two bytes `af82`**
```
secret    c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
public    fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
message   af82
signature 6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a
```

**TEST SHA(abc)** — message is the SHA-512 of "abc" (matches the SHA-512 vector above)
```
secret    833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42
public    ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf
message   ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
signature dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704
```

For each: assert `ed25519_public_key(secret) == public`, `ed25519_sign(secret, message) ==
signature`, and `ed25519_verify(public, message, signature) == true`. Add a negative test:
flip one bit of the signature or message and assert verify returns `false`.

---

## Dependency notes for the transport layer

- Kex uses `x25519` / `x25519_base` (§4), `sha256` (reused), and the `mpint` encoder from
  `wire/`.
- Host-key signing/verification uses `ed25519_sign` / `ed25519_verify` (§5).
- The record cipher uses `ChaCha20` (§2) + `poly1305` (§3).
- `keys/` uses `ed25519_public_key` to check that a parsed private key matches its public
  half.
