///|
/// Ed25519 signatures (RFC 8032 section 5.1) over the twisted Edwards
/// curve edwards25519, using SHA-512 from moonbitlang/x/crypto and the
/// GF(2^255 - 19) helpers in field.mbt.
///
/// Toy implementation: BigInt point arithmetic in extended coordinates,
/// plain double-and-add scalar multiplication, branches on secret data.
/// Not constant-time; never use for real security.

///|
/// d = -121665 / 121666 mod p
let ed_d : BigInt = fe_mul(fe_sub(0N, 121665N), fe_inv(121666N))

///|
/// Group order L = 2^252 + 27742317777372353535851937790883648493
pub let ed25519_l : BigInt = (1N << 252) +
  27742317777372353535851937790883648493N

///|
/// sqrt(-1) = 2^((p-1)/4) mod p, used to fix up the square root in
/// point decompression (RFC 8032 section 5.1.3).
let ed_sqrt_m1 : BigInt = fe_pow(2N, (field_p - 1N) / 4N)

///|
/// A point in extended twisted Edwards coordinates (X : Y : Z : T) with
/// x = X/Z, y = Y/Z, x*y = T/Z (RFC 8032 section 5.1.4).
priv struct EdPoint {
  x : BigInt
  y : BigInt
  z : BigInt
  t : BigInt
}

///|
/// Neutral element (0, 1).
let ed_identity : EdPoint = { x: 0N, y: 1N, z: 1N, t: 0N, }

///|
/// Base point B: y = 4/5, x is the positive root.
let ed_base : EdPoint = {
  let y = fe_mul(4N, fe_inv(5N))
  match ed_recover_x(y, false) {
    Some(x) => { x, y, z: 1N, t: fe_mul(x, y), }
    None => abort("ed25519: base point is not on the curve")
  }
}

///|
/// Recover x from y with the requested sign bit (RFC 8032 section 5.1.3).
/// Returns None if y is not the y-coordinate of any curve point, or if the
/// sign bit is set while x must be 0.
fn ed_recover_x(y : BigInt, sign : Bool) -> BigInt? {
  guard y < field_p else { return None }
  let y2 = fe_sq(y)
  // x^2 = (y^2 - 1) / (d y^2 + 1)
  let u = fe_sub(y2, 1N)
  let v = fe_add(fe_mul(ed_d, y2), 1N)
  let x2 = fe_mul(u, fe_inv(v))
  // Candidate root x = x2^((p+3)/8); it squares to either x2 or -x2.
  let mut x = fe_pow(x2, (field_p + 3N) / 8N)
  if fe_sq(x) != x2 {
    x = fe_mul(x, ed_sqrt_m1)
    if fe_sq(x) != x2 {
      return None
    }
  }
  if x.is_zero() && sign {
    return None
  }
  let x_is_odd = !(x & 1N).is_zero()
  if x_is_odd != sign {
    x = fe_sub(0N, x)
  }
  Some(x)
}

///|
/// Unified point addition (RFC 8032 section 5.1.4, a = -1, complete
/// formulas so P + P also works).
fn ed_add(p : EdPoint, q : EdPoint) -> EdPoint {
  let a = fe_mul(fe_sub(p.y, p.x), fe_sub(q.y, q.x))
  let b = fe_mul(fe_add(p.y, p.x), fe_add(q.y, q.x))
  let c = fe_mul(fe_mul(2N, p.t), fe_mul(q.t, ed_d))
  let d = fe_mul(fe_mul(2N, p.z), q.z)
  let e = fe_sub(b, a)
  let f = fe_sub(d, c)
  let g = fe_add(d, c)
  let h = fe_add(b, a)
  { x: fe_mul(e, f), y: fe_mul(g, h), z: fe_mul(f, g), t: fe_mul(e, h), }
}

///|
/// Scalar multiplication k*P by plain left-to-right double-and-add.
fn ed_scalar_mul(k : BigInt, p : EdPoint) -> EdPoint {
  let mut acc = ed_identity
  for i = k.bit_length() - 1; i >= 0; i = i - 1 {
    acc = ed_add(acc, acc)
    if !((k >> i) & 1N).is_zero() {
      acc = ed_add(acc, p)
    }
  }
  acc
}

///|
/// Point compression (RFC 8032 section 5.1.2): y little-endian with the
/// low bit of x stored in the top bit of the last byte.
fn ed_encode(p : EdPoint) -> FixedArray[Byte] {
  let zi = fe_inv(p.z)
  let x = fe_mul(p.x, zi)
  let y = fe_mul(p.y, zi)
  let out = bigint_to_le_bytes(y, 32)
  if !(x & 1N).is_zero() {
    out[31] = out[31] | b'\x80'
  }
  out
}

///|
/// Point decompression (RFC 8032 section 5.1.3). None for malformed input.
fn ed_decode(data : BytesView) -> EdPoint? {
  guard data.length() == 32 else { return None }
  let buf = FixedArray::make(32, b'\x00')
  buf.blit_from_bytesview(0, data)
  let sign = (buf[31] & b'\x80') != b'\x00'
  buf[31] = buf[31] & b'\x7f'
  let y = le_bytes_to_bigint(fixed_to_bytes(buf)[:])
  match ed_recover_x(y, sign) {
    Some(x) => Some({ x, y, z: 1N, t: fe_mul(x, y), })
    None => None
  }
}

///|
/// Key expansion (RFC 8032 section 5.1.5): returns (scalar s, prefix).
fn ed_expand_secret(secret : BytesView) -> (BigInt, Bytes) {
  guard secret.length() == 32 else { abort("ed25519: secret must be 32 bytes") }
  let h = @xcrypto.sha512(secret)
  let lo = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    lo[i] = h[i]
  }
  clamp_scalar25519(lo)
  let s = le_bytes_to_bigint(fixed_to_bytes(lo)[:])
  let prefix = Bytes::makei(32, i => h[32 + i])
  (s, prefix)
}

///|
/// SHA-512 over the concatenation of the given parts, read as a
/// little-endian integer and reduced mod L.
fn ed_hash_mod_l(parts : Array[BytesView]) -> BigInt {
  let hasher = @xcrypto.SHA512::new()
  for part in parts {
    hasher.update(part)
  }
  let digest = hasher.finalize()
  le_bytes_to_bigint(fixed_to_bytes(digest)[:]) % ed25519_l
}

///|
/// Derive the 32-byte public key A = s*B from a 32-byte seed.
pub fn ed25519_public_key(secret : BytesView) -> FixedArray[Byte] {
  let (s, _) = ed_expand_secret(secret)
  ed_encode(ed_scalar_mul(s, ed_base))
}

///|
/// Sign `msg` with the 32-byte seed; returns R (32) || S (32, LE).
pub fn ed25519_sign(secret : BytesView, msg : BytesView) -> FixedArray[Byte] {
  let (s, prefix) = ed_expand_secret(secret)
  let a_enc = fixed_to_bytes(ed_encode(ed_scalar_mul(s, ed_base)))
  let r = ed_hash_mod_l([prefix[:], msg])
  let r_enc = fixed_to_bytes(ed_encode(ed_scalar_mul(r, ed_base)))
  let k = ed_hash_mod_l([r_enc[:], a_enc[:], msg])
  let big_s = (r + k * s) % ed25519_l
  let out = FixedArray::make(64, b'\x00')
  out.blit_from_bytes(0, r_enc, 0, 32)
  let s_bytes = bigint_to_le_bytes(big_s, 32)
  for i in 0..<32 {
    out[32 + i] = s_bytes[i]
  }
  out
}

///|
/// Verify a 64-byte signature under a 32-byte public key. Returns false
/// (never aborts) on malformed lengths, undecodable points, or S >= L.
/// Uses the plain check S*B == R + k*A (RFC 8032 section 5.1.7).
pub fn ed25519_verify(
  public : BytesView,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  guard public.length() == 32 && sig.length() == 64 else { return false }
  guard ed_decode(public) is Some(a) else { return false }
  guard ed_decode(sig[0:32]) is Some(r) else { return false }
  let big_s = le_bytes_to_bigint(sig[32:64])
  guard big_s < ed25519_l else { return false }
  let k = ed_hash_mod_l([sig[0:32], public, msg])
  let lhs = ed_encode(ed_scalar_mul(big_s, ed_base))
  let rhs = ed_encode(ed_add(r, ed_scalar_mul(k, a)))
  fixed_to_bytes(lhs) == fixed_to_bytes(rhs)
}
