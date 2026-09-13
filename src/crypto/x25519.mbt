///|
/// X25519 Diffie-Hellman function (RFC 7748 section 5): Montgomery-ladder
/// scalar multiplication on Curve25519 over GF(2^255 - 19).
///
/// Toy implementation: the conditional swap is a plain branch and the
/// field arithmetic is BigInt, so this is not constant-time. Never use for
/// real security.

///|
/// (486662 - 2) / 4
let x25519_a24 : BigInt = 121665N

///|
/// Decode and clamp a 32-byte little-endian scalar (decodeScalar25519).
fn decode_scalar25519(scalar : BytesView) -> BigInt {
  guard scalar.length() == 32 else { abort("x25519: scalar must be 32 bytes") }
  let k = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    k[i] = scalar[i]
  }
  clamp_scalar25519(k)
  le_bytes_to_bigint(fixed_to_bytes(k)[:])
}

///|
/// Decode a 32-byte little-endian u-coordinate, ignoring the top bit
/// (decodeUCoordinate). The result is reduced mod p.
fn decode_u_coordinate(u : BytesView) -> BigInt {
  guard u.length() == 32 else { abort("x25519: u must be 32 bytes") }
  let b = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    b[i] = u[i]
  }
  b[31] = b[31] & b'\x7f'
  fe_reduce(le_bytes_to_bigint(fixed_to_bytes(b)[:]))
}

///|
/// X25519(k, u): scalar multiplication with the RFC 7748 Montgomery ladder.
pub fn x25519(scalar : BytesView, u : BytesView) -> FixedArray[Byte] {
  let k = decode_scalar25519(scalar)
  let x_1 = decode_u_coordinate(u)
  let mut x_2 = 1N
  let mut z_2 = 0N
  let mut x_3 = x_1
  let mut z_3 = 1N
  let mut swap = false
  for t = 254; t >= 0; t = t - 1 {
    let k_t = !((k >> t) & 1N).is_zero()
    // cswap(swap XOR k_t)
    if swap != k_t {
      let tx = x_2
      x_2 = x_3
      x_3 = tx
      let tz = z_2
      z_2 = z_3
      z_3 = tz
    }
    swap = k_t
    let a = fe_add(x_2, z_2)
    let aa = fe_sq(a)
    let b = fe_sub(x_2, z_2)
    let bb = fe_sq(b)
    let e = fe_sub(aa, bb)
    let c = fe_add(x_3, z_3)
    let d = fe_sub(x_3, z_3)
    let da = fe_mul(d, a)
    let cb = fe_mul(c, b)
    x_3 = fe_sq(fe_add(da, cb))
    z_3 = fe_mul(x_1, fe_sq(fe_sub(da, cb)))
    x_2 = fe_mul(aa, bb)
    z_2 = fe_mul(e, fe_add(aa, fe_mul(x25519_a24, e)))
  }
  if swap {
    let tx = x_2
    x_2 = x_3
    x_3 = tx
    let tz = z_2
    z_2 = z_3
    z_3 = tz
  }
  bigint_to_le_bytes(fe_mul(x_2, fe_inv(z_2)), 32)
}

///|
/// X25519 against the base point u = 9 (public-key derivation).
pub fn x25519_base(scalar : BytesView) -> FixedArray[Byte] {
  let base = FixedArray::make(32, b'\x00')
  base[0] = b'\x09'
  x25519(scalar, fixed_to_bytes(base)[:])
}
