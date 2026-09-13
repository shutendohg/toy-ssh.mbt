///|
/// Byte-order helpers shared by the self-built primitives.
///
/// X25519 / Ed25519 encode integers little-endian; `BigInt::from_octets` /
/// `to_octets` are big-endian, so the LE helpers simply reverse the octets.
/// Toy code: nothing here is constant-time.

///|
/// Copy a `FixedArray[Byte]` into an immutable `Bytes` (the core
/// `Bytes::from_fixedarray` is deprecated).
pub fn fixed_to_bytes(a : FixedArray[Byte]) -> Bytes {
  Bytes::from_iter(a.iter())
}

///|
/// Interpret `data` as an unsigned little-endian integer.
pub fn le_bytes_to_bigint(data : BytesView) -> BigInt {
  let n = data.length()
  let be = FixedArray::make(n, b'\x00')
  for i in 0..<n {
    be[i] = data[n - 1 - i]
  }
  BigInt::from_octets(fixed_to_bytes(be)[:])
}

///|
/// Encode a non-negative `n` as `len` little-endian bytes. Aborts if `n`
/// does not fit (a programming error in this code base, never user input).
pub fn bigint_to_le_bytes(n : BigInt, len : Int) -> FixedArray[Byte] {
  guard n >= 0N && n.bit_length() <= len * 8 else {
    abort("bigint_to_le_bytes: value out of range")
  }
  let be = n.to_octets(length=len)
  let out = FixedArray::make(len, b'\x00')
  for i in 0..<len {
    out[i] = be[len - 1 - i]
  }
  out
}

///|
/// Interpret `data` as an unsigned big-endian integer.
pub fn be_bytes_to_bigint(data : BytesView) -> BigInt {
  BigInt::from_octets(data)
}

///|
/// Clamp a 32-byte little-endian scalar in place, as both X25519
/// (RFC 7748 section 5, decodeScalar25519) and Ed25519 (RFC 8032 section
/// 5.1.5) require: clear the low 3 bits, clear bit 255, set bit 254.
pub fn clamp_scalar25519(k : FixedArray[Byte]) -> Unit {
  guard k.length() == 32 else { abort("clamp_scalar25519: need 32 bytes") }
  k[0] = k[0] & b'\xf8'
  k[31] = (k[31] & b'\x7f') | b'\x40'
}
