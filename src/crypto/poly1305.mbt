///|
/// Poly1305 one-time authenticator (RFC 8439 section 2.5).
///
/// Toy implementation on top of `BigInt`: not constant-time, allocates per
/// block. Fine for an educational SSH; never use for real security.

///|
/// p = 2^130 - 5
let poly1305_p : BigInt = (1N << 130) - 5N

///|
/// Compute the 16-byte Poly1305 tag of `msg` under the 32-byte one-time
/// `key` = r (16 bytes, clamped here) || s (16 bytes).
pub fn poly1305(key : BytesView, msg : BytesView) -> FixedArray[Byte] {
  guard key.length() == 32 else { abort("poly1305: key must be 32 bytes") }
  // Clamp r: clear the top 4 bits of bytes 3,7,11,15 and the bottom 2 bits
  // of bytes 4,8,12 (RFC 8439 section 2.5.1).
  let r_bytes = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    r_bytes[i] = key[i]
  }
  for i in [3, 7, 11, 15] {
    r_bytes[i] = r_bytes[i] & b'\x0f'
  }
  for i in [4, 8, 12] {
    r_bytes[i] = r_bytes[i] & b'\xfc'
  }
  let r = le_bytes_to_bigint(fixed_to_bytes(r_bytes)[:])
  let s = le_bytes_to_bigint(key[16:32])
  let mut acc = 0N
  let mut off = 0
  let n = msg.length()
  while off < n {
    let take = if n - off >= 16 { 16 } else { n - off }
    // Block value: the chunk as a little-endian integer with a 1 bit
    // appended just above its last byte (RFC 8439 section 2.5.1).
    let block = le_bytes_to_bigint(msg[off:off + take]) + (1N << (8 * take))
    acc = (acc + block) * r % poly1305_p
    off += take
  }
  // Add s and keep the low 128 bits.
  let tag = (acc + s) & ((1N << 128) - 1N)
  bigint_to_le_bytes(tag, 16)
}
