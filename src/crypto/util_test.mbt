// Byte-order helper tests (docs/08 section 4: LE vs BE is where curve bugs hide).

///|
test "le_bytes_to_bigint reads little-endian" {
  // 0x0102 stored LE is [02, 01].
  inspect(@crypto.le_bytes_to_bigint(b"\x02\x01"), content="258")
  // Leading (high) zero bytes at the end of the LE buffer do not matter.
  inspect(@crypto.le_bytes_to_bigint(b"\x09\x00\x00\x00"), content="9")
  inspect(@crypto.le_bytes_to_bigint(b""), content="0")
}

///|
test "be_bytes_to_bigint reads big-endian" {
  inspect(@crypto.be_bytes_to_bigint(b"\x01\x02"), content="258")
}

///|
test "bigint_to_le_bytes pads to the requested length" {
  let out = @crypto.bigint_to_le_bytes(258N, 4)
  inspect(@hex.encode(@crypto.fixed_to_bytes(out)), content="02010000")
  let zero = @crypto.bigint_to_le_bytes(0N, 3)
  inspect(@hex.encode(@crypto.fixed_to_bytes(zero)), content="000000")
}

///|
test "le round trip on a 32-byte value with the high bit set" {
  let hex = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221180"
  let n = @crypto.le_bytes_to_bigint(@hex.decode(hex))
  let back = @crypto.bigint_to_le_bytes(n, 32)
  inspect(@hex.encode(@crypto.fixed_to_bytes(back)), content=hex)
}

///|
test "clamp_scalar25519 clears low 3 bits, clears bit 255, sets bit 254" {
  let k = FixedArray::make(32, b'\xff')
  @crypto.clamp_scalar25519(k)
  inspect(k[0], content="b'\\xF8'")
  inspect(k[31], content="b'\\x7F'")
  let z = FixedArray::make(32, b'\x00')
  @crypto.clamp_scalar25519(z)
  inspect(z[0], content="b'\\x00'")
  inspect(z[31], content="b'\\x40'")
}
