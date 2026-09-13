// X25519 vectors from docs/03 section 4 (RFC 7748 sections 5.2 and 6.1).

///|
fn hex_of(a : FixedArray[Byte]) -> String {
  @crypto.hex_encode(@crypto.fixed_to_bytes(a))
}

///|
test "x25519 RFC 7748 section 5.2 scalarmult vectors" {
  let out1 = @crypto.x25519(
    @crypto.hex_decode(
      "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    ),
    @crypto.hex_decode(
      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
    ),
  )
  inspect(
    hex_of(out1),
    content="c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
  )
  let out2 = @crypto.x25519(
    @crypto.hex_decode(
      "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
    ),
    @crypto.hex_decode(
      "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
    ),
  )
  inspect(
    hex_of(out2),
    content="95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
  )
}

///|
test "x25519 RFC 7748 section 5.2 iterated (1 and 1000)" {
  let base = @crypto.hex_decode(
    "0900000000000000000000000000000000000000000000000000000000000000",
  )
  let mut k = base
  let mut u = base
  let mut result_1 = ""
  for i in 0..<1000 {
    let next = @crypto.fixed_to_bytes(@crypto.x25519(k, u))
    u = k
    k = next
    if i == 0 {
      result_1 = @crypto.hex_encode(k)
    }
  }
  inspect(
    result_1,
    content="422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
  )
  inspect(
    @crypto.hex_encode(k),
    content="684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
  )
}

///|
test "x25519 RFC 7748 section 6.1 Diffie-Hellman" {
  let a = @crypto.hex_decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let b = @crypto.hex_decode(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  let ka = @crypto.x25519_base(a)
  let kb = @crypto.x25519_base(b)
  inspect(
    hex_of(ka),
    content="8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  inspect(
    hex_of(kb),
    content="de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
  let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  inspect(hex_of(@crypto.x25519(a, @crypto.fixed_to_bytes(kb))), content=shared)
  inspect(hex_of(@crypto.x25519(b, @crypto.fixed_to_bytes(ka))), content=shared)
}

///|
test "x25519 masks the high bit of u" {
  // RFC 7748 section 5: the top bit of the last byte of u is ignored, so
  // u and u|0x80 must give the same result.
  let k = @crypto.hex_decode(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
  )
  let u = @crypto.hex_decode(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
  )
  let u_hi = @crypto.hex_decode(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1ccc",
  )
  assert_eq(hex_of(@crypto.x25519(k, u)), hex_of(@crypto.x25519(k, u_hi)))
}
