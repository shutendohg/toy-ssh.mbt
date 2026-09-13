// Poly1305 vectors from docs/03 section 3 (RFC 8439 section 2.5.2).

///|
test "poly1305 RFC 8439 section 2.5.2 tag" {
  let key = @crypto.hex_decode(
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
  )
  let msg = b"Cryptographic Forum Research Group"
  let tag = @crypto.poly1305(key, msg)
  inspect(
    @crypto.hex_encode(@crypto.fixed_to_bytes(tag)),
    content="a8061dc1305136c6c22b8baf0c0127a9",
  )
}

///|
test "poly1305 empty message is just s" {
  // With no message blocks the accumulator stays 0, so tag = s (low 128 bits).
  let key = @crypto.hex_decode(
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
  )
  let tag = @crypto.poly1305(key, b"")
  inspect(
    @crypto.hex_encode(@crypto.fixed_to_bytes(tag)),
    content="0103808afb0db2fd4abff6af4149f51b",
  )
}
