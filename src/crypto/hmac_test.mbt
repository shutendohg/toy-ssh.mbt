// HMAC-SHA-256 vectors from RFC 4231, cross-checked with `openssl dgst`.

///|
/// RFC 4231 test cases 1 and 2, the vectors `hmac-sha2-256` rests on.
test "hmac-sha2-256 RFC 4231 test cases 1 and 2" {
  inspect(
    @hex.encode(
      @crypto.hmac_sha256(@hex.decode("0b".repeat(20))[:], b"Hi There"[:]),
    ),
    content="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  inspect(
    @hex.encode(
      @crypto.hmac_sha256(b"Jefe"[:], b"what do ya want for nothing?"[:]),
    ),
    content="5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
}
