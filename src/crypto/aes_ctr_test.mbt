// AES-128-CTR vectors from NIST SP 800-38A section F.5.1 (CTR-AES128.Encrypt),
// re-verified against `openssl enc -aes-128-ctr` before they were written down.

///|
let ctr_key : String = "2b7e151628aed2a6abf7158809cf4f3c"

///|
let ctr_iv : String = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

///|
let ctr_plain : String = "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710"

///|
let ctr_cipher : String = "874d6191b620e3261bef6864990db6ce" +
  "9806f66b7970fdff8617187bb9fffdff" +
  "5ae4df3edbd5d35e5b4f09020db03eab" +
  "1e031dda2fbe03d1792170a0f3009cee"

///|
test "aes128-ctr NIST SP 800-38A F.5.1 encrypt" {
  let out = @crypto.aes128_ctr(
    @hex.decode(ctr_key)[:],
    @hex.decode(ctr_iv)[:],
    @hex.decode(ctr_plain)[:],
  )
  inspect(@hex.encode(out), content=ctr_cipher)
}

///|
test "aes128-ctr decrypt is the same keystream" {
  let out = @crypto.aes128_ctr(
    @hex.decode(ctr_key)[:],
    @hex.decode(ctr_iv)[:],
    @hex.decode(ctr_cipher)[:],
  )
  inspect(@hex.encode(out), content=ctr_plain)
}

///|
test "aes128-ctr resuming at an advanced counter matches one long call" {
  let key = @hex.decode(ctr_key)
  let iv = @hex.decode(ctr_iv)
  let plain = @hex.decode(ctr_plain)
  // Two blocks, then the remaining two from a counter advanced by two:
  // this is exactly how the record layer chains packets.
  let first = @crypto.aes128_ctr(key[:], iv[:], plain[0:32])
  let second = @crypto.aes128_ctr(
    key[:],
    @crypto.ctr_advance(iv[:], 2)[:],
    plain[32:],
  )
  inspect(@hex.encode(first) + @hex.encode(second), content=ctr_cipher)
}

///|
test "ctr_advance carries across the whole 128-bit block" {
  // 2^128 - 1, advanced by one, wraps to zero.
  inspect(
    @hex.encode(@crypto.ctr_advance(@hex.decode("ff".repeat(16))[:], 1)),
    content="00000000000000000000000000000000",
  )
  // A carry out of the low 64 bits.
  inspect(
    @hex.encode(
      @crypto.ctr_advance(@hex.decode("0000000000000000ffffffffffffffff")[:], 3),
    ),
    content="00000000000000010000000000000002",
  )
}
