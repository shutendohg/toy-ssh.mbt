// Smoke tests for the primitives reused from moonbitlang/x/crypto
// (SHA-256, SHA-512, ChaCha20). These pin the library behaviour the
// transport layer will rely on; see docs/03.

///|
test "x/crypto sha256 of abc" {
  let d = @xcrypto.sha256(b"abc")
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(d)),
    content="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
test "x/crypto sha512 vectors (docs/03 section 1)" {
  let empty = @xcrypto.sha512(b"")
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(empty)),
    content="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
  let abc = @xcrypto.sha512(b"abc")
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(abc)),
    content="ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
  let two_blocks = @xcrypto.sha512(
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(two_blocks)),
    content="204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
  )
}

///|
test "x/crypto chacha20 reproduces RFC 8439 section 2.4.2 ciphertext" {
  let key = @hex.decode(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = @hex.decode("000000000000004a00000000")
  let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
  let cipher = @xcrypto.ChaCha::chacha20(key, nonce, counter=1)
  let out = FixedArray::make(plaintext.length(), b'\x00')
  cipher.transform(plaintext, out)
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(out)),
    content="6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
  )
}
