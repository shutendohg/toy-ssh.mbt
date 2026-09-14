// Ed25519 vectors from docs/03 section 5 (RFC 8032 section 7.1).

///|
fn ed_hex(a : FixedArray[Byte]) -> String {
  @hex.encode(@crypto.fixed_to_bytes(a))
}

///|
/// Assert public-key derivation, signing and verification for one vector.
fn check_vector(
  secret_hex : String,
  public_hex : String,
  msg_hex : String,
  sig_hex : String,
) -> Unit raise {
  let secret = @hex.decode(secret_hex)
  let msg = @hex.decode(msg_hex)
  let public = @crypto.ed25519_public_key(secret)
  assert_eq(ed_hex(public), public_hex)
  let sig = @crypto.Ed25519KeyPair::from_seed(secret[:]).sign(msg[:])
  assert_eq(ed_hex(sig), sig_hex)
  assert_true(
    @crypto.ed25519_verify(@hex.decode(public_hex), msg, @hex.decode(sig_hex)),
  )
}

///|
test "ed25519 RFC 8032 TEST 1 (empty message)" {
  check_vector(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  )
}

///|
test "ed25519 RFC 8032 TEST 2 (one byte)" {
  check_vector(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  )
}

///|
test "ed25519 RFC 8032 TEST 3 (two bytes)" {
  check_vector(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "af82", "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  )
}

///|
test "ed25519 RFC 8032 TEST SHA(abc)" {
  // The message is SHA-512("abc") (docs/03 section 1 vector).
  check_vector(
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42", "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
  )
}

///|
test "ed25519 verify rejects a flipped signature bit" {
  let public = @hex.decode(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  )
  let msg = b"\x72"
  let sig = @hex.decode(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  )
  assert_true(@crypto.ed25519_verify(public, msg, sig))
  // Flip one bit in R (byte 0).
  let bad_r = FixedArray::make(64, b'\x00')
  bad_r.blit_from_bytes(0, sig, 0, 64)
  bad_r[0] = bad_r[0] ^ b'\x01'
  assert_false(
    @crypto.ed25519_verify(public, msg, @crypto.fixed_to_bytes(bad_r)),
  )
  // Flip one bit in S (byte 32).
  let bad_s = FixedArray::make(64, b'\x00')
  bad_s.blit_from_bytes(0, sig, 0, 64)
  bad_s[32] = bad_s[32] ^ b'\x01'
  assert_false(
    @crypto.ed25519_verify(public, msg, @crypto.fixed_to_bytes(bad_s)),
  )
}

///|
test "ed25519 verify rejects a flipped message bit" {
  let public = @hex.decode(
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
  )
  let sig = @hex.decode(
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  )
  assert_true(@crypto.ed25519_verify(public, b"\xaf\x82", sig))
  assert_false(@crypto.ed25519_verify(public, b"\xaf\x83", sig))
}

///|
test "ed25519 verify rejects S >= L and malformed inputs" {
  let public = @hex.decode(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  let sig = @hex.decode(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  )
  assert_true(@crypto.ed25519_verify(public, b"", sig))
  // S + L is congruent to S mod L, so a naive verifier would accept it.
  // RFC 8032 section 5.1.7 requires S < L; this must be rejected.
  let l = (1N << 252) + 27742317777372353535851937790883648493N
  let s = @crypto.le_bytes_to_bigint(sig[32:64])
  let s_plus_l = @crypto.bigint_to_le_bytes(s + l, 32)
  let malleable = FixedArray::make(64, b'\x00')
  malleable.blit_from_bytes(0, sig, 0, 32)
  for i in 0..<32 {
    malleable[32 + i] = s_plus_l[i]
  }
  assert_false(
    @crypto.ed25519_verify(public, b"", @crypto.fixed_to_bytes(malleable)),
  )
  // Wrong lengths are rejected, not aborted on.
  assert_false(@crypto.ed25519_verify(public, b"", sig[0:63]))
  assert_false(@crypto.ed25519_verify(public[0:31], b"", sig))
  // A public key whose y-coordinate is not on the curve is rejected
  // (y = 1 with sign bit set: x = 0 is the only root, so x must have sign 0;
  // this encodes a point that cannot be decompressed).
  let bad_pub = FixedArray::make(32, b'\x00')
  bad_pub[0] = b'\x01'
  bad_pub[31] = b'\x80'
  assert_false(
    @crypto.ed25519_verify(@crypto.fixed_to_bytes(bad_pub), b"", sig),
  )
}

///|
test "Ed25519KeyPair: caches the public key and signs like the seed API" {
  // RFC 8032 section 7.1 TEST 1.
  let seed = @hex.decode(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let kp = @crypto.Ed25519KeyPair::from_seed(seed[:])
  inspect(
    @hex.encode(kp.public()[:]),
    content="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  assert_eq(kp.seed(), seed)
  inspect(
    ed_hex(kp.sign(b""[:])),
    content="e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  )
  // Signing twice must not disturb the cached state.
  assert_eq(ed_hex(kp.sign(b"abc"[:])), ed_hex(kp.sign(b"abc"[:])))
}
