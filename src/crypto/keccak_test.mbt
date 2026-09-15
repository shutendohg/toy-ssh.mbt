// FIPS 202 vectors for SHA3-256, SHA3-512, SHAKE128 and SHAKE256.
//
// Provenance of every expected value below:
//   - The empty-input and "abc" digests, and the 32-byte SHAKE outputs for
//     the empty input, are the published FIPS 202 / NIST example values.
//   - Every other value (the multi-block inputs, the rate-boundary inputs,
//     the long SHAKE outputs, the 34-byte-seed stream) was generated with
//     Python's hashlib, which wraps the Keccak reference implementation:
//     `python3 -c 'import hashlib; print(hashlib.sha3_256(b"...").hexdigest())'`
//     and `hashlib.shake_128(b"...").hexdigest(n)`.
// No expected value here came from this MoonBit code.

///|
/// `n` copies of the ASCII byte `a`, used for the multi-block and
/// rate-boundary inputs.
fn repeat_a(n : Int) -> Bytes {
  @crypto.fixed_to_bytes(FixedArray::make(n, b'a'))
}

///|
test "sha3_256 FIPS 202 example digests" {
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.sha3_256(b""))),
    content="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.sha3_256(b"abc"))),
    content="3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
  )
}

///|
test "sha3_256 of a multi-block input (200 bytes > rate 136)" {
  // hashlib: sha3_256(b"a" * 200)
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.sha3_256(repeat_a(200)))),
    content="cce34485baf2bf2aca99b94833892a4f52896d3d153f7b840cc4f9fe695f1387",
  )
}

///|
test "sha3_256 around its 136-byte rate block" {
  // One byte short of the rate: the suffix and the final high bit share a
  // byte. Exactly the rate: the padding needs a whole extra block.
  // hashlib: sha3_256(b"a" * 135 / 136 / 137)
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.sha3_256(repeat_a(135)))),
    content="8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.sha3_256(repeat_a(136)))),
    content="3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.sha3_256(repeat_a(137)))),
    content="f8d6846cedd2ccfadf15c5879ef95af724d799eed7391fb1c91f95344e738614",
  )
}

///|
test "sha3_512 FIPS 202 example digests" {
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.sha3_512(b""))),
    content="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.sha3_512(b"abc"))),
    content="b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
  )
}

///|
test "shake128 and shake256 of the empty input (32 bytes)" {
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.shake128(b"", 32))),
    content="7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.shake256(b"", 32))),
    content="46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
  )
}

///|
test "shake128 and shake256 of \"abc\" (32 bytes)" {
  // hashlib: shake_128(b"abc").hexdigest(32), shake_256(b"abc").hexdigest(32)
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.shake128(b"abc", 32))),
    content="5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.shake256(b"abc", 32))),
    content="483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
  )
}

///|
test "shake128 around its 168-byte rate block" {
  // hashlib: shake_128(b"a" * 167 / 168 / 169).hexdigest(32)
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.shake128(repeat_a(167), 32))),
    content="4f5c6c53ae8190a8ff8a55b2125d28703052d10278570960c2066a905d916c34",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.shake128(repeat_a(168), 32))),
    content="c22e11586c22b713bde373fce93314d76829de2c21d940a28eb659b8dec953a2",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@crypto.shake128(repeat_a(169), 32))),
    content="09fc23f3acfd944380db0c7f5b1bde62d3a43c6e4c61ca9cb3dfee54904b36a8",
  )
}

///|
test "shake128 squeezes past one rate block (200 bytes)" {
  // hashlib: shake_128(b"").hexdigest(200) — the full 200 bytes, so the
  // permutation between output blocks is checked, not just the first one.
  let out = @crypto.shake128(b"", 200)
  assert_eq(out.length(), 200)
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(out)),
    content="7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f877",
  )
}

///|
test "shake128 long output (512 bytes, 4 rate blocks)" {
  // No published FIPS 202 vector covers 512 bytes of output, so this pins
  // the length plus the first and last 32 bytes against
  // hashlib: shake_128(b"").hexdigest(512).
  let out = @crypto.shake128(b"", 512)
  assert_eq(out.length(), 512)
  let head = FixedArray::make(32, b'\x00')
  let tail = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    head[i] = out[i]
    tail[i] = out[512 - 32 + i]
  }
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(head)),
    content="7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(tail)),
    content="43e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f",
  )
}

///|
test "Shake128 incremental squeeze matches one long shake128 call" {
  // A 34-byte seed, the shape ML-KEM's SampleNTT absorbs.
  let seed = @hex.decode(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
  )
  let one_shot = @crypto.shake128(seed, 200)

  // 200 single-byte squeezes, which crosses the 168-byte rate boundary.
  let sponge = @crypto.Shake128::new(seed)
  let byte_at_a_time = FixedArray::make(200, b'\x00')
  for i in 0..<200 {
    let chunk = sponge.squeeze(1)
    assert_eq(chunk.length(), 1)
    byte_at_a_time[i] = chunk[0]
  }
  assert_eq(
    @hex.encode(@crypto.fixed_to_bytes(byte_at_a_time)),
    @hex.encode(@crypto.fixed_to_bytes(one_shot)),
  )

  // Three bytes at a time, the way SampleNTT actually pulls, plus an
  // uneven remainder so the chunk size does not divide the rate.
  let sponge3 = @crypto.Shake128::new(seed)
  let by_threes = FixedArray::make(200, b'\x00')
  let mut off = 0
  while off < 198 {
    let chunk = sponge3.squeeze(3)
    for i in 0..<3 {
      by_threes[off + i] = chunk[i]
    }
    off += 3
  }
  let last = sponge3.squeeze(2)
  by_threes[198] = last[0]
  by_threes[199] = last[1]
  assert_eq(
    @hex.encode(@crypto.fixed_to_bytes(by_threes)),
    @hex.encode(@crypto.fixed_to_bytes(one_shot)),
  )

  // And the stream itself, against hashlib: shake_128(seed).hexdigest(200).
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(one_shot)),
    content="42b3c5cbdc45441a59489b99a72a74fb0cb4c1a2b0182aeb5f48f925d8eee07c25f0a91e8dc67d9b662bb680e7752e23dabcf03f6b239ccb0c16479a42bb3fe1885bbae558ca2124a98f8f3d3f6d043e63e331f3a3c90b98a789161262d8b8b9098107fdb355390a186aef7783cb5c99db3f061588b4936439f55083011f1c16a3ee6ff0946da9011aa4c733d076842fb28de18befc062a81bef7da5835fbd6c8d009639833727e43f9c5fd56de35c29efa2faec0c126c063e06ba87d4fd2542959d24fb34265c54",
  )
}

///|
test "Shake128 zero-length squeeze is a no-op" {
  let sponge = @crypto.Shake128::new(b"")
  assert_eq(sponge.squeeze(0).length(), 0)
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(sponge.squeeze(32))),
    content="7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  )
  assert_eq(@crypto.shake128(b"", 0).length(), 0)
}
