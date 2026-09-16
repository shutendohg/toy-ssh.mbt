// The arithmetic layer of ML-KEM-768 (FIPS 203): polynomials over
// Z_3329[X]/(X^256+1), the NTT, byte encoding and coefficient compression.
// Tested by the mathematical properties the spec defines, because FIPS 203
// gives no standalone vectors for these steps; the official KAT covers them
// indirectly once the whole KEM is assembled.

///|
test "the ring parameters are the FIPS 203 values" {
  inspect(@crypto.MLKEM_Q, content="3329")
  inspect(@crypto.MLKEM_N, content="256")
}

///|
test "zeta is a primitive 256th root of unity mod q" {
  // FIPS 203 fixes zeta = 17. Everything in the NTT rests on this, so
  // check the order directly rather than trusting a hard-coded table.
  let mut x = 1
  for _ in 0..<128 {
    x = x * 17 % @crypto.MLKEM_Q
  }
  // zeta^128 == -1 mod q, so zeta has order 256 and not 128.
  inspect(x, content="3328")
  for _ in 0..<128 {
    x = x * 17 % @crypto.MLKEM_Q
  }
  inspect(x, content="1")
}

///|
/// A deterministic polynomial, so the tests do not need randomness.
fn sample_poly(seed : Int) -> FixedArray[Int] {
  let f = FixedArray::make(@crypto.MLKEM_N, 0)
  let mut x = seed
  for i in 0..<@crypto.MLKEM_N {
    x = (x * 1103515245 + 12345) % 2147483647
    f[i] = x.abs() % @crypto.MLKEM_Q
  }
  f
}

///|
test "the inverse NTT undoes the NTT" {
  for seed in [1, 7, 12345] {
    let f = sample_poly(seed)
    let hat = @crypto.mlkem_ntt(f)
    let back = @crypto.mlkem_ntt_inverse(hat)
    for i in 0..<@crypto.MLKEM_N {
      assert_eq(back[i], f[i])
    }
  }
}

///|
test "multiplying in the NTT domain agrees with schoolbook multiplication" {
  // This is the property that makes the NTT worth having, and it catches a
  // wrong zeta ordering, which a round trip alone would not.
  fn schoolbook(f : FixedArray[Int], g : FixedArray[Int]) -> FixedArray[Int] {
    let out = FixedArray::make(@crypto.MLKEM_N, 0)
    for i in 0..<@crypto.MLKEM_N {
      for j in 0..<@crypto.MLKEM_N {
        let k = i + j
        let term = f[i] * g[j] % @crypto.MLKEM_Q
        if k < @crypto.MLKEM_N {
          out[k] = (out[k] + term) % @crypto.MLKEM_Q
        } else {
          // X^256 = -1 in this ring.
          let w = k - @crypto.MLKEM_N
          out[w] = (out[w] - term + @crypto.MLKEM_Q) % @crypto.MLKEM_Q
        }
      }
    }
    out
  }

  let f = sample_poly(3)
  let g = sample_poly(9)
  let want = schoolbook(f, g)
  let got = @crypto.mlkem_ntt_inverse(
    @crypto.mlkem_multiply_ntt(@crypto.mlkem_ntt(f), @crypto.mlkem_ntt(g)),
  )
  for i in 0..<@crypto.MLKEM_N {
    assert_eq(got[i], want[i])
  }
}

///|
test "byte encoding round-trips at every width ML-KEM-768 uses" {
  // d = 12 for the key, 10 for u, 4 for v, 1 for the message.
  for d in [1, 4, 10, 12] {
    let limit = if d == 12 { @crypto.MLKEM_Q } else { 1 << d }
    let f = FixedArray::make(@crypto.MLKEM_N, 0)
    for i in 0..<@crypto.MLKEM_N {
      f[i] = i % limit
    }
    let bytes = @crypto.mlkem_byte_encode(f, d)
    assert_eq(bytes.length(), 32 * d)
    let back = @crypto.mlkem_byte_decode(bytes[:], d)
    for i in 0..<@crypto.MLKEM_N {
      assert_eq(back[i], f[i])
    }
  }
}

///|
test "compression loses only the low bits it is meant to" {
  // FIPS 203: Decompress(Compress(x)) is within q/2^(d+1) of x.
  for d in [10, 4] {
    let bound = @crypto.MLKEM_Q / (1 << (d + 1)) + 1
    for x in [0, 1, 832, 1664, 2496, 3328] {
      let y = @crypto.mlkem_compress(x, d)
      assert_true(y >= 0 && y < 1 << d)
      let back = @crypto.mlkem_decompress(y, d)
      let diff = if back > x { back - x } else { x - back }
      let wrapped = if diff > @crypto.MLKEM_Q / 2 {
        @crypto.MLKEM_Q - diff
      } else {
        diff
      }
      assert_true(wrapped <= bound)
    }
  }
  // d = 1 is the message bit: 0 stays 0, and anything near q/2 becomes 1.
  inspect(@crypto.mlkem_compress(0, 1), content="0")
  inspect(@crypto.mlkem_compress(1664, 1), content="1")
  inspect(@crypto.mlkem_decompress(1, 1), content="1665")
  inspect(@crypto.mlkem_decompress(0, 1), content="0")
}
