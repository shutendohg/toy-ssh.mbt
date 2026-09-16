///|
/// The arithmetic layer of ML-KEM-768 (FIPS 203): polynomials over
/// Z_q[X]/(X^256+1) with q = 3329, the number-theoretic transform, byte
/// encoding at the widths the scheme uses, and coefficient compression.
///
/// The sampling and hashing steps (SampleNTT, SamplePolyCBD, G/H/J/PRF)
/// live with the KEM itself, because they need SHAKE.
///
/// Toy code. Never use for real security: nothing here is constant-time,
/// and the coefficient arithmetic uses plain `Int` division rather than
/// Montgomery or Barrett reduction, which is clearer and slower.

///|
/// The ML-KEM modulus (FIPS 203 section 2.3).
pub const MLKEM_Q : Int = 3329

///|
/// Coefficients per polynomial.
pub const MLKEM_N : Int = 256

///|
/// FIPS 203 fixes this primitive 256th root of unity mod q.
const MLKEM_ZETA : Int = 17

///|
/// `a + b` and `a - b` in Z_q, for inputs already reduced.
fn q_add(a : Int, b : Int) -> Int {
  let s = a + b
  if s >= MLKEM_Q {
    s - MLKEM_Q
  } else {
    s
  }
}

///|
fn q_sub(a : Int, b : Int) -> Int {
  let d = a - b
  if d < 0 {
    d + MLKEM_Q
  } else {
    d
  }
}

///|
fn q_mul(a : Int, b : Int) -> Int {
  a * b % MLKEM_Q
}

///|
/// `base^exp mod q` by square and multiply.
fn q_pow(base : Int, exp : Int) -> Int {
  let mut result = 1
  let mut b = base % MLKEM_Q
  let mut e = exp
  while e > 0 {
    if e % 2 == 1 {
      result = q_mul(result, b)
    }
    b = q_mul(b, b)
    e = e / 2
  }
  result
}

///|
/// Reverse the low 7 bits, which is the order FIPS 203 stores the zetas in.
fn bit_reverse_7(i : Int) -> Int {
  let mut out = 0
  for b in 0..<7 {
    if ((i >> b) & 1) == 1 {
      out = out | (1 << (6 - b))
    }
  }
  out
}

///|
/// `zeta^BitRev7(i)` for i in 0..<128 (FIPS 203 Algorithm 9's table).
///
/// Computed rather than pasted: a wrong entry in a hand-copied table shows
/// up only as garbage far downstream, while this is checked by the order
/// of zeta and by the multiplication property in the tests.
let mlkem_zetas : FixedArray[Int] = {
  let t = FixedArray::make(128, 0)
  for i in 0..<128 {
    t[i] = q_pow(MLKEM_ZETA, bit_reverse_7(i))
  }
  t
}

///|
/// The number-theoretic transform (FIPS 203 Algorithm 9). Takes a
/// polynomial's 256 coefficients and returns its NTT representation.
pub fn mlkem_ntt(f : FixedArray[Int]) -> FixedArray[Int] {
  guard f.length() == MLKEM_N else {
    abort("mlkem_ntt: expected \{MLKEM_N} coefficients")
  }
  let out = FixedArray::make(MLKEM_N, 0)
  for i in 0..<MLKEM_N {
    out[i] = f[i]
  }
  let mut len = 128
  let mut k = 1
  while len >= 2 {
    let mut start = 0
    while start < MLKEM_N {
      let zeta = mlkem_zetas[k]
      k = k + 1
      for j = start; j < start + len; j = j + 1 {
        let t = q_mul(zeta, out[j + len])
        out[j + len] = q_sub(out[j], t)
        out[j] = q_add(out[j], t)
      }
      start = start + 2 * len
    }
    len = len / 2
  }
  out
}

///|
/// The inverse transform (FIPS 203 Algorithm 10).
pub fn mlkem_ntt_inverse(f : FixedArray[Int]) -> FixedArray[Int] {
  guard f.length() == MLKEM_N else {
    abort("mlkem_ntt_inverse: expected \{MLKEM_N} coefficients")
  }
  let out = FixedArray::make(MLKEM_N, 0)
  for i in 0..<MLKEM_N {
    out[i] = f[i]
  }
  let mut len = 2
  let mut k = 127
  while len <= 128 {
    let mut start = 0
    while start < MLKEM_N {
      let zeta = mlkem_zetas[k]
      k = k - 1
      for j = start; j < start + len; j = j + 1 {
        let t = out[j]
        out[j] = q_add(t, out[j + len])
        out[j + len] = q_mul(zeta, q_sub(out[j + len], t))
      }
      start = start + 2 * len
    }
    len = len * 2
  }
  // Multiply by 128^-1 mod q (FIPS 203 uses the constant 3303).
  for i in 0..<MLKEM_N {
    out[i] = q_mul(out[i], 3303)
  }
  out
}

///|
/// One degree-2 product in the NTT domain (FIPS 203 Algorithm 12).
fn base_case_multiply(
  a0 : Int,
  a1 : Int,
  b0 : Int,
  b1 : Int,
  gamma : Int,
) -> (Int, Int) {
  let c0 = q_add(q_mul(a0, b0), q_mul(q_mul(a1, b1), gamma))
  let c1 = q_add(q_mul(a0, b1), q_mul(a1, b0))
  (c0, c1)
}

///|
/// Multiply two polynomials in the NTT domain (FIPS 203 Algorithm 11).
pub fn mlkem_multiply_ntt(
  f : FixedArray[Int],
  g : FixedArray[Int],
) -> FixedArray[Int] {
  guard f.length() == MLKEM_N && g.length() == MLKEM_N else {
    abort("mlkem_multiply_ntt: expected \{MLKEM_N} coefficients")
  }
  let out = FixedArray::make(MLKEM_N, 0)
  for i in 0..<128 {
    // gamma = zeta^(2*BitRev7(i)+1)
    let gamma = q_mul(mlkem_zetas[i], mlkem_zetas[i]) |> q_mul(MLKEM_ZETA)
    let (c0, c1) = base_case_multiply(
      f[2 * i],
      f[2 * i + 1],
      g[2 * i],
      g[2 * i + 1],
      gamma,
    )
    out[2 * i] = c0
    out[2 * i + 1] = c1
  }
  out
}

///|
/// Pack 256 `d`-bit integers into 32*d bytes (FIPS 203 Algorithm 5).
pub fn mlkem_byte_encode(f : FixedArray[Int], d : Int) -> Bytes {
  guard f.length() == MLKEM_N && d >= 1 && d <= 12 else {
    abort("mlkem_byte_encode: bad input")
  }
  let out = FixedArray::make(32 * d, b'\x00')
  let mut bit = 0
  for i in 0..<MLKEM_N {
    let v = f[i]
    for b in 0..<d {
      if ((v >> b) & 1) == 1 {
        let byte = bit / 8
        out[byte] = out[byte] | (1 << (bit % 8)).to_byte()
      }
      bit = bit + 1
    }
  }
  Bytes::from_iter(out.iter())
}

///|
/// Unpack 32*d bytes into 256 `d`-bit integers (FIPS 203 Algorithm 6).
/// For d = 12 the values are reduced mod q, as the spec's ByteDecode does.
pub fn mlkem_byte_decode(data : BytesView, d : Int) -> FixedArray[Int] {
  guard data.length() == 32 * d && d >= 1 && d <= 12 else {
    abort("mlkem_byte_decode: bad input")
  }
  let out = FixedArray::make(MLKEM_N, 0)
  let mut bit = 0
  for i in 0..<MLKEM_N {
    let mut v = 0
    for b in 0..<d {
      let byte = data[bit / 8].to_int()
      if ((byte >> (bit % 8)) & 1) == 1 {
        v = v | (1 << b)
      }
      bit = bit + 1
    }
    out[i] = if d == 12 { v % MLKEM_Q } else { v }
  }
  out
}

///|
/// Compress a coefficient to `d` bits (FIPS 203 section 4.2.1): round
/// `x * 2^d / q` to the nearest integer, mod 2^d.
pub fn mlkem_compress(x : Int, d : Int) -> Int {
  guard d >= 1 && d <= 12 else { abort("mlkem_compress: bad width") }
  // Rounding half up, done in integers: (x * 2^(d+1) + q) / (2 * q).
  let numerator = x * (1 << (d + 1)) + MLKEM_Q
  numerator / (2 * MLKEM_Q) % (1 << d)
}

///|
/// The matching decompression: round `y * q / 2^d`.
pub fn mlkem_decompress(y : Int, d : Int) -> Int {
  guard d >= 1 && d <= 12 else { abort("mlkem_decompress: bad width") }
  (y * MLKEM_Q * 2 + (1 << d)) / (1 << (d + 1))
}
