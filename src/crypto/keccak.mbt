///|
/// Keccak-f[1600] and the FIPS 202 functions this project needs:
/// SHA3-256, SHA3-512, SHAKE128 and SHAKE256, plus an incremental
/// SHAKE128 squeeze for ML-KEM's rejection sampling.
///
/// `moonbitlang/x/crypto` has no SHA-3 or SHAKE (it stops at the SHA-1 /
/// SHA-2 family), so the sponge is built by hand here. The reference is
/// FIPS 202 (SHA-3 Standard: Permutation-Based Hash and Extendable-Output
/// Functions, August 2015): the permutation is section 3.2 / 3.4, the
/// sponge and the `pad10*1` rule are section 5, and the domain-separation
/// suffixes are section 6.
///
/// Toy code: not constant-time and not hardened. Never use for real
/// security.

///|
/// Round constants of Keccak-f[1600] (FIPS 202 section 3.2.5). These are
/// the 24 standard values of `RC[i]`, produced by the section 3.2.5 LFSR
/// and hard-coded here.
let keccak_round_constants : FixedArray[UInt64] = [
  0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
  0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
  0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
  0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
  0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
  0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
]

///|
/// Rotation offsets of the rho step (FIPS 202 section 3.2.2), indexed by
/// the flattened lane index `x + 5 * y`. Lane (0, 0) has offset 0, which
/// `rotl64` special-cases.
let keccak_rho_offsets : FixedArray[Int] = [
  0, 1, 62, 28, 27, // y = 0
   36, 44, 6, 55, 20, // y = 1
   3, 10, 43, 25, 39, // y = 2
   41, 45, 15, 21, 8, // y = 3
   18, 2, 61, 56, 14, // y = 4
]

///|
/// Rotate a 64-bit lane left by `n` bits, `0 <= n < 64`. `n == 0` is
/// special-cased: the naive expression would shift by 64, which is not
/// defined uniformly across backends.
fn rotl64(x : UInt64, n : Int) -> UInt64 {
  if n == 0 {
    x
  } else {
    (x << n) | (x >> (64 - n))
  }
}

///|
/// The Keccak-f[1600] permutation, in place on 25 lanes of 64 bits
/// flattened as `x + 5 * y` (FIPS 202 section 3.4, 24 rounds). The two
/// scratch arrays are allocated once per call and reused across rounds.
fn keccak_f1600(a : FixedArray[UInt64]) -> Unit {
  let c = FixedArray::make(5, 0UL)
  let b = FixedArray::make(25, 0UL)
  for round in 0..<24 {
    // theta: C[x] = column parity, D[x] = C[x-1] ^ rotl(C[x+1], 1).
    for x in 0..<5 {
      c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
    }
    for x in 0..<5 {
      let d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1)
      for y in 0..<5 {
        a[x + 5 * y] = a[x + 5 * y] ^ d
      }
    }
    // rho and pi combined: B[x, y] = rotl(A[(x + 3y) mod 5, x], r[...]).
    for y in 0..<5 {
      for x in 0..<5 {
        let src = (x + 3 * y) % 5 + 5 * x
        b[x + 5 * y] = rotl64(a[src], keccak_rho_offsets[src])
      }
    }
    // chi: A[x, y] = B[x, y] ^ (~B[x+1, y] & B[x+2, y]).
    for y in 0..<5 {
      for x in 0..<5 {
        a[x + 5 * y] = b[x + 5 * y] ^
          (b[(x + 1) % 5 + 5 * y].lnot() & b[(x + 2) % 5 + 5 * y])
      }
    }
    // iota
    a[0] = a[0] ^ keccak_round_constants[round]
  }
}

///|
/// XOR one full rate block of `rate` bytes from `block` into the state.
/// Every rate used here is a multiple of 8, so blocks are lane-aligned and
/// each lane takes 8 consecutive little-endian bytes.
fn keccak_xor_block(
  a : FixedArray[UInt64],
  block : FixedArray[Byte],
  rate : Int,
) -> Unit {
  for lane in 0..<(rate / 8) {
    let mut v = 0UL
    for i in 0..<8 {
      v = v | (block[lane * 8 + i].to_uint64() << (8 * i))
    }
    a[lane] = a[lane] ^ v
  }
}

///|
/// Absorb all of `data` into the state, then apply the `pad10*1` padding
/// with the domain-separation suffix `suffix` (FIPS 202 sections 5.1 and
/// 6): `0x06` for SHA-3, `0x1f` for SHAKE. The state is left permuted, so
/// a first rate block of output is immediately available.
fn keccak_absorb(
  a : FixedArray[UInt64],
  data : BytesView,
  rate : Int,
  suffix : Byte,
) -> Unit {
  let block = FixedArray::make(rate, b'\x00')
  let n = data.length()
  let mut off = 0
  while n - off >= rate {
    for i in 0..<rate {
      block[i] = data[off + i]
    }
    keccak_xor_block(a, block, rate)
    keccak_f1600(a)
    off += rate
  }
  // Final, short block: the remaining bytes, the suffix, zeros, and the
  // high bit of the last byte. When only one byte is left over, the suffix
  // and that high bit land on the same byte (0x86 / 0x9f).
  let rest = n - off
  for i in 0..<rate {
    block[i] = b'\x00'
  }
  for i in 0..<rest {
    block[i] = data[off + i]
  }
  block[rest] = suffix
  block[rate - 1] = block[rate - 1] | b'\x80'
  keccak_xor_block(a, block, rate)
  keccak_f1600(a)
}

///|
/// Squeeze `n` bytes into `out` starting at `out_off`, resuming at byte
/// `pos` of the current rate block, and return the new position. The state
/// is permuted again whenever a block is exhausted (FIPS 202 section 5.2).
fn keccak_squeeze(
  a : FixedArray[UInt64],
  rate : Int,
  pos : Int,
  out : FixedArray[Byte],
  out_off : Int,
  n : Int,
) -> Int {
  let mut p = pos
  for i in 0..<n {
    if p == rate {
      keccak_f1600(a)
      p = 0
    }
    out[out_off + i] = (a[p / 8] >> (8 * (p % 8))).to_byte()
    p += 1
  }
  p
}

///|
/// One-shot sponge: absorb `data` with the given `rate` and domain
/// `suffix`, then squeeze `out_len` bytes.
fn keccak_sponge(
  data : BytesView,
  rate : Int,
  suffix : Byte,
  out_len : Int,
) -> FixedArray[Byte] {
  let a = FixedArray::make(25, 0UL)
  keccak_absorb(a, data, rate, suffix)
  let out = FixedArray::make(out_len, b'\x00')
  keccak_squeeze(a, rate, 0, out, 0, out_len) |> ignore
  out
}

///|
/// SHA3-256 (FIPS 202): 32-byte digest. Rate 136 bytes, domain suffix
/// `0x06`.
pub fn sha3_256(data : BytesView) -> FixedArray[Byte] {
  keccak_sponge(data, 136, b'\x06', 32)
}

///|
/// SHA3-512 (FIPS 202): 64-byte digest. Rate 72 bytes, domain suffix
/// `0x06`.
pub fn sha3_512(data : BytesView) -> FixedArray[Byte] {
  keccak_sponge(data, 72, b'\x06', 64)
}

///|
/// SHAKE128 (FIPS 202) extendable output: `out_len` bytes. Rate 168 bytes,
/// domain suffix `0x1f`. A negative `out_len` is a programming error and
/// aborts.
pub fn shake128(data : BytesView, out_len : Int) -> FixedArray[Byte] {
  guard out_len >= 0 else { abort("shake128: out_len must not be negative") }
  keccak_sponge(data, SHAKE128_RATE, b'\x1f', out_len)
}

///|
/// SHAKE256 (FIPS 202) extendable output: `out_len` bytes. Rate 136 bytes,
/// domain suffix `0x1f`. A negative `out_len` is a programming error and
/// aborts.
pub fn shake256(data : BytesView, out_len : Int) -> FixedArray[Byte] {
  guard out_len >= 0 else { abort("shake256: out_len must not be negative") }
  keccak_sponge(data, 136, b'\x1f', out_len)
}

///|
/// SHAKE128's rate in bytes (1600 bits of state minus 256 bits of
/// capacity).
const SHAKE128_RATE : Int = 168

///|
/// An incremental SHAKE128 squeeze. ML-KEM's `SampleNTT` absorbs a 34-byte
/// seed and then keeps pulling three bytes at a time until it has enough
/// coefficients below q, so it cannot say up front how much output it
/// needs. Successive `squeeze` calls produce exactly the byte stream that
/// one `shake128` call of the total length would.
///
/// The fields are not writable outside this package; use `Shake128::new`.
pub struct Shake128 {
  state : FixedArray[UInt64]
  mut pos : Int
}

///|
/// Absorb `data` and return a sponge ready to be squeezed.
pub fn Shake128::new(data : BytesView) -> Shake128 {
  let state = FixedArray::make(25, 0UL)
  keccak_absorb(state, data, SHAKE128_RATE, b'\x1f')
  { state, pos: 0, }
}

///|
/// Squeeze the next `n` bytes of output. Callable repeatedly. A negative
/// `n` is a programming error and aborts.
pub fn Shake128::squeeze(self : Shake128, n : Int) -> FixedArray[Byte] {
  guard n >= 0 else { abort("Shake128::squeeze: n must not be negative") }
  let out = FixedArray::make(n, b'\x00')
  self.pos = keccak_squeeze(self.state, SHAKE128_RATE, self.pos, out, 0, n)
  out
}
