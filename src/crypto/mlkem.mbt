///|
/// ML-KEM-768 (FIPS 203), the key encapsulation half of the
/// `mlkem768x25519-sha256` key exchange.
///
/// Parameters for the 768 variant: k = 3 polynomials, eta1 = eta2 = 2,
/// du = 10 and dv = 4 bits of compression. The arithmetic lives in
/// `mlkem_poly.mbt`; the sampling and hashing here need SHAKE, from
/// `keccak.mbt`.
///
/// The seeded, deterministic forms are what this exposes: the caller
/// supplies the randomness, which keeps the whole scheme testable and
/// keeps this package free of IO, matching the rest of `crypto`.
///
/// Toy code. Never use for real security. Nothing here is constant-time,
/// and a real implementation would also reject malformed encapsulation
/// keys by re-encoding them (FIPS 203 section 7.2's "modulus check"),
/// which this does — see `mlkem768_encaps`.

///|
/// Polynomials per vector.
const MLKEM768_K : Int = 3

///|
/// The CBD parameter for both the secret and the error polynomials.
const MLKEM768_ETA : Int = 2

///|
/// Compression width for `u`.
const MLKEM768_DU : Int = 10

///|
/// Compression width for `v`.
const MLKEM768_DV : Int = 4

///|
/// Bytes in an encoded 12-bit polynomial: 256 * 12 / 8.
const MLKEM_POLY_BYTES : Int = 384

///|
/// Encapsulation key: `ByteEncode12(t_hat)` for k polynomials, then rho.
pub const MLKEM768_ENCAPS_KEY_LEN : Int = 1184

///|
/// Decapsulation key: the PKE key, the encapsulation key, its hash, and z.
pub const MLKEM768_DECAPS_KEY_LEN : Int = 2400

///|
/// Ciphertext: 32 * (du * k + dv).
pub const MLKEM768_CIPHERTEXT_LEN : Int = 1088

///|
pub const MLKEM768_SHARED_SECRET_LEN : Int = 32

// ---------------------------------------------------------------------------
// FIPS 203 section 4.1: the hash and PRF wrappers
// ---------------------------------------------------------------------------

///|
/// `G(c) = SHA3-512(c)`, split into two 32-byte halves.
fn mlkem_g(data : BytesView) -> (Bytes, Bytes) {
  let h = fixed_to_bytes(sha3_512(data))
  (h[0:32].to_owned(), h[32:64].to_owned())
}

///|
/// `H(c) = SHA3-256(c)`.
fn mlkem_h(data : BytesView) -> Bytes {
  fixed_to_bytes(sha3_256(data))
}

///|
/// `J(c) = SHAKE256(c, 32)`, the implicit-rejection hash.
fn mlkem_j(data : BytesView) -> Bytes {
  fixed_to_bytes(shake256(data, 32))
}

///|
/// `PRF_eta(s, b) = SHAKE256(s || b, 64 * eta)`.
fn mlkem_prf(s : BytesView, b : Byte, eta : Int) -> Bytes {
  let input = s.to_owned() + Bytes::make(1, b)
  fixed_to_bytes(shake256(input[:], 64 * eta))
}

// ---------------------------------------------------------------------------
// FIPS 203 Algorithms 7 and 8: sampling
// ---------------------------------------------------------------------------

///|
/// `SampleNTT` (Algorithm 7): rejection-sample a polynomial already in the
/// NTT domain from a 34-byte seed. Three squeezed bytes yield two
/// candidate coefficients; each is kept only if it is below q, which is
/// why the squeeze has to be incremental.
fn mlkem_sample_ntt(seed : BytesView) -> FixedArray[Int] {
  let xof = Shake128::new(seed)
  let a = FixedArray::make(MLKEM_N, 0)
  let mut j = 0
  while j < MLKEM_N {
    let c = xof.squeeze(3)
    let c0 = c[0].to_int()
    let c1 = c[1].to_int()
    let c2 = c[2].to_int()
    let d1 = c0 + 256 * (c1 % 16)
    let d2 = c1 / 16 + 16 * c2
    if d1 < MLKEM_Q {
      a[j] = d1
      j = j + 1
    }
    if d2 < MLKEM_Q && j < MLKEM_N {
      a[j] = d2
      j = j + 1
    }
  }
  a
}

///|
/// `SamplePolyCBD_eta` (Algorithm 8): a centred binomial distribution,
/// read as 2*eta bits per coefficient from `bytes`.
fn mlkem_sample_cbd(data : BytesView, eta : Int) -> FixedArray[Int] {
  guard data.length() == 64 * eta else {
    abort("mlkem_sample_cbd: expected \{64 * eta} bytes")
  }
  let f = FixedArray::make(MLKEM_N, 0)
  for i in 0..<MLKEM_N {
    let mut x = 0
    let mut y = 0
    for b in 0..<eta {
      let bit = 2 * i * eta + b
      if ((data[bit / 8].to_int() >> (bit % 8)) & 1) == 1 {
        x = x + 1
      }
    }
    for b in 0..<eta {
      let bit = 2 * i * eta + eta + b
      if ((data[bit / 8].to_int() >> (bit % 8)) & 1) == 1 {
        y = y + 1
      }
    }
    f[i] = (x - y + MLKEM_Q) % MLKEM_Q
  }
  f
}

// ---------------------------------------------------------------------------
// Vector and matrix helpers
// ---------------------------------------------------------------------------

///|
/// `A_hat[i][j] = SampleNTT(rho || j || i)`. The byte order of the two
/// indices is the classic transposition trap: it is `j` then `i`.
fn mlkem_expand_matrix(rho : BytesView) -> Array[Array[FixedArray[Int]]] {
  let a = []
  for i in 0..<MLKEM768_K {
    let row = []
    for j in 0..<MLKEM768_K {
      let seed = rho.to_owned() +
        Bytes::make(1, j.to_byte()) +
        Bytes::make(1, i.to_byte())
      row.push(mlkem_sample_ntt(seed[:]))
    }
    a.push(row)
  }
  a
}

///|
/// Coefficient-wise sum in Z_q.
fn poly_add(f : FixedArray[Int], g : FixedArray[Int]) -> FixedArray[Int] {
  let out = FixedArray::make(MLKEM_N, 0)
  for i in 0..<MLKEM_N {
    out[i] = q_add(f[i], g[i])
  }
  out
}

///|
fn poly_sub(f : FixedArray[Int], g : FixedArray[Int]) -> FixedArray[Int] {
  let out = FixedArray::make(MLKEM_N, 0)
  for i in 0..<MLKEM_N {
    out[i] = q_sub(f[i], g[i])
  }
  out
}

///|
/// Encode k polynomials at `d` bits each.
fn encode_vector(v : Array[FixedArray[Int]], d : Int) -> Bytes {
  let mut out = b""
  for f in v {
    out = out + mlkem_byte_encode(f, d)
  }
  out
}

///|
/// The inverse of `encode_vector`.
fn decode_vector(data : BytesView, d : Int) -> Array[FixedArray[Int]] {
  let v = []
  for i in 0..<MLKEM768_K {
    v.push(mlkem_byte_decode(data[i * 32 * d:(i + 1) * 32 * d], d))
  }
  v
}

///|
/// Compress every coefficient of every polynomial.
fn compress_vector(
  v : Array[FixedArray[Int]],
  d : Int,
) -> Array[FixedArray[Int]] {
  let out = []
  for f in v {
    let g = FixedArray::make(MLKEM_N, 0)
    for i in 0..<MLKEM_N {
      g[i] = mlkem_compress(f[i], d)
    }
    out.push(g)
  }
  out
}

///|
fn decompress_vector(
  v : Array[FixedArray[Int]],
  d : Int,
) -> Array[FixedArray[Int]] {
  let out = []
  for f in v {
    let g = FixedArray::make(MLKEM_N, 0)
    for i in 0..<MLKEM_N {
      g[i] = mlkem_decompress(f[i], d)
    }
    out.push(g)
  }
  out
}

// ---------------------------------------------------------------------------
// FIPS 203 Algorithms 13-15: K-PKE
// ---------------------------------------------------------------------------

///|
/// `K-PKE.KeyGen` (Algorithm 13) from a 32-byte seed `d`.
fn kpke_keygen(d : BytesView) -> (Bytes, Bytes) {
  // FIPS 203's final version appends the parameter k to the seed before
  // hashing. Leaving it out yields keys that no conforming peer can use.
  let (rho, sigma) = mlkem_g(
    (d.to_owned() + Bytes::make(1, MLKEM768_K.to_byte()))[:],
  )
  let a_hat = mlkem_expand_matrix(rho[:])
  let s = []
  let e = []
  for i in 0..<MLKEM768_K {
    s.push(
      mlkem_sample_cbd(
        mlkem_prf(sigma[:], i.to_byte(), MLKEM768_ETA)[:],
        MLKEM768_ETA,
      ),
    )
  }
  for i in 0..<MLKEM768_K {
    e.push(
      mlkem_sample_cbd(
        mlkem_prf(sigma[:], (MLKEM768_K + i).to_byte(), MLKEM768_ETA)[:],
        MLKEM768_ETA,
      ),
    )
  }
  let s_hat = []
  let e_hat = []
  for i in 0..<MLKEM768_K {
    s_hat.push(mlkem_ntt(s[i]))
    e_hat.push(mlkem_ntt(e[i]))
  }
  // t_hat[i] = sum_j A_hat[i][j] * s_hat[j] + e_hat[i]
  let t_hat = []
  for i in 0..<MLKEM768_K {
    let mut acc = FixedArray::make(MLKEM_N, 0)
    for j in 0..<MLKEM768_K {
      acc = poly_add(acc, mlkem_multiply_ntt(a_hat[i][j], s_hat[j]))
    }
    t_hat.push(poly_add(acc, e_hat[i]))
  }
  (encode_vector(t_hat, 12) + rho, encode_vector(s_hat, 12))
}

///|
/// `K-PKE.Encrypt` (Algorithm 14): encrypt the 32-byte message `m` under
/// `ek` with randomness `r`.
fn kpke_encrypt(ek : BytesView, m : BytesView, r : BytesView) -> Bytes {
  let t_len = MLKEM768_K * MLKEM_POLY_BYTES
  let t_hat = decode_vector(ek[0:t_len], 12)
  let rho = ek[t_len:t_len + 32]
  let a_hat = mlkem_expand_matrix(rho)
  let y = []
  for i in 0..<MLKEM768_K {
    y.push(
      mlkem_sample_cbd(mlkem_prf(r, i.to_byte(), MLKEM768_ETA)[:], MLKEM768_ETA),
    )
  }
  let e1 = []
  for i in 0..<MLKEM768_K {
    e1.push(
      mlkem_sample_cbd(
        mlkem_prf(r, (MLKEM768_K + i).to_byte(), MLKEM768_ETA)[:],
        MLKEM768_ETA,
      ),
    )
  }
  let e2 = mlkem_sample_cbd(
    mlkem_prf(r, (2 * MLKEM768_K).to_byte(), MLKEM768_ETA)[:],
    MLKEM768_ETA,
  )
  let y_hat = []
  for i in 0..<MLKEM768_K {
    y_hat.push(mlkem_ntt(y[i]))
  }
  // u = NTT^-1(A_hat^T * y_hat) + e1, so the matrix is read transposed.
  let u = []
  for i in 0..<MLKEM768_K {
    let mut acc = FixedArray::make(MLKEM_N, 0)
    for j in 0..<MLKEM768_K {
      acc = poly_add(acc, mlkem_multiply_ntt(a_hat[j][i], y_hat[j]))
    }
    u.push(poly_add(mlkem_ntt_inverse(acc), e1[i]))
  }
  // mu = Decompress1(ByteDecode1(m))
  let mu = FixedArray::make(MLKEM_N, 0)
  let m_bits = mlkem_byte_decode(m, 1)
  for i in 0..<MLKEM_N {
    mu[i] = mlkem_decompress(m_bits[i], 1)
  }
  // v = NTT^-1(t_hat^T * y_hat) + e2 + mu
  let mut acc = FixedArray::make(MLKEM_N, 0)
  for j in 0..<MLKEM768_K {
    acc = poly_add(acc, mlkem_multiply_ntt(t_hat[j], y_hat[j]))
  }
  let v = poly_add(poly_add(mlkem_ntt_inverse(acc), e2), mu)
  encode_vector(compress_vector(u, MLKEM768_DU), MLKEM768_DU) +
  mlkem_byte_encode(
    {
      let g = FixedArray::make(MLKEM_N, 0)
      for i in 0..<MLKEM_N {
        g[i] = mlkem_compress(v[i], MLKEM768_DV)
      }
      g
    },
    MLKEM768_DV,
  )
}

///|
/// `K-PKE.Decrypt` (Algorithm 15): recover the 32-byte message.
fn kpke_decrypt(dk : BytesView, c : BytesView) -> Bytes {
  let c1_len = 32 * MLKEM768_DU * MLKEM768_K
  let u = decompress_vector(
    decode_vector(c[0:c1_len], MLKEM768_DU),
    MLKEM768_DU,
  )
  let v_packed = mlkem_byte_decode(
    c[c1_len:c1_len + 32 * MLKEM768_DV],
    MLKEM768_DV,
  )
  let v = FixedArray::make(MLKEM_N, 0)
  for i in 0..<MLKEM_N {
    v[i] = mlkem_decompress(v_packed[i], MLKEM768_DV)
  }
  let s_hat = decode_vector(dk, 12)
  let mut acc = FixedArray::make(MLKEM_N, 0)
  for j in 0..<MLKEM768_K {
    acc = poly_add(acc, mlkem_multiply_ntt(s_hat[j], mlkem_ntt(u[j])))
  }
  let w = poly_sub(v, mlkem_ntt_inverse(acc))
  let bits = FixedArray::make(MLKEM_N, 0)
  for i in 0..<MLKEM_N {
    bits[i] = mlkem_compress(w[i], 1)
  }
  mlkem_byte_encode(bits, 1)
}

// ---------------------------------------------------------------------------
// FIPS 203 Algorithms 16-18: ML-KEM
// ---------------------------------------------------------------------------

///|
/// `ML-KEM.KeyGen_internal` (Algorithm 16) from the two 32-byte seeds the
/// standard calls `d` and `z`. Returns `(encapsulation key, decapsulation
/// key)`.
pub fn mlkem768_keygen(d : BytesView, z : BytesView) -> (Bytes, Bytes) {
  guard d.length() == 32 && z.length() == 32 else {
    abort("mlkem768_keygen: both seeds must be 32 bytes")
  }
  let (ek, dk_pke) = kpke_keygen(d)
  (ek, dk_pke + ek + mlkem_h(ek[:]) + z.to_owned())
}

///|
/// `ML-KEM.Encaps_internal` (Algorithm 17) with the 32-byte message `m`
/// supplied by the caller. Returns `(ciphertext, shared secret)`.
///
/// The encapsulation key is checked by re-encoding it (FIPS 203 section
/// 7.2): a key whose 12-bit coefficients are not all below q would make
/// two implementations disagree, so it is refused rather than used.
pub fn mlkem768_encaps(ek : BytesView, m : BytesView) -> (Bytes, Bytes) {
  guard ek.length() == MLKEM768_ENCAPS_KEY_LEN else {
    abort(
      "mlkem768_encaps: encapsulation key must be \{MLKEM768_ENCAPS_KEY_LEN} bytes",
    )
  }
  guard m.length() == 32 else { abort("mlkem768_encaps: m must be 32 bytes") }
  let t_len = MLKEM768_K * MLKEM_POLY_BYTES
  guard encode_vector(decode_vector(ek[0:t_len], 12), 12) ==
    ek[0:t_len].to_owned() else {
    abort("mlkem768_encaps: malformed encapsulation key")
  }
  let (k, r) = mlkem_g((m.to_owned() + mlkem_h(ek))[:])
  (kpke_encrypt(ek, m, r[:]), k)
}

///|
/// `ML-KEM.Decaps_internal` (Algorithm 18). Never fails: a ciphertext that
/// does not re-encrypt to itself yields a secret derived from the key's own
/// rejection value `z`, so the caller learns nothing it could act on and
/// an attacker learns nothing from the outcome.
pub fn mlkem768_decaps(dk : BytesView, c : BytesView) -> Bytes {
  guard dk.length() == MLKEM768_DECAPS_KEY_LEN else {
    abort(
      "mlkem768_decaps: decapsulation key must be \{MLKEM768_DECAPS_KEY_LEN} bytes",
    )
  }
  guard c.length() == MLKEM768_CIPHERTEXT_LEN else {
    abort(
      "mlkem768_decaps: ciphertext must be \{MLKEM768_CIPHERTEXT_LEN} bytes",
    )
  }
  let dk_pke_len = MLKEM768_K * MLKEM_POLY_BYTES
  let dk_pke = dk[0:dk_pke_len]
  let ek = dk[dk_pke_len:dk_pke_len + MLKEM768_ENCAPS_KEY_LEN]
  let h = dk[dk_pke_len + MLKEM768_ENCAPS_KEY_LEN:dk_pke_len +
    MLKEM768_ENCAPS_KEY_LEN +
    32]
  let z = dk[dk_pke_len + MLKEM768_ENCAPS_KEY_LEN + 32:]
  let m = kpke_decrypt(dk_pke, c)
  let (k, r) = mlkem_g((m + h.to_owned())[:])
  let k_reject = mlkem_j((z.to_owned() + c.to_owned())[:])
  if kpke_encrypt(ek, m[:], r[:]) == c.to_owned() {
    k
  } else {
    k_reject
  }
}
