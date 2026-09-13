///|
/// Arithmetic in GF(p), p = 2^255 - 19, shared by X25519 (RFC 7748) and
/// Ed25519 (RFC 8032). Elements are `BigInt` values kept in [0, p).
///
/// Toy implementation: BigInt is not constant-time and every operation
/// allocates. Clarity over speed; never use for real security.

///|
/// p = 2^255 - 19
pub let field_p : BigInt = (1N << 255) - 19N

///|
pub fn fe_add(a : BigInt, b : BigInt) -> BigInt {
  (a + b) % field_p
}

///|
/// a - b mod p. Both inputs are in [0, p), so adding p first keeps the
/// intermediate non-negative and avoids depending on the sign convention
/// of `BigInt::mod`.
pub fn fe_sub(a : BigInt, b : BigInt) -> BigInt {
  (a + field_p - b) % field_p
}

///|
pub fn fe_mul(a : BigInt, b : BigInt) -> BigInt {
  a * b % field_p
}

///|
pub fn fe_sq(a : BigInt) -> BigInt {
  a * a % field_p
}

///|
/// a^e mod p via the core square-and-multiply.
pub fn fe_pow(a : BigInt, e : BigInt) -> BigInt {
  a.pow(e, modulus=field_p)
}

///|
/// Multiplicative inverse by Fermat: a^(p-2). fe_inv(0) = 0.
pub fn fe_inv(a : BigInt) -> BigInt {
  fe_pow(a, field_p - 2N)
}

///|
/// Reduce an arbitrary non-negative integer into [0, p).
pub fn fe_reduce(a : BigInt) -> BigInt {
  a % field_p
}
