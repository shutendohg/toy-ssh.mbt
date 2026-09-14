// Fixtures shared by the userauth tests. The key pair is a real
// `ssh-keygen`-generated Ed25519 key (docs/06 M3); the second key exists
// only to prove that a signature by the wrong key is rejected.

///|
/// `ssh-ed25519` public key blob of `KEY_SEED_HEX`.
const KEY_BLOB_HEX : String = "0000000b7373682d65643235353139000000205327249c998e5c6526bb29aaf2c3547e710734f9f86ad7c339d37ba14f40e7a7"

///|
const KEY_SEED_HEX : String = "4769cb68b5132480f4a45bb160d4a78640c0055eb0ca449538c5b3b6c99b727c"

///|
/// RFC 8032 TEST 1 seed: the "other" key, never authorized.
const OTHER_SEED_HEX : String = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

///|
fn key_blob() -> Bytes raise {
  @hex.decode(KEY_BLOB_HEX)
}

///|
fn key_pair() -> @crypto.Ed25519KeyPair raise {
  @crypto.Ed25519KeyPair::from_seed(@hex.decode(KEY_SEED_HEX)[:])
}

///|
fn other_pair() -> @crypto.Ed25519KeyPair raise {
  @crypto.Ed25519KeyPair::from_seed(@hex.decode(OTHER_SEED_HEX)[:])
}

///|
/// A fixed, obviously-not-random session id.
fn session_id() -> Bytes {
  Bytes::make(32, b'\x5a')
}
