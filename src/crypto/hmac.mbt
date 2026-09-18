///|
/// `hmac-sha2-256`, the MAC of the aes128-ctr suite (docs/06 M5). The
/// primitive itself comes from `moonbitlang/x/crypto`; only the naming is
/// ours.

///|
/// HMAC-SHA-256 over `message`, the MAC behind `hmac-sha2-256`. A thin
/// wrapper over `moonbitlang/x/crypto`'s generic HMAC so callers do not
/// have to name the hasher; the 32-byte result is returned whole (SSH
/// never truncates this one).
pub fn hmac_sha256(key : BytesView, message : BytesView) -> Bytes {
  fixed_to_bytes(@xcrypto.hmac(@xcrypto.SHA256::new(), key, message))
}

///|
/// Length in bytes of an `hmac-sha2-256` tag and of its key.
pub const HMAC_SHA256_LEN : Int = 32
