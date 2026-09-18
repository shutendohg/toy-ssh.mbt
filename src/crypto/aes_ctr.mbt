///|
/// AES-128 in counter mode (NIST SP 800-38A section 6.5), built on the ECB
/// block encryption from `moonbitlang/x/crypto`: the keystream is the
/// encryption of successive counter blocks, XORed into the data. Only the
/// counter bookkeeping is ours; the block cipher is not self-built.
///
/// SSH runs one continuous counter per direction across every packet
/// (RFC 4344 section 4), so the counter is a value the caller carries
/// rather than state hidden in here: encrypt a chunk with `aes128_ctr`,
/// then step the counter with `ctr_advance` by the number of blocks it
/// consumed.
///
/// Toy code: not constant-time. Never use for real security.

///|
/// AES block size in bytes; also the counter block size.
pub const AES_BLOCK_LEN : Int = 16

///|
/// AES-128 key length in bytes.
pub const AES128_KEY_LEN : Int = 16

///|
/// `data` XOR the AES-128-CTR keystream that starts at counter block
/// `counter`. Works for any length: the final partial block is truncated,
/// which is why a caller chaining calls must keep every chunk but the last
/// a multiple of `AES_BLOCK_LEN`.
///
/// Key and counter lengths are ours to get right (they come from key
/// derivation, never from a peer), so a wrong length aborts.
pub fn aes128_ctr(
  key : BytesView,
  counter : BytesView,
  data : BytesView,
) -> Bytes {
  guard key.length() == AES128_KEY_LEN else {
    abort("aes128_ctr: key must be \{AES128_KEY_LEN} bytes")
  }
  guard counter.length() == AES_BLOCK_LEN else {
    abort("aes128_ctr: counter must be \{AES_BLOCK_LEN} bytes")
  }
  let blocks = (data.length() + AES_BLOCK_LEN - 1) / AES_BLOCK_LEN
  // All the counter blocks in one buffer, encrypted in a single ECB call:
  // `aes_ecb_encrypt` expands the key schedule once per call, so a call per
  // block would expand it thousands of times for one large packet.
  let counters = FixedArray::make(blocks * AES_BLOCK_LEN, b'\x00')
  let block = FixedArray::make(AES_BLOCK_LEN, b'\x00')
  for i in 0..<AES_BLOCK_LEN {
    block[i] = counter[i]
  }
  for n in 0..<blocks {
    for i in 0..<AES_BLOCK_LEN {
      counters[n * AES_BLOCK_LEN + i] = block[i]
    }
    ctr_increment(block)
  }
  let stream = @xcrypto.aes_ecb_encrypt(key, fixed_to_bytes(counters)[:]) catch {
    _ => abort("aes128_ctr: invalid key or block length")
  }
  let out = FixedArray::make(data.length(), b'\x00')
  for i in 0..<data.length() {
    out[i] = data[i] ^ stream[i]
  }
  fixed_to_bytes(out)
}

///|
/// Add one to a counter block in place, big-endian, wrapping at 2^128.
fn ctr_increment(block : FixedArray[Byte]) -> Unit {
  for i = AES_BLOCK_LEN - 1; i >= 0; i = i - 1 {
    block[i] = (block[i].to_int() + 1).to_byte()
    if block[i] != b'\x00' {
      return
    }
  }
}

///|
/// The counter block `blocks` steps on from `counter`: a big-endian
/// increment over the whole 16 bytes, wrapping at 2^128 (SP 800-38A's
/// "standard incrementing function" with m = 128).
pub fn ctr_advance(counter : BytesView, blocks : Int) -> Bytes {
  guard counter.length() == AES_BLOCK_LEN else {
    abort("ctr_advance: counter must be \{AES_BLOCK_LEN} bytes")
  }
  guard blocks >= 0 else { abort("ctr_advance: negative step") }
  let out = FixedArray::make(AES_BLOCK_LEN, b'\x00')
  let mut carry = blocks.to_uint64()
  for i = AES_BLOCK_LEN - 1; i >= 0; i = i - 1 {
    let sum = counter[i].to_uint64() + (carry & 0xffUL)
    out[i] = (sum & 0xffUL).to_byte()
    carry = (carry >> 8) + (sum >> 8)
  }
  fixed_to_bytes(out)
}
