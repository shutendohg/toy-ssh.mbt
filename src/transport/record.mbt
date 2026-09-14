///|
/// `chacha20-poly1305@openssh.com` record layer (docs/02 section 7,
/// OpenSSH `PROTOCOL.chacha20poly1305`). Replaces the plaintext framing in
/// `packet.mbt` once NEWKEYS is active. Sans-IO: pure functions over bytes;
/// padding bytes are injected by the caller like `encode_packet`.
///
/// Sequence numbers: the caller keeps one `UInt` per direction, starting at
/// 0 after NEWKEYS (strict kex), incremented by one per packet and wrapping
/// mod 2^32. `RecordState` below packages that bookkeeping.
///
/// Toy code. Never use for real security.

///|
/// The exact `ProtocolError` text raised when the Poly1305 tag does not
/// verify. The transport maps this one message to SSH_DISCONNECT_MAC_ERROR,
/// so it is a constant rather than free text.
pub const MAC_FAILURE : String = "MAC/tag verification failed"

///|
/// Alignment of the encrypted body: `1 + payload + padding` is a multiple
/// of 8 (the length field is excluded because it is encrypted separately).
const AEAD_ALIGN : Int = 8

///|
/// The per-direction 64-byte key material split into its two ChaCha20 keys.
/// Byte order is the classic bug: `content` (K_2) is the FIRST 32 bytes,
/// `length` (K_1) the SECOND 32 bytes, matching Go's `x/crypto/ssh`.
pub(all) struct RecordKey {
  /// K_2: encrypts the packet body and derives the Poly1305 key.
  content : Bytes
  /// K_1: encrypts the 4-byte packet_length field.
  length : Bytes
} derive(Debug, Eq)

///|
/// Split a 64-byte per-direction key. Aborts on any other length: keys come
/// from our own key derivation, never from the peer.
pub fn RecordKey::new(key : BytesView) -> RecordKey {
  guard key.length() == 64 else {
    abort("RecordKey::new: key must be 64 bytes")
  }
  { content: key[0:32].to_owned(), length: key[32:64].to_owned(), }
}

///|
/// 12-byte IETF ChaCha20 nonce for packet `seqnum`: 8 zero bytes followed
/// by the big-endian sequence number (docs/03 section 2, "the nonce trap").
pub fn record_nonce(seqnum : UInt) -> Bytes {
  let w = @wire.Writer::new(size_hint=12)
  w.write_uint64(0)
  w.write_uint32(seqnum)
  w.to_bytes()
}

///|
/// Padding length for an AEAD packet carrying `payload_len` bytes:
/// `padding_length || payload || padding` (WITHOUT the 4-byte length field,
/// unlike `padding_length`) must be a multiple of 8, with at least 4 bytes
/// of padding.
pub fn aead_padding_length(payload_len : Int) -> Int {
  let size_wo_pad = 1 + payload_len
  let mut pad = AEAD_ALIGN - size_wo_pad % AEAD_ALIGN
  if pad < 4 {
    pad = pad + AEAD_ALIGN
  }
  pad
}

///|
/// Poly1305 tag length in bytes.
const TAG_LEN : Int = 16

///|
/// ChaCha20 keystream XOR: returns `data` XOR keystream(key, nonce, counter).
/// The key and nonce lengths are ours to get right, so a library rejection
/// is a programmer error, not a protocol error.
fn chacha20_xor(
  key : BytesView,
  nonce : Bytes,
  counter : UInt,
  data : BytesView,
) -> FixedArray[Byte] {
  let cipher = @xcrypto.ChaCha::chacha20(key, nonce, counter~) catch {
    _ => abort("chacha20: invalid key or nonce length")
  }
  let out = FixedArray::make(data.length(), b'\x00')
  cipher.transform(data, out)
  out
}

///|
/// Poly1305 one-time key for this packet: the first 32 bytes of the
/// counter-0 keystream block under the content key (docs/02 section 7
/// step 3).
fn poly_key(key : RecordKey, nonce : Bytes) -> Bytes {
  @crypto.fixed_to_bytes(
    chacha20_xor(key.content[:], nonce, 0, Bytes::make(32, b'\x00')[:]),
  )
}

///|
/// Seal `payload` as one `chacha20-poly1305@openssh.com` packet under
/// `key` with packet sequence number `seqnum`. `fill(n)` must return exactly
/// `n` padding bytes (random in real senders; injected so the codec stays
/// free of randomness). Output is `enc_len (4) || enc_body || tag (16)`.
/// Raises if `4 + packet_length` would exceed `MAX_PACKET_TOTAL` (the tag
/// is not counted, matching the plaintext framing's cap on `4 +
/// packet_length`).
pub fn seal_packet(
  key : RecordKey,
  seqnum : UInt,
  payload : BytesView,
  fill~ : (Int) -> Bytes,
) -> Bytes raise ProtocolError {
  let pad_len = aead_padding_length(payload.length())
  let packet_length = 1 + payload.length() + pad_len
  if 4 + packet_length > MAX_PACKET_TOTAL {
    raise ProtocolError("packet too large")
  }
  let padding = fill(pad_len)
  guard padding.length() == pad_len else {
    abort("padding filler returned the wrong number of bytes")
  }
  let nonce = record_nonce(seqnum)
  // Step 1: plaintext body = padding_length || payload || padding.
  let body = @wire.Writer::new(size_hint=packet_length)
  body.write_byte(pad_len.to_byte())
  body.write_raw(payload)
  body.write_raw(padding[:])
  // Step 2: length field under K_1, counter 0.
  let len_plain = @wire.Writer::new(size_hint=4)
  len_plain.write_uint32(packet_length.reinterpret_as_uint())
  let enc_len = chacha20_xor(key.length[:], nonce, 0, len_plain.to_bytes()[:])
  // Step 3/4: Poly1305 key from counter 0, body under counter 1 (K_2).
  let pk = poly_key(key, nonce)
  let enc_body = chacha20_xor(key.content[:], nonce, 1, body.to_bytes()[:])
  // Step 5/6: tag over the ciphertext of both fields, then assemble.
  let out = @wire.Writer::new(size_hint=4 + packet_length + TAG_LEN)
  out.write_raw(@crypto.fixed_to_bytes(enc_len)[:])
  out.write_raw(@crypto.fixed_to_bytes(enc_body)[:])
  let authed = out.to_bytes()
  let tag = @crypto.poly1305(pk[:], authed[:])
  out.write_raw(@crypto.fixed_to_bytes(tag)[:])
  out.to_bytes()
}

///|
/// Non-short-circuit equality: XOR-accumulates every byte so the result
/// does not depend on where the first difference is. Toy: not constant
/// time in any rigorous sense (BigInt Poly1305 is not either).
fn tags_equal(a : BytesView, b : BytesView) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut acc = b'\x00'
  for i in 0..<a.length() {
    acc = acc | (a[i] ^ b[i])
  }
  acc == b'\x00'
}

///|
/// Open the first `chacha20-poly1305@openssh.com` packet at the start of
/// `buf` under `key` with expected sequence number `seqnum`. Returns
/// `NeedMoreData` when the buffer holds less than a full packet; the length
/// is decrypted and sanity-checked from the first 4 bytes alone, so a peer
/// cannot make us buffer without bound. Raises `ProtocolError` with a
/// message containing "MAC/tag" when the tag does not verify (the transport
/// maps that to `SSH_DISCONNECT_MAC_ERROR`), and other `ProtocolError`s on
/// framing violations. Nothing is decrypted before the tag verifies except
/// the length field, which the tag also covers.
pub fn open_packet(
  key : RecordKey,
  seqnum : UInt,
  buf : BytesView,
) -> PacketParse raise ProtocolError {
  if buf.length() < 4 {
    return NeedMoreData
  }
  let nonce = record_nonce(seqnum)
  // Step 1: decrypt the length under K_1, counter 0, and sanity-check it.
  let len_plain = chacha20_xor(key.length[:], nonce, 0, buf[0:4])
  let packet_length_u32 = @wire.Reader::new(
    @crypto.fixed_to_bytes(len_plain)[:],
  ).read_uint32() catch {
    _ => abort("unreachable: 4 bytes always hold a uint32")
  }
  if packet_length_u32 > (MAX_PACKET_TOTAL - 4).reinterpret_as_uint() {
    raise ProtocolError("packet too large")
  }
  let packet_length = packet_length_u32.reinterpret_as_int()
  // padding_length byte + at least 4 padding bytes.
  if packet_length < 5 {
    raise ProtocolError("packet too small")
  }
  if packet_length % AEAD_ALIGN != 0 {
    raise ProtocolError("packet not aligned")
  }
  // Step 2: wait for enc_body || tag.
  let total = 4 + packet_length + TAG_LEN
  if buf.length() < total {
    return NeedMoreData
  }
  // Step 3/4: verify the tag over enc_len || enc_body before decrypting.
  let pk = poly_key(key, nonce)
  let want = @crypto.poly1305(pk[:], buf[0:4 + packet_length])
  if !tags_equal(@crypto.fixed_to_bytes(want)[:], buf[4 + packet_length:total]) {
    raise ProtocolError(MAC_FAILURE)
  }
  // Step 5/6: decrypt the body under K_2, counter 1, and strip padding.
  let body = @crypto.fixed_to_bytes(
    chacha20_xor(key.content[:], nonce, 1, buf[4:4 + packet_length]),
  )
  let padding_len = body[0].to_int()
  if padding_len < 4 {
    raise ProtocolError("padding too short")
  }
  let payload_len = packet_length - 1 - padding_len
  if payload_len < 0 {
    raise ProtocolError("padding exceeds packet")
  }
  let payload = body[1:1 + payload_len].to_owned()
  Packet(payload~, consumed=total)
}

///|
/// One direction of an established record layer: the split key plus the
/// running packet sequence number. `seq` starts at 0 (strict kex resets it
/// after NEWKEYS), advances by one per packet sealed or successfully
/// opened, and wraps mod 2^32 through `UInt` arithmetic. Mutable so the
/// transport can reset it on NEWKEYS.
pub(all) struct RecordState {
  key : RecordKey
  mut seq : UInt
}

///|
/// Fresh state for a 64-byte per-direction key, sequence number 0.
pub fn RecordState::new(key : BytesView) -> RecordState {
  { key: RecordKey::new(key), seq: 0, }
}

///|
/// `seal_packet` with this state's key and sequence number, then advance
/// the sequence number. On a raise nothing was sent, so `seq` stays put.
pub fn RecordState::seal_next(
  self : RecordState,
  payload : BytesView,
  fill~ : (Int) -> Bytes,
) -> Bytes raise ProtocolError {
  let out = seal_packet(self.key, self.seq, payload, fill~)
  self.seq = self.seq + 1
  out
}

///|
/// `open_packet` with this state's key and sequence number. Advances the
/// sequence number only when a packet is returned; `NeedMoreData` and a
/// raised error leave it unchanged.
pub fn RecordState::open_next(
  self : RecordState,
  buf : BytesView,
) -> PacketParse raise ProtocolError {
  let result = open_packet(self.key, self.seq, buf)
  match result {
    Packet(..) => self.seq = self.seq + 1
    NeedMoreData => ()
  }
  result
}
