///|
/// Plaintext binary packet protocol, RFC 4253 section 6 / docs/02 section 2.
/// Only valid before NEWKEYS; the AEAD framing (docs/02 section 7) is M2.

///|
/// Largest packet_length we accept (RFC 4253 section 6.1 minimum guarantee).
pub const MAX_PACKET_LENGTH : Int = 35000

///|
/// Alignment for the no-cipher state: max(8, block size) with no cipher.
const PLAINTEXT_ALIGN : Int = 8

///|
/// Padding length for a plaintext packet carrying `payload_len` bytes:
/// `packet_length || padding_length || payload || padding` (including the
/// 4-byte length field) must be a multiple of 8, with at least 4 bytes of
/// padding.
pub fn padding_length(payload_len : Int) -> Int {
  let size_wo_pad = 4 + 1 + payload_len
  let mut pad = PLAINTEXT_ALIGN - size_wo_pad % PLAINTEXT_ALIGN
  if pad < 4 {
    pad = pad + PLAINTEXT_ALIGN
  }
  pad
}

///|
/// Deterministic all-zero padding filler for tests. Real senders should
/// use random padding (RFC 4253 section 6: padding SHOULD be random).
pub fn zero_padding(n : Int) -> Bytes {
  Bytes::make(n, b'\x00')
}

///|
/// Frame `payload` as a plaintext packet. `fill(n)` must return exactly `n`
/// padding bytes; it is a parameter so the codec stays free of randomness.
pub fn encode_packet(payload : BytesView, fill~ : (Int) -> Bytes) -> Bytes {
  let pad_len = padding_length(payload.length())
  let padding = fill(pad_len)
  guard padding.length() == pad_len else {
    abort("padding filler returned the wrong number of bytes")
  }
  let w = @wire.Writer::new(size_hint=4 + 1 + payload.length() + pad_len)
  w.write_uint32((1 + payload.length() + pad_len).reinterpret_as_uint())
  w.write_byte(pad_len.to_byte())
  w.write_raw(payload)
  w.write_raw(padding[:])
  w.to_bytes()
}

///|
/// Result of trying to pull one plaintext packet off a receive buffer.
pub(all) enum PacketParse {
  /// Not enough buffered bytes yet; call again with more input.
  NeedMoreData
  /// One packet decoded. `consumed` is how many input bytes it spanned.
  Packet(payload~ : Bytes, consumed~ : Int)
} derive(Debug, Eq)

///|
/// Decode the first plaintext packet at the start of `buf`. Raises
/// `ProtocolError` on framing violations (oversize, undersize, bad padding,
/// misalignment); returns `NeedMoreData` when the packet is incomplete.
pub fn decode_packet(buf : BytesView) -> PacketParse raise ProtocolError {
  if buf.length() < 4 {
    return NeedMoreData
  }
  let packet_length = (buf[0].to_int() << 24) |
    (buf[1].to_int() << 16) |
    (buf[2].to_int() << 8) |
    buf[3].to_int()
  // Reject absurd lengths before waiting for more bytes, so a hostile peer
  // cannot make us buffer without bound.
  if packet_length < 0 || packet_length > MAX_PACKET_LENGTH {
    raise ProtocolError("packet too large")
  }
  // padding_length byte + at least 4 padding bytes.
  if packet_length < 5 {
    raise ProtocolError("packet too small")
  }
  if (4 + packet_length) % PLAINTEXT_ALIGN != 0 {
    raise ProtocolError("packet not aligned")
  }
  if buf.length() < 4 + packet_length {
    return NeedMoreData
  }
  let padding_len = buf[4].to_int()
  if padding_len < 4 {
    raise ProtocolError("padding too short")
  }
  let payload_len = packet_length - 1 - padding_len
  if payload_len < 0 {
    raise ProtocolError("padding exceeds packet")
  }
  let payload = buf[5:5 + payload_len].to_owned()
  Packet(payload~, consumed=4 + packet_length)
}
