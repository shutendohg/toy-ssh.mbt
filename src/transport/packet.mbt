///|
/// Plaintext binary packet protocol, RFC 4253 section 6 / docs/02 section 2.
/// Only valid before NEWKEYS; the AEAD framing (docs/02 section 7) is M2.

///|
/// Largest total packet size we accept or produce, counting the 4-byte
/// `packet_length` field (RFC 4253 section 6.1: implementations must handle
/// packets up to 35000 bytes in total; docs/02 section 2).
pub const MAX_PACKET_TOTAL : Int = 35000

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
/// Raises if the framed packet would exceed `MAX_PACKET_TOTAL`: higher
/// layers must split their data (channel window / max packet size) before
/// it gets here.
pub fn encode_packet(
  payload : BytesView,
  fill~ : (Int) -> Bytes,
) -> Bytes raise ProtocolError {
  let pad_len = padding_length(payload.length())
  if 4 + 1 + payload.length() + pad_len > MAX_PACKET_TOTAL {
    raise ProtocolError("packet too large")
  }
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
  // Fewer than 4 bytes buffered: the length field itself is incomplete.
  let packet_length_u32 = @wire.Reader::new(buf).read_uint32() catch {
    _ => return NeedMoreData
  }
  // Reject absurd lengths before waiting for more bytes, so a hostile peer
  // cannot make us buffer without bound. Compare as UInt so a top bit set
  // in the length field cannot wrap into a small or negative Int.
  if packet_length_u32 > (MAX_PACKET_TOTAL - 4).reinterpret_as_uint() {
    raise ProtocolError("packet too large")
  }
  let packet_length = packet_length_u32.reinterpret_as_int()
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
