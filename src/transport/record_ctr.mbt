///|
/// `aes128-ctr` + `hmac-sha2-256` record layer (RFC 4253 section 6.4,
/// RFC 4344 section 4), the non-AEAD half of docs/06 M5.
///
/// The shape is the classic SSH one, and it is *not* encrypt-then-MAC: the
/// MAC covers the plaintext packet prefixed with the sequence number, while
/// the ciphertext covers that same packet including its length field. A
/// receiver therefore has to decrypt the first block to learn how long the
/// packet is, before anything has been authenticated -- the known weakness
/// that `hmac-...-etm@openssh.com` and AEAD suites exist to fix. We keep the
/// standard construction because it is what interoperates, and sanity-check
/// the decrypted length hard before trusting it.
///
/// CTR keeps one counter per direction running across every packet: it
/// starts at the derived IV and never restarts. `RecordState` owns that
/// counter; the functions here take it as a parameter so they stay pure.
///
/// Toy code. Never use for real security.

///|
/// Block size of the packet framing for a CTR cipher.
const CTR_ALIGN : Int = 16

///|
/// Padding length for an `aes128-ctr` packet carrying `payload_len` bytes:
/// here the 4-byte length field *is* encrypted, so the whole
/// `length || padding_length || payload || padding` must be a multiple of
/// the block size, with at least 4 bytes of padding.
pub fn ctr_padding_length(payload_len : Int) -> Int {
  let size_wo_pad = 4 + 1 + payload_len
  let mut pad = CTR_ALIGN - size_wo_pad % CTR_ALIGN
  if pad < 4 {
    pad = pad + CTR_ALIGN
  }
  pad
}

///|
/// The plaintext packet `length || padding_length || payload || padding`.
fn ctr_plaintext(payload : BytesView, padding : BytesView) -> Bytes {
  let packet_length = 1 + payload.length() + padding.length()
  let w = @wire.Writer::new(size_hint=4 + packet_length)
  w.write_uint32(packet_length.reinterpret_as_uint())
  w.write_byte(padding.length().to_byte())
  w.write_raw(payload)
  w.write_raw(padding)
  w.to_bytes()
}

///|
/// MAC over `seqnum || plaintext packet` (RFC 4253 section 6.4).
fn ctr_mac(mac_key : BytesView, seqnum : UInt, plain : BytesView) -> Bytes {
  let w = @wire.Writer::new(size_hint=4 + plain.length())
  w.write_uint32(seqnum)
  w.write_raw(plain)
  @crypto.hmac_sha256(mac_key, w.to_bytes()[:])
}

///|
/// Seal `payload` as one `aes128-ctr` + `hmac-sha2-256` packet under
/// `keys`, starting the keystream at `counter`. `fill(n)` returns the `n`
/// padding bytes (random in real senders, injected here so the codec stays
/// free of randomness). Output is `ciphertext || mac (32)`. Raises if
/// `4 + packet_length` would exceed `MAX_PACKET_TOTAL`, matching the other
/// two framings.
pub fn seal_ctr_packet(
  keys : DirectionKeys,
  seqnum : UInt,
  counter : BytesView,
  payload : BytesView,
  fill~ : (Int) -> Bytes,
) -> Bytes raise ProtocolError {
  let pad_len = ctr_padding_length(payload.length())
  let packet_length = 1 + payload.length() + pad_len
  if 4 + packet_length > MAX_PACKET_TOTAL {
    raise ProtocolError("packet too large")
  }
  let padding = fill(pad_len)
  guard padding.length() == pad_len else {
    abort("padding filler returned the wrong number of bytes")
  }
  let plain = ctr_plaintext(payload, padding[:])
  let cipher = @crypto.aes128_ctr(keys.enc[:], counter, plain[:])
  let mac = ctr_mac(keys.mac[:], seqnum, plain[:])
  cipher + mac
}

///|
/// Open the first `aes128-ctr` + `hmac-sha2-256` packet at the start of
/// `buf`, whose keystream starts at `counter`. Returns `NeedMoreData` until
/// the whole packet and its MAC have arrived; raises `ProtocolError` with
/// `MAC_FAILURE` when the MAC does not verify, and other `ProtocolError`s
/// on framing violations.
///
/// The length comes out of the cipher before the MAC has been checked (see
/// the file header), so it is rejected unless it is within the packet cap,
/// large enough for one padding byte plus the minimum padding, and block
/// aligned -- a peer still cannot make us buffer or allocate without bound.
pub fn open_ctr_packet(
  keys : DirectionKeys,
  seqnum : UInt,
  counter : BytesView,
  buf : BytesView,
) -> PacketParse raise ProtocolError {
  if buf.length() < CTR_ALIGN {
    return NeedMoreData
  }
  let first = @crypto.aes128_ctr(keys.enc[:], counter, buf[0:CTR_ALIGN])
  let packet_length_u32 = @wire.Reader::new(first[0:4]).read_uint32() catch {
    _ => abort("unreachable: 4 bytes always hold a uint32")
  }
  if packet_length_u32 > (MAX_PACKET_TOTAL - 4).reinterpret_as_uint() {
    raise ProtocolError("packet too large")
  }
  let packet_length = packet_length_u32.reinterpret_as_int()
  if packet_length < 5 {
    raise ProtocolError("packet too small")
  }
  if (4 + packet_length) % CTR_ALIGN != 0 {
    raise ProtocolError("packet not aligned")
  }
  let total = 4 + packet_length + @crypto.HMAC_SHA256_LEN
  if buf.length() < total {
    return NeedMoreData
  }
  // The first block is already decrypted; the rest continues the keystream.
  let rest = @crypto.aes128_ctr(
    keys.enc[:],
    @crypto.ctr_advance(counter, 1)[:],
    buf[CTR_ALIGN:4 + packet_length],
  )
  let plain = first + rest
  let want = ctr_mac(keys.mac[:], seqnum, plain[:])
  if !tags_equal(want[:], buf[4 + packet_length:total]) {
    raise ProtocolError(MAC_FAILURE)
  }
  let padding_len = plain[4].to_int()
  if padding_len < 4 {
    raise ProtocolError("padding too short")
  }
  let payload_len = packet_length - 1 - padding_len
  if payload_len < 0 {
    raise ProtocolError("padding exceeds packet")
  }
  Packet(payload=plain[5:5 + payload_len].to_owned(), consumed=total)
}
