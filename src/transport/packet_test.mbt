// RFC 4253 section 6 plaintext binary packet protocol (docs/02 section 2).

///|
test "padding: total length is a multiple of 8 with at least 4 padding bytes" {
  // payload_len -> padding_len, per docs/02 section 2 formula
  let cases = [(0, 11), (1, 10), (5, 6), (6, 5), (7, 4), (8, 11), (12, 7)]
  for c in cases {
    let (payload_len, want) = c
    let pad = @transport.padding_length(payload_len)
    assert_eq(pad, want)
    assert_true(pad >= 4)
    assert_eq((4 + 1 + payload_len + pad) % 8, 0)
  }
}

///|
test "encode_packet: byte-exact fixture with injected padding" {
  // payload "abc" (3 bytes): 4+1+3 = 8 -> pad = 8, but 8 < 4 is false so pad = 8
  let pkt = @transport.encode_packet(b"abc"[:], fill=@transport.zero_padding)
  inspect(
    @hex.encode(pkt[:]),
    content="0000000c" + "08" + "616263" + "0000000000000000",
  )
  // custom filler is used verbatim
  let pkt2 = @transport.encode_packet(b""[:], fill=n => {
    Bytes::makei(n, i => (0xa0 + i).to_byte())
  })
  inspect(
    @hex.encode(pkt2[:]),
    content="0000000c" + "0b" + "a0a1a2a3a4a5a6a7a8a9aa",
  )
}

///|
test "decode_packet: round-trips payloads of every alignment" {
  for n in [0, 1, 5, 6, 7, 8, 100, 1000] {
    let payload = Bytes::makei(n, i => (i % 251).to_byte())
    let pkt = @transport.encode_packet(payload[:], fill=@transport.zero_padding)
    assert_eq(pkt.length() % 8, 0)
    match @transport.decode_packet(pkt[:]) {
      Packet(payload=got, consumed~) => {
        assert_eq(got, payload)
        assert_eq(consumed, pkt.length())
      }
      NeedMoreData => fail("complete packet reported as incomplete")
    }
  }
}

///|
test "decode_packet: reports NeedMoreData for partial input, consumes one packet" {
  let pkt = @transport.encode_packet(b"hello"[:], fill=@transport.zero_padding)
  debug_inspect(@transport.decode_packet(pkt[0:3]), content="NeedMoreData")
  debug_inspect(@transport.decode_packet(pkt[0:10]), content="NeedMoreData")
  // Two packets back to back: only the first is consumed.
  let two = pkt + pkt
  match @transport.decode_packet(two[:]) {
    Packet(payload~, consumed~) => {
      inspect(@hex.encode(payload[:]), content="68656c6c6f")
      assert_eq(consumed, pkt.length())
    }
    NeedMoreData => fail("unexpected NeedMoreData")
  }
}

///|
test "decode_packet: rejects malformed framing" {
  fn expect_err(buf : Bytes, want : String) -> Unit raise {
    try @transport.decode_packet(buf[:]) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected decode_packet to raise")
    }
  }
  // 4 + packet_length above the 35000 total cap (item 4): 34997 + 4 = 35001
  expect_err(b"\x00\x00\x88\xb5\x04", "ProtocolError(\"packet too large\")")
  // packet_length with the top bit set must not wrap to a negative Int (item 7)
  expect_err(b"\x80\x00\x00\x0c\x04", "ProtocolError(\"packet too large\")")
  expect_err(b"\xff\xff\xff\xff\x04", "ProtocolError(\"packet too large\")")
  // packet_length too small to hold padding_length + 4 padding bytes
  expect_err(
    b"\x00\x00\x00\x04\x03\x00\x00\x00", "ProtocolError(\"packet too small\")",
  )
  // padding_length < 4
  expect_err(
    b"\x00\x00\x00\x0c\x03abcdefgh\x00\x00\x00", "ProtocolError(\"padding too short\")",
  )
  // padding_length larger than the packet
  expect_err(
    b"\x00\x00\x00\x0c\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "ProtocolError(\"padding exceeds packet\")",
  )
  // total not aligned to 8 (packet_length 13 -> 17 bytes total)
  expect_err(
    b"\x00\x00\x00\x0d\x04abcdefgh\x00\x00\x00\x00", "ProtocolError(\"packet not aligned\")",
  )
}

///|
test "decode_packet: accepts a packet whose total size is exactly 35000" {
  // payload 34991 -> pad 4 -> 4 + 1 + 34991 + 4 = 35000
  let payload = Bytes::make(34991, b'\x5a')
  let pkt = @transport.encode_packet(payload[:], fill=@transport.zero_padding)
  assert_eq(pkt.length(), 35000)
  match @transport.decode_packet(pkt[:]) {
    Packet(payload=got, consumed~) => {
      assert_eq(got, payload)
      assert_eq(consumed, 35000)
    }
    NeedMoreData => fail("complete packet reported as incomplete")
  }
}

///|
test "encode_packet: refuses a packet whose total size would exceed 35000" {
  // payload 34992 -> pad 11 -> total 35008
  let payload = Bytes::make(34992, b'\x5a')
  try @transport.encode_packet(payload[:], fill=@transport.zero_padding) catch {
    e => debug_inspect(e, content="ProtocolError(\"packet too large\")")
  } noraise {
    _ => fail("expected encode_packet to raise")
  }
}
