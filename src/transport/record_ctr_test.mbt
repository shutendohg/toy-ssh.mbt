// aes128-ctr + hmac-sha2-256 record layer (docs/06 M5, RFC 4253 section 6.4,
// RFC 4344 section 4). The byte-exact fixture below was produced outside this
// code base -- `openssl enc -aes-128-ctr` for the cipher and Python's
// `hmac`/`hashlib` for the MAC -- so it cannot agree with a wrong
// implementation that merely agrees with itself.

///|
fn ctr_keys() -> @transport.DirectionKeys {
  {
    // 00 11 22 .. ff
    iv: Bytes::makei(16, i => (i * 0x11).to_byte()),
    enc: Bytes::makei(16, i => i.to_byte()),
    mac: Bytes::makei(32, i => (0x40 + i).to_byte()),
  }
}

///|
test "seal_ctr_packet: byte-exact fixture for seqnum 7, payload \"hello\"" {
  // plaintext packet: 0000000c 06 "hello" 000000000000 (16 bytes, one block)
  let pkt = @transport.seal_ctr_packet(
    ctr_keys(),
    7,
    ctr_keys().iv[:],
    b"hello"[:],
    fill=@transport.zero_padding,
  )
  inspect(
    @hex.encode(pkt),
    content="69c4e0d46c13615cb4a2b78070b4c55a" +
      "db5d45de6aa125284ae3234e1f31f5e7f887f74cd7103d19af05c1a77fc2962c",
  )
}

///|
test "open_ctr_packet: opens the fixture back to its payload" {
  let pkt = hx(
    "69c4e0d46c13615cb4a2b78070b4c55a" +
    "db5d45de6aa125284ae3234e1f31f5e7f887f74cd7103d19af05c1a77fc2962c",
  )
  match @transport.open_ctr_packet(ctr_keys(), 7, ctr_keys().iv[:], pkt[:]) {
    Packet(payload~, consumed~) => {
      assert_eq(payload, b"hello")
      assert_eq(consumed, 48)
    }
    NeedMoreData => fail("complete packet reported as incomplete")
  }
}

///|
test "aes128-ctr packets are block-aligned with at least 4 bytes of padding" {
  let keys = ctr_keys()
  for len in [0, 1, 5, 10, 11, 12, 16, 27, 100] {
    let payload = Bytes::makei(len, i => (i + 1).to_byte())
    let pkt = @transport.seal_ctr_packet(
      keys,
      0,
      keys.iv[:],
      payload[:],
      fill=@transport.zero_padding,
    )
    // ciphertext (everything but the 32-byte MAC) is a multiple of 16
    let ct_len = pkt.length() - 32
    assert_eq(ct_len % 16, 0)
    // padding = ciphertext - 4 length bytes - 1 padding-length byte - payload
    assert_true(ct_len - 5 - len >= 4)
    match @transport.open_ctr_packet(keys, 0, keys.iv[:], pkt[:]) {
      Packet(payload=got, consumed~) => {
        assert_eq(got, payload)
        assert_eq(consumed, pkt.length())
      }
      NeedMoreData => fail("round trip incomplete for length \{len}")
    }
  }
}

///|
test "RecordState(aes128-ctr): the counter runs on across packets" {
  let keys = ctr_keys()
  let tx = @transport.RecordState::new(Aes128CtrHmacSha256, keys)
  let rx = @transport.RecordState::new(Aes128CtrHmacSha256, keys)
  let p0 = tx.seal_next(b"one"[:], fill=@transport.zero_padding)
  let p1 = tx.seal_next(b"two"[:], fill=@transport.zero_padding)
  assert_eq(tx.seq, 2)
  // p0 is one block, so p1 starts at counter + 1 -- not back at the IV.
  assert_eq(
    p1,
    @transport.seal_ctr_packet(
      keys,
      1,
      @crypto.ctr_advance(keys.iv[:], 1)[:],
      b"two"[:],
      fill=@transport.zero_padding,
    ),
  )
  assert_not_eq(
    p1,
    @transport.seal_ctr_packet(
      keys,
      1,
      keys.iv[:],
      b"two"[:],
      fill=@transport.zero_padding,
    ),
  )
  let stream = p0 + p1
  let consumed = match rx.open_next(stream[:]) {
    Packet(payload~, consumed~) => {
      assert_eq(payload, b"one")
      consumed
    }
    NeedMoreData => fail("first packet incomplete")
  }
  match rx.open_next(stream[consumed:]) {
    Packet(payload~, ..) => assert_eq(payload, b"two")
    NeedMoreData => fail("second packet incomplete")
  }
  assert_eq(rx.seq, 2)
}

///|
test "open_ctr_packet: every flipped bit is rejected" {
  let keys = ctr_keys()
  let pkt = @transport.seal_ctr_packet(
    keys,
    3,
    keys.iv[:],
    b"payload"[:],
    fill=@transport.zero_padding,
  )
  for i in 0..<pkt.length() {
    let mutated = Bytes::makei(pkt.length(), j => {
      if j == i {
        pkt[j] ^ b'\x80'
      } else {
        pkt[j]
      }
    })
    // Bytes 0..4 are the encrypted length, and this suite has to trust it
    // enough to frame the packet before anything is authenticated: a flip
    // there either trips a framing check or announces a longer packet that
    // never arrives (`NeedMoreData`). It can never be accepted. From byte 4
    // on, only the MAC stands in the way, and it must be what rejects it.
    try @transport.open_ctr_packet(keys, 3, keys.iv[:], mutated[:]) catch {
      ProtocolError(msg) => if i >= 4 { assert_true(msg.contains("MAC")) }
    } noraise {
      NeedMoreData =>
        if i >= 4 {
          fail("a flip at byte \{i} was not caught by the MAC")
        }
      Packet(..) => fail("a flip at byte \{i} was accepted")
    }
  }
}

///|
test "open_ctr_packet: the wrong sequence number fails the MAC" {
  let keys = ctr_keys()
  let pkt = @transport.seal_ctr_packet(
    keys,
    3,
    keys.iv[:],
    b"payload"[:],
    fill=@transport.zero_padding,
  )
  try @transport.open_ctr_packet(keys, 4, keys.iv[:], pkt[:]) catch {
    e =>
      debug_inspect(e, content="ProtocolError(\"MAC/tag verification failed\")")
  } noraise {
    _ => fail("expected a MAC failure")
  }
}

///|
test "RecordState(aes128-ctr): a partial or bad packet changes no state" {
  let keys = ctr_keys()
  let tx = @transport.RecordState::new(Aes128CtrHmacSha256, keys)
  let rx = @transport.RecordState::new(Aes128CtrHmacSha256, keys)
  let pkt = tx.seal_next(b"hello"[:], fill=@transport.zero_padding)
  // Short of a full block, short of the MAC: both are "come back later".
  debug_inspect(rx.open_next(pkt[0:8]), content="NeedMoreData")
  debug_inspect(rx.open_next(pkt[0:pkt.length() - 1]), content="NeedMoreData")
  assert_eq(rx.seq, 0)
  let bad = Bytes::makei(pkt.length(), i => {
    if i == 0 {
      pkt[i] ^ b'\x01'
    } else {
      pkt[i]
    }
  })
  try rx.open_next(bad[:]) catch {
    _ => ()
  } noraise {
    _ => fail("expected open_next to raise")
  }
  assert_eq(rx.seq, 0)
  // ... and the counter did not move either: the good packet still opens.
  match rx.open_next(pkt[:]) {
    Packet(payload~, ..) => assert_eq(payload, b"hello")
    NeedMoreData => fail("complete packet reported as incomplete")
  }
  assert_eq(rx.seq, 1)
}
