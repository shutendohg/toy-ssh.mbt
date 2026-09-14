// SSH_MSG_DISCONNECT, SERVICE_REQUEST and SERVICE_ACCEPT codecs
// (RFC 4253 sections 10 and 11.1 / docs/02 section 8).

///|
test "disconnect: byte-exact encode and round trip" {
  let payload = @transport.encode_disconnect(
    @transport.SSH_DISCONNECT_PROTOCOL_ERROR,
    "bad",
  )
  // 01 | 00000002 | 00000003 "bad" | 00000000 (empty language tag)
  inspect(@hex.encode(payload[:]), content="01000000020000000362616400000000")
  let (code, desc) = @transport.decode_disconnect(payload[:])
  inspect(code, content="2")
  inspect(desc, content="bad")
}

///|
test "disconnect: rejects wrong message number and trailing bytes" {
  try
    @transport.decode_disconnect(
      b"\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00"[:],
    )
  catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"DISCONNECT: expected message 1, got 2\")",
      )
  } noraise {
    _ => fail("expected decode_disconnect to raise")
  }
  let extra = @transport.encode_disconnect(2, "x") + b"\x00"
  try @transport.decode_disconnect(extra[:]) catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"DISCONNECT: 1 trailing byte(s)\")",
      )
  } noraise {
    _ => fail("expected decode_disconnect to raise")
  }
}

///|
test "service request / accept: byte-exact encode and round trip" {
  let req = @transport.encode_service_request(@transport.SERVICE_USERAUTH)
  inspect(
    @hex.encode(req[:]),
    content="05" + "0000000c" + "7373682d7573657261757468",
  )
  inspect(@transport.decode_service_request(req[:]), content="ssh-userauth")
  let acc = @transport.encode_service_accept(@transport.SERVICE_USERAUTH)
  inspect(
    @hex.encode(acc[:]),
    content="06" + "0000000c" + "7373682d7573657261757468",
  )
  inspect(@transport.decode_service_accept(acc[:]), content="ssh-userauth")
}

///|
test "service request / accept: reject wrong message number and truncation" {
  try @transport.decode_service_request(b"\x06\x00\x00\x00\x00"[:]) catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"SERVICE_REQUEST: expected message 5, got 6\")",
      )
  } noraise {
    _ => fail("expected decode_service_request to raise")
  }
  try @transport.decode_service_accept(b"\x06\x00\x00\x00\x05ab"[:]) catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"SERVICE_ACCEPT: ShortRead(need=5, have=2)\")",
      )
  } noraise {
    _ => fail("expected decode_service_accept to raise")
  }
}
