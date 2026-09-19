// Connection protocol message codecs, RFC 4254 / docs/04 Part B.

///|
test "message numbers match RFC 4254 / docs/04 Part B" {
  inspect(@connection.SSH_MSG_GLOBAL_REQUEST.to_int(), content="80")
  inspect(@connection.SSH_MSG_REQUEST_SUCCESS.to_int(), content="81")
  inspect(@connection.SSH_MSG_REQUEST_FAILURE.to_int(), content="82")
  inspect(@connection.SSH_MSG_CHANNEL_OPEN.to_int(), content="90")
  inspect(@connection.SSH_MSG_CHANNEL_OPEN_CONFIRMATION.to_int(), content="91")
  inspect(@connection.SSH_MSG_CHANNEL_OPEN_FAILURE.to_int(), content="92")
  inspect(@connection.SSH_MSG_CHANNEL_WINDOW_ADJUST.to_int(), content="93")
  inspect(@connection.SSH_MSG_CHANNEL_DATA.to_int(), content="94")
  inspect(@connection.SSH_MSG_CHANNEL_EXTENDED_DATA.to_int(), content="95")
  inspect(@connection.SSH_MSG_CHANNEL_EOF.to_int(), content="96")
  inspect(@connection.SSH_MSG_CHANNEL_CLOSE.to_int(), content="97")
  inspect(@connection.SSH_MSG_CHANNEL_REQUEST.to_int(), content="98")
  inspect(@connection.SSH_MSG_CHANNEL_SUCCESS.to_int(), content="99")
  inspect(@connection.SSH_MSG_CHANNEL_FAILURE.to_int(), content="100")
  inspect(@connection.SSH_EXTENDED_DATA_STDERR, content="1")
  inspect(@connection.SSH_OPEN_UNKNOWN_CHANNEL_TYPE, content="3")
}

///|
test "channel open: byte-exact encode and round trip" {
  let payload = @connection.encode_channel_open(
    channel_type="session",
    sender_channel=0,
    initial_window_size=2097152,
    maximum_packet_size=32768,
  )
  inspect(
    @hex.encode(payload[:]),
    content="5a" +
      "00000007" +
      "73657373696f6e" +
      "00000000" +
      "00200000" +
      "00008000",
  )
  let open = @connection.decode_channel_open(payload[:])
  inspect(open.channel_type, content="session")
  inspect(open.sender_channel, content="0")
  inspect(open.initial_window_size, content="2097152")
  inspect(open.maximum_packet_size, content="32768")
}

///|
test "channel open confirmation and failure round trip" {
  let ok = @connection.encode_channel_open_confirmation(
    recipient_channel=7,
    sender_channel=1,
    initial_window_size=64,
    maximum_packet_size=16,
  )
  inspect(
    @hex.encode(ok[:]),
    content="5b" + "00000007" + "00000001" + "00000040" + "00000010",
  )
  let c = @connection.decode_channel_open_confirmation(ok[:])
  inspect(c.recipient_channel, content="7")
  inspect(c.sender_channel, content="1")
  inspect(c.initial_window_size, content="64")
  inspect(c.maximum_packet_size, content="16")
  let bad = @connection.encode_channel_open_failure(
    recipient_channel=7,
    reason=@connection.SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
    description="only session is supported",
  )
  let (rc, reason, desc) = @connection.decode_channel_open_failure(bad[:])
  inspect(rc, content="7")
  inspect(reason, content="3")
  inspect(desc, content="only session is supported")
}

///|
test "channel data, extended data, window adjust, eof and close" {
  let d = @connection.encode_channel_data(recipient_channel=1, data=b"hi")
  inspect(@hex.encode(d[:]), content="5e" + "00000001" + "00000002" + "6869")
  let (dc, data) = @connection.decode_channel_data(d[:])
  inspect(dc, content="1")
  inspect(@hex.encode(data[:]), content="6869")
  let e = @connection.encode_channel_extended_data(
    recipient_channel=1,
    data_type=@connection.SSH_EXTENDED_DATA_STDERR,
    data=b"e",
  )
  inspect(
    @hex.encode(e[:]),
    content="5f" + "00000001" + "00000001" + "00000001" + "65",
  )
  let (ec, dtype, edata) = @connection.decode_channel_extended_data(e[:])
  inspect(ec, content="1")
  inspect(dtype, content="1")
  inspect(@hex.encode(edata[:]), content="65")
  let w = @connection.encode_channel_window_adjust(
    recipient_channel=2,
    bytes_to_add=1024,
  )
  inspect(@hex.encode(w[:]), content="5d" + "00000002" + "00000400")
  let (wc, add) = @connection.decode_channel_window_adjust(w[:])
  inspect(wc, content="2")
  inspect(add, content="1024")
  inspect(
    @hex.encode(@connection.encode_channel_eof(recipient_channel=3)[:]),
    content="60" + "00000003",
  )
  inspect(
    @connection.decode_channel_eof(b"\x60\x00\x00\x00\x03"[:]),
    content="3",
  )
  inspect(
    @hex.encode(@connection.encode_channel_close(recipient_channel=3)[:]),
    content="61" + "00000003",
  )
  inspect(
    @connection.decode_channel_close(b"\x61\x00\x00\x00\x03"[:]),
    content="3",
  )
}

///|
test "channel request: exec, shell, exit-status and an unknown request" {
  let x = @connection.encode_exec_request(
    recipient_channel=1,
    command="uname -a",
    want_reply=true,
  )
  inspect(
    @hex.encode(x[:]),
    content="62" +
      "00000001" +
      "00000004" +
      "65786563" +
      "01" +
      "00000008" +
      "756e616d65202d61",
  )
  let req = @connection.decode_channel_request(x[:])
  inspect(req.recipient_channel, content="1")
  inspect(req.want_reply, content="true")
  guard req.request is Exec(command) else { fail("expected Exec") }
  inspect(command, content="uname -a")
  let sh = @connection.encode_shell_request(
    recipient_channel=1,
    want_reply=true,
  )
  inspect(
    @hex.encode(sh[:]),
    content="62" + "00000001" + "00000005" + "7368656c6c" + "01",
  )
  guard @connection.decode_channel_request(sh[:]).request is Shell else {
    fail("expected Shell")
  }
  let st = @connection.encode_exit_status_request(
    recipient_channel=1,
    exit_status=3,
  )
  inspect(
    @hex.encode(st[:]),
    content="62" +
      "00000001" +
      "0000000b" +
      "657869742d737461747573" +
      "00" +
      "00000003",
  )
  guard @connection.decode_channel_request(st[:]).request is ExitStatus(code) else {
    fail("expected ExitStatus")
  }
  inspect(code, content="3")
  // A request we do not implement decodes as Other so the peer can be
  // answered CHANNEL_FAILURE rather than treated as a protocol error.
  // (`pty-req` used to be the example here; M5 implements it, so this
  // uses one we still do not support.)
  let x11 = b"\x62\x00\x00\x00\x01\x00\x00\x00\x07x11-req\x01rest"
  let other = @connection.decode_channel_request(x11[:])
  guard other.request is Other(name) else { fail("expected Other") }
  inspect(name, content="x11-req")
  inspect(other.want_reply, content="true")
}

///|
test "global request: want_reply and the success/failure replies" {
  let g = b"\x50\x00\x00\x00\x15hostkeys-00@openssh.com\x00"
  let payload = @connection.encode_global_request(
    name="hostkeys-00@openssh.com",
    want_reply=false,
  )
  inspect(
    @hex.encode(payload[:]),
    content="50" +
      "00000017" +
      "686f73746b6579732d3030406f70656e7373682e636f6d" +
      "00",
  )
  let (name, want_reply) = @connection.decode_global_request(payload[:])
  inspect(name, content="hostkeys-00@openssh.com")
  inspect(want_reply, content="false")
  ignore(g)
  inspect(@hex.encode(@connection.encode_request_failure()[:]), content="52")
}

///|
test "decoders reject the wrong message number and trailing bytes" {
  fn expect_err(
    thunk : () -> Unit raise @connection.ConnectionError,
  ) -> Unit raise {
    try thunk() catch {
      ConnectionError(_) => ()
    } noraise {
      _ => fail("expected a ConnectionError")
    }
  }
  expect_err(() => {
    ignore(
      @connection.decode_channel_data(
        b"\x5f\x00\x00\x00\x01\x00\x00\x00\x00"[:],
      ),
    )
  })
  expect_err(() => {
    ignore(@connection.decode_channel_eof(b"\x60\x00\x00\x00\x03\xff"[:]))
  })
  expect_err(() => {
    ignore(@connection.decode_channel_open(b"\x5a\x00\x00\x00\x07session"[:]))
  })
  expect_err(() => {
    ignore(@connection.decode_channel_window_adjust(b"\x5d\x00\x00\x00"[:]))
  })
}

///|
/// `direct-tcpip` (RFC 4254 section 7.2): the CHANNEL_OPEN carries four
/// type-specific fields after the common ones. Fixture built with Python's
/// `struct`, not by this code.
test "direct-tcpip: byte-exact channel open and round trip" {
  let extra = @connection.encode_direct_tcpip_extra(
    host="example.com",
    port=80,
    originator_host="127.0.0.1",
    originator_port=54321,
  )
  let payload = @connection.encode_channel_open(
    channel_type=@connection.CHANNEL_DIRECT_TCPIP,
    sender_channel=0,
    initial_window_size=2097152,
    maximum_packet_size=32768,
    extra~,
  )
  inspect(
    @hex.encode(payload[:]),
    content="5a0000000c6469726563742d746370697000000000002000000000800000" +
      "00000b6578616d706c652e636f6d00000050000000093132372e302e302e310000d431",
  )
  let open = @connection.decode_channel_open(payload[:])
  inspect(open.channel_type, content="direct-tcpip")
  let target = @connection.decode_direct_tcpip(open.extra[:])
  inspect(target.host, content="example.com")
  inspect(target.port, content="80")
  inspect(target.originator_host, content="127.0.0.1")
  inspect(target.originator_port, content="54321")
}

///|
test "direct-tcpip: a session open carries no type-specific data" {
  let payload = @connection.encode_channel_open(
    channel_type=@connection.CHANNEL_SESSION,
    sender_channel=0,
    initial_window_size=2097152,
    maximum_packet_size=32768,
  )
  assert_eq(@connection.decode_channel_open(payload[:]).extra, b"")
}

///|
test "direct-tcpip: a truncated or over-long target is refused" {
  let good = @connection.encode_direct_tcpip_extra(
    host="h",
    port=80,
    originator_host="o",
    originator_port=1,
  )
  try @connection.decode_direct_tcpip(good[0:good.length() - 1]) catch {
    ConnectionError(msg) => assert_true(msg.contains("direct-tcpip"))
  } noraise {
    _ => fail("expected a truncated target to raise")
  }
  try @connection.decode_direct_tcpip((good + b"\x00")[:]) catch {
    ConnectionError(msg) => assert_true(msg.contains("direct-tcpip"))
  } noraise {
    _ => fail("expected trailing bytes to raise")
  }
}
