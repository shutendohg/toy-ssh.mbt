// `direct-tcpip` on the server side (docs/04 Part B, docs/06 M5): one
// channel per forwarded TCP connection, so this is also where the channel
// table earns its keep — `ssh -L` keeps several open at once.

///|
/// A peer's CHANNEL_OPEN for `direct-tcpip`, addressed from its channel
/// `sender`.
fn forward_open(sender : UInt, host : String, port : UInt) -> Bytes {
  @connection.encode_channel_open(
    channel_type=@connection.CHANNEL_DIRECT_TCPIP,
    sender_channel=sender,
    initial_window_size=4096,
    maximum_packet_size=1024,
    extra=@connection.encode_direct_tcpip_extra(
      host~,
      port~,
      originator_host="127.0.0.1",
      originator_port=54321,
    ),
  )
}

///|
fn forwarding_server() -> @connection.ServerSession {
  @connection.ServerSession::new(
    window_size=4096,
    max_packet_size=1024,
    allow_forward=true,
  )
}

///|
test "direct-tcpip is refused unless forwarding is switched on" {
  // The default matters: a toy SSH server that forwards for anyone who
  // authenticates is an open relay onto whatever it can reach.
  let s = @connection.ServerSession::new(window_size=4096, max_packet_size=1024)
  let ev = s.on_payload(forward_open(7, "example.com", 80)[:])
  assert_eq(ev.length(), 0)
  let out = s.take_outgoing()
  assert_eq(out.length(), 1)
  let (recipient, reason, description) = @connection.decode_channel_open_failure(
    out[0][:],
  )
  assert_eq(recipient, 7)
  assert_eq(reason, @connection.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
  assert_true(description.contains("forward"))
}

///|
test "direct-tcpip: the channel is confirmed only once the connect succeeds" {
  let s = forwarding_server()
  let ev = s.on_payload(forward_open(7, "example.com", 80)[:])
  guard ev.length() == 1 else { fail("server events: \{ev.length()}") }
  guard ev[0] is ForwardRequest(channel~, host~, port~) else {
    fail("expected ForwardRequest")
  }
  inspect(host, content="example.com")
  inspect(port, content="80")
  // Nothing is sent yet: confirming before the TCP connect would mean
  // opening a channel we might immediately have to close.
  assert_eq(s.take_outgoing().length(), 0)
  s.forward_connected(channel~)
  let out = s.take_outgoing()
  assert_eq(out.length(), 1)
  let conf = @connection.decode_channel_open_confirmation(out[0][:])
  assert_eq(conf.recipient_channel, 7)
  assert_eq(conf.sender_channel, channel)
}

///|
test "direct-tcpip: a failed connect is reported as an open failure" {
  let s = forwarding_server()
  let ev = s.on_payload(forward_open(3, "nowhere.invalid", 9)[:])
  guard ev[0] is ForwardRequest(channel~, ..) else {
    fail("expected ForwardRequest")
  }
  s.forward_failed(channel~, description="connection refused")
  let out = s.take_outgoing()
  assert_eq(out.length(), 1)
  let (recipient, reason, description) = @connection.decode_channel_open_failure(
    out[0][:],
  )
  assert_eq(recipient, 3)
  assert_eq(reason, @connection.SSH_OPEN_CONNECT_FAILED)
  assert_eq(description, "connection refused")
  // The channel is gone; a later message for it is a protocol error.
  try
    s.on_payload(
      @connection.encode_channel_data(recipient_channel=channel, data=b"x")[:],
    )
  catch {
    ConnectionError(_) => ()
  } noraise {
    _ => fail("expected the forwarded channel to be gone")
  }
}

///|
test "direct-tcpip: bytes relay in both directions on one channel" {
  let s = forwarding_server()
  let ev = s.on_payload(forward_open(7, "example.com", 80)[:])
  guard ev[0] is ForwardRequest(channel~, ..) else {
    fail("expected ForwardRequest")
  }
  s.forward_connected(channel~)
  ignore(s.take_outgoing())
  // Peer to target.
  let ev2 = s.on_payload(
    @connection.encode_channel_data(recipient_channel=channel, data=b"GET /")[:],
  )
  guard ev2.length() == 1 else { fail("server events: \{ev2.length()}") }
  guard ev2[0] is Stdin(channel=got, data~) else { fail("expected Stdin") }
  assert_eq(got, channel)
  assert_eq(data, b"GET /")
  // Target to peer.
  s.send_data(channel~, b"200 OK"[:])
  let out = s.take_outgoing()
  assert_eq(out.length(), 1)
  let (recipient, back) = @connection.decode_channel_data(out[0][:])
  assert_eq(recipient, 7)
  assert_eq(back, b"200 OK")
  // The target hung up: EOF then CLOSE, in that order, behind the data.
  s.send_eof(channel~)
  s.close_channel(channel~)
  let out2 = s.take_outgoing()
  assert_eq(out2.length(), 2)
  assert_eq(out2[0][0], @connection.SSH_MSG_CHANNEL_EOF)
  assert_eq(out2[1][0], @connection.SSH_MSG_CHANNEL_CLOSE)
}

///|
test "direct-tcpip: several channels are open at once and stay apart" {
  let s = forwarding_server()
  let a = match s.on_payload(forward_open(1, "a.example", 80)[:])[0] {
    ForwardRequest(channel~, ..) => channel
    _ => fail("expected ForwardRequest")
  }
  let b = match s.on_payload(forward_open(2, "b.example", 443)[:])[0] {
    ForwardRequest(channel~, ..) => channel
    _ => fail("expected ForwardRequest")
  }
  assert_not_eq(a, b)
  s.forward_connected(channel=a)
  s.forward_connected(channel=b)
  ignore(s.take_outgoing())
  s.send_data(channel=a, b"to-a"[:])
  s.send_data(channel=b, b"to-b"[:])
  let out = s.take_outgoing()
  assert_eq(out.length(), 2)
  // Each carries the peer's own id for that channel, not the other's.
  // Which channel drains first is not part of the contract, so collect
  // the pairs rather than pinning an order.
  let seen = out
    .map(p => {
      let (recipient, data) = @connection.decode_channel_data(p[:])
      "\{recipient}:" + @hex.encode(data[:])
    })
    ..sort()
  debug_inspect(
    seen,
    content=(
      #|["1:746f2d61", "2:746f2d62"]
    ),
  )
  // Closing one leaves the other alone.
  ignore(s.on_payload(@connection.encode_channel_close(recipient_channel=a)[:]))
  s.send_data(channel=b, b"still here"[:])
  assert_eq(s.take_outgoing().length(), 2) // b's CLOSE reply, then b's data
}

///|
test "direct-tcpip: a session channel and a forward coexist" {
  let s = forwarding_server()
  let session_open = @connection.encode_channel_open(
    channel_type=@connection.CHANNEL_SESSION,
    sender_channel=0,
    initial_window_size=4096,
    maximum_packet_size=1024,
  )
  ignore(s.on_payload(session_open[:]))
  let conf = @connection.decode_channel_open_confirmation(
    s.take_outgoing()[0][:],
  )
  let session_channel = conf.sender_channel
  let ev = s.on_payload(forward_open(9, "example.com", 80)[:])
  guard ev[0] is ForwardRequest(channel~, ..) else {
    fail("expected ForwardRequest")
  }
  assert_not_eq(channel, session_channel)
  // The session channel still behaves like a session.
  let ev2 = s.on_payload(
    @connection.encode_exec_request(
      recipient_channel=session_channel,
      command="true",
      want_reply=true,
    )[:],
  )
  guard ev2[0] is ExecRequest(channel=exec_channel, command~) else {
    fail("expected ExecRequest")
  }
  assert_eq(exec_channel, session_channel)
  assert_eq(command, "true")
}

///|
test "direct-tcpip: a malformed target is a protocol error" {
  let s = forwarding_server()
  let bad = @connection.encode_channel_open(
    channel_type=@connection.CHANNEL_DIRECT_TCPIP,
    sender_channel=1,
    initial_window_size=4096,
    maximum_packet_size=1024,
    extra=b"\x00\x00\x00\x02ab",
  )
  try s.on_payload(bad[:]) catch {
    ConnectionError(msg) => assert_true(msg.contains("direct-tcpip"))
  } noraise {
    _ => fail("expected a ConnectionError")
  }
}

///|
test "an exec request cannot be aimed at a forwarded channel" {
  let s = forwarding_server()
  guard s.on_payload(forward_open(7, "example.com", 80)[:])[0]
    is ForwardRequest(channel~, ..) else {
    fail("expected ForwardRequest")
  }
  s.forward_connected(channel~)
  ignore(s.take_outgoing())
  let ev = s.on_payload(
    @connection.encode_exec_request(
      recipient_channel=channel,
      command="true",
      want_reply=true,
    )[:],
  )
  assert_eq(ev.length(), 0)
  let out = s.take_outgoing()
  assert_eq(out.length(), 1)
  assert_eq(out[0][0], @connection.SSH_MSG_CHANNEL_FAILURE)
}
