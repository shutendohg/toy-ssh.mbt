// The per-channel state machine and window accounting (docs/04 Part B,
// docs/06 M4 acceptance 4).

///|
/// Pump payloads between a client and a server session until neither has
/// anything left to send.
fn pump(
  c : @connection.ClientSession,
  s : @connection.ServerSession,
) -> (Array[@connection.ClientEvent], Array[@connection.ServerEvent]) raise {
  let ce : Array[@connection.ClientEvent] = []
  let se : Array[@connection.ServerEvent] = []
  for _ in 0..<50 {
    let from_c = c.take_outgoing()
    let from_s = s.take_outgoing()
    if from_c.is_empty() && from_s.is_empty() {
      break
    }
    for p in from_c {
      se.append(s.on_payload(p[:]))
    }
    for p in from_s {
      ce.append(c.on_payload(p[:]))
    }
  }
  (ce, se)
}

///|
test "exec: open, run, stdout, stderr, exit status and dual close" {
  let c = @connection.ClientSession::new(
    window_size=2097152,
    max_packet_size=32768,
  )
  let s = @connection.ServerSession::new(
    window_size=2097152,
    max_packet_size=32768,
  )
  c.request_exec("echo hello")
  let (ce, se) = pump(c, s)
  // The server saw the open and the exec request.
  guard se.length() == 1 else { fail("server events: \{se.length()}") }
  guard se[0] is ExecRequest(command~, ..) else { fail("expected ExecRequest") }
  inspect(command, content="echo hello")
  // The client saw the channel open and its request succeed.
  inspect(ce.length(), content="0")
  assert_true(c.is_running())
  // The server streams output, then reports the exit status and closes.
  s.send_data(channel=0, b"hello\n")
  s.send_stderr(channel=0, b"oops\n")
  s.finish(channel=0, exit_status=3)
  let (ce2, _) = pump(c, s)
  let seen = ce2.map(e => {
    match e {
      Stdout(d) => "out:" + @hex.encode(d[:])
      Stderr(d) => "err:" + @hex.encode(d[:])
      ExitStatus(code) => "exit:\{code}"
      Eof => "eof"
      Closed => "closed"
      OpenFailed(reason~, description~) => "openfail:\{reason}:\{description}"
      PtyRefused => "ptyrefused"
    }
  })
  debug_inspect(
    seen,
    content=(
      #|["out:68656c6c6f0a", "err:6f6f70730a", "exit:3", "eof", "closed"]
    ),
  )
  debug_inspect(c.exit_status(), content="Some(3)")
  assert_true(c.is_closed())
  assert_true(s.is_closed())
}

///|
test "shell: the server is told to start a shell" {
  let c = @connection.ClientSession::new(window_size=1024, max_packet_size=256)
  let s = @connection.ServerSession::new(window_size=1024, max_packet_size=256)
  c.request_shell()
  let (_, se) = pump(c, s)
  guard se.length() == 1 && se[0] is ShellRequest(..) else {
    fail("expected ShellRequest")
  }
  // Client stdin reaches the server as channel data.
  c.send_stdin(b"pwd\n")
  let (_, se2) = pump(c, s)
  guard se2.length() == 1 else { fail("server events: \{se2.length()}") }
  guard se2[0] is Stdin(data~, ..) else { fail("expected Stdin") }
  inspect(@hex.encode(data[:]), content="7077640a")
  // And the client's EOF closes the server's stdin.
  c.send_eof()
  let (_, se3) = pump(c, s)
  guard se3.length() == 1 && se3[0] is StdinEof(..) else {
    fail("expected StdinEof")
  }
}

///|
test "open failure: the client reports it and the channel is closed" {
  let c = @connection.ClientSession::new(window_size=64, max_packet_size=64)
  c.request_exec("true")
  let open = c.take_outgoing()
  inspect(open.length(), content="1")
  let payload = @connection.encode_channel_open_failure(
    recipient_channel=0,
    reason=@connection.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
    description="no sessions here",
  )
  let ev = c.on_payload(payload[:])
  guard ev.length() == 1 else { fail("client events: \{ev.length()}") }
  guard ev[0] is OpenFailed(reason~, description~) else {
    fail("expected OpenFailed")
  }
  inspect(reason, content="1")
  inspect(description, content="no sessions here")
  assert_true(c.is_closed())
}

///|
test "windowing: data is split to the peer's maximum packet size" {
  // A 300-byte payload with a 128-byte maximum must arrive as three
  // messages: the CHANNEL_DATA header costs 9 of those 128 bytes, so each
  // carries at most 119 (RFC 4254: never exceed maximum_packet_size).
  let c = @connection.ClientSession::new(window_size=4096, max_packet_size=128)
  let s = @connection.ServerSession::new(window_size=4096, max_packet_size=128)
  c.request_exec("cat")
  ignore(pump(c, s))
  s.send_data(channel=0, Bytes::makei(300, i => (i % 251).to_byte()))
  let out = s.take_outgoing()
  inspect(out.length(), content="3")
  let mut total = 0
  for p in out {
    let (_, data) = @connection.decode_channel_data(p[:])
    assert_true(data.length() <= 119)
    // The whole message, header included, fits the advertised maximum.
    assert_true(p.length() <= 128)
    total = total + data.length()
  }
  inspect(total, content="300")
}

///|
test "windowing: the sender stops at the peer's window and resumes on adjust" {
  // The client grants a 10-byte window, so the server may only send 10
  // bytes until it is replenished.
  let c = @connection.ClientSession::new(window_size=10, max_packet_size=128)
  let s = @connection.ServerSession::new(window_size=4096, max_packet_size=128)
  c.request_exec("cat")
  ignore(pump(c, s))
  s.send_data(channel=0, Bytes::make(25, b'x'))
  let first = s.take_outgoing()
  let mut sent = 0
  for p in first {
    let (_, data) = @connection.decode_channel_data(p[:])
    sent = sent + data.length()
  }
  inspect(sent, content="10")
  // Nothing more until the peer grants credit.
  inspect(s.take_outgoing().length(), content="0")
  ignore(
    s.on_payload(
      @connection.encode_channel_window_adjust(
        recipient_channel=0,
        bytes_to_add=15,
      )[:],
    ),
  )
  let second = s.take_outgoing()
  let mut sent2 = 0
  for p in second {
    let (_, data) = @connection.decode_channel_data(p[:])
    sent2 = sent2 + data.length()
  }
  inspect(sent2, content="15")
}

///|
test "windowing: the receiver replenishes the peer once it has consumed half" {
  // The server grants 100 bytes; after the client has sent more than half
  // of it the server must send a WINDOW_ADJUST so the transfer continues.
  let c = @connection.ClientSession::new(window_size=4096, max_packet_size=64)
  let s = @connection.ServerSession::new(window_size=100, max_packet_size=64)
  c.request_shell()
  ignore(pump(c, s))
  c.send_stdin(Bytes::make(40, b'a'))
  ignore(pump(c, s))
  // Under half consumed: no adjust yet.
  inspect(s.take_outgoing().length(), content="0")
  c.send_stdin(Bytes::make(40, b'b'))
  for p in c.take_outgoing() {
    ignore(s.on_payload(p[:]))
  }
  let adjust = s.take_outgoing()
  inspect(adjust.length(), content="1")
  let (_, add) = @connection.decode_channel_window_adjust(adjust[0][:])
  inspect(add, content="80")
}

///|
test "protocol errors: wrong channel id, a second exec, and data after close" {
  let c = @connection.ClientSession::new(window_size=64, max_packet_size=64)
  let s = @connection.ServerSession::new(window_size=64, max_packet_size=64)
  c.request_exec("true")
  ignore(pump(c, s))
  // A message for a channel we never opened.
  try
    s.on_payload(@connection.encode_channel_eof(recipient_channel=42)[:])
  catch {
    ConnectionError(_) => ()
  } noraise {
    _ => fail("expected an unknown-channel error")
  }
  // A second exec on the same channel (docs/04: refuse it).
  let second = @connection.encode_exec_request(
    recipient_channel=0,
    command="again",
    want_reply=true,
  )
  let ev = s.on_payload(second[:])
  inspect(ev.length(), content="0")
  let reply = s.take_outgoing()
  inspect(reply.length(), content="1")
  inspect(@connection.decode_channel_failure(reply[0][:]), content="0")
}

///|
test "an unsupported channel request is refused, as is an unknown global one" {
  let s = @connection.ServerSession::new(window_size=64, max_packet_size=64)
  let c = @connection.ClientSession::new(window_size=64, max_packet_size=64)
  c.request_shell()
  ignore(pump(c, s))
  // `pty-req` is implemented since M5, but only before the shell starts;
  // `x11-req` is not implemented at all. Both are refused here.
  let x11 = b"\x62\x00\x00\x00\x00\x00\x00\x00\x07x11-req\x01rest"
  inspect(s.on_payload(x11[:]).length(), content="0")
  let reply = s.take_outgoing()
  inspect(reply.length(), content="1")
  inspect(@connection.decode_channel_failure(reply[0][:]), content="0")
  // A global request with want_reply must be failed, not ignored.
  let g = @connection.encode_global_request(
    name="hostkeys-00@openssh.com",
    want_reply=true,
  )
  inspect(s.on_payload(g[:]).length(), content="0")
  let greply = s.take_outgoing()
  inspect(greply.length(), content="1")
  inspect(@hex.encode(greply[0][:]), content="52")
  // Without want_reply it is silently ignored.
  let g2 = @connection.encode_global_request(
    name="hostkeys-00@openssh.com",
    want_reply=false,
  )
  inspect(s.on_payload(g2[:]).length(), content="0")
  inspect(s.take_outgoing().length(), content="0")
}

///|
test "ordering: EOF and the exit status never overtake queued data" {
  // A real interop failure: with data waiting for window credit, an EOF
  // queued afterwards went out first, and the peer then rejected the data
  // that followed as arriving after EOF.
  let c = @connection.ClientSession::new(window_size=4096, max_packet_size=128)
  let s = @connection.ServerSession::new(window_size=10, max_packet_size=128)
  c.request_exec("cat")
  ignore(pump(c, s))
  // 25 bytes of stdin against a 10-byte window, then EOF straight away.
  c.send_stdin(Bytes::make(25, b'x'))
  c.send_eof()
  let first = c.take_outgoing()
  // Only data fits now; the EOF must still be queued.
  debug_inspect(first.map(p => p[0].to_int()), content="[94]")
  ignore(
    c.on_payload(
      @connection.encode_channel_window_adjust(
        recipient_channel=0,
        bytes_to_add=100,
      )[:],
    ),
  )
  let rest = c.take_outgoing()
  // The remaining data, then EOF last.
  inspect(rest.length(), content="2")
  inspect(rest[0][0].to_int(), content="94")
  inspect(rest[1][0].to_int(), content="96")
}

///|
test "ordering: the server's exit status and close follow its last output" {
  let c = @connection.ClientSession::new(window_size=10, max_packet_size=128)
  let s = @connection.ServerSession::new(window_size=4096, max_packet_size=128)
  c.request_exec("seq 1 100")
  ignore(pump(c, s))
  s.send_data(channel=0, Bytes::make(25, b'o'))
  s.finish(channel=0, exit_status=0)
  let first = s.take_outgoing()
  inspect(first.length(), content="1")
  inspect(first[0][0].to_int(), content="94")
  ignore(
    s.on_payload(
      @connection.encode_channel_window_adjust(
        recipient_channel=0,
        bytes_to_add=100,
      )[:],
    ),
  )
  let rest = s.take_outgoing()
  // data, then exit-status (98), EOF (96), CLOSE (97).
  debug_inspect(rest.map(p => p[0].to_int()), content="[94, 98, 96, 97]")
}

///|
test "ordering: flow control is never blocked behind our own data" {
  // A WINDOW_ADJUST stuck behind data that is itself waiting for credit
  // would deadlock both sides. It goes out on the priority lane.
  let c = @connection.ClientSession::new(window_size=100, max_packet_size=128)
  let s = @connection.ServerSession::new(window_size=100, max_packet_size=128)
  c.request_exec("cat")
  ignore(pump(c, s))
  // Exhaust the server's credit so its own output is stuck.
  s.send_data(channel=0, Bytes::make(500, b'o'))
  ignore(s.take_outgoing())
  // The client now sends enough to owe the server a WINDOW_ADJUST.
  c.send_stdin(Bytes::make(80, b'i'))
  for p in c.take_outgoing() {
    ignore(s.on_payload(p[:]))
  }
  let out = s.take_outgoing()
  // The adjust is there even though the server's own data is blocked.
  inspect(out.length(), content="1")
  inspect(out[0][0].to_int(), content="93")
}

///|
test "a peer advertising an absurd window and packet size cannot make us overrun the transport" {
  // The transport caps a whole SSH packet at 35000 bytes and aborts if a
  // payload exceeds it, so a connection message must stay under that no
  // matter what the peer advertises.
  let s = @connection.ServerSession::new(
    window_size=4096,
    max_packet_size=32768,
  )
  let open = @connection.encode_channel_open(
    channel_type="session",
    sender_channel=0,
    initial_window_size=0xffffffff,
    maximum_packet_size=0xffffffff,
  )
  ignore(s.on_payload(open[:]))
  ignore(
    s.on_payload(
      @connection.encode_exec_request(
        recipient_channel=0,
        command="yes",
        want_reply=true,
      )[:],
    ),
  )
  ignore(s.take_outgoing())
  // One megabyte of output, far more than any single packet may carry.
  s.send_data(channel=0, Bytes::make(1048576, b'o'))
  let out = s.take_outgoing()
  assert_true(out.length() > 1)
  let mut total = 0
  for p in out {
    // Every message fits a 35000-byte SSH packet with room for the
    // transport's own framing.
    assert_true(p.length() <= 32768)
    let (_, data) = @connection.decode_channel_data(p[:])
    total = total + data.length()
  }
  inspect(total, content="1048576")
}

///|
test "the server refuses channel messages before the channel is open" {
  // Every channel-addressed message needs a channel. Accepting these
  // before CHANNEL_OPEN let a peer ask for exec without ever opening one.
  for
    payload in [
      @connection.encode_exec_request(
        recipient_channel=0,
        command="true",
        want_reply=true,
      ),
      @connection.encode_channel_window_adjust(
        recipient_channel=0,
        bytes_to_add=1,
      ),
      @connection.encode_channel_data(recipient_channel=0, data=b"x"),
      @connection.encode_channel_eof(recipient_channel=0),
      @connection.encode_channel_close(recipient_channel=0),
    ] {
    let s = @connection.ServerSession::new(
      window_size=4096,
      max_packet_size=32768,
    )
    try s.on_payload(payload[:]) catch {
      ConnectionError(_) => ()
    } noraise {
      _ => fail("expected a ConnectionError for message \{payload[0].to_int()}")
    }
  }
}

///|
test "the client holds EOF until the peer's channel id is known" {
  // Its own standard input can reach end of file before the server
  // confirms the channel. An EOF built then was addressed to channel 0 and
  // sent on a channel that did not exist yet; it worked against OpenSSH
  // only because sshd happens to number the first session 0.
  let c = @connection.ClientSession::new(window_size=4096, max_packet_size=128)
  c.request_exec("cat")
  let open = c.take_outgoing()
  inspect(open.length(), content="1")
  c.send_eof()
  // Nothing may go out yet.
  inspect(c.take_outgoing().length(), content="0")
  // The server confirms with its own id 7.
  ignore(
    c.on_payload(
      @connection.encode_channel_open_confirmation(
        recipient_channel=0,
        sender_channel=7,
        initial_window_size=4096,
        maximum_packet_size=128,
      )[:],
    ),
  )
  let out = c.take_outgoing()
  // The exec request, then the EOF, both addressed to channel 7.
  debug_inspect(out.map(p => p[0].to_int()), content="[98, 96]")
  inspect(@connection.decode_channel_eof(out[1][:]), content="7")
}

///|
test "the client refuses channel messages before the channel is confirmed" {
  for
    payload in [
      @connection.encode_channel_data(recipient_channel=0, data=b"x"),
      @connection.encode_channel_window_adjust(
        recipient_channel=0,
        bytes_to_add=0xffffffff,
      ),
      @connection.encode_channel_eof(recipient_channel=0),
      @connection.encode_channel_close(recipient_channel=0),
      @connection.encode_channel_success(recipient_channel=0),
    ] {
    let c = @connection.ClientSession::new(
      window_size=4096,
      max_packet_size=128,
    )
    c.request_exec("true")
    ignore(c.take_outgoing())
    try c.on_payload(payload[:]) catch {
      ConnectionError(_) => ()
    } noraise {
      _ => fail("expected a ConnectionError for message \{payload[0].to_int()}")
    }
  }
}
