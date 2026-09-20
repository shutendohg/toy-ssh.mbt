// `pty-req` and `window-change` (RFC 4254 sections 6.2 and 6.7, docs/06
// M5). Fixtures built with Python's `struct`, not by this code.

///|
/// ECHO (opcode 53) on, then TTY_OP_END.
fn test_modes() -> Bytes {
  b"\x35\x00\x00\x00\x01\x00"
}

///|
test "pty-req: byte-exact encode and round trip" {
  let payload = @connection.encode_pty_request(
    recipient_channel=0,
    term="xterm-256color",
    cols=80,
    rows=24,
    width_px=640,
    height_px=480,
    modes=test_modes(),
    want_reply=true,
  )
  inspect(
    @hex.encode(payload[:]),
    content="6200000000000000077074792d726571010000000e787465726d2d3235366" +
      "36f6c6f720000005000000018000002800000_1e000000006350000000100".replace(
        old="_",
        new="0",
      ),
  )
  let req = @connection.decode_channel_request(payload[:])
  inspect(req.recipient_channel, content="0")
  inspect(req.want_reply, content="true")
  guard req.request
    is PtyReq(term~, cols~, rows~, width_px~, height_px~, modes~) else {
    fail("expected PtyReq, got \{Repr(req.request)}")
  }
  inspect(term, content="xterm-256color")
  inspect(cols, content="80")
  inspect(rows, content="24")
  inspect(width_px, content="640")
  inspect(height_px, content="480")
  assert_eq(modes, test_modes())
}

///|
test "window-change: byte-exact encode and round trip" {
  let payload = @connection.encode_window_change_request(
    recipient_channel=0,
    cols=100,
    rows=30,
    width_px=800,
    height_px=600,
  )
  inspect(
    @hex.encode(payload[:]),
    content="62000000000000000d77696e646f772d6368616e676500000000640000001e0000032000000258",
  )
  let req = @connection.decode_channel_request(payload[:])
  // RFC 4254 section 6.7: window-change never asks for a reply.
  inspect(req.want_reply, content="false")
  guard req.request is WindowChange(cols~, rows~, width_px~, height_px~) else {
    fail("expected WindowChange")
  }
  inspect(cols, content="100")
  inspect(rows, content="30")
  inspect(width_px, content="800")
  inspect(height_px, content="600")
}

///|
/// A server that has accepted a `session` channel, and its channel id.
fn session_server() -> (@connection.ServerSession, UInt) raise {
  let s = @connection.ServerSession::new(window_size=4096, max_packet_size=1024)
  ignore(
    s.on_payload(
      @connection.encode_channel_open(
        channel_type=@connection.CHANNEL_SESSION,
        sender_channel=0,
        initial_window_size=4096,
        maximum_packet_size=1024,
      )[:],
    ),
  )
  let conf = @connection.decode_channel_open_confirmation(
    s.take_outgoing()[0][:],
  )
  (s, conf.sender_channel)
}

///|
test "pty-req before a shell is accepted and reported" {
  let (s, channel) = session_server()
  let ev = s.on_payload(
    @connection.encode_pty_request(
      recipient_channel=channel,
      term="xterm",
      cols=80,
      rows=24,
      width_px=0,
      height_px=0,
      modes=test_modes(),
      want_reply=true,
    )[:],
  )
  guard ev.length() == 1 else { fail("server events: \{ev.length()}") }
  guard ev[0] is PtyRequest(channel=got, term~, cols~, rows~, ..) else {
    fail("expected PtyRequest")
  }
  assert_eq(got, channel)
  assert_eq(term, "xterm")
  assert_eq(cols, 80)
  assert_eq(rows, 24)
  let out = s.take_outgoing()
  assert_eq(out.length(), 1)
  assert_eq(out[0][0], @connection.SSH_MSG_CHANNEL_SUCCESS)
  // The shell that follows is reported as running on a terminal.
  let ev2 = s.on_payload(
    @connection.encode_shell_request(recipient_channel=channel, want_reply=true)[:],
  )
  guard ev2[0] is ShellRequest(pty=true, ..) else {
    fail("expected ShellRequest with a pty, got \{Repr(ev2[0])}")
  }
}

///|
test "without pty-req a shell is reported as having no terminal" {
  let (s, channel) = session_server()
  let ev = s.on_payload(
    @connection.encode_shell_request(recipient_channel=channel, want_reply=true)[:],
  )
  guard ev[0] is ShellRequest(pty=false, ..) else {
    fail("expected ShellRequest without a pty")
  }
}

///|
test "pty-req after the command started is refused" {
  let (s, channel) = session_server()
  ignore(
    s.on_payload(
      @connection.encode_shell_request(
        recipient_channel=channel,
        want_reply=false,
      )[:],
    ),
  )
  ignore(s.take_outgoing())
  let ev = s.on_payload(
    @connection.encode_pty_request(
      recipient_channel=channel,
      term="xterm",
      cols=80,
      rows=24,
      width_px=0,
      height_px=0,
      modes=test_modes(),
      want_reply=true,
    )[:],
  )
  assert_eq(ev.length(), 0)
  let out = s.take_outgoing()
  assert_eq(out.length(), 1)
  assert_eq(out[0][0], @connection.SSH_MSG_CHANNEL_FAILURE)
}

///|
test "window-change is reported and never answered" {
  let (s, channel) = session_server()
  // A resize only means something once a terminal exists.
  ignore(
    s.on_payload(
      @connection.encode_pty_request(
        recipient_channel=channel,
        term="xterm",
        cols=80,
        rows=24,
        width_px=0,
        height_px=0,
        modes=test_modes(),
        want_reply=false,
      )[:],
    ),
  )
  ignore(s.take_outgoing())
  let ev = s.on_payload(
    @connection.encode_window_change_request(
      recipient_channel=channel,
      cols=120,
      rows=40,
      width_px=0,
      height_px=0,
    )[:],
  )
  guard ev.length() == 1 else { fail("server events: \{ev.length()}") }
  guard ev[0] is WindowChange(channel=got, cols~, rows~, ..) else {
    fail("expected WindowChange")
  }
  assert_eq(got, channel)
  assert_eq(cols, 120)
  assert_eq(rows, 40)
  // want_reply is false on the wire, so nothing goes back.
  assert_eq(s.take_outgoing().length(), 0)
}

///|
test "a pty cannot be asked for on a forwarded channel" {
  let s = @connection.ServerSession::new(
    window_size=4096,
    max_packet_size=1024,
    allow_forward=true,
  )
  guard s.on_payload(
      @connection.encode_channel_open(
        channel_type=@connection.CHANNEL_DIRECT_TCPIP,
        sender_channel=1,
        initial_window_size=4096,
        maximum_packet_size=1024,
        extra=@connection.encode_direct_tcpip_extra(
          host="h",
          port=80,
          originator_host="o",
          originator_port=1,
        ),
      )[:],
    )[0]
    is ForwardRequest(channel~, ..) else {
    fail("expected ForwardRequest")
  }
  s.forward_connected(channel~)
  ignore(s.take_outgoing())
  let ev = s.on_payload(
    @connection.encode_pty_request(
      recipient_channel=channel,
      term="xterm",
      cols=80,
      rows=24,
      width_px=0,
      height_px=0,
      modes=test_modes(),
      want_reply=true,
    )[:],
  )
  assert_eq(ev.length(), 0)
  assert_eq(s.take_outgoing()[0][0], @connection.SSH_MSG_CHANNEL_FAILURE)
}

///|
test "a second pty-req on the same channel is refused" {
  // `pty-req` starts nothing, so nothing else stops a peer from repeating
  // it — and each one costs the server a real pseudo-terminal.
  let (s, channel) = session_server()
  fn ask() -> Array[@connection.ServerEvent] raise {
    s.on_payload(
      @connection.encode_pty_request(
        recipient_channel=channel,
        term="xterm",
        cols=80,
        rows=24,
        width_px=0,
        height_px=0,
        modes=test_modes(),
        want_reply=true,
      )[:],
    )
  }

  assert_eq(ask().length(), 1)
  assert_eq(s.take_outgoing()[0][0], @connection.SSH_MSG_CHANNEL_SUCCESS)
  assert_eq(ask().length(), 0)
  assert_eq(s.take_outgoing()[0][0], @connection.SSH_MSG_CHANNEL_FAILURE)
  // The first terminal still counts: the shell that follows runs on it.
  let ev = s.on_payload(
    @connection.encode_shell_request(
      recipient_channel=channel,
      want_reply=false,
    )[:],
  )
  guard ev[0] is ShellRequest(pty=true, ..) else {
    fail("expected ShellRequest with a pty")
  }
}

// ---------------------------------------------------------------------------
// Client side: asking for a terminal
// ---------------------------------------------------------------------------

///|
fn test_pty_params() -> @connection.PtyParams {
  {
    term: "xterm-256color",
    cols: 80,
    rows: 24,
    width_px: 0,
    height_px: 0,
    modes: test_modes(),
  }
}

///|
/// Drive the two halves until both are quiet, the way `pump` does in
/// session_test.mbt.
fn pty_pump(
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
test "client pty: pty-req is asked for, then the shell runs on it" {
  let c = @connection.ClientSession::new(window_size=1024, max_packet_size=256)
  let s = @connection.ServerSession::new(window_size=1024, max_packet_size=256)
  c.request_pty(test_pty_params())
  c.request_shell()
  let (_, se) = pty_pump(c, s)
  guard se.length() == 2 else { fail("server events: \{se.length()}") }
  guard se[0] is PtyRequest(term~, cols~, rows~, ..) else {
    fail("expected PtyRequest first, got \{Repr(se[0])}")
  }
  inspect(term, content="xterm-256color")
  inspect(cols, content="80")
  inspect(rows, content="24")
  guard se[1] is ShellRequest(pty~, ..) else {
    fail("expected ShellRequest second, got \{Repr(se[1])}")
  }
  assert_true(pty)
  assert_true(c.is_running())
}

///|
/// The shell must not be asked for until the terminal is granted: a server
/// that refuses the terminal would otherwise already be starting a shell
/// on pipes, which is not what the user asked for.
test "client pty: the shell waits for the pty-req reply" {
  let c = @connection.ClientSession::new(window_size=1024, max_packet_size=256)
  let s = @connection.ServerSession::new(window_size=1024, max_packet_size=256)
  c.request_pty(test_pty_params())
  c.request_shell()
  for p in c.take_outgoing() {
    ignore(s.on_payload(p[:]))
  }
  for p in s.take_outgoing() {
    ignore(c.on_payload(p[:]))
  }
  let first = c.take_outgoing()
  guard first.length() == 1 else {
    fail("expected one message after the open, got \{first.length()}")
  }
  guard @connection.decode_channel_request(first[0][:]).request is PtyReq(..) else {
    fail("expected pty-req alone")
  }
  assert_false(c.is_running())
}

///|
/// A server refusing `pty-req` is exercising RFC 4254 section 6.2, not
/// breaking the protocol: a restricted or pty-starved server says no this
/// way. So the session ends, but as a refusal the caller can report — not
/// as a framing error we would accuse the peer of on the wire.
test "client pty: a refused terminal ends the session without blaming the peer" {
  let c = @connection.ClientSession::new(window_size=1024, max_packet_size=256)
  let s = @connection.ServerSession::new(window_size=1024, max_packet_size=256)
  c.request_pty(test_pty_params())
  c.request_shell()
  for p in c.take_outgoing() {
    ignore(s.on_payload(p[:]))
  }
  for p in s.take_outgoing() {
    ignore(c.on_payload(p[:]))
  }
  ignore(c.take_outgoing())
  let failed = @connection.encode_channel_failure(recipient_channel=0)
  let ev = c.on_payload(failed[:])
  guard ev.length() == 1 && ev[0] is PtyRefused else {
    fail("expected PtyRefused, got \{ev.length()} event(s)")
  }
  assert_true(c.is_closed())
  assert_false(c.is_running())
}

///|
/// A CHANNEL_FAILURE for the `exec` or `shell` itself is still a hard
/// error: we asked for the one thing the channel exists to do.
test "client pty: a refused shell is still an error" {
  let c = @connection.ClientSession::new(window_size=1024, max_packet_size=256)
  let s = @connection.ServerSession::new(window_size=1024, max_packet_size=256)
  c.request_shell()
  for p in c.take_outgoing() {
    ignore(s.on_payload(p[:]))
  }
  for p in s.take_outgoing() {
    ignore(c.on_payload(p[:]))
  }
  ignore(c.take_outgoing())
  let failed = @connection.encode_channel_failure(recipient_channel=0)
  try c.on_payload(failed[:]) |> ignore catch {
    ConnectionError(msg) => assert_true(msg.contains("shell"))
  } noraise {
    _ => fail("expected the refusal to raise")
  }
}

///|
test "client pty: window-change reaches the server" {
  let c = @connection.ClientSession::new(window_size=1024, max_packet_size=256)
  let s = @connection.ServerSession::new(window_size=1024, max_packet_size=256)
  c.request_pty(test_pty_params())
  c.request_shell()
  ignore(pty_pump(c, s))
  c.send_window_change(cols=100, rows=30, width_px=800, height_px=600)
  let out = c.take_outgoing()
  guard out.length() == 1 else { fail("expected one message") }
  assert_eq(
    out[0],
    @connection.encode_window_change_request(
      recipient_channel=0,
      cols=100,
      rows=30,
      width_px=800,
      height_px=600,
    ),
  )
  let se = s.on_payload(out[0][:])
  guard se.length() == 1 && se[0] is WindowChange(cols~, rows~, ..) else {
    fail("expected WindowChange")
  }
  inspect(cols, content="100")
  inspect(rows, content="30")
}

///|
/// A plain `shell` must stay plain: nothing may slip a terminal into the
/// path the non-PTY interop runs exercise.
test "client pty: a plain shell asks for no terminal" {
  let c = @connection.ClientSession::new(window_size=1024, max_packet_size=256)
  let s = @connection.ServerSession::new(window_size=1024, max_packet_size=256)
  c.request_shell()
  let (_, se) = pty_pump(c, s)
  guard se.length() == 1 && se[0] is ShellRequest(pty~, ..) else {
    fail("expected one ShellRequest")
  }
  assert_false(pty)
}

///|
/// `ssh -t host command` also runs on a terminal, so the terminal is not
/// tied to `shell`: the request that follows it is whatever was asked for.
test "client pty: exec can run on a terminal too" {
  let c = @connection.ClientSession::new(window_size=1024, max_packet_size=256)
  let s = @connection.ServerSession::new(window_size=1024, max_packet_size=256)
  c.request_pty(test_pty_params())
  c.request_exec("top -b -n 1")
  let (_, se) = pty_pump(c, s)
  guard se.length() == 2 else { fail("server events: \{se.length()}") }
  guard se[0] is PtyRequest(..) else { fail("expected PtyRequest first") }
  guard se[1] is ExecRequest(command~, ..) else {
    fail("expected ExecRequest second, got \{Repr(se[1])}")
  }
  inspect(command, content="top -b -n 1")
  assert_true(c.is_running())
}
