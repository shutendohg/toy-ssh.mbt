///|
/// One `session` channel, as a pair of sans-IO state machines: the client
/// asks for `exec` or `shell`, the server runs it and streams the result
/// back. Only one channel per connection, which is all docs/00 asks for.
///
/// Both machines share the same bookkeeping (`Channel` below): our channel
/// id, the peer's id to address, how much credit the peer has granted us
/// (`send_window`), how much we have granted the peer (`recv_window`), the
/// peer's maximum packet size, and which of EOF and CLOSE have been sent
/// and received.

///|
/// Our channel id. There is only ever one channel, so it is always 0.
const LOCAL_CHANNEL : UInt = 0

///|
/// Bytes a CHANNEL_DATA message spends on its own header: the message
/// number, the recipient channel, and the data length prefix.
const DATA_OVERHEAD : UInt = 9

///|
/// CHANNEL_EXTENDED_DATA adds the `data_type_code`.
const EXTENDED_DATA_OVERHEAD : UInt = 13

///|
/// The smallest `maximum_packet_size` we can work with: it has to leave
/// room for a message header plus something worth sending.
const MIN_MAX_PACKET : UInt = 64

///|
/// A queued byte stream waiting for window credit, and its data type:
/// stdout goes out as CHANNEL_DATA, stderr as CHANNEL_EXTENDED_DATA.
struct Pending {
  data : Bytes
  /// `None` for CHANNEL_DATA, `Some(code)` for CHANNEL_EXTENDED_DATA.
  extended : UInt?
}

///|
/// Flow-control and teardown state shared by both sides.
struct Channel {
  mut remote_channel : UInt
  /// Credit the peer has granted us; we may send this many data bytes.
  mut send_window : UInt
  /// The peer's maximum packet size: no single message may carry more.
  mut send_max_packet : UInt
  /// Credit we have granted the peer, and how much of it it has used.
  mut recv_window : UInt
  mut recv_used : UInt
  /// The window we advertise, used to decide when to replenish.
  recv_window_size : UInt
  /// The maximum packet size we advertise to the peer.
  recv_max_packet : UInt
  mut eof_sent : Bool
  mut eof_received : Bool
  mut close_sent : Bool
  mut close_received : Bool
}

///|
fn Channel::new(window_size : UInt, max_packet_size : UInt) -> Channel {
  {
    remote_channel: 0,
    send_window: 0,
    send_max_packet: 0,
    recv_window: window_size,
    recv_used: 0,
    recv_window_size: window_size,
    recv_max_packet: max_packet_size,
    eof_sent: false,
    eof_received: false,
    close_sent: false,
    close_received: false,
  }
}

///|
/// Split `queue` into messages that fit both the peer's window and its
/// maximum packet size, appending them to `out`. Whatever does not fit
/// stays queued until a WINDOW_ADJUST arrives.
fn Channel::drain(
  self : Channel,
  queue : Array[Pending],
  out : Array[Bytes],
) -> Unit {
  while !queue.is_empty() && self.send_window > 0 {
    let head = queue[0]
    // `maximum_packet_size` caps the whole message, so the header has to
    // come out of it: sending more than the peer allows risks a
    // disconnect, while sending less is always legal.
    let overhead = match head.extended {
      None => DATA_OVERHEAD
      Some(_) => EXTENDED_DATA_OVERHEAD
    }
    let payload_cap = self.send_max_packet - overhead
    let room = if self.send_window < payload_cap {
      self.send_window
    } else {
      payload_cap
    }
    let take = if head.data.length().reinterpret_as_uint() < room {
      head.data.length()
    } else {
      room.reinterpret_as_int()
    }
    if take == 0 {
      break
    }
    let chunk = head.data[0:take]
    out.push(
      match head.extended {
        None =>
          encode_channel_data(recipient_channel=self.remote_channel, data=chunk)
        Some(code) =>
          encode_channel_extended_data(
            recipient_channel=self.remote_channel,
            data_type=code,
            data=chunk,
          )
      },
    )
    self.send_window = self.send_window - take.reinterpret_as_uint()
    if take == head.data.length() {
      queue.remove(0) |> ignore
    } else {
      queue[0] = { data: head.data[take:].to_owned(), extended: head.extended, }
    }
  }
}

///|
/// Account for `len` bytes received from the peer and, once more than half
/// the advertised window has been used, grant it back (docs/04 "a simple
/// correct policy"). Returns the WINDOW_ADJUST to send, if any.
fn Channel::consume(self : Channel, len : Int) -> Bytes? raise ConnectionError {
  let used = len.reinterpret_as_uint()
  if used > self.recv_window {
    raise ConnectionError(
      "peer sent \{used} byte(s) with only \{self.recv_window} of window left",
    )
  }
  self.recv_window = self.recv_window - used
  self.recv_used = self.recv_used + used
  if self.recv_used * 2 >= self.recv_window_size {
    let grant = self.recv_used
    self.recv_used = 0
    self.recv_window = self.recv_window + grant
    Some(
      encode_channel_window_adjust(
        recipient_channel=self.remote_channel,
        bytes_to_add=grant,
      ),
    )
  } else {
    None
  }
}

///|
/// Note a WINDOW_ADJUST from the peer.
fn Channel::grant(self : Channel, add : UInt) -> Unit {
  self.send_window = self.send_window + add
}

///|
/// Record what the peer granted us when the channel opened. A
/// `maximum_packet_size` too small to hold a message header would leave us
/// unable to send anything, so refuse it rather than loop forever.
fn Channel::accept_peer_limits(
  self : Channel,
  remote_channel : UInt,
  initial_window_size : UInt,
  maximum_packet_size : UInt,
  ctx : String,
) -> Unit raise ConnectionError {
  if maximum_packet_size < MIN_MAX_PACKET {
    raise ConnectionError(
      "\{ctx}: maximum_packet_size \{maximum_packet_size} is below the \{MIN_MAX_PACKET}-byte minimum",
    )
  }
  self.remote_channel = remote_channel
  self.send_window = initial_window_size
  self.send_max_packet = maximum_packet_size
}

///|
/// Every message must address the one channel we have. A peer naming any
/// other id is talking about a channel that does not exist.
fn check_channel(channel : UInt, ctx : String) -> Unit raise ConnectionError {
  if channel != LOCAL_CHANNEL {
    raise ConnectionError("\{ctx}: no channel \{channel}")
  }
}

///|
/// EOF means the peer will send no more data in that direction, so data
/// after it is a protocol violation rather than something to deliver.
fn Channel::check_not_after_eof(
  self : Channel,
  ctx : String,
) -> Unit raise ConnectionError {
  if self.eof_received {
    raise ConnectionError("\{ctx}: the peer already sent EOF")
  }
}

///|
fn Channel::is_closed(self : Channel) -> Bool {
  self.close_sent && self.close_received
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

///|
/// What the client's session reports to its caller.
pub(all) enum ClientEvent {
  /// The command's standard output.
  Stdout(Bytes)
  /// The command's standard error (EXTENDED_DATA with code 1).
  Stderr(Bytes)
  /// The command's exit status; record it and exit with it, like `ssh`.
  ExitStatus(UInt)
  /// The peer will send no more data.
  Eof
  /// Both sides have sent CLOSE; the channel is gone.
  Closed
  /// The server refused to open the channel.
  OpenFailed(reason~ : UInt, description~ : String)
} derive(Debug, Eq)

///|
/// The client half: opens one `session`, asks for `exec` or `shell`, feeds
/// standard input, and collects output and the exit status.
pub struct ClientSession {
  ch : Channel
  outgoing : Array[Bytes]
  queue : Array[Pending]
  /// The request to send once the channel is open.
  mut want : ChannelRequestKind?
  mut request_sent : Bool
  mut running : Bool
  mut exit_status : UInt?
  mut open_failed : Bool
}

///|
/// `window_size` and `max_packet_size` are what we advertise to the peer.
pub fn ClientSession::new(
  window_size~ : UInt,
  max_packet_size~ : UInt,
) -> ClientSession {
  {
    ch: Channel::new(window_size, max_packet_size),
    outgoing: [],
    queue: [],
    want: None,
    request_sent: false,
    running: false,
    exit_status: None,
    open_failed: false,
  }
}

///|
/// Payloads queued for the peer; the caller hands each to the transport.
pub fn ClientSession::take_outgoing(self : ClientSession) -> Array[Bytes] {
  self.ch.drain(self.queue, self.outgoing)
  let out = self.outgoing.copy()
  self.outgoing.clear()
  out
}

///|
/// The exit status, once the server has reported one.
pub fn ClientSession::exit_status(self : ClientSession) -> UInt? {
  self.exit_status
}

///|
/// True between the request succeeding and the channel closing.
pub fn ClientSession::is_running(self : ClientSession) -> Bool {
  self.running
}

///|
pub fn ClientSession::is_closed(self : ClientSession) -> Bool {
  self.ch.is_closed() || self.open_failed
}

///|
/// Open the channel and run `command` on the server.
pub fn ClientSession::request_exec(
  self : ClientSession,
  command : String,
) -> Unit {
  self.start(Exec(command))
}

///|
/// Open the channel and start the server's login shell.
pub fn ClientSession::request_shell(self : ClientSession) -> Unit {
  self.start(Shell)
}

///|
fn ClientSession::start(
  self : ClientSession,
  want : ChannelRequestKind,
) -> Unit {
  guard self.want is None else {
    abort("ClientSession: a request is already in flight")
  }
  self.want = Some(want)
  self.outgoing.push(
    encode_channel_open(
      channel_type=CHANNEL_SESSION,
      sender_channel=LOCAL_CHANNEL,
      initial_window_size=self.ch.recv_window_size,
      maximum_packet_size=self.ch.recv_max_packet,
    ),
  )
}

///|
/// Queue standard input for the command.
pub fn ClientSession::send_stdin(
  self : ClientSession,
  data : BytesView,
) -> Unit {
  if data.length() == 0 {
    return
  }
  self.queue.push({ data: data.to_owned(), extended: None, })
}

///|
/// Tell the peer we will send no more standard input.
pub fn ClientSession::send_eof(self : ClientSession) -> Unit {
  if self.ch.eof_sent {
    return
  }
  self.ch.eof_sent = true
  self.outgoing.push(
    encode_channel_eof(recipient_channel=self.ch.remote_channel),
  )
}

///|
/// Feed one decrypted payload from the peer.
pub fn ClientSession::on_payload(
  self : ClientSession,
  payload : BytesView,
) -> Array[ClientEvent] raise ConnectionError {
  let events : Array[ClientEvent] = []
  guard payload.length() > 0 else {
    raise ConnectionError("empty connection payload")
  }
  match payload[0] {
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
      let c = decode_channel_open_confirmation(payload)
      check_channel(c.recipient_channel, "CHANNEL_OPEN_CONFIRMATION")
      self.ch.accept_peer_limits(
        c.sender_channel,
        c.initial_window_size,
        c.maximum_packet_size,
        "CHANNEL_OPEN_CONFIRMATION",
      )
      guard self.want is Some(want) else {
        raise ConnectionError("CHANNEL_OPEN_CONFIRMATION: nothing was opened")
      }
      if self.request_sent {
        raise ConnectionError("CHANNEL_OPEN_CONFIRMATION: channel already open")
      }
      self.request_sent = true
      self.outgoing.push(
        match want {
          Exec(command) =>
            encode_exec_request(
              recipient_channel=self.ch.remote_channel,
              command~,
              want_reply=true,
            )
          Shell =>
            encode_shell_request(
              recipient_channel=self.ch.remote_channel,
              want_reply=true,
            )
          _ => abort("ClientSession: unsupported request")
        },
      )
    }
    SSH_MSG_CHANNEL_OPEN_FAILURE => {
      let (recipient, reason, description) = decode_channel_open_failure(
        payload,
      )
      check_channel(recipient, "CHANNEL_OPEN_FAILURE")
      self.open_failed = true
      events.push(OpenFailed(reason~, description~))
    }
    SSH_MSG_CHANNEL_SUCCESS => {
      check_channel(decode_channel_success(payload), "CHANNEL_SUCCESS")
      self.running = true
    }
    SSH_MSG_CHANNEL_FAILURE => {
      check_channel(decode_channel_failure(payload), "CHANNEL_FAILURE")
      raise ConnectionError("the server refused the exec or shell request")
    }
    SSH_MSG_CHANNEL_DATA => {
      let (channel, data) = decode_channel_data(payload)
      check_channel(channel, "CHANNEL_DATA")
      self.ch.check_not_after_eof("CHANNEL_DATA")
      self.receive(data.length(), events)
      events.push(Stdout(data))
    }
    SSH_MSG_CHANNEL_EXTENDED_DATA => {
      let (channel, code, data) = decode_channel_extended_data(payload)
      check_channel(channel, "CHANNEL_EXTENDED_DATA")
      self.receive(data.length(), events)
      // Anything but stderr is unknown to us; RFC 4254 lets us drop it.
      if code == SSH_EXTENDED_DATA_STDERR {
        events.push(Stderr(data))
      }
    }
    SSH_MSG_CHANNEL_WINDOW_ADJUST => {
      let (channel, add) = decode_channel_window_adjust(payload)
      check_channel(channel, "CHANNEL_WINDOW_ADJUST")
      self.ch.grant(add)
    }
    SSH_MSG_CHANNEL_REQUEST => {
      let req = decode_channel_request(payload)
      check_channel(req.recipient_channel, "CHANNEL_REQUEST")
      match req.request {
        ExitStatus(code) => {
          self.exit_status = Some(code)
          events.push(ExitStatus(code))
        }
        _ =>
          if req.want_reply {
            self.outgoing.push(
              encode_channel_failure(recipient_channel=self.ch.remote_channel),
            )
          }
      }
    }
    SSH_MSG_CHANNEL_EOF => {
      check_channel(decode_channel_eof(payload), "CHANNEL_EOF")
      self.ch.eof_received = true
      events.push(Eof)
    }
    SSH_MSG_CHANNEL_CLOSE => {
      check_channel(decode_channel_close(payload), "CHANNEL_CLOSE")
      self.ch.close_received = true
      self.close(events)
    }
    SSH_MSG_GLOBAL_REQUEST => {
      let (_, want_reply) = decode_global_request(payload)
      if want_reply {
        self.outgoing.push(encode_request_failure())
      }
    }
    other =>
      raise ConnectionError("connection: unexpected message \{other.to_int()}")
  }
  events
}

///|
/// Account for received data and queue a window adjust if one is due.
fn ClientSession::receive(
  self : ClientSession,
  len : Int,
  events : Array[ClientEvent],
) -> Unit raise ConnectionError {
  ignore(events)
  if self.ch.consume(len) is Some(adjust) {
    self.outgoing.push(adjust)
  }
}

///|
/// Answer the peer's CLOSE with our own and report the channel gone.
fn ClientSession::close(
  self : ClientSession,
  events : Array[ClientEvent],
) -> Unit {
  if !self.ch.close_sent {
    self.ch.close_sent = true
    self.outgoing.push(
      encode_channel_close(recipient_channel=self.ch.remote_channel),
    )
  }
  self.running = false
  events.push(Closed)
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

///|
/// What the server's session reports to its caller, which owns the child
/// process.
pub(all) enum ServerEvent {
  /// Run this command (`sh -c command`) and stream its output back.
  ExecRequest(String)
  /// Start the login shell with no PTY.
  ShellRequest
  /// Standard input for the running command.
  Stdin(Bytes)
  /// The peer will send no more standard input; close the child's stdin.
  StdinEof
  /// Both sides have sent CLOSE; the channel is gone.
  Closed
} derive(Debug, Eq)

///|
/// The server half: accepts one `session`, reports the request, and
/// streams the command's output and exit status back.
pub struct ServerSession {
  ch : Channel
  outgoing : Array[Bytes]
  queue : Array[Pending]
  mut opened : Bool
  mut started : Bool
  mut finished : Bool
}

///|
pub fn ServerSession::new(
  window_size~ : UInt,
  max_packet_size~ : UInt,
) -> ServerSession {
  {
    ch: Channel::new(window_size, max_packet_size),
    outgoing: [],
    queue: [],
    opened: false,
    started: false,
    finished: false,
  }
}

///|
pub fn ServerSession::take_outgoing(self : ServerSession) -> Array[Bytes] {
  self.ch.drain(self.queue, self.outgoing)
  let out = self.outgoing.copy()
  self.outgoing.clear()
  out
}

///|
pub fn ServerSession::is_closed(self : ServerSession) -> Bool {
  self.ch.is_closed()
}

///|
/// Queue the command's standard output.
pub fn ServerSession::send_stdout(
  self : ServerSession,
  data : BytesView,
) -> Unit {
  if data.length() == 0 {
    return
  }
  self.queue.push({ data: data.to_owned(), extended: None, })
}

///|
/// Queue the command's standard error.
pub fn ServerSession::send_stderr(
  self : ServerSession,
  data : BytesView,
) -> Unit {
  if data.length() == 0 {
    return
  }
  self.queue.push({
    data: data.to_owned(),
    extended: Some(SSH_EXTENDED_DATA_STDERR),
  })
}

///|
/// The command exited: report its status, then EOF and CLOSE (docs/04
/// "Closing & exit status"). Queued output is still flushed first, because
/// `take_outgoing` drains the data queue before these.
pub fn ServerSession::finish(self : ServerSession, exit_status~ : UInt) -> Unit {
  if self.finished {
    return
  }
  self.finished = true
  self.ch.drain(self.queue, self.outgoing)
  self.outgoing.push(
    encode_exit_status_request(
      recipient_channel=self.ch.remote_channel,
      exit_status~,
    ),
  )
  if !self.ch.eof_sent {
    self.ch.eof_sent = true
    self.outgoing.push(
      encode_channel_eof(recipient_channel=self.ch.remote_channel),
    )
  }
  if !self.ch.close_sent {
    self.ch.close_sent = true
    self.outgoing.push(
      encode_channel_close(recipient_channel=self.ch.remote_channel),
    )
  }
}

///|
pub fn ServerSession::on_payload(
  self : ServerSession,
  payload : BytesView,
) -> Array[ServerEvent] raise ConnectionError {
  let events : Array[ServerEvent] = []
  guard payload.length() > 0 else {
    raise ConnectionError("empty connection payload")
  }
  match payload[0] {
    SSH_MSG_CHANNEL_OPEN => {
      let open = decode_channel_open(payload)
      if self.opened {
        // One channel per connection is all we support.
        self.outgoing.push(
          encode_channel_open_failure(
            recipient_channel=open.sender_channel,
            reason=SSH_OPEN_RESOURCE_SHORTAGE,
            description="only one session channel is supported",
          ),
        )
        return events
      }
      if open.channel_type != CHANNEL_SESSION {
        self.outgoing.push(
          encode_channel_open_failure(
            recipient_channel=open.sender_channel,
            reason=SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
            description="only \{CHANNEL_SESSION} is supported",
          ),
        )
        return events
      }
      self.opened = true
      self.ch.accept_peer_limits(
        open.sender_channel,
        open.initial_window_size,
        open.maximum_packet_size,
        "CHANNEL_OPEN",
      )
      self.outgoing.push(
        encode_channel_open_confirmation(
          recipient_channel=open.sender_channel,
          sender_channel=LOCAL_CHANNEL,
          initial_window_size=self.ch.recv_window_size,
          maximum_packet_size=self.ch.recv_max_packet,
        ),
      )
    }
    SSH_MSG_CHANNEL_REQUEST => {
      let req = decode_channel_request(payload)
      check_channel(req.recipient_channel, "CHANNEL_REQUEST")
      let accepted = match req.request {
        // docs/04: refuse a second exec or shell on the same channel.
        Exec(command) if !self.started => {
          self.started = true
          events.push(ExecRequest(command))
          true
        }
        Shell if !self.started => {
          self.started = true
          events.push(ShellRequest)
          true
        }
        // Everything else, `pty-req` included, is refused.
        _ => false
      }
      if req.want_reply {
        self.outgoing.push(
          if accepted {
            encode_channel_success(recipient_channel=self.ch.remote_channel)
          } else {
            encode_channel_failure(recipient_channel=self.ch.remote_channel)
          },
        )
      }
    }
    SSH_MSG_CHANNEL_DATA => {
      let (channel, data) = decode_channel_data(payload)
      check_channel(channel, "CHANNEL_DATA")
      self.ch.check_not_after_eof("CHANNEL_DATA")
      if self.ch.consume(data.length()) is Some(adjust) {
        self.outgoing.push(adjust)
      }
      events.push(Stdin(data))
    }
    SSH_MSG_CHANNEL_WINDOW_ADJUST => {
      let (channel, add) = decode_channel_window_adjust(payload)
      check_channel(channel, "CHANNEL_WINDOW_ADJUST")
      self.ch.grant(add)
    }
    SSH_MSG_CHANNEL_EOF => {
      check_channel(decode_channel_eof(payload), "CHANNEL_EOF")
      self.ch.eof_received = true
      events.push(StdinEof)
    }
    SSH_MSG_CHANNEL_CLOSE => {
      check_channel(decode_channel_close(payload), "CHANNEL_CLOSE")
      self.ch.close_received = true
      if !self.ch.close_sent {
        self.ch.close_sent = true
        self.outgoing.push(
          encode_channel_close(recipient_channel=self.ch.remote_channel),
        )
      }
      events.push(Closed)
    }
    SSH_MSG_GLOBAL_REQUEST => {
      let (_, want_reply) = decode_global_request(payload)
      if want_reply {
        self.outgoing.push(encode_request_failure())
      }
    }
    other =>
      raise ConnectionError("connection: unexpected message \{other.to_int()}")
  }
  events
}
