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
/// The largest connection message we will build, whatever the peer
/// advertises.
///
/// The transport caps a whole SSH packet at 35000 bytes and treats a
/// payload beyond that as a programmer error, so trusting a peer's
/// `maximum_packet_size` would let it push us over that limit: an
/// advertised 4 GiB turned a megabyte of output into one message.
const MAX_CHANNEL_MESSAGE : UInt = 32768

///|
/// One item of the ordered outgoing stream.
///
/// Data waits for window credit, and anything queued behind it has to wait
/// too: EOF means "no more data", so letting it overtake queued data makes
/// the peer reject the data that follows. Flow control and request replies
/// do *not* belong here — see the `priority` lane, which must never be
/// blocked behind our own data or the two sides can deadlock waiting for
/// each other's window.
enum Pending {
  /// `None` for CHANNEL_DATA, `Some(code)` for CHANNEL_EXTENDED_DATA.
  Data(data~ : Bytes, extended~ : UInt?)
  /// Ordered after the data before it, and encoded only when drained:
  /// the peer's channel id is not known until it confirms the channel, so
  /// baking it in at queue time addressed everything to channel 0.
  Eof
  Close
  ExitStatus(UInt)
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
  /// Set once the peer has told us its channel id and limits.
  mut peer_known : Bool
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
    peer_known: false,
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
  // Nothing in this queue can be addressed until the peer has told us its
  // channel id and packet limit.
  if !self.peer_known {
    return
  }
  while !queue.is_empty() {
    match queue[0] {
      Eof => {
        out.push(encode_channel_eof(recipient_channel=self.remote_channel))
        queue.remove(0) |> ignore
      }
      Close => {
        out.push(encode_channel_close(recipient_channel=self.remote_channel))
        queue.remove(0) |> ignore
      }
      ExitStatus(code) => {
        out.push(
          encode_exit_status_request(
            recipient_channel=self.remote_channel,
            exit_status=code,
          ),
        )
        queue.remove(0) |> ignore
      }
      Data(data~, extended~) => {
        if self.send_window == 0 {
          return
        }
        // `maximum_packet_size` caps the whole message, so the header has
        // to come out of it: sending more than the peer allows risks a
        // disconnect, while sending less is always legal.
        let overhead = match extended {
          None => DATA_OVERHEAD
          Some(_) => EXTENDED_DATA_OVERHEAD
        }
        let limit = if self.send_max_packet < MAX_CHANNEL_MESSAGE {
          self.send_max_packet
        } else {
          MAX_CHANNEL_MESSAGE
        }
        // `accept_peer_limits` refuses anything below MIN_MAX_PACKET, so
        // this cannot underflow; guard anyway rather than rely on it from
        // two files away.
        if limit <= overhead {
          return
        }
        let payload_cap = limit - overhead
        let room = if self.send_window < payload_cap {
          self.send_window
        } else {
          payload_cap
        }
        let take = if data.length().reinterpret_as_uint() < room {
          data.length()
        } else {
          room.reinterpret_as_int()
        }
        if take == 0 {
          return
        }
        let chunk = data[0:take]
        out.push(
          match extended {
            None =>
              encode_channel_data(
                recipient_channel=self.remote_channel,
                data=chunk,
              )
            Some(code) =>
              encode_channel_extended_data(
                recipient_channel=self.remote_channel,
                data_type=code,
                data=chunk,
              )
          },
        )
        self.send_window = self.send_window - take.reinterpret_as_uint()
        if take == data.length() {
          queue.remove(0) |> ignore
        } else {
          queue[0] = Data(data=data[take:].to_owned(), extended~)
        }
      }
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
  self.peer_known = true
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
/// The same check plus "a channel exists at all": a channel-addressed
/// message that arrives before the channel was opened and confirmed names
/// something that does not exist yet.
fn check_open_channel(
  opened : Bool,
  channel : UInt,
  ctx : String,
) -> Unit raise ConnectionError {
  if !opened {
    raise ConnectionError("\{ctx}: no channel has been opened")
  }
  check_channel(channel, ctx)
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
/// How many bytes are queued and not yet sent, so a caller feeding us
/// standard input can stop reading instead of buffering without bound.
pub fn ClientSession::queued_bytes(self : ClientSession) -> Int {
  let mut total = 0
  for item in self.queue {
    match item {
      Data(data~, ..) => total = total + data.length()
      _ => ()
    }
  }
  total
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
  self.queue.push(Data(data=data.to_owned(), extended=None))
}

///|
/// Tell the peer we will send no more standard input.
pub fn ClientSession::send_eof(self : ClientSession) -> Unit {
  if self.ch.eof_sent {
    return
  }
  self.ch.eof_sent = true
  // Queued behind any data still waiting for window credit: EOF means "no
  // more data", so overtaking it makes the peer reject what follows.
  self.queue.push(Eof)
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
      check_open_channel(
        self.ch.peer_known,
        decode_channel_success(payload),
        "CHANNEL_SUCCESS",
      )
      self.running = true
    }
    SSH_MSG_CHANNEL_FAILURE => {
      check_open_channel(
        self.ch.peer_known,
        decode_channel_failure(payload),
        "CHANNEL_FAILURE",
      )
      raise ConnectionError("the server refused the exec or shell request")
    }
    SSH_MSG_CHANNEL_DATA => {
      let (channel, data) = decode_channel_data(payload)
      check_open_channel(self.ch.peer_known, channel, "CHANNEL_DATA")
      self.ch.check_not_after_eof("CHANNEL_DATA")
      self.receive(data.length(), events)
      events.push(Stdout(data))
    }
    SSH_MSG_CHANNEL_EXTENDED_DATA => {
      let (channel, code, data) = decode_channel_extended_data(payload)
      check_open_channel(self.ch.peer_known, channel, "CHANNEL_EXTENDED_DATA")
      self.receive(data.length(), events)
      // Anything but stderr is unknown to us; RFC 4254 lets us drop it.
      if code == SSH_EXTENDED_DATA_STDERR {
        events.push(Stderr(data))
      }
    }
    SSH_MSG_CHANNEL_WINDOW_ADJUST => {
      let (channel, add) = decode_channel_window_adjust(payload)
      check_open_channel(self.ch.peer_known, channel, "CHANNEL_WINDOW_ADJUST")
      self.ch.grant(add)
    }
    SSH_MSG_CHANNEL_REQUEST => {
      let req = decode_channel_request(payload)
      check_open_channel(
        self.ch.peer_known,
        req.recipient_channel,
        "CHANNEL_REQUEST",
      )
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
      check_open_channel(
        self.ch.peer_known,
        decode_channel_eof(payload),
        "CHANNEL_EOF",
      )
      self.ch.eof_received = true
      events.push(Eof)
    }
    SSH_MSG_CHANNEL_CLOSE => {
      check_open_channel(
        self.ch.peer_known,
        decode_channel_close(payload),
        "CHANNEL_CLOSE",
      )
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
/// What an open channel is for. A `session` runs a command; a forward
/// relays bytes to a TCP address the peer named.
enum ChannelPurpose {
  Session
  Forward
} derive(Eq)

///|
/// One open channel on the server: its purpose, its flow-control state and
/// its own ordered send queue. Queues are per channel because credit is:
/// one channel stalled on its window must not hold up another.
struct ServerChannel {
  purpose : ChannelPurpose
  ch : Channel
  queue : Array[Pending]
  /// Forwards only: false until the TCP connect succeeded and we sent the
  /// confirmation. Nothing may be addressed to the peer before that.
  mut confirmed : Bool
  /// Sessions only: an exec or shell has been accepted.
  mut started : Bool
  /// Sessions only: a `pty-req` was accepted before anything started.
  mut pty : Bool
  mut finished : Bool
}

///|
/// What the server's session reports to its caller, which owns the child
/// process or the forwarded socket. Every event names the channel it is
/// about: several may be open at once.
pub(all) enum ServerEvent {
  /// Run this command (`sh -c command`) and stream its output back.
  ExecRequest(channel~ : UInt, command~ : String)
  /// Start the login shell. `pty` is true when the peer asked for a
  /// terminal first and we accepted it, so the caller runs the shell on
  /// the pty rather than on pipes.
  ShellRequest(channel~ : UInt, pty~ : Bool)
  /// The peer wants a terminal on this channel, before it starts
  /// anything. `modes` is the raw encoded modes string.
  PtyRequest(
    channel~ : UInt,
    term~ : String,
    cols~ : UInt,
    rows~ : UInt,
    width_px~ : UInt,
    height_px~ : UInt,
    modes~ : Bytes
  )
  /// The peer's terminal was resized.
  WindowChange(
    channel~ : UInt,
    cols~ : UInt,
    rows~ : UInt,
    width_px~ : UInt,
    height_px~ : UInt
  )
  /// Connect to `host`:`port` and relay the channel to it, then call
  /// `forward_connected` or `forward_failed`. Nothing is sent to the peer
  /// until one of those happens.
  ForwardRequest(channel~ : UInt, host~ : String, port~ : UInt)
  /// Data from the peer: standard input for a session, bytes for the
  /// forwarded socket.
  Stdin(channel~ : UInt, data~ : Bytes)
  /// The peer will send no more; close that direction.
  StdinEof(channel~ : UInt)
  /// Both sides have sent CLOSE; the channel is gone.
  Closed(channel~ : UInt)
} derive(Debug, Eq)

///|
/// The server half: accepts channels, reports what each one is for, and
/// streams data, exit statuses and teardown back.
pub struct ServerSession {
  channels : Map[UInt, ServerChannel]
  outgoing : Array[Bytes]
  /// The window and packet size we advertise on every channel we accept.
  window_size : UInt
  max_packet_size : UInt
  /// Whether `direct-tcpip` is allowed at all. Off by default: a server
  /// that forwards for anyone who authenticates is an open relay onto
  /// whatever it can reach from where it runs.
  allow_forward : Bool
  /// Our channel ids, handed out in order and never reused.
  mut next_id : UInt
  /// One `session` at a time, as before M5; forwards are unlimited.
  mut session_open : Bool
  /// Whether any channel has ever been opened, which is what makes
  /// "no channels left" mean "the peer is done" rather than "not started".
  mut opened_any : Bool
}

///|
pub fn ServerSession::new(
  window_size~ : UInt,
  max_packet_size~ : UInt,
  allow_forward? : Bool = false,
) -> ServerSession {
  {
    channels: {},
    outgoing: [],
    window_size,
    max_packet_size,
    allow_forward,
    next_id: 0,
    session_open: false,
    opened_any: false,
  }
}

///|
/// The channel `id`, or a `ConnectionError` naming it: a peer addressing a
/// channel we do not have is talking about something that does not exist.
fn ServerSession::channel(
  self : ServerSession,
  id : UInt,
  ctx : String,
) -> ServerChannel raise ConnectionError {
  match self.channels.get(id) {
    Some(c) => c
    None => raise ConnectionError("\{ctx}: no channel \{id}")
  }
}

///|
/// Payloads queued for the peer; the caller hands each to the transport.
/// Every channel gets its turn, so one blocked on its window does not
/// starve the others.
pub fn ServerSession::take_outgoing(self : ServerSession) -> Array[Bytes] {
  for _, c in self.channels {
    if c.confirmed {
      c.ch.drain(c.queue, self.outgoing)
    }
  }
  let out = self.outgoing.copy()
  self.outgoing.clear()
  out
}

///|
/// True once a channel has been opened and every channel has since gone.
/// A connection that has not opened anything yet is not "closed": a caller
/// that hangs up on this would tear the connection down right after
/// authentication.
pub fn ServerSession::is_closed(self : ServerSession) -> Bool {
  self.opened_any && self.channels.is_empty()
}

///|
/// Bytes queued and not yet sent on one channel, so whoever feeds it can
/// stop reading instead of buffering without bound.
pub fn ServerSession::queued_bytes(
  self : ServerSession,
  channel~ : UInt,
) -> Int {
  match self.channels.get(channel) {
    None => 0
    Some(c) => {
      let mut total = 0
      for item in c.queue {
        match item {
          Data(data~, ..) => total = total + data.length()
          _ => ()
        }
      }
      total
    }
  }
}

///|
/// Queue data for the peer: a command's standard output, or bytes read
/// from the forwarded socket.
pub fn ServerSession::send_data(
  self : ServerSession,
  channel~ : UInt,
  data : BytesView,
) -> Unit {
  if data.length() == 0 {
    return
  }
  match self.channels.get(channel) {
    // The channel can be gone already: the socket pump and the peer's
    // CLOSE race, and losing that race is not an error.
    None => ()
    Some(c) => c.queue.push(Data(data=data.to_owned(), extended=None))
  }
}

///|
/// Queue a command's standard error (EXTENDED_DATA, code 1).
pub fn ServerSession::send_stderr(
  self : ServerSession,
  channel~ : UInt,
  data : BytesView,
) -> Unit {
  if data.length() == 0 {
    return
  }
  match self.channels.get(channel) {
    None => ()
    Some(c) =>
      c.queue.push(
        Data(data=data.to_owned(), extended=Some(SSH_EXTENDED_DATA_STDERR)),
      )
  }
}

///|
/// Tell the peer this channel will carry no more data from us. Queued
/// behind whatever is still waiting for window credit.
pub fn ServerSession::send_eof(self : ServerSession, channel~ : UInt) -> Unit {
  match self.channels.get(channel) {
    None => ()
    Some(c) =>
      if !c.ch.eof_sent {
        c.ch.eof_sent = true
        c.queue.push(Eof)
      }
  }
}

///|
/// Close the channel from our side.
pub fn ServerSession::close_channel(
  self : ServerSession,
  channel~ : UInt,
) -> Unit {
  match self.channels.get(channel) {
    None => ()
    Some(c) =>
      if !c.ch.close_sent {
        c.ch.close_sent = true
        c.queue.push(Close)
      }
  }
}

///|
/// The command exited: report its status, then EOF and CLOSE (docs/04
/// "Closing & exit status"). Queued output is flushed first, because
/// `drain` works through the queue in order.
pub fn ServerSession::finish(
  self : ServerSession,
  channel~ : UInt,
  exit_status~ : UInt,
) -> Unit {
  match self.channels.get(channel) {
    None => ()
    Some(c) => {
      if c.finished {
        return
      }
      c.finished = true
      c.queue.push(ExitStatus(exit_status))
      if !c.ch.eof_sent {
        c.ch.eof_sent = true
        c.queue.push(Eof)
      }
      if !c.ch.close_sent {
        c.ch.close_sent = true
        c.queue.push(Close)
      }
    }
  }
}

///|
/// The TCP connect for a forwarded channel succeeded: confirm it, which is
/// the first thing the peer hears about this channel.
pub fn ServerSession::forward_connected(
  self : ServerSession,
  channel~ : UInt,
) -> Unit {
  guard self.channels.get(channel) is Some(c) else { return }
  guard c.purpose == Forward && !c.confirmed else {
    abort("ServerSession: channel \{channel} is not a pending forward")
  }
  c.confirmed = true
  self.outgoing.push(
    encode_channel_open_confirmation(
      recipient_channel=c.ch.remote_channel,
      sender_channel=channel,
      initial_window_size=c.ch.recv_window_size,
      maximum_packet_size=c.ch.recv_max_packet,
    ),
  )
}

///|
/// The TCP connect failed: refuse the channel and forget it. The peer
/// never saw it open, so this is an open failure rather than a close.
pub fn ServerSession::forward_failed(
  self : ServerSession,
  channel~ : UInt,
  description~ : String,
) -> Unit {
  guard self.channels.get(channel) is Some(c) else { return }
  guard c.purpose == Forward && !c.confirmed else {
    abort("ServerSession: channel \{channel} is not a pending forward")
  }
  self.outgoing.push(
    encode_channel_open_failure(
      recipient_channel=c.ch.remote_channel,
      reason=SSH_OPEN_CONNECT_FAILED,
      description~,
    ),
  )
  self.channels.remove(channel)
}

///|
/// Take the next channel id. Ids are never reused, so a stale message
/// naming a closed channel is rejected instead of hitting a new one.
fn ServerSession::allocate(self : ServerSession) -> UInt {
  let id = self.next_id
  self.next_id = self.next_id + 1
  id
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
    SSH_MSG_CHANNEL_OPEN => self.on_channel_open(payload, events)
    SSH_MSG_CHANNEL_REQUEST => {
      let req = decode_channel_request(payload)
      let c = self.channel(req.recipient_channel, "CHANNEL_REQUEST")
      let fresh_session = c.purpose == Session && !c.started
      // One terminal per session: `pty-req` starts nothing, so without
      // this a peer could ask again and again, and each request costs the
      // server a real pty.
      let want_pty = fresh_session && !c.pty
      let accepted = match req.request {
        // docs/04: refuse a second exec or shell on the same channel, and
        // anything at all on a forwarded one — it carries bytes, not
        // commands.
        Exec(command) if fresh_session => {
          c.started = true
          events.push(ExecRequest(channel=req.recipient_channel, command~))
          true
        }
        Shell if fresh_session => {
          c.started = true
          events.push(ShellRequest(channel=req.recipient_channel, pty=c.pty))
          true
        }
        // A terminal is only meaningful on a session, and only before the
        // command that would run on it (RFC 4254 section 6.2 puts
        // `pty-req` first; honouring a late one would mean re-parenting a
        // running process).
        PtyReq(term~, cols~, rows~, width_px~, height_px~, modes~) if want_pty => {
          c.pty = true
          events.push(
            PtyRequest(
              channel=req.recipient_channel,
              term~,
              cols~,
              rows~,
              width_px~,
              height_px~,
              modes~,
            ),
          )
          true
        }
        // A resize is only interesting once there is a terminal, and it
        // never wants a reply.
        WindowChange(cols~, rows~, width_px~, height_px~) if c.pty => {
          events.push(
            WindowChange(
              channel=req.recipient_channel,
              cols~,
              rows~,
              width_px~,
              height_px~,
            ),
          )
          true
        }
        // Everything else is refused.
        _ => false
      }
      if req.want_reply {
        self.outgoing.push(
          if accepted {
            encode_channel_success(recipient_channel=c.ch.remote_channel)
          } else {
            encode_channel_failure(recipient_channel=c.ch.remote_channel)
          },
        )
      }
    }
    SSH_MSG_CHANNEL_DATA => {
      let (channel, data) = decode_channel_data(payload)
      let c = self.channel(channel, "CHANNEL_DATA")
      c.ch.check_not_after_eof("CHANNEL_DATA")
      if c.ch.consume(data.length()) is Some(adjust) {
        self.outgoing.push(adjust)
      }
      events.push(Stdin(channel~, data~))
    }
    SSH_MSG_CHANNEL_WINDOW_ADJUST => {
      let (channel, add) = decode_channel_window_adjust(payload)
      self.channel(channel, "CHANNEL_WINDOW_ADJUST").ch.grant(add)
    }
    SSH_MSG_CHANNEL_EOF => {
      let channel = decode_channel_eof(payload)
      self.channel(channel, "CHANNEL_EOF").ch.eof_received = true
      events.push(StdinEof(channel~))
    }
    SSH_MSG_CHANNEL_CLOSE => {
      let channel = decode_channel_close(payload)
      let c = self.channel(channel, "CHANNEL_CLOSE")
      c.ch.close_received = true
      if !c.ch.close_sent {
        c.ch.close_sent = true
        self.outgoing.push(
          encode_channel_close(recipient_channel=c.ch.remote_channel),
        )
      }
      if c.purpose == Session {
        self.session_open = false
      }
      self.channels.remove(channel)
      events.push(Closed(channel~))
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
/// A peer's CHANNEL_OPEN: accept a `session` (one at a time) straight
/// away, hold a `direct-tcpip` until the caller has connected, refuse
/// anything else.
fn ServerSession::on_channel_open(
  self : ServerSession,
  payload : BytesView,
  events : Array[ServerEvent],
) -> Unit raise ConnectionError {
  let open = decode_channel_open(payload)
  fn refuse(reason : UInt, description : String) -> Unit {
    self.outgoing.push(
      encode_channel_open_failure(
        recipient_channel=open.sender_channel,
        reason~,
        description~,
      ),
    )
  }

  let purpose = match open.channel_type {
    CHANNEL_SESSION => {
      // `session` defines no type-specific data, so anything after the
      // common fields is something we do not understand.
      if open.extra.length() > 0 {
        raise ConnectionError(
          "CHANNEL_OPEN: \{open.extra.length()} trailing byte(s) on a session open",
        )
      }
      if self.session_open {
        // One session channel per connection is all we support.
        refuse(
          SSH_OPEN_RESOURCE_SHORTAGE,
          "only one session channel is supported",
        )
        return
      }
      Session
    }
    CHANNEL_DIRECT_TCPIP => {
      if !self.allow_forward {
        refuse(
          SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
          "tcp forwarding is not enabled on this server",
        )
        return
      }
      Forward
    }
    other => {
      refuse(
        SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
        "channel type \{other} is not supported",
      )
      return
    }
  }
  // Read the target before committing to anything: an unreadable open is
  // a protocol violation, not a channel to refuse politely.
  let target = match purpose {
    Forward => Some(decode_direct_tcpip(open.extra[:]))
    Session => None
  }
  let id = self.allocate()
  self.opened_any = true
  let ch = Channel::new(self.window_size, self.max_packet_size)
  ch.accept_peer_limits(
    open.sender_channel,
    open.initial_window_size,
    open.maximum_packet_size,
    "CHANNEL_OPEN",
  )
  self.channels[id] = {
    purpose,
    ch,
    queue: [],
    // A session is confirmed here and now; a forward waits for its TCP
    // connect to succeed.
    confirmed: purpose == Session,
    started: false,
    pty: false,
    finished: false,
  }
  match target {
    Some(t) => events.push(ForwardRequest(channel=id, host=t.host, port=t.port))
    None => {
      self.session_open = true
      self.outgoing.push(
        encode_channel_open_confirmation(
          recipient_channel=open.sender_channel,
          sender_channel=id,
          initial_window_size=self.window_size,
          maximum_packet_size=self.max_packet_size,
        ),
      )
    }
  }
}
