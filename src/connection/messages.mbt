///|
/// Connection-protocol message numbers (RFC 4254 / docs/04 Part B).

///|
pub const SSH_MSG_GLOBAL_REQUEST : Byte = 80

///|
pub const SSH_MSG_REQUEST_SUCCESS : Byte = 81

///|
pub const SSH_MSG_REQUEST_FAILURE : Byte = 82

///|
pub const SSH_MSG_CHANNEL_OPEN : Byte = 90

///|
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION : Byte = 91

///|
pub const SSH_MSG_CHANNEL_OPEN_FAILURE : Byte = 92

///|
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST : Byte = 93

///|
pub const SSH_MSG_CHANNEL_DATA : Byte = 94

///|
pub const SSH_MSG_CHANNEL_EXTENDED_DATA : Byte = 95

///|
pub const SSH_MSG_CHANNEL_EOF : Byte = 96

///|
pub const SSH_MSG_CHANNEL_CLOSE : Byte = 97

///|
pub const SSH_MSG_CHANNEL_REQUEST : Byte = 98

///|
pub const SSH_MSG_CHANNEL_SUCCESS : Byte = 99

///|
pub const SSH_MSG_CHANNEL_FAILURE : Byte = 100

///|
/// `data_type_code` for stderr on CHANNEL_EXTENDED_DATA.
pub const SSH_EXTENDED_DATA_STDERR : UInt = 1

///|
/// CHANNEL_OPEN_FAILURE reason codes (RFC 4254 section 5.1).
pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED : UInt = 1

///|
pub const SSH_OPEN_CONNECT_FAILED : UInt = 2

///|
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE : UInt = 3

///|
pub const SSH_OPEN_RESOURCE_SHORTAGE : UInt = 4

///|
/// The channel type a shell or a command runs on.
pub const CHANNEL_SESSION : String = "session"

///|
/// Local port forwarding (RFC 4254 section 7.2): the peer asks us to
/// connect somewhere and relay bytes over the channel. This is what
/// `ssh -L` opens, one channel per accepted local connection.
pub const CHANNEL_DIRECT_TCPIP : String = "direct-tcpip"

// ---------------------------------------------------------------------------
// CHANNEL_OPEN and its replies
// ---------------------------------------------------------------------------

///|
pub(all) struct ChannelOpen {
  channel_type : String
  sender_channel : UInt
  initial_window_size : UInt
  maximum_packet_size : UInt
  /// Whatever the channel type appends to the common fields: empty for
  /// `session`, the target and originator for `direct-tcpip`. Kept raw
  /// because only the channel type knows how to read it.
  extra : Bytes
} derive(Debug, Eq)

///|
pub fn encode_channel_open(
  channel_type~ : String,
  sender_channel~ : UInt,
  initial_window_size~ : UInt,
  maximum_packet_size~ : UInt,
  extra? : Bytes = b"",
) -> Bytes {
  let w = @wire.Writer::new(size_hint=32 + extra.length())
  w.write_byte(SSH_MSG_CHANNEL_OPEN)
  w.write_str(channel_type)
  w.write_uint32(sender_channel)
  w.write_uint32(initial_window_size)
  w.write_uint32(maximum_packet_size)
  w.write_raw(extra[:])
  w.to_bytes()
}

///|
pub fn decode_channel_open(
  payload : BytesView,
) -> ChannelOpen raise ConnectionError {
  let ctx = "CHANNEL_OPEN"
  let r = expect_message(payload, SSH_MSG_CHANNEL_OPEN, ctx)
  let open = {
    channel_type: r.read_str(),
    sender_channel: r.read_uint32(),
    initial_window_size: r.read_uint32(),
    maximum_packet_size: r.read_uint32(),
    // The rest belongs to the channel type; `session` leaves none.
    extra: r.read_bytes(r.remaining()).to_owned(),
  } catch {
    e => raise wire_error(ctx, e)
  }
  open
}

///|
/// The `direct-tcpip` target and the originator the peer reports for it.
/// The originator is informational; we do not act on it.
pub(all) struct DirectTcpip {
  host : String
  port : UInt
  originator_host : String
  originator_port : UInt
} derive(Debug, Eq)

///|
/// The type-specific half of a `direct-tcpip` CHANNEL_OPEN.
pub fn encode_direct_tcpip_extra(
  host~ : String,
  port~ : UInt,
  originator_host~ : String,
  originator_port~ : UInt,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=32)
  w.write_str(host)
  w.write_uint32(port)
  w.write_str(originator_host)
  w.write_uint32(originator_port)
  w.to_bytes()
}

///|
/// Read that half back. The whole of `extra` must be consumed: trailing
/// bytes mean the peer sent something we do not understand, and a channel
/// we cannot read is one we should not open.
pub fn decode_direct_tcpip(
  extra : BytesView,
) -> DirectTcpip raise ConnectionError {
  let ctx = "direct-tcpip"
  let r = @wire.Reader::new(extra)
  let target = {
    host: r.read_str(),
    port: r.read_uint32(),
    originator_host: r.read_str(),
    originator_port: r.read_uint32(),
  } catch {
    e => raise wire_error(ctx, e)
  }
  expect_end(r, ctx)
  target
}

///|
pub(all) struct ChannelOpenConfirmation {
  recipient_channel : UInt
  sender_channel : UInt
  initial_window_size : UInt
  maximum_packet_size : UInt
} derive(Debug, Eq)

///|
pub fn encode_channel_open_confirmation(
  recipient_channel~ : UInt,
  sender_channel~ : UInt,
  initial_window_size~ : UInt,
  maximum_packet_size~ : UInt,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=20)
  w.write_byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
  w.write_uint32(recipient_channel)
  w.write_uint32(sender_channel)
  w.write_uint32(initial_window_size)
  w.write_uint32(maximum_packet_size)
  w.to_bytes()
}

///|
pub fn decode_channel_open_confirmation(
  payload : BytesView,
) -> ChannelOpenConfirmation raise ConnectionError {
  let ctx = "CHANNEL_OPEN_CONFIRMATION"
  let r = expect_message(payload, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, ctx)
  let c = {
    recipient_channel: r.read_uint32(),
    sender_channel: r.read_uint32(),
    initial_window_size: r.read_uint32(),
    maximum_packet_size: r.read_uint32(),
  } catch {
    e => raise wire_error(ctx, e)
  }
  expect_end(r, ctx)
  c
}

///|
/// `uint32 recipient || uint32 reason || string description || string ""`.
pub fn encode_channel_open_failure(
  recipient_channel~ : UInt,
  reason~ : UInt,
  description~ : String,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=40)
  w.write_byte(SSH_MSG_CHANNEL_OPEN_FAILURE)
  w.write_uint32(recipient_channel)
  w.write_uint32(reason)
  w.write_str(description)
  w.write_string(b"")
  w.to_bytes()
}

///|
/// Returns `(recipient_channel, reason, description)`; the language tag is
/// read and discarded.
pub fn decode_channel_open_failure(
  payload : BytesView,
) -> (UInt, UInt, String) raise ConnectionError {
  let ctx = "CHANNEL_OPEN_FAILURE"
  let r = expect_message(payload, SSH_MSG_CHANNEL_OPEN_FAILURE, ctx)
  let out = try {
    let recipient = r.read_uint32()
    let reason = r.read_uint32()
    let description = r.read_str()
    ignore(r.read_string())
    (recipient, reason, description)
  } catch {
    e => raise wire_error(ctx, e)
  }
  expect_end(r, ctx)
  out
}

// ---------------------------------------------------------------------------
// Data, flow control and the one-field messages
// ---------------------------------------------------------------------------

///|
pub fn encode_channel_data(
  recipient_channel~ : UInt,
  data~ : BytesView,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=9 + data.length())
  w.write_byte(SSH_MSG_CHANNEL_DATA)
  w.write_uint32(recipient_channel)
  w.write_string(data)
  w.to_bytes()
}

///|
pub fn decode_channel_data(
  payload : BytesView,
) -> (UInt, Bytes) raise ConnectionError {
  let ctx = "CHANNEL_DATA"
  let r = expect_message(payload, SSH_MSG_CHANNEL_DATA, ctx)
  let out = (r.read_uint32(), r.read_string().to_owned()) catch {
    e => raise wire_error(ctx, e)
  }
  expect_end(r, ctx)
  out
}

///|
pub fn encode_channel_extended_data(
  recipient_channel~ : UInt,
  data_type~ : UInt,
  data~ : BytesView,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=13 + data.length())
  w.write_byte(SSH_MSG_CHANNEL_EXTENDED_DATA)
  w.write_uint32(recipient_channel)
  w.write_uint32(data_type)
  w.write_string(data)
  w.to_bytes()
}

///|
pub fn decode_channel_extended_data(
  payload : BytesView,
) -> (UInt, UInt, Bytes) raise ConnectionError {
  let ctx = "CHANNEL_EXTENDED_DATA"
  let r = expect_message(payload, SSH_MSG_CHANNEL_EXTENDED_DATA, ctx)
  let out = (r.read_uint32(), r.read_uint32(), r.read_string().to_owned()) catch {
    e => raise wire_error(ctx, e)
  }
  expect_end(r, ctx)
  out
}

///|
pub fn encode_channel_window_adjust(
  recipient_channel~ : UInt,
  bytes_to_add~ : UInt,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=9)
  w.write_byte(SSH_MSG_CHANNEL_WINDOW_ADJUST)
  w.write_uint32(recipient_channel)
  w.write_uint32(bytes_to_add)
  w.to_bytes()
}

///|
pub fn decode_channel_window_adjust(
  payload : BytesView,
) -> (UInt, UInt) raise ConnectionError {
  let ctx = "CHANNEL_WINDOW_ADJUST"
  let r = expect_message(payload, SSH_MSG_CHANNEL_WINDOW_ADJUST, ctx)
  let out = (r.read_uint32(), r.read_uint32()) catch {
    e => raise wire_error(ctx, e)
  }
  expect_end(r, ctx)
  out
}

///|
fn encode_channel_only(msg : Byte, recipient_channel : UInt) -> Bytes {
  let w = @wire.Writer::new(size_hint=5)
  w.write_byte(msg)
  w.write_uint32(recipient_channel)
  w.to_bytes()
}

///|
fn decode_channel_only(
  payload : BytesView,
  msg : Byte,
  ctx : String,
) -> UInt raise ConnectionError {
  let r = expect_message(payload, msg, ctx)
  let channel = r.read_uint32() catch { e => raise wire_error(ctx, e) }
  expect_end(r, ctx)
  channel
}

///|
pub fn encode_channel_eof(recipient_channel~ : UInt) -> Bytes {
  encode_channel_only(SSH_MSG_CHANNEL_EOF, recipient_channel)
}

///|
pub fn decode_channel_eof(payload : BytesView) -> UInt raise ConnectionError {
  decode_channel_only(payload, SSH_MSG_CHANNEL_EOF, "CHANNEL_EOF")
}

///|
pub fn encode_channel_close(recipient_channel~ : UInt) -> Bytes {
  encode_channel_only(SSH_MSG_CHANNEL_CLOSE, recipient_channel)
}

///|
pub fn decode_channel_close(payload : BytesView) -> UInt raise ConnectionError {
  decode_channel_only(payload, SSH_MSG_CHANNEL_CLOSE, "CHANNEL_CLOSE")
}

///|
pub fn encode_channel_success(recipient_channel~ : UInt) -> Bytes {
  encode_channel_only(SSH_MSG_CHANNEL_SUCCESS, recipient_channel)
}

///|
pub fn decode_channel_success(
  payload : BytesView,
) -> UInt raise ConnectionError {
  decode_channel_only(payload, SSH_MSG_CHANNEL_SUCCESS, "CHANNEL_SUCCESS")
}

///|
pub fn encode_channel_failure(recipient_channel~ : UInt) -> Bytes {
  encode_channel_only(SSH_MSG_CHANNEL_FAILURE, recipient_channel)
}

///|
pub fn decode_channel_failure(
  payload : BytesView,
) -> UInt raise ConnectionError {
  decode_channel_only(payload, SSH_MSG_CHANNEL_FAILURE, "CHANNEL_FAILURE")
}

// ---------------------------------------------------------------------------
// CHANNEL_REQUEST
// ---------------------------------------------------------------------------

///|
/// The channel requests we understand. Anything else decodes as `Other`
/// so the peer can be answered CHANNEL_FAILURE instead of being treated
/// as a protocol violation (`pty-req` arrives this way).
pub(all) enum ChannelRequestKind {
  Exec(String)
  Shell
  ExitStatus(UInt)
  /// `pty-req` (RFC 4254 section 6.2). `modes` is the encoded terminal
  /// modes string, kept raw: we pass the size on to the kernel but leave
  /// the modes alone (docs/04).
  PtyReq(
    term~ : String,
    cols~ : UInt,
    rows~ : UInt,
    width_px~ : UInt,
    height_px~ : UInt,
    modes~ : Bytes
  )
  /// `window-change` (RFC 4254 section 6.7).
  WindowChange(cols~ : UInt, rows~ : UInt, width_px~ : UInt, height_px~ : UInt)
  Other(String)
} derive(Debug, Eq)

///|
pub(all) struct ChannelRequest {
  recipient_channel : UInt
  want_reply : Bool
  request : ChannelRequestKind
} derive(Debug, Eq)

///|
/// `byte 98 || uint32 recipient || string "exec" || boolean || string command`.
pub fn encode_exec_request(
  recipient_channel~ : UInt,
  command~ : String,
  want_reply~ : Bool,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=24 + command.length())
  w.write_byte(SSH_MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_str("exec")
  w.write_boolean(want_reply)
  w.write_str(command)
  w.to_bytes()
}

///|
/// `byte 98 || uint32 recipient || string "shell" || boolean`.
pub fn encode_shell_request(
  recipient_channel~ : UInt,
  want_reply~ : Bool,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=16)
  w.write_byte(SSH_MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_str("shell")
  w.write_boolean(want_reply)
  w.to_bytes()
}

///|
/// `exit-status` never asks for a reply (RFC 4254 section 6.10).
pub fn encode_exit_status_request(
  recipient_channel~ : UInt,
  exit_status~ : UInt,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=24)
  w.write_byte(SSH_MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_str("exit-status")
  w.write_boolean(false)
  w.write_uint32(exit_status)
  w.to_bytes()
}

///|
/// `byte 98 || uint32 recipient || string "pty-req" || boolean || string
/// TERM || uint32 x4 || string modes` (RFC 4254 section 6.2).
pub fn encode_pty_request(
  recipient_channel~ : UInt,
  term~ : String,
  cols~ : UInt,
  rows~ : UInt,
  width_px~ : UInt,
  height_px~ : UInt,
  modes~ : Bytes,
  want_reply~ : Bool,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=48 + term.length() + modes.length())
  w.write_byte(SSH_MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_str("pty-req")
  w.write_boolean(want_reply)
  w.write_str(term)
  w.write_uint32(cols)
  w.write_uint32(rows)
  w.write_uint32(width_px)
  w.write_uint32(height_px)
  w.write_string(modes[:])
  w.to_bytes()
}

///|
/// `window-change` never asks for a reply (RFC 4254 section 6.7), so the
/// boolean is always false.
pub fn encode_window_change_request(
  recipient_channel~ : UInt,
  cols~ : UInt,
  rows~ : UInt,
  width_px~ : UInt,
  height_px~ : UInt,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=40)
  w.write_byte(SSH_MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_str("window-change")
  w.write_boolean(false)
  w.write_uint32(cols)
  w.write_uint32(rows)
  w.write_uint32(width_px)
  w.write_uint32(height_px)
  w.to_bytes()
}

///|
/// Parse a CHANNEL_REQUEST. Request-specific fields are only read for the
/// kinds we implement; an unknown request keeps its name and its tail is
/// ignored, because we cannot know that tail's shape.
pub fn decode_channel_request(
  payload : BytesView,
) -> ChannelRequest raise ConnectionError {
  let ctx = "CHANNEL_REQUEST"
  let r = expect_message(payload, SSH_MSG_CHANNEL_REQUEST, ctx)
  let (recipient_channel, name, want_reply) = (
    r.read_uint32(),
    r.read_str(),
    r.read_boolean(),
  ) catch {
    e => raise wire_error(ctx, e)
  }
  let request = match name {
    "exec" => {
      let command = r.read_str() catch { e => raise wire_error(ctx, e) }
      expect_end(r, ctx)
      Exec(command)
    }
    "shell" => {
      expect_end(r, ctx)
      Shell
    }
    "exit-status" => {
      let code = r.read_uint32() catch { e => raise wire_error(ctx, e) }
      expect_end(r, ctx)
      ExitStatus(code)
    }
    "pty-req" => {
      let req : ChannelRequestKind = try {
        let term = r.read_str()
        PtyReq(
          term~,
          cols=r.read_uint32(),
          rows=r.read_uint32(),
          width_px=r.read_uint32(),
          height_px=r.read_uint32(),
          modes=r.read_string().to_owned(),
        )
      } catch {
        e => raise wire_error(ctx, e)
      }
      expect_end(r, ctx)
      req
    }
    "window-change" => {
      let req : ChannelRequestKind = WindowChange(
        cols=r.read_uint32(),
        rows=r.read_uint32(),
        width_px=r.read_uint32(),
        height_px=r.read_uint32(),
      ) catch {
        e => raise wire_error(ctx, e)
      }
      expect_end(r, ctx)
      req
    }
    other => Other(other)
  }
  { recipient_channel, want_reply, request, }
}

// ---------------------------------------------------------------------------
// GLOBAL_REQUEST
// ---------------------------------------------------------------------------

///|
/// We originate none; OpenSSH sends `hostkeys-00@openssh.com`.
pub fn encode_global_request(name~ : String, want_reply~ : Bool) -> Bytes {
  let w = @wire.Writer::new(size_hint=16 + name.length())
  w.write_byte(SSH_MSG_GLOBAL_REQUEST)
  w.write_str(name)
  w.write_boolean(want_reply)
  w.to_bytes()
}

///|
/// Returns `(name, want_reply)`. Request-specific data is ignored: we
/// implement no global request, so its shape is unknown to us.
pub fn decode_global_request(
  payload : BytesView,
) -> (String, Bool) raise ConnectionError {
  let ctx = "GLOBAL_REQUEST"
  let r = expect_message(payload, SSH_MSG_GLOBAL_REQUEST, ctx)
  (r.read_str(), r.read_boolean()) catch {
    e => raise wire_error(ctx, e)
  }
}

///|
pub fn encode_request_failure() -> Bytes {
  Bytes::make(1, SSH_MSG_REQUEST_FAILURE)
}

///|
pub fn encode_request_success() -> Bytes {
  Bytes::make(1, SSH_MSG_REQUEST_SUCCESS)
}
