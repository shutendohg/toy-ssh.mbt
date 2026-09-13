///|
/// SSH_MSG_DISCONNECT (RFC 4253 section 11.1) and the service request /
/// accept pair (RFC 4253 section 10); docs/02 section 8.

///|
/// The only service we request after NEWKEYS.
pub const SERVICE_USERAUTH : String = "ssh-userauth"

///|
/// `byte(1) || uint32 reason_code || string description || string ""`.
/// The language tag is always empty.
pub fn encode_disconnect(reason : UInt, description : String) -> Bytes {
  let w = @wire.Writer::new()
  w.write_byte(SSH_MSG_DISCONNECT)
  w.write_uint32(reason)
  w.write_str(description)
  w.write_string(b"")
  w.to_bytes()
}

///|
/// Parse a DISCONNECT payload into `(reason_code, description)`. The
/// language tag is read and discarded.
pub fn decode_disconnect(
  payload : BytesView,
) -> (UInt, String) raise ProtocolError {
  let ctx = "DISCONNECT"
  let r = expect_message(payload, SSH_MSG_DISCONNECT, ctx)
  let out = read_disconnect_fields(r) catch { e => raise wire_error(ctx, e) }
  expect_end(r, ctx)
  out
}

///|
fn read_disconnect_fields(
  r : @wire.Reader,
) -> (UInt, String) raise @wire.WireError {
  let reason = r.read_uint32()
  let description = r.read_str()
  ignore(r.read_string())
  (reason, description)
}

///|
/// `byte(5) || string service_name`.
pub fn encode_service_request(service : String) -> Bytes {
  encode_service(SSH_MSG_SERVICE_REQUEST, service)
}

///|
/// `byte(6) || string service_name`.
pub fn encode_service_accept(service : String) -> Bytes {
  encode_service(SSH_MSG_SERVICE_ACCEPT, service)
}

///|
pub fn decode_service_request(
  payload : BytesView,
) -> String raise ProtocolError {
  decode_service(payload, SSH_MSG_SERVICE_REQUEST, "SERVICE_REQUEST")
}

///|
pub fn decode_service_accept(payload : BytesView) -> String raise ProtocolError {
  decode_service(payload, SSH_MSG_SERVICE_ACCEPT, "SERVICE_ACCEPT")
}

///|
fn encode_service(msg : Byte, service : String) -> Bytes {
  let w = @wire.Writer::new()
  w.write_byte(msg)
  w.write_str(service)
  w.to_bytes()
}

///|
fn decode_service(
  payload : BytesView,
  msg : Byte,
  name : String,
) -> String raise ProtocolError {
  let r = expect_message(payload, msg, name)
  let service = r.read_str() catch {
    e => raise ProtocolError("\{name}: \{Repr(e)}")
  }
  expect_end(r, name)
  service
}
