///|
/// The SSH connection protocol (RFC 4254), restricted to a single
/// `session` channel carrying `exec` or a non-PTY `shell`. See docs/04
/// Part B.
///
/// Sans-IO: this package parses and builds packet **payloads** and tracks
/// channel state. It never touches sockets, the clock or child processes;
/// the caller hands payloads to the transport and runs the process.
///
/// Toy code. Never use for real security.

///|
/// A peer-caused violation of the connection protocol. The caller turns
/// this into an `SSH_MSG_DISCONNECT` (docs/01 "Error handling policy").
pub(all) suberror ConnectionError {
  ConnectionError(String)
} derive(Debug, Eq)

///|
/// Wrap a `WireError` raised while decoding message `ctx`.
fn wire_error(ctx : String, e : @wire.WireError) -> ConnectionError {
  ConnectionError("\{ctx}: \{Repr(e)}")
}

///|
/// Open a reader over `payload` and check its message number.
fn expect_message(
  payload : BytesView,
  msg : Byte,
  ctx : String,
) -> @wire.Reader raise ConnectionError {
  let r = @wire.Reader::new(payload)
  let got = r.read_byte() catch { e => raise wire_error(ctx, e) }
  if got != msg {
    raise ConnectionError(
      "\{ctx}: expected message \{msg.to_int()}, got \{got.to_int()}",
    )
  }
  r
}

///|
/// Every message must be consumed exactly.
fn expect_end(r : @wire.Reader, ctx : String) -> Unit raise ConnectionError {
  if !r.is_at_end() {
    raise ConnectionError("\{ctx}: \{r.remaining()} trailing byte(s)")
  }
}
