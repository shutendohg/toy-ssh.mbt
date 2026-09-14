///|
/// Helpers shared by the transport message codecs: every payload starts
/// with its message number and must be consumed exactly, and wire-level
/// failures are reported as `ProtocolError` per docs/01.

///|
/// Wrap a `WireError` raised while decoding message `ctx`.
fn wire_error(ctx : String, e : @wire.WireError) -> ProtocolError {
  ProtocolError("\{ctx}: \{Repr(e)}")
}

///|
/// Open a reader over `payload` and check its message number. `ctx` is
/// the message name used in error text.
fn expect_message(
  payload : BytesView,
  msg : Byte,
  ctx : String,
) -> @wire.Reader raise ProtocolError {
  let r = @wire.Reader::new(payload)
  let got = r.read_byte() catch { e => raise wire_error(ctx, e) }
  if got != msg {
    raise ProtocolError(
      "\{ctx}: expected message \{msg.to_int()}, got \{got.to_int()}",
    )
  }
  r
}

///|
/// Every transport message must be consumed exactly.
fn expect_end(r : @wire.Reader, ctx : String) -> Unit raise ProtocolError {
  if !r.is_at_end() {
    raise ProtocolError("\{ctx}: \{r.remaining()} trailing byte(s)")
  }
}
