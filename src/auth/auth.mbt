///|
/// SSH user authentication (RFC 4252); docs/04 Part A.
///
/// This package is sans-IO and deliberately independent of `transport` and
/// `keys`: it consumes and produces **payloads** (decrypted packet bodies)
/// and the caller hands them to the transport. The handful of protocol
/// constants it needs are duplicated here rather than imported, so that
/// the layers stay separable (docs/01).
///
/// Toy code. Never use for real security.

///|
/// A peer-caused protocol violation detected while decoding a userauth
/// message. The state machines turn this into an event (docs/01 "Error
/// handling policy" keeps peer-caused errors out of `raise` at the machine
/// boundary); the codecs raise it so callers can inspect the reason.
pub(all) suberror AuthError {
  AuthError(String)
} derive(Debug, Eq)

///|
pub const SSH_MSG_USERAUTH_REQUEST : Byte = 50

///|
pub const SSH_MSG_USERAUTH_FAILURE : Byte = 51

///|
pub const SSH_MSG_USERAUTH_SUCCESS : Byte = 52

///|
pub const SSH_MSG_USERAUTH_BANNER : Byte = 53

///|
/// Context-specific reuse of 60 by the `publickey` method (RFC 4252 §7).
pub const SSH_MSG_USERAUTH_PK_OK : Byte = 60

///|
/// The only service userauth ever grants access to.
pub const SERVICE_CONNECTION : String = "ssh-connection"

///|
pub const METHOD_NONE : String = "none"

///|
pub const METHOD_PASSWORD : String = "password"

///|
pub const METHOD_PUBLICKEY : String = "publickey"

///|
/// The only public key algorithm in our suite (docs/00).
pub const PUBLICKEY_ALGORITHM : String = "ssh-ed25519"

///|
/// Wrap a `WireError` raised while decoding message `ctx`.
fn wire_error(ctx : String, e : @wire.WireError) -> AuthError {
  AuthError("\{ctx}: \{Repr(e)}")
}

///|
/// Open a reader over `payload` and check its message number. `ctx` is
/// the message name used in error text.
fn expect_message(
  payload : BytesView,
  msg : Byte,
  ctx : String,
) -> @wire.Reader raise AuthError {
  let r = @wire.Reader::new(payload)
  let got = r.read_byte() catch { e => raise wire_error(ctx, e) }
  if got != msg {
    raise AuthError(
      "\{ctx}: expected message \{msg.to_int()}, got \{got.to_int()}",
    )
  }
  r
}

///|
/// Every userauth message must be consumed exactly.
fn expect_end(r : @wire.Reader, ctx : String) -> Unit raise AuthError {
  if !r.is_at_end() {
    raise AuthError("\{ctx}: \{r.remaining()} trailing byte(s)")
  }
}
