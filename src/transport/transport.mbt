///|
/// SSH transport layer (RFC 4253). M0 ships only the plaintext parts:
/// version exchange, the unencrypted binary packet framing, and the
/// KEXINIT codec. Everything here is sans-IO: pure functions over bytes.
///
/// Toy code. Never use for real security.

///|
/// A peer-caused protocol violation detected while decoding. The transport
/// state machine (M2) turns this into `SSH_MSG_DISCONNECT` with
/// `SSH_DISCONNECT_PROTOCOL_ERROR`; see docs/01 "Error handling policy".
pub(all) suberror ProtocolError {
  ProtocolError(String)
} derive(Debug, Eq)

///|
/// Which side of the connection we are. Affects the advertised KEXINIT
/// lists (strict-kex marker differs per role).
pub(all) enum Role {
  Client
  Server
} derive(Debug, Eq)
