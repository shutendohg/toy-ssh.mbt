///|
/// The server-side userauth state machine (docs/04 Part A "Auth state
/// machines"). Sans-IO: it consumes request payloads and queues reply
/// payloads; the caller moves them through the transport.

///|
/// What the caller must supply. The authentication policy arrives as
/// callbacks, so this package needs neither file IO nor a dependency on
/// `keys`: parsing `authorized_keys` and the password table is the
/// caller's job.
pub(all) struct AuthServerConfig {
  /// The transport session id (`H` of the first kex). Publickey
  /// signatures are always verified against **this** value; there is no
  /// session id on the wire.
  session_id : Bytes
  /// `(user, password) -> accepted`. A toy: plaintext, not constant-time.
  check_password : (String, String) -> Bool
  /// `(user, public_key_blob) -> the key may authenticate as this user`.
  authorize_public_key : (String, Bytes) -> Bool
  /// Sent as `SSH_MSG_USERAUTH_BANNER` before the first reply.
  banner : String?
  /// How many FAILUREs we answer before reporting `TooManyFailures`
  /// (docs/04 suggests 6).
  max_failures : Int
}

///|
/// What the server tells its caller. Peer-caused decoding failures are
/// reported as `ProtocolViolation` rather than raised, because only the
/// transport can send DISCONNECT (docs/01 "Error handling policy").
pub(all) enum AuthServerEvent {
  /// Every well-formed request, before it is judged.
  Request(user~ : String, service~ : String, auth_method~ : AuthMethod)
  /// SUCCESS has been queued; `user` is authenticated.
  Authenticated(user~ : String)
  /// `max_failures` FAILUREs have been sent. The server keeps answering
  /// FAILURE (docs/04); the caller should disconnect, since only the
  /// transport layer can send `SSH_MSG_DISCONNECT`. Reported once.
  TooManyFailures(user~ : String)
  /// An undecodable or misplaced payload. The caller should disconnect
  /// with `SSH_DISCONNECT_PROTOCOL_ERROR`.
  ProtocolViolation(String)
} derive(Debug, Eq)

///|
/// The methods we tell a client can continue.
const CONTINUE_METHODS : String = "publickey,password"

///|
pub struct AuthServer {
  cfg : AuthServerConfig
  outgoing : Array[Bytes]
  mut authenticated : String?
  mut last_user : String
  mut failures : Int
  mut limit_reported : Bool
}

///|
/// Create a server and queue the banner, if any.
pub fn AuthServer::new(cfg : AuthServerConfig) -> AuthServer {
  let s = {
    cfg,
    outgoing: [],
    authenticated: None,
    last_user: "",
    failures: 0,
    limit_reported: false,
  }
  if cfg.banner is Some(text) {
    s.outgoing.push(encode_userauth_banner(text, ""))
  }
  s
}

///|
/// Reply payloads queued so far, in order. Drains the queue.
pub fn AuthServer::take_outgoing(self : AuthServer) -> Array[Bytes] {
  let out = self.outgoing.copy()
  self.outgoing.clear()
  out
}

///|
/// The authenticated user, once SUCCESS has been sent. The connection
/// layer needs it for `exec` (docs/04).
pub fn AuthServer::user(self : AuthServer) -> String? {
  self.authenticated
}

///|
pub fn AuthServer::is_authenticated(self : AuthServer) -> Bool {
  self.authenticated is Some(_)
}

///|
/// How many FAILUREs have been sent.
pub fn AuthServer::failure_count(self : AuthServer) -> Int {
  self.failures
}

///|
/// Feed one decrypted payload. Returns the events it produced; replies
/// are queued in `take_outgoing`. After SUCCESS every further userauth
/// message is ignored (RFC 4252, docs/04).
pub fn AuthServer::on_payload(
  self : AuthServer,
  payload : BytesView,
) -> Array[AuthServerEvent] {
  let events : Array[AuthServerEvent] = []
  if self.is_authenticated() {
    return events
  }
  let req = try decode_userauth_request(payload) catch {
    AuthError(text) => {
      events.push(ProtocolViolation(text))
      return events
    }
  } noraise {
    req => req
  }
  self.last_user = req.user
  events.push(
    Request(user=req.user, service=req.service, auth_method=req.auth_method),
  )
  // Userauth only ever grants access to "ssh-connection".
  if req.service != SERVICE_CONNECTION {
    self.reject(events)
    return events
  }
  match req.auth_method {
    // A probe, a password change we do not support, and a method we do
    // not implement all get the same answer: the methods that can
    // continue.
    NoneAuth | PasswordChange(_) | Unknown(_) => self.reject(events)
    Password(password~) =>
      if (self.cfg.check_password)(req.user, password) {
        self.accept(events, req.user)
      } else {
        self.reject(events)
      }
    PublicKeyQuery(algorithm~, blob~) =>
      if self.key_is_acceptable(req.user, algorithm, blob) {
        self.outgoing.push(encode_userauth_pk_ok(algorithm, blob[:]))
      } else {
        self.reject(events)
      }
    PublicKeySigned(algorithm~, blob~, signature~) =>
      if self.signature_is_valid(req.user, algorithm, blob, signature) {
        self.accept(events, req.user)
      } else {
        self.reject(events)
      }
  }
  events
}

///|
/// Is this key one `user` may authenticate with, in an algorithm we
/// implement and a blob we can parse? A key we reject is answered with
/// FAILURE, never a protocol error: offering an algorithm we do not
/// implement is normal client behaviour.
fn AuthServer::key_is_acceptable(
  self : AuthServer,
  user : String,
  algorithm : String,
  blob : Bytes,
) -> Bool {
  algorithm == PUBLICKEY_ALGORITHM &&
  // Parsing the blob also pins its inner algorithm to ssh-ed25519, so a
  // blob disagreeing with the outer name cannot slip through.
  ed25519_public_or_none(blob) is Some(_) &&
  (self.cfg.authorize_public_key)(user, blob)
}

///|
/// The key must be authorized **and** the signature must verify over the
/// data rebuilt from our own session id.
fn AuthServer::signature_is_valid(
  self : AuthServer,
  user : String,
  algorithm : String,
  blob : Bytes,
  signature : Bytes,
) -> Bool {
  guard self.key_is_acceptable(user, algorithm, blob) else { return false }
  guard ed25519_public_or_none(blob) is Some(public) else { return false }
  guard (try decode_ed25519_signature_blob(signature[:]) catch {
      _ => None
    } noraise {
      sig => Some(sig)
    })
    is Some(sig) else {
    return false
  }
  let data = publickey_signed_data(
    self.cfg.session_id[:],
    user,
    SERVICE_CONNECTION,
    algorithm,
    blob[:],
  )
  @crypto.ed25519_verify(public[:], data[:], sig[:])
}

///|
/// The 32-byte key inside an `ssh-ed25519` blob, or `None` if the blob is
/// not one.
fn ed25519_public_or_none(blob : Bytes) -> Bytes? {
  try decode_ed25519_public_key_blob(blob[:]) catch {
    _ => None
  } noraise {
    key => Some(key)
  }
}

///|
/// Queue SUCCESS and remember the user.
fn AuthServer::accept(
  self : AuthServer,
  events : Array[AuthServerEvent],
  user : String,
) -> Unit {
  self.authenticated = Some(user)
  self.outgoing.push(encode_userauth_success())
  events.push(Authenticated(user~))
}

///|
/// Queue FAILURE and, the first time the limit is reached, report it.
fn AuthServer::reject(
  self : AuthServer,
  events : Array[AuthServerEvent],
) -> Unit {
  self.failures = self.failures + 1
  self.outgoing.push(encode_userauth_failure([CONTINUE_METHODS], false))
  if self.failures >= self.cfg.max_failures && !self.limit_reported {
    self.limit_reported = true
    events.push(TooManyFailures(user=self.last_user))
  }
}
