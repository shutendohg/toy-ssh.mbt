///|
/// The client-side userauth state machine (docs/04 Part A "Auth state
/// machines"). Sans-IO: it queues request payloads and interprets reply
/// payloads. Signing happens here, so the caller passes in an already
/// parsed `@crypto.Ed25519KeyPair` — no file IO and no `keys` dependency.

///|
/// What the client tells its caller (docs/01 `AuthEvent`).
pub(all) enum AuthEvent {
  /// `SSH_MSG_USERAUTH_BANNER` text, to print as-is.
  Banner(String)
  /// Authenticated; the connection layer takes over.
  Success
  /// A method was refused. `refused` is the method the server was
  /// answering — `none` for the opening probe, which is a question about
  /// what the server accepts rather than a failed attempt. `methods` is
  /// what the server says can continue and `partial` its
  /// `partial_success` flag.
  Failure(refused~ : String, methods~ : Array[String], partial~ : Bool)
  /// No method left to try (or one we cannot answer). The caller should
  /// disconnect.
  GiveUp(String)
  /// An undecodable or misplaced payload from the server. The caller
  /// should disconnect with `SSH_DISCONNECT_PROTOCOL_ERROR`.
  ProtocolViolation(String)
} derive(Debug, Eq)

///|
/// What the caller must supply. Credentials are optional: the client
/// tries `publickey` then `password`, skipping whatever is absent.
pub(all) struct AuthClientConfig {
  user : String
  /// The transport session id (`H` of the first kex); publickey
  /// signatures are computed over it.
  session_id : Bytes
  /// Send a `none` probe first to learn the server's method list
  /// (docs/04: our client MAY).
  probe_none : Bool
  /// The signing key for `publickey`, if we have one.
  key : @crypto.Ed25519KeyPair?
  /// The password for `password`, if we have one.
  password : String?
  /// Use the two-phase publickey flow (query, then signature) instead of
  /// signing straight away. Signing straight away costs one round trip
  /// less; the query phase is what OpenSSH does by default.
  query_first : Bool
}

///|
/// How far the current attempt has got. Opaque outside the package; use
/// `is_authenticated` / `is_done`.
pub enum ClientPhase {
  /// A `none` probe is outstanding.
  Probe
  /// A publickey query (`boolean FALSE`) is outstanding.
  PkQuery
  /// A publickey signature (`boolean TRUE`) is outstanding.
  PkSigned
  /// A password request is outstanding.
  PasswordSent
  /// SUCCESS received.
  Authenticated
  /// Nothing left to try.
  GaveUp
}

///|
pub struct AuthClient {
  cfg : AuthClientConfig
  outgoing : Array[Bytes]
  /// Methods still to try, in order.
  remaining : Array[String]
  mut phase : ClientPhase
}

///|
/// Create a client and queue its first request: the `none` probe if
/// configured, otherwise the first method we have credentials for.
pub fn AuthClient::new(cfg : AuthClientConfig) -> AuthClient {
  let remaining : Array[String] = []
  if cfg.key is Some(_) {
    remaining.push(METHOD_PUBLICKEY)
  }
  if cfg.password is Some(_) {
    remaining.push(METHOD_PASSWORD)
  }
  let c = { cfg, outgoing: [], remaining, phase: Probe, }
  if cfg.probe_none {
    c.outgoing.push(c.request(NoneAuth))
  } else {
    // A client with no credentials at all gives up before sending
    // anything; the caller sees it through `is_done`.
    ignore(c.advance())
  }
  c
}

///|
/// Request payloads queued so far, in order. Drains the queue.
pub fn AuthClient::take_outgoing(self : AuthClient) -> Array[Bytes] {
  let out = self.outgoing.copy()
  self.outgoing.clear()
  out
}

///|
pub fn AuthClient::is_authenticated(self : AuthClient) -> Bool {
  self.phase is Authenticated
}

///|
/// True once the outcome is settled: authenticated, or out of methods.
pub fn AuthClient::is_done(self : AuthClient) -> Bool {
  match self.phase {
    Authenticated | GaveUp => true
    _ => false
  }
}

///|
/// Feed one decrypted payload. Returns the events it produced; requests
/// are queued in `take_outgoing`. Once done, further userauth messages
/// are ignored.
pub fn AuthClient::on_payload(
  self : AuthClient,
  payload : BytesView,
) -> Array[AuthEvent] {
  let events : Array[AuthEvent] = []
  if self.is_done() {
    return events
  }
  if payload.length() == 0 {
    events.push(ProtocolViolation("userauth: empty payload"))
    return events
  }
  try self.dispatch(payload, events) catch {
    AuthError(text) => events.push(ProtocolViolation(text))
  } noraise {
    _ => ()
  }
  events
}

///|
fn AuthClient::dispatch(
  self : AuthClient,
  payload : BytesView,
  events : Array[AuthEvent],
) -> Unit raise AuthError {
  match payload[0] {
    SSH_MSG_USERAUTH_BANNER => {
      let (message, _) = decode_userauth_banner(payload)
      events.push(Banner(message))
    }
    SSH_MSG_USERAUTH_SUCCESS => {
      decode_userauth_success(payload)
      self.phase = Authenticated
      events.push(Success)
    }
    SSH_MSG_USERAUTH_FAILURE => {
      let (methods, partial) = decode_userauth_failure(payload)
      // We never send `partial_success` and have no second factor to
      // offer if a server does: treat it as a give-up rather than
      // looping on methods we cannot satisfy.
      if partial {
        self.phase = GaveUp
        events.push(
          GiveUp("userauth: partial success is not supported by this client"),
        )
      } else {
        events.push(Failure(refused=self.refused_method(), methods~, partial~))
        ignore(self.advance_reporting(events))
      }
    }
    SSH_MSG_USERAUTH_PK_OK =>
      if self.phase is PkQuery {
        let (algorithm, blob) = decode_userauth_pk_ok(payload)
        // RFC 4252 section 7: the reply carries back the algorithm name
        // and key blob from the request. Signing whatever the server
        // echoes would let it choose part of what our key signs, so sign
        // only for the offer we actually made.
        guard self.cfg.key is Some(key) else {
          raise AuthError("USERAUTH_PK_OK: no publickey offered")
        }
        let offered = encode_ed25519_public_key_blob(key.public()[:])
        if algorithm != PUBLICKEY_ALGORITHM || blob != offered {
          raise AuthError(
            "USERAUTH_PK_OK: reply does not echo the offered \{PUBLICKEY_ALGORITHM} key",
          )
        }
        self.outgoing.push(self.sign_request(algorithm, blob))
        self.phase = PkSigned
      } else {
        raise AuthError("USERAUTH_PK_OK: no publickey query outstanding")
      }
    other => raise AuthError("userauth: unexpected message \{other.to_int()}")
  }
}

///|
/// The method the outstanding request used, which is what a FAILURE is
/// answering. Only the phases that have a request in flight can be seen
/// here: `on_payload` returns early once we are done.
fn AuthClient::refused_method(self : AuthClient) -> String {
  match self.phase {
    Probe => METHOD_NONE
    PkQuery | PkSigned => METHOD_PUBLICKEY
    PasswordSent => METHOD_PASSWORD
    Authenticated | GaveUp => METHOD_NONE
  }
}

///|
/// Queue the next method's request, or give up. Returns false when there
/// was nothing left to try.
fn AuthClient::advance(self : AuthClient) -> Bool {
  if self.remaining.is_empty() {
    self.phase = GaveUp
    return false
  }
  let next = self.remaining.remove(0)
  if next == METHOD_PUBLICKEY {
    guard self.cfg.key is Some(key) else {
      // `remaining` is built from the config, so this cannot happen.
      abort("AuthClient: publickey queued without a key")
    }
    let blob = encode_ed25519_public_key_blob(key.public()[:])
    if self.cfg.query_first {
      self.outgoing.push(
        self.request(PublicKeyQuery(algorithm=PUBLICKEY_ALGORITHM, blob~)),
      )
      self.phase = PkQuery
    } else {
      self.outgoing.push(self.sign_request(PUBLICKEY_ALGORITHM, blob))
      self.phase = PkSigned
    }
  } else {
    guard self.cfg.password is Some(password) else {
      abort("AuthClient: password queued without a password")
    }
    self.outgoing.push(self.request(Password(password~)))
    self.phase = PasswordSent
  }
  true
}

///|
/// `advance`, reporting the give-up as an event.
fn AuthClient::advance_reporting(
  self : AuthClient,
  events : Array[AuthEvent],
) -> Bool {
  if self.advance() {
    return true
  }
  events.push(GiveUp("userauth: no authentication method left to try"))
  false
}

///|
/// Build an authentication-form publickey request, signing the exact
/// blob of RFC 4252 section 7 over our own session id.
fn AuthClient::sign_request(
  self : AuthClient,
  algorithm : String,
  blob : Bytes,
) -> Bytes {
  guard self.cfg.key is Some(key) else {
    abort("AuthClient: signing without a key")
  }
  let data = publickey_signed_data(
    self.cfg.session_id[:],
    self.cfg.user,
    SERVICE_CONNECTION,
    algorithm,
    blob[:],
  )
  let signature = encode_ed25519_signature_blob(
    @crypto.fixed_to_bytes(key.sign(data[:]))[:],
  )
  self.request(PublicKeySigned(algorithm~, blob~, signature~))
}

///|
fn AuthClient::request(self : AuthClient, auth_method : AuthMethod) -> Bytes {
  encode_userauth_request({
    user: self.cfg.user,
    service: SERVICE_CONNECTION,
    auth_method,
  })
}
