///|
/// The sans-IO transport state machine (docs/01 "state-machine contract",
/// docs/02). It owns the version exchange, the single key exchange, the
/// switch to the AEAD record layer, and delivery of post-handshake packets
/// to the next layer. It never touches sockets, the clock or randomness:
/// every random input arrives through `TransportConfig`.
///
/// Toy code. Never use for real security.

///|
/// Everything the machine needs that the caller must supply. Random values
/// are parameters so the machine is deterministic and testable.
pub(all) struct TransportConfig {
  role : Role
  /// 16 random bytes for our KEXINIT.
  cookie : Bytes
  /// 32 random bytes: our ephemeral X25519 scalar.
  ephemeral_scalar : Bytes
  /// Server only: the 32-byte Ed25519 host key seed.
  host_seed : Bytes?
  /// Padding filler (random in production, `zero_padding` in tests).
  fill : (Int) -> Bytes
  /// Client only: called with the server's host key blob `K_S`; returning
  /// false aborts the key exchange (docs/05 known_hosts policy lives in the
  /// caller).
  accept_host_key : (Bytes) -> Bool
}

///|
pub(all) enum TransportEvent {
  /// NEWKEYS done both ways. `session_id` is the exchange hash `H`.
  Established(session_id~ : Bytes)
  /// A decrypted post-handshake packet for the next layer.
  Packet(payload~ : Bytes)
  /// The connection is over. `by_peer` is true when the peer sent
  /// SSH_MSG_DISCONNECT, false when we decided to disconnect (a DISCONNECT
  /// packet has then been queued in the outgoing buffer).
  Disconnect(code~ : UInt, description~ : String, by_peer~ : Bool)
} derive(Debug, Eq)

///|
/// Handshake progress. Opaque outside the package; use `is_established` /
/// `is_closed`.
pub enum State {
  /// Waiting for the peer's identification line.
  VersionWait
  /// Waiting for the peer's KEXINIT.
  KexInitWait
  /// Client: waiting for KEX_ECDH_REPLY. Server: waiting for KEX_ECDH_INIT.
  KexWait
  /// We have sent NEWKEYS; waiting for the peer's.
  NewKeysWait
  Established
  Closed
} derive(Eq)

///|
/// Internal: a fatal condition together with the disconnect reason code
/// we report for it. Wraps `ProtocolError` at the point where the reason
/// is known instead of guessing from error text.
priv suberror Fatal {
  Fatal(code~ : UInt, description~ : String)
}

///|
const KEXINIT_NOT_FIRST : String = "KEXINIT was not the first packet"

///|
fn kex_failed(e : ProtocolError) -> Fatal {
  let ProtocolError(description) = e
  Fatal(code=SSH_DISCONNECT_KEY_EXCHANGE_FAILED, description~)
}

///|
fn protocol_error(e : ProtocolError) -> Fatal {
  let ProtocolError(description) = e
  Fatal(code=SSH_DISCONNECT_PROTOCOL_ERROR, description~)
}

///|
pub struct Transport {
  cfg : TransportConfig
  /// Server: the expanded host key. Client: `None`.
  host_key : @crypto.Ed25519KeyPair?
  mut state : State
  mut inbuf : Bytes
  outbuf : @buffer.Buffer
  /// Our KEXINIT payload (`I_C` or `I_S`).
  our_kexinit : KexInit
  our_kexinit_payload : Bytes
  mut peer_version : Bytes
  mut peer_kexinit : KexInit?
  mut peer_kexinit_payload : Bytes
  mut negotiated : Negotiated?
  mut session_id : Bytes?
  mut keys : SessionKeys?
  /// Plaintext packet counters; they seed the record-layer sequence
  /// numbers when the peer does not do strict kex.
  mut plain_send_seq : UInt
  mut plain_recv_seq : UInt
  mut send_rec : RecordState?
  mut recv_rec : RecordState?
}

///|
/// Create a machine and queue our identification line and KEXINIT. Under
/// strict kex the first packet must be KEXINIT, so nothing else is ever
/// sent first.
pub fn Transport::new(cfg : TransportConfig) -> Transport {
  guard cfg.ephemeral_scalar.length() == 32 else {
    abort("Transport: ephemeral scalar must be 32 bytes")
  }
  // Expand the host key once instead of on every signature.
  let host_key = match cfg.host_seed {
    Some(seed) => {
      guard seed.length() == 32 else {
        abort("Transport: host key seed must be 32 bytes")
      }
      Some(@crypto.Ed25519KeyPair::from_seed(seed[:]))
    }
    None => {
      guard cfg.role == Client else {
        abort("Transport: server needs a host key seed")
      }
      None
    }
  }
  let our_kexinit = KexInit::for_role(cfg.role, cookie=cfg.cookie)
  let our_kexinit_payload = our_kexinit.encode() catch {
    _ => abort("Transport: our own KEXINIT does not encode")
  }
  let t = {
    cfg,
    host_key,
    state: VersionWait,
    inbuf: b"",
    outbuf: @buffer.Buffer(size_hint=1024),
    our_kexinit,
    our_kexinit_payload,
    peer_version: b"",
    peer_kexinit: None,
    peer_kexinit_payload: b"",
    negotiated: None,
    session_id: None,
    keys: None,
    plain_send_seq: 0,
    plain_recv_seq: 0,
    send_rec: None,
    recv_rec: None,
  }
  t.outbuf.write_bytes(version_line())
  t.send_plain(our_kexinit_payload)
  t
}

///|
/// Bytes queued for the peer; the caller writes them to the socket.
pub fn Transport::take_outgoing(self : Transport) -> Bytes {
  let out = self.outbuf.to_bytes()
  self.outbuf.reset()
  out
}

///|
/// `H` of the (only) key exchange, once known.
pub fn Transport::session_id(self : Transport) -> Bytes? {
  self.session_id
}

///|
pub fn Transport::is_established(self : Transport) -> Bool {
  self.state == Established
}

///|
pub fn Transport::is_closed(self : Transport) -> Bool {
  self.state == Closed
}

///|
/// The key exchange method the negotiation settled on. `negotiate` only
/// ever returns a name we advertise, and every name we advertise maps to a
/// method (pinned by a test), so a missing one is our bug, not the peer's.
fn Transport::kex_method(self : Transport) -> KexMethod {
  guard self.negotiated is Some(n) else {
    abort("Transport: key exchange before negotiation")
  }
  match kex_method(n.kex) {
    Some(k) => k
    None => abort("Transport: negotiated an unimplemented kex \{n.kex}")
  }
}

///|
/// Whether strict kex was negotiated (both markers present). False until
/// the peer's KEXINIT has been seen.
pub fn Transport::strict_kex(self : Transport) -> Bool {
  match self.negotiated {
    Some(n) => n.strict_kex
    None => false
  }
}

///|
/// Queue a next-layer payload, encrypted. Calling it before `Established`
/// is a programmer error; calling it after the connection closed is
/// ignored, so event handlers need not track the close themselves.
pub fn Transport::send_packet(self : Transport, payload : BytesView) -> Unit {
  if self.state == Closed {
    return
  }
  guard self.state == Established else {
    abort("Transport::send_packet before Established")
  }
  self.send_encrypted(payload)
}

///|
/// Disconnect on our own initiative: queue SSH_MSG_DISCONNECT (encrypted
/// if the record layer is up) and close. Safe to call in any state.
pub fn Transport::disconnect(
  self : Transport,
  code : UInt,
  description : String,
) -> Unit {
  if self.state == Closed {
    return
  }
  let payload = encode_disconnect(code, description)
  match self.send_rec {
    Some(_) => self.send_encrypted(payload[:])
    None => self.send_plain(payload)
  }
  self.state = Closed
}

///|
/// Feed bytes from the peer. Returns the events produced, in order. Once
/// closed, input is ignored.
pub fn Transport::on_received(
  self : Transport,
  data : BytesView,
) -> Array[TransportEvent] {
  let events : Array[TransportEvent] = []
  if self.state == Closed {
    return events
  }
  self.inbuf = self.inbuf + data.to_owned()
  self.drive(events) catch {
    Fatal(code~, description~) => {
      self.disconnect(code, description)
      events.push(Disconnect(code~, description~, by_peer=false))
    }
  }
  events
}

// ---------------------------------------------------------------------------
// Receive side
// ---------------------------------------------------------------------------

///|
/// Consume as much of `inbuf` as possible.
fn Transport::drive(
  self : Transport,
  events : Array[TransportEvent],
) -> Unit raise Fatal {
  while self.state != Closed {
    if self.state == VersionWait {
      match
        (parse_version(self.inbuf[:]) catch { e => raise protocol_error(e) }) {
        NeedMoreData => return
        Version(version~, consumed~) => {
          self.peer_version = version
          self.consume(consumed)
          self.state = KexInitWait
        }
      }
      continue
    }
    let parsed = match self.recv_rec {
      Some(rec) =>
        rec.open_next(self.inbuf[:]) catch {
          ProtocolError(description) => {
            // Exactly one record-layer failure is a MAC error; the rest are
            // framing errors.
            let code = if description == MAC_FAILURE {
              SSH_DISCONNECT_MAC_ERROR
            } else {
              SSH_DISCONNECT_PROTOCOL_ERROR
            }
            raise Fatal(code~, description~)
          }
        }
      None =>
        decode_packet(self.inbuf[:]) catch {
          e => raise protocol_error(e)
        }
    }
    match parsed {
      NeedMoreData => return
      Packet(payload~, consumed~) => {
        self.consume(consumed)
        if self.recv_rec is None {
          self.plain_recv_seq = self.plain_recv_seq + 1
        }
        self.handle_payload(payload, events)
      }
    }
  }
}

///|
fn Transport::consume(self : Transport, n : Int) -> Unit {
  self.inbuf = self.inbuf[n:].to_owned()
}

///|
/// Dispatch one decoded payload according to the current state.
fn Transport::handle_payload(
  self : Transport,
  payload : Bytes,
  events : Array[TransportEvent],
) -> Unit raise Fatal {
  if payload.length() == 0 {
    raise Fatal(
      code=SSH_DISCONNECT_PROTOCOL_ERROR,
      description="empty packet payload",
    )
  }
  let msg = payload[0]
  // Messages that are legal at any time.
  if msg == SSH_MSG_DISCONNECT {
    let (code, description) = decode_disconnect(payload[:]) catch {
      e => raise protocol_error(e)
    }
    self.state = Closed
    events.push(Disconnect(code~, description~, by_peer=true))
    return
  }
  let in_kex = self.state != Established
  if msg == SSH_MSG_IGNORE ||
    msg == SSH_MSG_DEBUG ||
    msg == SSH_MSG_UNIMPLEMENTED ||
    msg == SSH_MSG_EXT_INFO {
    if in_kex && (self.strict_kex() || msg == SSH_MSG_EXT_INFO) {
      raise Fatal(
        code=SSH_DISCONNECT_PROTOCOL_ERROR,
        description="message \{msg.to_int()} is not allowed during strict key exchange",
      )
    }
    return
  }
  match self.state {
    KexInitWait =>
      self.on_kexinit(payload) catch {
        ProtocolError(d) as e if d == KEXINIT_NOT_FIRST =>
          raise protocol_error(e)
        e => raise kex_failed(e)
      }
    KexWait =>
      try {
        match self.cfg.role {
          Client => self.on_ecdh_reply(payload)
          Server => self.on_ecdh_init(payload)
        }
      } catch {
        e => raise kex_failed(e)
      }
    NewKeysWait =>
      self.on_newkeys(payload, events) catch {
        e => raise protocol_error(e)
      }
    Established => {
      if msg == SSH_MSG_KEXINIT {
        raise Fatal(
          code=SSH_DISCONNECT_PROTOCOL_ERROR,
          description="rekeying is not supported",
        )
      }
      events.push(Packet(payload~))
    }
    VersionWait | Closed => abort("unreachable transport state")
  }
}

///|
fn Transport::on_kexinit(
  self : Transport,
  payload : Bytes,
) -> Unit raise ProtocolError {
  let peer = KexInit::decode(payload[:])
  let negotiated = negotiate(self.cfg.role, self.our_kexinit, peer)
  // Under strict kex the peer's KEXINIT must be its very first packet
  // (docs/02 section 3). We only learn "strict" now, so check the count
  // of plaintext packets received so far (this one included).
  if negotiated.strict_kex && self.plain_recv_seq != 1 {
    raise ProtocolError(KEXINIT_NOT_FIRST)
  }
  self.peer_kexinit = Some(peer)
  self.peer_kexinit_payload = payload
  self.negotiated = Some(negotiated)
  self.state = KexWait
  if self.cfg.role == Client {
    let init : KexEcdhInit = {
      q_c: kex_client_public(self.kex_method(), self.cfg.ephemeral_scalar[:]),
    }
    self.send_plain(init.encode())
  }
}

///|
/// Server: answer KEX_ECDH_INIT with KEX_ECDH_REPLY and NEWKEYS.
fn Transport::on_ecdh_init(
  self : Transport,
  payload : Bytes,
) -> Unit raise ProtocolError {
  let init = KexEcdhInit::decode(payload[:])
  let (q_s, k_encoded) = kex_server_exchange(
    self.kex_method(),
    self.cfg.ephemeral_scalar[:],
    init.q_c[:],
  )
  guard self.host_key is Some(host_key) else {
    abort("server without host key")
  }
  let k_s = encode_ed25519_host_key(host_key.public()[:])
  let h = exchange_hash(
    v_c=self.peer_version,
    v_s=@ascii.encode(OUR_VERSION),
    i_c=self.peer_kexinit_payload,
    i_s=self.our_kexinit_payload,
    k_s~,
    q_c=init.q_c,
    q_s~,
    k_encoded~,
  )
  let reply : KexEcdhReply = {
    k_s,
    q_s,
    signature: sign_exchange_hash(host_key, h[:]),
  }
  self.send_plain(reply.encode())
  self.finish_kex(k_encoded, h)
}

///|
/// Client: verify KEX_ECDH_REPLY, then send NEWKEYS.
fn Transport::on_ecdh_reply(
  self : Transport,
  payload : Bytes,
) -> Unit raise ProtocolError {
  let reply = KexEcdhReply::decode(payload[:])
  ignore(decode_ed25519_host_key(reply.k_s[:]))
  if !(self.cfg.accept_host_key)(reply.k_s) {
    raise ProtocolError("host key rejected")
  }
  let kex = self.kex_method()
  let q_c = kex_client_public(kex, self.cfg.ephemeral_scalar[:])
  let k_encoded = kex_client_shared(
    kex,
    self.cfg.ephemeral_scalar[:],
    reply.q_s[:],
  )
  let h = exchange_hash(
    v_c=@ascii.encode(OUR_VERSION),
    v_s=self.peer_version,
    i_c=self.our_kexinit_payload,
    i_s=self.peer_kexinit_payload,
    k_s=reply.k_s,
    q_c~,
    q_s=reply.q_s,
    k_encoded~,
  )
  verify_exchange_hash(reply.k_s[:], h[:], reply.signature[:])
  self.finish_kex(k_encoded, h)
}

///|
/// Derive keys, send NEWKEYS and switch our send side to the record layer.
fn Transport::finish_kex(
  self : Transport,
  k_encoded : Bytes,
  h : Bytes,
) -> Unit {
  let keys = derive_session_keys(k_encoded[:], h[:], h[:])
  self.session_id = Some(h)
  self.keys = Some(keys)
  self.send_plain(Bytes::make(1, SSH_MSG_NEWKEYS))
  let rec = RecordState::new(keys.send_key(self.cfg.role)[:])
  if !self.strict_kex() {
    rec.seq = self.plain_send_seq
  }
  self.send_rec = Some(rec)
  self.state = NewKeysWait
}

///|
fn Transport::on_newkeys(
  self : Transport,
  payload : Bytes,
  events : Array[TransportEvent],
) -> Unit raise ProtocolError {
  if payload != Bytes::make(1, SSH_MSG_NEWKEYS) {
    raise ProtocolError(
      "expected NEWKEYS (\{SSH_MSG_NEWKEYS.to_int()}), got \{payload[0].to_int()}",
    )
  }
  guard self.keys is Some(keys) && self.session_id is Some(session_id) else {
    abort("NEWKEYS before keys were derived")
  }
  let rec = RecordState::new(keys.recv_key(self.cfg.role)[:])
  if !self.strict_kex() {
    rec.seq = self.plain_recv_seq
  }
  self.recv_rec = Some(rec)
  self.state = Established
  events.push(Established(session_id~))
}

// ---------------------------------------------------------------------------
// Send side
// ---------------------------------------------------------------------------

///|
fn Transport::send_plain(self : Transport, payload : Bytes) -> Unit {
  let pkt = encode_packet(payload[:], fill=self.cfg.fill) catch {
    _ => abort("Transport: handshake payload exceeds the packet cap")
  }
  self.outbuf.write_bytes(pkt)
  self.plain_send_seq = self.plain_send_seq + 1
}

///|
fn Transport::send_encrypted(self : Transport, payload : BytesView) -> Unit {
  guard self.send_rec is Some(rec) else { abort("record layer not ready") }
  let pkt = rec.seal_next(payload, fill=self.cfg.fill) catch {
    _ => abort("Transport: payload exceeds the packet cap; split it first")
  }
  self.outbuf.write_bytes(pkt)
}
