///|
/// Key exchange for the transport layer (docs/02 sections 3-6):
/// KEXINIT negotiation, the curve25519-sha256 ECDH messages, the exchange
/// hash and its Ed25519 signature, and RFC 4253 section 7.2 key derivation.
///
/// Everything here is sans-IO and free of randomness: ephemeral scalars,
/// cookies and host keys are parameters. The pieces are kept separate so a
/// second kex method (a PQC hybrid, docs/06 M6) can swap the shared-secret
/// derivation without touching the hash or key derivation.
///
/// Toy code. Never use for real security.

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

///|
/// Outcome of KEXINIT negotiation. MAC slots are absent on purpose: the only
/// cipher is AEAD, so the MAC is implicit (docs/02 section 3).
pub(all) struct Negotiated {
  kex : String
  host_key : String
  cipher_client_to_server : String
  cipher_server_to_client : String
  compression_client_to_server : String
  compression_server_to_client : String
  /// True only when both sides advertised their role's strict-kex marker.
  strict_kex : Bool
} derive(Debug, Eq)

///|
/// Kex methods we can actually run (the strict-kex markers are excluded;
/// they are pseudo-algorithms, RFC 4253 section 7.1 / docs/02 section 3).
fn is_strict_marker(name : String) -> Bool {
  name == KEX_STRICT_CLIENT || name == KEX_STRICT_SERVER
}

///|
/// RFC 4253 section 7.1: the client's first preference that the server also
/// supports. `None` when the lists share nothing.
fn first_common(client : Array[String], server : Array[String]) -> String? {
  for name in client {
    if server.contains(name) {
      return Some(name)
    }
  }
  None
}

///|
fn pick(
  client : Array[String],
  server : Array[String],
  slot : String,
) -> String raise ProtocolError {
  match first_common(client, server) {
    Some(name) => name
    None => raise ProtocolError("negotiate: no common \{slot}")
  }
}

///|
/// Negotiate algorithms between our KEXINIT and the peer's, from `role`'s
/// point of view. Raises `ProtocolError` when any slot has no common
/// algorithm (the transport maps this to
/// `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`).
///
/// Deliberate toy limitation: a peer that sets `first_kex_packet_follows`
/// is rejected instead of handling or discarding its guessed packet
/// (docs/02 section 3 says we always send `false` ourselves).
pub fn negotiate(
  role : Role,
  ours : KexInit,
  peer : KexInit,
) -> Negotiated raise ProtocolError {
  if peer.first_kex_packet_follows {
    raise ProtocolError("negotiate: first_kex_packet_follows is not supported")
  }
  let (client, server) = match role {
    Client => (ours, peer)
    Server => (peer, ours)
  }
  let client_kex = client.kex_algorithms.filter(n => !is_strict_marker(n))
  let server_kex = server.kex_algorithms.filter(n => !is_strict_marker(n))
  let strict_kex = client.kex_algorithms.contains(KEX_STRICT_CLIENT) &&
    server.kex_algorithms.contains(KEX_STRICT_SERVER)
  {
    kex: pick(client_kex, server_kex, "kex algorithm"),
    host_key: pick(
      client.server_host_key_algorithms,
      server.server_host_key_algorithms,
      "host key algorithm",
    ),
    cipher_client_to_server: pick(
      client.encryption_client_to_server,
      server.encryption_client_to_server,
      "cipher client->server",
    ),
    cipher_server_to_client: pick(
      client.encryption_server_to_client,
      server.encryption_server_to_client,
      "cipher server->client",
    ),
    compression_client_to_server: pick(
      client.compression_client_to_server,
      server.compression_client_to_server,
      "compression client->server",
    ),
    compression_server_to_client: pick(
      client.compression_server_to_client,
      server.compression_server_to_client,
      "compression server->client",
    ),
    strict_kex,
  }
}

// ---------------------------------------------------------------------------
// ECDH messages (docs/02 section 4)
// ---------------------------------------------------------------------------

///|
/// SSH_MSG_KEX_ECDH_INIT (30): the client's 32-byte ephemeral X25519 key.
pub(all) struct KexEcdhInit {
  q_c : Bytes
} derive(Debug, Eq)

///|
/// SSH_MSG_KEX_ECDH_REPLY (31). `k_s` and `signature` are kept as opaque
/// blobs here; `decode_ed25519_host_key` / `decode_ed25519_signature`
/// validate their contents.
pub(all) struct KexEcdhReply {
  k_s : Bytes
  q_s : Bytes
  signature : Bytes
} derive(Debug, Eq)

///|
/// Length of an X25519 public key / shared secret.
const ECDH_POINT_LEN : Int = 32

///|
fn kex_expect_point(
  name : String,
  ctx : String,
  q : BytesView,
) -> Unit raise ProtocolError {
  if q.length() != ECDH_POINT_LEN {
    raise ProtocolError(
      "\{ctx}: \{name} must be \{ECDH_POINT_LEN} bytes, got \{q.length()}",
    )
  }
}

///|
/// Payload: message byte, `string Q_C`. Our own Q_C of the wrong length is
/// a programmer error and aborts.
pub fn KexEcdhInit::encode(self : KexEcdhInit) -> Bytes {
  guard self.q_c.length() == ECDH_POINT_LEN else {
    abort("KEX_ECDH_INIT: Q_C must be 32 bytes")
  }
  let w = @wire.Writer::new(size_hint=40)
  w.write_byte(SSH_MSG_KEX_ECDH_INIT)
  w.write_string(self.q_c[:])
  w.to_bytes()
}

///|
/// Parse a KEX_ECDH_INIT payload; the whole payload must be consumed and
/// Q_C must be exactly 32 bytes.
pub fn KexEcdhInit::decode(
  payload : BytesView,
) -> KexEcdhInit raise ProtocolError {
  let ctx = "KEX_ECDH_INIT"
  let r = expect_message(payload, SSH_MSG_KEX_ECDH_INIT, ctx)
  let q_c = r.read_string() catch { e => raise wire_error(ctx, e) }
  kex_expect_point("Q_C", ctx, q_c)
  expect_end(r, ctx)
  { q_c: q_c.to_owned(), }
}

///|
/// Payload: message byte, `string K_S`, `string Q_S`, `string signature`.
pub fn KexEcdhReply::encode(self : KexEcdhReply) -> Bytes {
  let w = @wire.Writer::new(size_hint=200)
  w.write_byte(SSH_MSG_KEX_ECDH_REPLY)
  w.write_string(self.k_s[:])
  w.write_string(self.q_s[:])
  w.write_string(self.signature[:])
  w.to_bytes()
}

///|
/// Parse a KEX_ECDH_REPLY payload; the whole payload must be consumed and
/// Q_S must be exactly 32 bytes. K_S and the signature are not validated
/// here (see the blob decoders).
pub fn KexEcdhReply::decode(
  payload : BytesView,
) -> KexEcdhReply raise ProtocolError {
  let ctx = "KEX_ECDH_REPLY"
  let r = expect_message(payload, SSH_MSG_KEX_ECDH_REPLY, ctx)
  let (k_s, q_s, signature) = (
    r.read_string(),
    r.read_string(),
    r.read_string(),
  ) catch {
    e => raise wire_error(ctx, e)
  }
  kex_expect_point("Q_S", ctx, q_s)
  expect_end(r, ctx)
  { k_s: k_s.to_owned(), q_s: q_s.to_owned(), signature: signature.to_owned(), }
}

// ---------------------------------------------------------------------------
// Key exchange methods
// ---------------------------------------------------------------------------

///|
/// A key exchange method: how the two `KEX_ECDH` blobs are built and how
/// the shared secret `K` is derived from them.
///
/// This is the seam the design called for in docs/02: everything above it
/// (the exchange hash, the signature, key derivation) is identical for
/// every method, so a new method plugs in here without touching the
/// transport state machine. Note that `K` comes out of these functions
/// **already wire-encoded**, because the encoding is part of the method:
/// `curve25519-sha256` feeds an `mpint`, while the ML-KEM hybrid feeds a
/// `string` (see docs/02).
pub(all) enum KexMethod {
  /// `curve25519-sha256` and its `@libssh.org` alias: X25519, `mpint(K)`.
  Curve25519
} derive(Debug, Eq)

///|
/// The method a negotiated kex name selects, or `None` for a name we do
/// not implement. The strict-kex markers are not methods.
pub fn kex_method(name : String) -> KexMethod? {
  match name {
    KEX_CURVE25519_SHA256 | KEX_CURVE25519_SHA256_LIBSSH => Some(Curve25519)
    _ => None
  }
}

///|
/// Client side: the blob that goes in `KEX_ECDH_INIT`.
pub fn kex_client_public(
  kex : KexMethod,
  ephemeral_scalar : BytesView,
) -> Bytes {
  match kex {
    Curve25519 => ecdh_public(ephemeral_scalar)
  }
}

///|
/// Server side: answer the client's blob with our own and the encoded
/// shared secret. A malformed blob is the peer's fault.
pub fn kex_server_exchange(
  kex : KexMethod,
  ephemeral_scalar : BytesView,
  client_blob : BytesView,
) -> (Bytes, Bytes) raise ProtocolError {
  match kex {
    Curve25519 => {
      let raw = shared_secret(ephemeral_scalar, client_blob)
      (ecdh_public(ephemeral_scalar), shared_secret_mpint(raw[:]))
    }
  }
}

///|
/// Client side: the encoded shared secret, from the server's blob.
pub fn kex_client_shared(
  kex : KexMethod,
  ephemeral_scalar : BytesView,
  server_blob : BytesView,
) -> Bytes raise ProtocolError {
  match kex {
    Curve25519 => {
      let raw = shared_secret(ephemeral_scalar, server_blob)
      shared_secret_mpint(raw[:])
    }
  }
}

// ---------------------------------------------------------------------------
// Ed25519 host key and signature blobs (docs/02 section 5, RFC 8709)
// ---------------------------------------------------------------------------

///|
const ED25519_KEY_LEN : Int = 32

///|
const ED25519_SIG_LEN : Int = 64

///|
/// `string "ssh-ed25519" || string body`.
fn encode_ed25519_blob(body : BytesView) -> Bytes {
  let w = @wire.Writer::new(size_hint=16 + 4 + body.length())
  w.write_named_blob(HOSTKEY_ED25519, body)
  w.to_bytes()
}

///|
/// Parse `string "ssh-ed25519" || string body`, checking the algorithm
/// name, the body length, and that nothing trails.
fn decode_ed25519_blob(
  blob : BytesView,
  ctx : String,
  what : String,
  want_len : Int,
) -> Bytes raise ProtocolError {
  let r = @wire.Reader::new(blob)
  let (name, body) = r.read_named_blob() catch { e => raise wire_error(ctx, e) }
  if name != HOSTKEY_ED25519 {
    raise ProtocolError("\{ctx}: expected \{HOSTKEY_ED25519}, got \{name}")
  }
  if body.length() != want_len {
    raise ProtocolError(
      "\{ctx}: \{what} must be \{want_len} bytes, got \{body.length()}",
    )
  }
  expect_end(r, ctx)
  body.to_owned()
}

///|
/// Public host key blob `K_S` for a 32-byte Ed25519 public key. A wrong
/// length is a programmer error (the key is ours) and aborts.
pub fn encode_ed25519_host_key(public : BytesView) -> Bytes {
  guard public.length() == ED25519_KEY_LEN else {
    abort("host key: Ed25519 public key must be 32 bytes")
  }
  encode_ed25519_blob(public)
}

///|
/// Extract the 32-byte Ed25519 public key from a `K_S` blob.
pub fn decode_ed25519_host_key(blob : BytesView) -> Bytes raise ProtocolError {
  decode_ed25519_blob(blob, "host key", "key", ED25519_KEY_LEN)
}

///|
/// Signature blob for a 64-byte raw Ed25519 signature (ours; wrong length
/// aborts).
pub fn encode_ed25519_signature(sig : BytesView) -> Bytes {
  guard sig.length() == ED25519_SIG_LEN else {
    abort("signature: Ed25519 signature must be 64 bytes")
  }
  encode_ed25519_blob(sig)
}

///|
/// Extract the 64-byte raw Ed25519 signature from a signature blob.
pub fn decode_ed25519_signature(blob : BytesView) -> Bytes raise ProtocolError {
  decode_ed25519_blob(blob, "signature", "signature", ED25519_SIG_LEN)
}

// ---------------------------------------------------------------------------
// Shared secret (docs/02 section 4)
// ---------------------------------------------------------------------------

///|
/// Ephemeral public key Q = X25519(scalar, 9) for our 32-byte scalar.
pub fn ecdh_public(scalar : BytesView) -> Bytes {
  @crypto.fixed_to_bytes(@crypto.x25519_base(scalar))
}

///|
/// Raw 32-byte shared secret K_raw = X25519(own_scalar, peer_q). A
/// malformed or low-order peer point is a `ProtocolError` (the transport
/// maps it to `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`). Kept separate from
/// `exchange_hash` so a hybrid kex can supply a different secret later.
pub fn shared_secret(
  own_scalar : BytesView,
  peer_q : BytesView,
) -> Bytes raise ProtocolError {
  match @crypto.x25519(own_scalar, peer_q) {
    Some(k) => @crypto.fixed_to_bytes(k)
    None =>
      raise ProtocolError(
        "kex: peer ephemeral public key is invalid or low-order",
      )
  }
}

///|
/// The shared secret as a full wire `mpint` (uint32 length + body, with a
/// leading 0x00 when the top bit of K_raw is set). This exact byte string
/// is what goes into the exchange hash and into key derivation
/// (RFC 4253 sections 7.2 and 8: "K is encoded as mpint").
pub fn shared_secret_mpint(k_raw : BytesView) -> Bytes {
  let w = @wire.Writer::new(size_hint=40)
  w.write_mpint(k_raw)
  w.to_bytes()
}

// ---------------------------------------------------------------------------
// Exchange hash and host signature (docs/02 sections 4-5)
// ---------------------------------------------------------------------------

///|
/// H = SHA256(string(V_C) || string(V_S) || string(I_C) || string(I_S)
///            || string(K_S) || string(Q_C) || string(Q_S) || mpint(K)).
/// `v_c` / `v_s` are the version strings without CR LF; `i_c` / `i_s` are
/// the full KEXINIT payloads; `k_encoded` is the wire-encoded shared
/// secret from the negotiated method (an `mpint` for curve25519, a
/// `string` for the ML-KEM hybrid) — see
/// `shared_secret_mpint` and is appended as-is.
pub fn exchange_hash(
  v_c~ : Bytes,
  v_s~ : Bytes,
  i_c~ : Bytes,
  i_s~ : Bytes,
  k_s~ : Bytes,
  q_c~ : Bytes,
  q_s~ : Bytes,
  k_encoded~ : Bytes,
) -> Bytes {
  let w = @wire.Writer::new(size_hint=512)
  w.write_string(v_c[:])
  w.write_string(v_s[:])
  w.write_string(i_c[:])
  w.write_string(i_s[:])
  w.write_string(k_s[:])
  w.write_string(q_c[:])
  w.write_string(q_s[:])
  w.write_raw(k_encoded[:])
  @crypto.fixed_to_bytes(@xcrypto.sha256(w.to_bytes()))
}

///|
/// Server side: sign the 32-byte exchange hash with the Ed25519 host key
/// and return the `ssh-ed25519` signature blob.
pub fn sign_exchange_hash(
  host_key : @crypto.Ed25519KeyPair,
  h : BytesView,
) -> Bytes {
  let sig = @crypto.fixed_to_bytes(host_key.sign(h))
  encode_ed25519_signature(sig[:])
}

///|
/// Client side: check the server's signature blob over `h` against the
/// host key blob `k_s`. Any malformed blob or a bad signature raises
/// `ProtocolError`. Checking `k_s` against known_hosts is the caller's job.
pub fn verify_exchange_hash(
  k_s : BytesView,
  h : BytesView,
  signature_blob : BytesView,
) -> Unit raise ProtocolError {
  let public = decode_ed25519_host_key(k_s)
  let sig = decode_ed25519_signature(signature_blob)
  if !@crypto.ed25519_verify(public[:], h, sig[:]) {
    raise ProtocolError("kex: host key signature does not verify")
  }
}

// ---------------------------------------------------------------------------
// Key derivation (docs/02 section 6, RFC 4253 section 7.2)
// ---------------------------------------------------------------------------

///|
/// K1 = HASH(K || H || X || session_id), K2 = HASH(K || H || K1),
/// K3 = HASH(K || H || K1 || K2), ...; the concatenation truncated to
/// `len` bytes. `k_encoded` is the wire-encoded shared secret
/// (length prefix included) as produced by `shared_secret_mpint`;
/// `letter` is the ASCII key letter 'A'..'F'.
pub fn derive_key(
  k_encoded : BytesView,
  h : BytesView,
  session_id : BytesView,
  letter : Byte,
  len : Int,
) -> Bytes {
  guard len >= 0 else { abort("derive_key: negative length") }
  let seed = @wire.Writer::new(
    size_hint=k_encoded.length() + h.length() + 1 + session_id.length(),
  )
  seed.write_raw(k_encoded)
  seed.write_raw(h)
  seed.write_byte(letter)
  seed.write_raw(session_id)
  let mut block = @crypto.fixed_to_bytes(@xcrypto.sha256(seed.to_bytes()))
  let out = @wire.Writer::new(size_hint=len)
  out.write_raw(block[:])
  while out.length() < len {
    let next = @wire.Writer::new(
      size_hint=k_encoded.length() + h.length() + out.length(),
    )
    next.write_raw(k_encoded)
    next.write_raw(h)
    next.write_raw(out.to_bytes()[:])
    block = @crypto.fixed_to_bytes(@xcrypto.sha256(next.to_bytes()))
    out.write_raw(block[:])
  }
  out.to_bytes()[0:len].to_owned()
}

///|
/// The encryption keys for `chacha20-poly1305@openssh.com`: 64 bytes each.
/// Only 'C' (client->server) and 'D' (server->client) are derived. The IV
/// letters 'A'/'B' and MAC letters 'E'/'F' are not used by the AEAD (its
/// nonce comes from the sequence number and its Poly1305 key from the
/// stream), so they are deliberately not computed.
pub(all) struct SessionKeys {
  c : Bytes
  d : Bytes
} derive(Debug, Eq)

///|
/// Length in bytes of a chacha20-poly1305@openssh.com key (two 32-byte
/// ChaCha20 keys).
pub const CHACHA20_POLY1305_KEY_LEN : Int = 64

///|
/// Derive the C and D keys. On the first (and, for us, only) key exchange
/// `session_id` equals `h`.
pub fn derive_session_keys(
  k_encoded : BytesView,
  h : BytesView,
  session_id : BytesView,
) -> SessionKeys {
  {
    c: derive_key(k_encoded, h, session_id, b'C', CHACHA20_POLY1305_KEY_LEN),
    d: derive_key(k_encoded, h, session_id, b'D', CHACHA20_POLY1305_KEY_LEN),
  }
}

///|
/// The key `role` encrypts with: client sends with C, server with D.
pub fn SessionKeys::send_key(self : SessionKeys, role : Role) -> Bytes {
  match role {
    Client => self.c
    Server => self.d
  }
}

///|
/// The key `role` decrypts with: the mirror of `send_key`.
pub fn SessionKeys::recv_key(self : SessionKeys, role : Role) -> Bytes {
  match role {
    Client => self.d
    Server => self.c
  }
}
