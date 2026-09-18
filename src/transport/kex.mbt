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
/// Outcome of KEXINIT negotiation. A MAC slot is the empty string when the
/// chosen cipher is AEAD: RFC 4253's MAC has no meaning there, and no MAC
/// algorithm is negotiated for it (docs/02 section 3).
pub(all) struct Negotiated {
  kex : String
  host_key : String
  cipher_client_to_server : String
  cipher_server_to_client : String
  mac_client_to_server : String
  mac_server_to_client : String
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
/// Whether a cipher name needs a MAC negotiated alongside it. Listed by
/// name rather than probed through `cipher_method`, which would need a MAC
/// name to probe with and so would silently answer `false` for a future
/// suite that uses a different one. An unknown name answers `false`: it is
/// no cipher of ours, and `pick` has already failed by the time it matters.
fn needs_mac(cipher : String) -> Bool {
  match cipher {
    CIPHER_AES128_CTR => true
    _ => false
  }
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
  // RFC 4253 section 7.1 settles the kex first, and a kex mismatch is the
  // more useful thing to report when several slots are empty at once.
  let kex = pick(client_kex, server_kex, "kex algorithm")
  let host_key = pick(
    client.server_host_key_algorithms,
    server.server_host_key_algorithms,
    "host key algorithm",
  )
  let cipher_c2s = pick(
    client.encryption_client_to_server,
    server.encryption_client_to_server,
    "cipher client->server",
  )
  let cipher_s2c = pick(
    client.encryption_server_to_client,
    server.encryption_server_to_client,
    "cipher server->client",
  )
  // A MAC is negotiated only for a cipher that needs one; an AEAD peer is
  // allowed to advertise no MAC at all.
  let mac_c2s = if needs_mac(cipher_c2s) {
    pick(
      client.mac_client_to_server,
      server.mac_client_to_server,
      "MAC client->server",
    )
  } else {
    ""
  }
  let mac_s2c = if needs_mac(cipher_s2c) {
    pick(
      client.mac_server_to_client,
      server.mac_server_to_client,
      "MAC server->client",
    )
  } else {
    ""
  }
  {
    kex,
    host_key,
    cipher_client_to_server: cipher_c2s,
    cipher_server_to_client: cipher_s2c,
    mac_client_to_server: mac_c2s,
    mac_server_to_client: mac_s2c,
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

///|
/// The record-layer method both directions will run on.
///
/// Deliberate toy limitation: the two directions must agree. SSH allows
/// them to differ, but a peer only ends up here by advertising disjoint
/// preferences on purpose, and one method per connection keeps the key
/// derivation and the record layer a single case.
pub fn Negotiated::cipher_method(
  self : Negotiated,
) -> CipherMethod raise ProtocolError {
  if self.cipher_client_to_server != self.cipher_server_to_client ||
    self.mac_client_to_server != self.mac_server_to_client {
    raise ProtocolError(
      "negotiate: the two directions must use the same cipher and MAC",
    )
  }
  match cipher_method(self.cipher_client_to_server, self.mac_client_to_server) {
    Some(m) => m
    None =>
      raise ProtocolError(
        "negotiate: unsupported cipher/MAC \{self.cipher_client_to_server}/\{self.mac_client_to_server}",
      )
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
/// Payload: message byte, `string Q_C`. The blob comes from the negotiated
/// method, which decides how long it is.
pub fn KexEcdhInit::encode(self : KexEcdhInit) -> Bytes {
  let w = @wire.Writer::new(size_hint=40)
  w.write_byte(SSH_MSG_KEX_ECDH_INIT)
  w.write_string(self.q_c[:])
  w.to_bytes()
}

///|
/// Parse a KEX_ECDH_INIT payload; the whole payload must be consumed and
/// The blob is opaque here: how long it should be is the negotiated
/// method's business (32 bytes for X25519, 1216 for the ML-KEM hybrid),
/// and each method checks it before use.
pub fn KexEcdhInit::decode(
  payload : BytesView,
) -> KexEcdhInit raise ProtocolError {
  let ctx = "KEX_ECDH_INIT"
  let r = expect_message(payload, SSH_MSG_KEX_ECDH_INIT, ctx)
  let q_c = r.read_string() catch { e => raise wire_error(ctx, e) }
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
/// Parse a KEX_ECDH_REPLY payload; the whole payload must be consumed.
/// Q_S is opaque here, like Q_C: its length belongs to the negotiated
/// method. K_S and the signature are not validated here either (see the
/// blob decoders).
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
  /// `mlkem768x25519-sha256`: ML-KEM-768 alongside X25519, with
  /// `string(SHA256(mlkem_ss || x25519_ss))` as `K`.
  MlKem768X25519
} derive(Debug, Eq)

///|
/// What the client keeps between sending `KEX_ECDH_INIT` and receiving the
/// reply. For X25519 alone the scalar in the config is enough; the hybrid
/// also has an ML-KEM decapsulation key, which is far too large to
/// regenerate for free and must be the *same* one the public blob came
/// from.
pub struct KexClientState {
  scalar : Bytes
  /// The blob we sent, kept because the exchange hash needs it again when
  /// the reply arrives. Rebuilding it would mean a second ML-KEM key
  /// generation, the most expensive step in the handshake.
  public : Bytes
  /// The hybrid's ML-KEM decapsulation key, if this method has one.
  decaps_key : Bytes?
}

///|
/// The blob we sent in `KEX_ECDH_INIT`, which is also `Q_C` in the
/// exchange hash.
pub fn KexClientState::public(self : KexClientState) -> Bytes {
  self.public
}

///|
/// The method a negotiated kex name selects, or `None` for a name we do
/// not implement. The strict-kex markers are not methods.
pub fn kex_method(name : String) -> KexMethod? {
  match name {
    KEX_CURVE25519_SHA256 | KEX_CURVE25519_SHA256_LIBSSH => Some(Curve25519)
    KEX_MLKEM768X25519_SHA256 => Some(MlKem768X25519)
    _ => None
  }
}

///|
/// Bytes of ML-KEM randomness each role needs: the client generates a key
/// pair from `d || z`, the server encapsulates with one 32-byte message.
pub const KEM_CLIENT_RANDOM_LEN : Int = 64

///|
pub const KEM_SERVER_RANDOM_LEN : Int = 32

///|
/// Client side: the blob for `KEX_ECDH_INIT`, and the state to keep until
/// the reply arrives.
///
/// `kem_random` is only read by a method that needs it; it must hold
/// `KEM_CLIENT_RANDOM_LEN` bytes for the hybrid.
pub fn kex_client_init(
  kex : KexMethod,
  ephemeral_scalar : BytesView,
  kem_random : BytesView,
) -> (Bytes, KexClientState) {
  match kex {
    Curve25519 => {
      let public = ecdh_public(ephemeral_scalar)
      (
        public,
        { scalar: ephemeral_scalar.to_owned(), public, decaps_key: None, },
      )
    }
    MlKem768X25519 => {
      guard kem_random.length() >= KEM_CLIENT_RANDOM_LEN else {
        abort(
          "hybrid kex needs \{KEM_CLIENT_RANDOM_LEN} bytes of ML-KEM randomness",
        )
      }
      let (ek, dk) = @crypto.mlkem768_keygen(
        kem_random[0:32],
        kem_random[32:64],
      )
      let public = ek + ecdh_public(ephemeral_scalar)
      (
        public,
        { scalar: ephemeral_scalar.to_owned(), public, decaps_key: Some(dk), },
      )
    }
  }
}

///|
/// Server side: answer the client's blob with our own and the encoded
/// shared secret. A malformed blob is the peer's fault.
///
/// `kem_random` must hold `KEM_SERVER_RANDOM_LEN` bytes for the hybrid: the
/// message ML-KEM encapsulates.
pub fn kex_server_exchange(
  kex : KexMethod,
  ephemeral_scalar : BytesView,
  kem_random : BytesView,
  client_blob : BytesView,
) -> (Bytes, Bytes) raise ProtocolError {
  match kex {
    Curve25519 => {
      // Checked here rather than left to X25519's own length guard, so a
      // truncated blob reports a framing error instead of being reported
      // as a low-order point, and so this arm does not depend on an
      // invariant of another package.
      expect_blob_length(client_blob, ECDH_POINT_LEN, "Q_C")
      let raw = shared_secret(ephemeral_scalar, client_blob)
      (ecdh_public(ephemeral_scalar), shared_secret_mpint(raw[:]))
    }
    MlKem768X25519 => {
      guard kem_random.length() >= KEM_SERVER_RANDOM_LEN else {
        abort(
          "hybrid kex needs \{KEM_SERVER_RANDOM_LEN} bytes of ML-KEM randomness",
        )
      }
      let ek_len = @crypto.MLKEM768_ENCAPS_KEY_LEN
      expect_blob_length(client_blob, ek_len + ECDH_POINT_LEN, "client blob")
      // A malformed encapsulation key would make the two sides disagree
      // rather than fail, so refuse it here instead of aborting inside
      // the KEM.
      if !@crypto.mlkem768_encaps_key_is_valid(client_blob[0:ek_len]) {
        raise ProtocolError("hybrid kex: malformed ML-KEM encapsulation key")
      }
      let (ct, kem_ss) = @crypto.mlkem768_encaps(
        client_blob[0:ek_len],
        kem_random[0:32],
      )
      let x_ss = shared_secret(ephemeral_scalar, client_blob[ek_len:])
      (
        ct + ecdh_public(ephemeral_scalar),
        hybrid_shared_secret(kem_ss[:], x_ss[:]),
      )
    }
  }
}

///|
/// Client side: the encoded shared secret, from the server's blob.
pub fn kex_client_shared(
  kex : KexMethod,
  state : KexClientState,
  server_blob : BytesView,
) -> Bytes raise ProtocolError {
  match kex {
    Curve25519 => {
      expect_blob_length(server_blob, ECDH_POINT_LEN, "Q_S")
      let raw = shared_secret(state.scalar[:], server_blob)
      shared_secret_mpint(raw[:])
    }
    MlKem768X25519 => {
      let ct_len = @crypto.MLKEM768_CIPHERTEXT_LEN
      expect_blob_length(server_blob, ct_len + ECDH_POINT_LEN, "server blob")
      guard state.decaps_key is Some(dk) else {
        abort("hybrid kex: no ML-KEM key was generated")
      }
      let kem_ss = @crypto.mlkem768_decaps(dk[:], server_blob[0:ct_len])
      let x_ss = shared_secret(state.scalar[:], server_blob[ct_len:])
      hybrid_shared_secret(kem_ss[:], x_ss[:])
    }
  }
}

///|
/// A peer's key exchange blob must be exactly as long as the negotiated
/// method says. The codecs treat it as an opaque string, so this is where
/// the length is enforced.
fn expect_blob_length(
  blob : BytesView,
  want : Int,
  name : String,
) -> Unit raise ProtocolError {
  if blob.length() != want {
    raise ProtocolError(
      "kex: \{name} must be \{want} bytes, got \{blob.length()}",
    )
  }
}

///|
/// `K = string(SHA256(mlkem_ss || x25519_ss))`, both halves raw.
///
/// The raw concatenation is the trap: plain `curve25519-sha256` feeds its
/// X25519 secret in as an `mpint`, while the hybrid feeds both secrets in
/// as plain bytes and then hashes them (OpenSSH's
/// `kexc25519_shared_key_ext` with `raw = 1`). The result is a `string`,
/// not an `mpint`.
fn hybrid_shared_secret(kem_ss : BytesView, x_ss : BytesView) -> Bytes {
  let concat = @wire.Writer::new(size_hint=64)
  concat.write_raw(kem_ss)
  concat.write_raw(x_ss)
  let digest = @crypto.fixed_to_bytes(@xcrypto.sha256(concat.to_bytes()))
  let w = @wire.Writer::new(size_hint=40)
  w.write_string(digest[:])
  w.to_bytes()
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
/// Both directions' key material. On the first (and, for us, only) key
/// exchange `session_id` equals `h`.
pub(all) struct SessionKeys {
  c2s : DirectionKeys
  s2c : DirectionKeys
} derive(Debug, Eq)

///|
/// Length in bytes of a chacha20-poly1305@openssh.com key (two 32-byte
/// ChaCha20 keys).
pub const CHACHA20_POLY1305_KEY_LEN : Int = 64

///|
/// Derive both directions for `suite`, RFC 4253 section 7.2: IV 'A'/'B',
/// encryption key 'C'/'D', integrity key 'E'/'F', client-to-server first.
/// A method that does not use a letter derives 0 bytes for it rather than
/// deriving and discarding one -- the AEAD has no IV and no MAC key.
pub fn derive_session_keys(
  suite : CipherMethod,
  k_encoded : BytesView,
  h : BytesView,
  session_id : BytesView,
) -> SessionKeys {
  let (iv_len, enc_len, mac_len) = suite.key_lengths()
  let letter = (l, len) => derive_key(k_encoded, h, session_id, l, len)
  {
    c2s: {
      iv: letter(b'A', iv_len),
      enc: letter(b'C', enc_len),
      mac: letter(b'E', mac_len),
    },
    s2c: {
      iv: letter(b'B', iv_len),
      enc: letter(b'D', enc_len),
      mac: letter(b'F', mac_len),
    },
  }
}

///|
/// The keys `role` encrypts with: client sends client-to-server.
pub fn SessionKeys::send_keys(self : SessionKeys, role : Role) -> DirectionKeys {
  match role {
    Client => self.c2s
    Server => self.s2c
  }
}

///|
/// The keys `role` decrypts with: the mirror of `send_keys`.
pub fn SessionKeys::recv_keys(self : SessionKeys, role : Role) -> DirectionKeys {
  match role {
    Client => self.s2c
    Server => self.c2s
  }
}
