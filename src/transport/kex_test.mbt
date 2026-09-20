// Key exchange: negotiation, ECDH messages, exchange hash, key derivation.
// docs/02 sections 3-6, docs/06 M2 TDD order 1-3.

// ---------------------------------------------------------------------------
// 1. Negotiation (docs/02 section 3, RFC 4253 section 7.1)
// ---------------------------------------------------------------------------

///|
fn cookie() -> Bytes {
  Bytes::make(16, b'\x00')
}

///|
test "negotiate: happy path as client against our own server KEXINIT" {
  let ours = @transport.KexInit::for_role(Client, cookie=cookie())
  let peer = @transport.KexInit::for_role(Server, cookie=cookie())
  let n = @transport.negotiate(Client, ours, peer)
  debug_inspect(
    n,
    content=(
      #|{
      #|  kex: "mlkem768x25519-sha256",
      #|  host_key: "ssh-ed25519",
      #|  cipher_client_to_server: "chacha20-poly1305@openssh.com",
      #|  cipher_server_to_client: "chacha20-poly1305@openssh.com",
      #|  mac_client_to_server: "",
      #|  mac_server_to_client: "",
      #|  compression_client_to_server: "none",
      #|  compression_server_to_client: "none",
      #|  strict_kex: true,
      #|}
    ),
  )
}

///|
test "negotiate: happy path as server against our own client KEXINIT" {
  let ours = @transport.KexInit::for_role(Server, cookie=cookie())
  let peer = @transport.KexInit::for_role(Client, cookie=cookie())
  let n = @transport.negotiate(Server, ours, peer)
  inspect(n.kex, content="mlkem768x25519-sha256")
  inspect(n.host_key, content="ssh-ed25519")
  inspect(n.strict_kex, content="true")
}

///|
test "negotiate: the client's first preference wins even if the server lists ours second" {
  // OpenSSH-like peer: a list where our kex and host key are not first.
  let ours = @transport.KexInit::for_role(Client, cookie=cookie())
  let peer = {
    ..@transport.KexInit::for_role(Server, cookie=cookie()),
    kex_algorithms: [
      "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org",
      "kex-strict-s-v00@openssh.com",
    ],
    server_host_key_algorithms: ["rsa-sha2-512", "ssh-ed25519"],
    encryption_client_to_server: ["aes128-ctr", "chacha20-poly1305@openssh.com"],
    encryption_server_to_client: [
      "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
    ],
    compression_client_to_server: ["zlib@openssh.com", "none"],
    compression_server_to_client: ["none", "zlib@openssh.com"],
  }
  let n = @transport.negotiate(Client, ours, peer)
  inspect(n.kex, content="curve25519-sha256")
  inspect(n.host_key, content="ssh-ed25519")
  inspect(n.cipher_client_to_server, content="chacha20-poly1305@openssh.com")
  inspect(n.cipher_server_to_client, content="chacha20-poly1305@openssh.com")
  inspect(n.compression_client_to_server, content="none")
  inspect(n.compression_server_to_client, content="none")
  inspect(n.strict_kex, content="true")
}

///|
test "negotiate: as server, a client preferring the libssh alias gets that name" {
  let ours = @transport.KexInit::for_role(Server, cookie=cookie())
  let peer = {
    ..@transport.KexInit::for_role(Client, cookie=cookie()),
    kex_algorithms: ["curve25519-sha256@libssh.org", "curve25519-sha256"],
  }
  let n = @transport.negotiate(Server, ours, peer)
  inspect(n.kex, content="curve25519-sha256@libssh.org")
  // The peer did not send the client strict marker.
  inspect(n.strict_kex, content="false")
}

///|
test "negotiate: each slot with no common algorithm is a ProtocolError" {
  fn expect_err(
    role : @transport.Role,
    peer : @transport.KexInit,
    want : String,
  ) -> Unit raise {
    let ours = @transport.KexInit::for_role(role, cookie=cookie())
    try @transport.negotiate(role, ours, peer) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected negotiate to raise")
    }
  }
  let server = @transport.KexInit::for_role(Server, cookie=cookie())
  let client = @transport.KexInit::for_role(Client, cookie=cookie())
  expect_err(
    Client,
    { ..server, kex_algorithms: ["diffie-hellman-group14-sha256"], },
    "ProtocolError(\"negotiate: no common kex algorithm\")",
  )
  // Strict markers alone are not kex methods.
  expect_err(
    Client,
    { ..server, kex_algorithms: ["kex-strict-s-v00@openssh.com"], },
    "ProtocolError(\"negotiate: no common kex algorithm\")",
  )
  expect_err(
    Server,
    { ..client, server_host_key_algorithms: ["rsa-sha2-512"], },
    "ProtocolError(\"negotiate: no common host key algorithm\")",
  )
  expect_err(
    Client,
    { ..server, encryption_client_to_server: ["aes256-gcm@openssh.com"], },
    "ProtocolError(\"negotiate: no common cipher client->server\")",
  )
  expect_err(
    Server,
    { ..client, encryption_server_to_client: [], },
    "ProtocolError(\"negotiate: no common cipher server->client\")",
  )
  expect_err(
    Client,
    { ..server, compression_client_to_server: ["zlib"], },
    "ProtocolError(\"negotiate: no common compression client->server\")",
  )
  expect_err(
    Server,
    { ..client, compression_server_to_client: ["zlib"], },
    "ProtocolError(\"negotiate: no common compression server->client\")",
  )
  // Deliberate toy limitation: we never handle a guessed first kex packet.
  expect_err(
    Client,
    { ..server, first_kex_packet_follows: true, },
    "ProtocolError(\"negotiate: first_kex_packet_follows is not supported\")",
  )
}

///|
test "negotiate: strict-kex requires the peer's role-specific marker" {
  let server = @transport.KexInit::for_role(Server, cookie=cookie())
  let client = @transport.KexInit::for_role(Client, cookie=cookie())
  // Peer server that advertises the *client* marker: does not count.
  let wrong_marker = {
    ..server,
    kex_algorithms: ["curve25519-sha256", "kex-strict-c-v00@openssh.com"],
  }
  inspect(
    @transport.negotiate(Client, client, wrong_marker).strict_kex,
    content="false",
  )
  // Peer server with no marker at all.
  let no_marker = { ..server, kex_algorithms: ["curve25519-sha256"], }
  inspect(
    @transport.negotiate(Client, client, no_marker).strict_kex,
    content="false",
  )
  // Mirror for the server role.
  let wrong_marker_c = {
    ..client,
    kex_algorithms: ["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
  }
  inspect(
    @transport.negotiate(Server, server, wrong_marker_c).strict_kex,
    content="false",
  )
  // Both markers present (a peer that lists both): counts for either role.
  let both = {
    ..server,
    kex_algorithms: [
      "curve25519-sha256", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com",
    ],
  }
  inspect(@transport.negotiate(Client, client, both).strict_kex, content="true")
  // If *we* did not advertise our marker, strict is off even if the peer did.
  let ours_no_marker = { ..client, kex_algorithms: ["curve25519-sha256"], }
  inspect(
    @transport.negotiate(Client, ours_no_marker, server).strict_kex,
    content="false",
  )
}

// ---------------------------------------------------------------------------
// 2. ECDH messages, host key / signature blobs, shared secret, exchange hash
//    (docs/02 sections 4-5)
// ---------------------------------------------------------------------------

///|
/// RFC 7748 section 6.1 X25519 vector: Alice's and Bob's keys.
const ALICE_SK : String = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"

///|
const ALICE_PK : String = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

///|
const BOB_SK : String = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"

///|
const BOB_PK : String = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

///|
const ALICE_BOB_K : String = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

///|
/// RFC 8032 section 7.1 TEST 1 Ed25519 seed and public key.
const HOST_SEED : String = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

///|
const HOST_PK : String = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

///|
fn hx(s : String) -> Bytes raise {
  @hex.decode(s)
}

///|
test "KexEcdhInit: byte-exact encode and round-trip" {
  let q_c = hx(ALICE_PK)
  let m : @transport.KexEcdhInit = { q_c, }
  let payload = m.encode()
  inspect(@hex.encode(payload[:]), content="1e00000020" + ALICE_PK)
  assert_eq(@transport.KexEcdhInit::decode(payload[:]), m)
}

///|
test "KexEcdhInit::decode: rejects wrong message, trailing bytes, truncation" {
  fn expect_err(buf : Bytes, want : String) -> Unit raise {
    try @transport.KexEcdhInit::decode(buf[:]) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected KexEcdhInit::decode to raise")
    }
  }
  let good = ({ q_c: hx(ALICE_PK), } : @transport.KexEcdhInit).encode()
  expect_err(
    b"\x1f" + good[1:].to_owned(),
    "ProtocolError(\"KEX_ECDH_INIT: expected message 30, got 31\")",
  )
  // A blob of an unexpected length is *not* a codec error: how long it
  // should be belongs to the negotiated method, which checks it before
  // use (see the kex dispatch tests). The codec only cares that the
  // string is well formed.
  let short_blob = b"\x1e\x00\x00\x00\x1f" + good[5:36].to_owned()
  inspect(
    @transport.KexEcdhInit::decode(short_blob[:]).q_c.length(),
    content="31",
  )
  expect_err(
    good + b"\x00",
    "ProtocolError(\"KEX_ECDH_INIT: 1 trailing byte(s)\")",
  )
  expect_err(
    good[0:20].to_owned(),
    "ProtocolError(\"KEX_ECDH_INIT: ShortRead(need=32, have=15)\")",
  )
}

///|
test "KexEcdhReply: byte-exact encode and round-trip" {
  let k_s = @transport.encode_ed25519_host_key(hx(HOST_PK)[:])
  let sig = @transport.encode_ed25519_signature(Bytes::make(64, b'\xaa')[:])
  let m : @transport.KexEcdhReply = { k_s, q_s: hx(BOB_PK), signature: sig, }
  let payload = m.encode()
  inspect(
    @hex.encode(payload[:]),
    content="1f" +
      "00000033" +
      "0000000b7373682d65643235353139" +
      "00000020" +
      HOST_PK +
      "00000020" +
      BOB_PK +
      "00000053" +
      "0000000b7373682d65643235353139" +
      "00000040" +
      @hex.encode(Bytes::make(64, b'\xaa')[:]),
  )
  assert_eq(@transport.KexEcdhReply::decode(payload[:]), m)
}

///|
test "KexEcdhReply::decode: rejects wrong message, wrong Q_S length, trailing" {
  fn expect_err(buf : Bytes, want : String) -> Unit raise {
    try @transport.KexEcdhReply::decode(buf[:]) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected KexEcdhReply::decode to raise")
    }
  }
  let good = (
    {
      k_s: @transport.encode_ed25519_host_key(hx(HOST_PK)[:]),
      q_s: hx(BOB_PK),
      signature: @transport.encode_ed25519_signature(
        Bytes::make(64, b'\xaa')[:],
      ),
    } : @transport.KexEcdhReply).encode()
  expect_err(
    b"\x1e" + good[1:].to_owned(),
    "ProtocolError(\"KEX_ECDH_REPLY: expected message 31, got 30\")",
  )
  // As with Q_C, the length of Q_S is the method's business.
  let short_q : @transport.KexEcdhReply = {
    k_s: b"",
    q_s: b"\x01",
    signature: b"",
  }
  assert_eq(@transport.KexEcdhReply::decode(short_q.encode()[:]), short_q)
  expect_err(
    good + b"\x00",
    "ProtocolError(\"KEX_ECDH_REPLY: 1 trailing byte(s)\")",
  )
  expect_err(
    b"", "ProtocolError(\"KEX_ECDH_REPLY: ShortRead(need=1, have=0)\")",
  )
}

///|
test "ed25519 host key blob: encode/decode and rejections" {
  let blob = @transport.encode_ed25519_host_key(hx(HOST_PK)[:])
  inspect(
    @hex.encode(blob[:]),
    content="0000000b7373682d6564323535313900000020" + HOST_PK,
  )
  assert_eq(@transport.decode_ed25519_host_key(blob[:]), hx(HOST_PK))
  fn expect_err(buf : Bytes, want : String) -> Unit raise {
    try @transport.decode_ed25519_host_key(buf[:]) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected decode_ed25519_host_key to raise")
    }
  }
  expect_err(
    b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01\x00", "ProtocolError(\"host key: expected ssh-ed25519, got ssh-rsa\")",
  )
  expect_err(
    b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x02\x00\x00", "ProtocolError(\"host key: key must be 32 bytes, got 2\")",
  )
  expect_err(blob + b"\x00", "ProtocolError(\"host key: 1 trailing byte(s)\")")
  expect_err(
    blob[0:10].to_owned(),
    "ProtocolError(\"host key: ShortRead(need=11, have=6)\")",
  )
}

///|
test "ed25519 signature blob: encode/decode and rejections" {
  let raw = Bytes::makei(64, i => i.to_byte())
  let blob = @transport.encode_ed25519_signature(raw[:])
  inspect(
    @hex.encode(blob[:]),
    content="0000000b7373682d6564323535313900000040" + @hex.encode(raw[:]),
  )
  assert_eq(@transport.decode_ed25519_signature(blob[:]), raw)
  fn expect_err(buf : Bytes, want : String) -> Unit raise {
    try @transport.decode_ed25519_signature(buf[:]) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected decode_ed25519_signature to raise")
    }
  }
  expect_err(
    b"\x00\x00\x00\x0crsa-sha2-512\x00\x00\x00\x00", "ProtocolError(\"signature: expected ssh-ed25519, got rsa-sha2-512\")",
  )
  expect_err(
    b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x03\x00\x00\x00", "ProtocolError(\"signature: signature must be 64 bytes, got 3\")",
  )
  expect_err(blob + b"\x00", "ProtocolError(\"signature: 1 trailing byte(s)\")")
}

///|
test "ecdh_public / shared_secret: RFC 7748 section 6.1 vector" {
  inspect(
    @hex.encode(@transport.ecdh_public(hx(ALICE_SK)[:])[:]),
    content=ALICE_PK,
  )
  inspect(@hex.encode(@transport.ecdh_public(hx(BOB_SK)[:])[:]), content=BOB_PK)
  let k1 = @transport.shared_secret(hx(ALICE_SK)[:], hx(BOB_PK)[:])
  let k2 = @transport.shared_secret(hx(BOB_SK)[:], hx(ALICE_PK)[:])
  inspect(@hex.encode(k1[:]), content=ALICE_BOB_K)
  assert_eq(k1, k2)
}

///|
test "shared_secret: low-order or malformed peer point is a ProtocolError" {
  fn expect_err(peer : Bytes, want : String) -> Unit raise {
    try @transport.shared_secret(hx(ALICE_SK)[:], peer[:]) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected shared_secret to raise")
    }
  }
  // u = 0 is a low-order point: X25519 yields all zeros.
  expect_err(
    Bytes::make(32, b'\x00'),
    "ProtocolError(\"kex: peer ephemeral public key is invalid or low-order\")",
  )
  expect_err(
    Bytes::make(31, b'\x09'),
    "ProtocolError(\"kex: peer ephemeral public key is invalid or low-order\")",
  )
}

///|
test "shared_secret_mpint: leading 0x00 iff the top bit of K_raw is set" {
  // Top bit clear: 32-byte body, no sign byte.
  let clear = hx(ALICE_BOB_K)
  let m1 = @transport.shared_secret_mpint(clear[:])
  inspect(@hex.encode(m1[:]), content="00000020" + ALICE_BOB_K)
  // Top bit set: 33-byte body with a leading zero (the classic interop trap).
  let set = b"\x80" + Bytes::make(31, b'\x11')
  let m2 = @transport.shared_secret_mpint(set[:])
  inspect(@hex.encode(m2[:]), content="0000002100" + @hex.encode(set[:]))
  // A K_raw with leading zero bytes is shortened (RFC 4251 mpint rules).
  let m3 = @transport.shared_secret_mpint(
    (b"\x00\x00\x7f" + Bytes::make(29, b'\x22'))[:],
  )
  inspect(m3.length(), content="34")
}

///|
/// Runs the whole kex dance in memory with fixed inputs and returns
/// (H as seen by the server, H as seen by the client, K_S, signature blob).
fn dance(i_c : Bytes, i_s : Bytes) -> (Bytes, Bytes, Bytes, Bytes) raise {
  let v_c = b"SSH-2.0-toy_ssh_0.1"
  let v_s = b"SSH-2.0-OpenSSH_9.9"
  let c_sk = hx(ALICE_SK)
  let s_sk = hx(BOB_SK)
  let host_seed = hx(HOST_SEED)

  // Client: ephemeral key, sends KEX_ECDH_INIT.
  let q_c = @transport.ecdh_public(c_sk[:])
  let init_payload = ({ q_c, } : @transport.KexEcdhInit).encode()

  // Server: receives Q_C, computes Q_S and K, builds H, signs.
  let init = @transport.KexEcdhInit::decode(init_payload[:])
  let q_s = @transport.ecdh_public(s_sk[:])
  let k_srv = @transport.shared_secret_mpint(
    @transport.shared_secret(s_sk[:], init.q_c[:])[:],
  )
  let k_s = @transport.encode_ed25519_host_key(
    @crypto.fixed_to_bytes(@crypto.ed25519_public_key(host_seed[:]))[:],
  )
  let h_srv = @transport.exchange_hash(
    v_c~,
    v_s~,
    i_c~,
    i_s~,
    k_s~,
    q_c=init.q_c,
    q_s~,
    k_encoded=k_srv,
  )
  let signature = @transport.sign_exchange_hash(
    @crypto.Ed25519KeyPair::from_seed(host_seed[:]),
    h_srv[:],
  )
  let reply_payload = ({ k_s, q_s, signature, } : @transport.KexEcdhReply).encode()

  // Client: receives the reply, computes K and H, verifies.
  let reply = @transport.KexEcdhReply::decode(reply_payload[:])
  let k_cli = @transport.shared_secret_mpint(
    @transport.shared_secret(c_sk[:], reply.q_s[:])[:],
  )
  let h_cli = @transport.exchange_hash(
    v_c~,
    v_s~,
    i_c~,
    i_s~,
    k_s=reply.k_s,
    q_c~,
    q_s=reply.q_s,
    k_encoded=k_cli,
  )
  (h_srv, h_cli, reply.k_s, reply.signature)
}

///|
test "kex dance: both sides agree on H and the host signature verifies" {
  let i_c = @transport.KexInit::for_role(
    Client,
    cookie=Bytes::make(16, b'\x11'),
  ).encode()
  let i_s = @transport.KexInit::for_role(
    Server,
    cookie=Bytes::make(16, b'\x22'),
  ).encode()
  let (h_srv, h_cli, k_s, signature) = dance(i_c, i_s)
  assert_eq(h_srv, h_cli)
  inspect(h_cli.length(), content="32")
  assert_eq(@transport.decode_ed25519_host_key(k_s[:]), hx(HOST_PK))
  @transport.verify_exchange_hash(k_s[:], h_cli[:], signature[:])
  // Self-generated regression fixture for docs/06 M2 acceptance 2. Not
  // cross-checked against OpenSSH debug output.
  //
  // It moves whenever the advertised algorithm lists change, because
  // I_C and I_S are the whole KEXINIT payloads: adding
  // mlkem768x25519-sha256 to the kex list changed this value. That is the
  // fixture doing its job, not a regression — but check that the *inputs*
  // changed for a reason before updating it.
  inspect(
    @hex.encode(h_cli[:]),
    content=(
      #|7edb9505de14ea8c72e4fb6896146eafad84a5de30b081852ad03bc85698f826
    ),
  )
}

///|
test "kex dance: a flipped bit in I_C on the client side breaks verification" {
  let i_c = @transport.KexInit::for_role(
    Client,
    cookie=Bytes::make(16, b'\x11'),
  ).encode()
  let i_s = @transport.KexInit::for_role(
    Server,
    cookie=Bytes::make(16, b'\x22'),
  ).encode()
  let (_, h_good, k_s, signature) = dance(i_c, i_s)
  // Client hashes a tampered I_C (cookie bit flipped) while the server signed
  // the real one.
  let tampered = i_c[0:1].to_owned() + b"\x10" + i_c[2:].to_owned()
  let (_, h_bad, _, _) = dance(tampered, i_s)
  assert_not_eq(h_good, h_bad)
  try @transport.verify_exchange_hash(k_s[:], h_bad[:], signature[:]) catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"kex: host key signature does not verify\")",
      )
  } noraise {
    _ => fail("expected verification to fail")
  }
}

///|
test "verify_exchange_hash: malformed K_S or signature blob is a ProtocolError" {
  let h = Bytes::make(32, b'\x00')
  let k_s = @transport.encode_ed25519_host_key(hx(HOST_PK)[:])
  try
    @transport.verify_exchange_hash(
      b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x00",
      h[:],
      b"",
    )
  catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"host key: expected ssh-ed25519, got ssh-rsa\")",
      )
  } noraise {
    _ => fail("expected verification to fail")
  }
  try @transport.verify_exchange_hash(k_s[:], h[:], b"") catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"signature: ShortRead(need=4, have=0)\")",
      )
  } noraise {
    _ => fail("expected verification to fail")
  }
}

// ---------------------------------------------------------------------------
// 3. Key derivation (docs/02 section 6, RFC 4253 section 7.2)
// ---------------------------------------------------------------------------

///|
test "derive_key: 32 bytes is exactly HASH(K || H || X || session_id)" {
  let k = @transport.shared_secret_mpint(hx(ALICE_BOB_K)[:])
  let h = Bytes::make(32, b'\x5a')
  let sid = Bytes::make(32, b'\xa5')
  let want = @crypto.fixed_to_bytes(@xcrypto.sha256(k + h + b"C" + sid))
  assert_eq(@transport.derive_key(k[:], h[:], sid[:], b'C', 32), want)
  // Shorter requests truncate the same hash.
  assert_eq(
    @transport.derive_key(k[:], h[:], sid[:], b'C', 7),
    want[0:7].to_owned(),
  )
}

///|
test "derive_key: 64 bytes is K1 || K2 with K2 = HASH(K || H || K1)" {
  let k = @transport.shared_secret_mpint(hx(ALICE_BOB_K)[:])
  let h = Bytes::make(32, b'\x5a')
  let sid = Bytes::make(32, b'\x33')
  let k1 = @crypto.fixed_to_bytes(@xcrypto.sha256(k + h + b"D" + sid))
  let k2 = @crypto.fixed_to_bytes(@xcrypto.sha256(k + h + k1))
  assert_eq(@transport.derive_key(k[:], h[:], sid[:], b'D', 64), k1 + k2)
  // Different letters give different keys; session_id != H matters.
  assert_not_eq(
    @transport.derive_key(k[:], h[:], sid[:], b'C', 64),
    @transport.derive_key(k[:], h[:], sid[:], b'D', 64),
  )
  assert_not_eq(
    @transport.derive_key(k[:], h[:], sid[:], b'C', 64),
    @transport.derive_key(k[:], h[:], h[:], b'C', 64),
  )
}

///|
test "derive_session_keys: pinned C/D keys from the fixed-input dance" {
  let i_c = @transport.KexInit::for_role(
    Client,
    cookie=Bytes::make(16, b'\x11'),
  ).encode()
  let i_s = @transport.KexInit::for_role(
    Server,
    cookie=Bytes::make(16, b'\x22'),
  ).encode()
  let (h, _, _, _) = dance(i_c, i_s)
  let k = @transport.shared_secret_mpint(
    @transport.shared_secret(hx(ALICE_SK)[:], hx(BOB_PK)[:])[:],
  )
  // First kex: session_id == H.
  let keys = @transport.derive_session_keys(ChaCha20Poly1305, k[:], h[:], h[:])
  let c = keys.c2s.enc
  let d = keys.s2c.enc
  inspect(c.length(), content="64")
  inspect(d.length(), content="64")
  assert_eq(c, @transport.derive_key(k[:], h[:], h[:], b'C', 64))
  assert_eq(d, @transport.derive_key(k[:], h[:], h[:], b'D', 64))
  // The AEAD has no IV and no separate MAC key, so neither is derived.
  assert_eq(keys.c2s.iv, b"")
  assert_eq(keys.c2s.mac, b"")
  assert_eq(keys.s2c.iv, b"")
  assert_eq(keys.s2c.mac, b"")
  // Self-generated regression fixtures (not cross-checked against
  // OpenSSH). They derive from H, so they move with it — see the note on
  // the H fixture above.
  inspect(
    @hex.encode(c[:]),
    content=(
      #|1efb9b106b90512bd4307fcc618e5e34866ce06edd37b97dd304e17587a96f9587e4e816599f8321fbd0daf43a908de3a9cbcbda35f9826375a05648a954f1b3
    ),
  )
  inspect(
    @hex.encode(d[:]),
    content=(
      #|58efd805951f377c7dbeba388b6cc75b540d3e549afc9e706202e3ba9cbf081a6d5543926090b9eb3cf8491ec4eb4123bc899bef500680112059e0ee3e17058a
    ),
  )
  // Role mapping: client sends with C and receives with D; server mirrors.
  assert_eq(keys.send_keys(Client).enc, c)
  assert_eq(keys.recv_keys(Client).enc, d)
  assert_eq(keys.send_keys(Server).enc, d)
  assert_eq(keys.recv_keys(Server).enc, c)
}

///|
test "derive_session_keys: aes128-ctr takes all six letters A..F" {
  let i_c = @transport.KexInit::for_role(
    Client,
    cookie=Bytes::make(16, b'\x11'),
  ).encode()
  let i_s = @transport.KexInit::for_role(
    Server,
    cookie=Bytes::make(16, b'\x22'),
  ).encode()
  let (h, _, _, _) = dance(i_c, i_s)
  let k = @transport.shared_secret_mpint(
    @transport.shared_secret(hx(ALICE_SK)[:], hx(BOB_PK)[:])[:],
  )
  let keys = @transport.derive_session_keys(
    Aes128CtrHmacSha256,
    k[:],
    h[:],
    h[:],
  )
  // RFC 4253 section 7.2: A/B are the IVs, C/D the keys, E/F the MAC keys,
  // client-to-server first. Getting a letter or a direction wrong still
  // round-trips against ourselves, so each one is pinned here.
  assert_eq(keys.c2s.iv, @transport.derive_key(k[:], h[:], h[:], b'A', 16))
  assert_eq(keys.s2c.iv, @transport.derive_key(k[:], h[:], h[:], b'B', 16))
  assert_eq(keys.c2s.enc, @transport.derive_key(k[:], h[:], h[:], b'C', 16))
  assert_eq(keys.s2c.enc, @transport.derive_key(k[:], h[:], h[:], b'D', 16))
  assert_eq(keys.c2s.mac, @transport.derive_key(k[:], h[:], h[:], b'E', 32))
  assert_eq(keys.s2c.mac, @transport.derive_key(k[:], h[:], h[:], b'F', 32))
}

///|
test "kex methods: the advertised names map to implementations" {
  // Until now the negotiated kex name was stored and never used: X25519
  // was wired in directly. A second method needs a real dispatch point.
  guard @transport.kex_method(@transport.KEX_CURVE25519_SHA256) is Some(a) else {
    fail("curve25519-sha256 must be supported")
  }
  debug_inspect(a, content="Curve25519")
  guard @transport.kex_method(@transport.KEX_CURVE25519_SHA256_LIBSSH)
    is Some(b) else {
    fail("the @libssh.org alias must be supported")
  }
  debug_inspect(b, content="Curve25519")
  // A name we do not implement, and the strict-kex marker, are not methods.
  assert_true(@transport.kex_method("diffie-hellman-group14-sha256") is None)
  assert_true(@transport.kex_method(@transport.KEX_STRICT_CLIENT) is None)
  // Every name we advertise must map to something we can run.
  let ki = @transport.KexInit::for_role(Client, cookie=Bytes::make(16, b'\x11'))
  for name in ki.kex_algorithms {
    if name != @transport.KEX_STRICT_CLIENT {
      assert_true(@transport.kex_method(name) is Some(_))
    }
  }
}

///|
test "kex dispatch: curve25519 through the dispatch matches the direct calls" {
  let c_scalar = @hex.decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let s_scalar = @hex.decode(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  let kex = @transport.Curve25519
  // The client's blob is still just Q_C, and X25519 alone keeps no extra
  // state, so the ML-KEM randomness is ignored.
  let (q_c, state) = @transport.kex_client_init(kex, c_scalar[:], b""[:])
  assert_eq(q_c, @transport.ecdh_public(c_scalar[:]))
  // The server answers with its blob and the encoded shared secret.
  let (q_s, k_server) = @transport.kex_server_exchange(
    kex,
    s_scalar[:],
    b""[:],
    q_c[:],
  )
  assert_eq(q_s, @transport.ecdh_public(s_scalar[:]))
  // For curve25519 the encoding is the wire mpint, as before.
  let raw = @transport.shared_secret(s_scalar[:], q_c[:])
  assert_eq(k_server, @transport.shared_secret_mpint(raw[:]))
  // The client derives the same encoded secret from the server's blob.
  let k_client = @transport.kex_client_shared(kex, state, q_s[:])
  assert_eq(k_client, k_server)
}

///|
test "kex dispatch: a malformed peer blob is a protocol error" {
  let scalar = @hex.decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let (_, state) = @transport.kex_client_init(
    @transport.Curve25519,
    scalar[:],
    b""[:],
  )
  for bad in [b"", b"\x09", Bytes::make(33, b'\x09'), Bytes::make(32, b'\x00')] {
    try
      ignore(
        @transport.kex_server_exchange(
          @transport.Curve25519,
          scalar[:],
          b""[:],
          bad[:],
        ),
      )
    catch {
      ProtocolError(_) => ()
    } noraise {
      _ => fail("expected a ProtocolError for a \{bad.length()}-byte blob")
    }
    try
      ignore(@transport.kex_client_shared(@transport.Curve25519, state, bad[:]))
    catch {
      ProtocolError(_) => ()
    } noraise {
      _ => fail("expected a ProtocolError for a \{bad.length()}-byte blob")
    }
  }
}

///|
test "the ML-KEM hybrid is a known method and is advertised first" {
  guard @transport.kex_method(@transport.KEX_MLKEM768X25519_SHA256) is Some(m) else {
    fail("mlkem768x25519-sha256 must be supported")
  }
  debug_inspect(m, content="MlKem768X25519")
  // OpenSSH prefers it first, and so do we: a post-quantum exchange
  // should be the default rather than something a peer has to ask for.
  let ki = @transport.KexInit::for_role(Client, cookie=Bytes::make(16, b'\x11'))
  inspect(ki.kex_algorithms[0], content="mlkem768x25519-sha256")
}

///|
test "hybrid exchange: both sides derive the same secret, encoded as a string" {
  // Fixed seeds so the test is deterministic.
  let c_scalar = @hex.decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let s_scalar = @hex.decode(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  let c_kem = Bytes::makei(64, i => (0x40 + i).to_byte())
  let s_kem = Bytes::makei(32, i => (0x80 + i).to_byte())
  let kex = @transport.MlKem768X25519
  let (blob_c, state) = @transport.kex_client_init(kex, c_scalar[:], c_kem[:])
  // ML-KEM public key then the X25519 one, as one string (OpenSSH's
  // kex_kem_mlkem768x25519_keypair).
  inspect(blob_c.length(), content="1216")
  let (blob_s, k_server) = @transport.kex_server_exchange(
    kex,
    s_scalar[:],
    s_kem[:],
    blob_c[:],
  )
  // ML-KEM ciphertext then the X25519 public key.
  inspect(blob_s.length(), content="1120")
  let k_client = @transport.kex_client_shared(kex, state, blob_s[:])
  assert_eq(k_client, k_server)
  // K is a `string`, not an mpint: a 4-byte length of 32 then the hash.
  inspect(k_server.length(), content="36")
  inspect(@hex.encode(k_server[0:4]), content="00000020")
}

///|
test "hybrid exchange: malformed peer blobs are protocol errors" {
  let scalar = @hex.decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let kem = Bytes::makei(64, i => (0x40 + i).to_byte())
  let kex = @transport.MlKem768X25519
  let (_, state) = @transport.kex_client_init(kex, scalar[:], kem[:])
  // The server needs exactly 1184 + 32 bytes from the client.
  for bad in [b"", Bytes::make(1215, b'\x01'), Bytes::make(1217, b'\x01')] {
    try
      ignore(@transport.kex_server_exchange(kex, scalar[:], kem[0:32], bad[:]))
    catch {
      ProtocolError(_) => ()
    } noraise {
      _ => fail("expected a ProtocolError for \{bad.length()} bytes")
    }
  }
  // The client needs exactly 1088 + 32 bytes back.
  for bad in [b"", Bytes::make(1119, b'\x01'), Bytes::make(1121, b'\x01')] {
    try ignore(@transport.kex_client_shared(kex, state, bad[:])) catch {
      ProtocolError(_) => ()
    } noraise {
      _ => fail("expected a ProtocolError for \{bad.length()} bytes")
    }
  }
  // An all-zero X25519 half is a low-order point and must be refused even
  // though the ML-KEM half is well formed.
  let (blob_c, _) = @transport.kex_client_init(kex, scalar[:], kem[:])
  let (blob_s, _) = @transport.kex_server_exchange(
    kex,
    scalar[:],
    kem[0:32],
    blob_c[:],
  )
  let zeroed = blob_s.to_fixedarray()
  for i in 1088..<1120 {
    zeroed[i] = b'\x00'
  }
  try
    ignore(
      @transport.kex_client_shared(
        kex,
        state,
        Bytes::from_iter(zeroed.iter())[:],
      ),
    )
  catch {
    ProtocolError(_) => ()
  } noraise {
    _ => fail("expected a ProtocolError for an all-zero X25519 half")
  }
}

///|
test "a truncated blob reports a framing error, not a low-order point" {
  // The codecs treat the blob as an opaque string, so the length check
  // lives with the method. Before this, a 31-byte Q_C reached X25519 and
  // came back as "invalid or low-order", which blames an attack for what
  // is a framing bug.
  let scalar = @hex.decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let (_, state) = @transport.kex_client_init(
    @transport.Curve25519,
    scalar[:],
    b""[:],
  )
  try
    ignore(
      @transport.kex_server_exchange(
        @transport.Curve25519,
        scalar[:],
        b""[:],
        Bytes::make(31, b'\x09')[:],
      ),
    )
  catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"kex: Q_C must be 32 bytes, got 31\")",
      )
  } noraise {
    _ => fail("expected a ProtocolError")
  }
  try
    ignore(
      @transport.kex_client_shared(
        @transport.Curve25519,
        state,
        Bytes::make(33, b'\x09')[:],
      ),
    )
  catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"kex: Q_S must be 32 bytes, got 33\")",
      )
  } noraise {
    _ => fail("expected a ProtocolError")
  }
  // An all-zero blob of the right length still reports the real reason.
  try
    ignore(
      @transport.kex_server_exchange(
        @transport.Curve25519,
        scalar[:],
        b""[:],
        Bytes::make(32, b'\x00')[:],
      ),
    )
  catch {
    ProtocolError(m) =>
      assert_true(m.contains("low-order") || m.contains("invalid"))
  } noraise {
    _ => fail("expected a ProtocolError")
  }
}

///|
/// The summary a binary prints after the handshake. An AEAD suite has no
/// separate MAC, so it says nothing about one rather than printing an
/// empty name.
test "negotiate: the summary names what a run actually settled on" {
  let aead = @transport.negotiate(
    Client,
    @transport.KexInit::for_role(Client, cookie=cookie()),
    @transport.KexInit::for_role(Server, cookie=cookie()),
  )
  inspect(
    aead.summary(),
    content="kex=mlkem768x25519-sha256 host-key=ssh-ed25519 cipher=chacha20-poly1305@openssh.com strict-kex=true",
  )
  let ctr = @transport.negotiate(
    Client,
    @transport.KexInit::for_role(
      Client,
      cookie=cookie(),
      ciphers=Some([@transport.CIPHER_AES128_CTR]),
    ),
    @transport.KexInit::for_role(Server, cookie=cookie()),
  )
  inspect(
    ctr.summary(),
    content="kex=mlkem768x25519-sha256 host-key=ssh-ed25519 cipher=aes128-ctr mac=hmac-sha2-256 strict-kex=true",
  )
}
