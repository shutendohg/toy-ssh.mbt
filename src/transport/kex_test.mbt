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
      #|  kex: "curve25519-sha256",
      #|  host_key: "ssh-ed25519",
      #|  cipher_client_to_server: "chacha20-poly1305@openssh.com",
      #|  cipher_server_to_client: "chacha20-poly1305@openssh.com",
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
  inspect(n.kex, content="curve25519-sha256")
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
    { ..server, encryption_client_to_server: ["aes128-ctr"], },
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
test "KexEcdhInit::decode: rejects wrong message, wrong Q length, trailing, truncated" {
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
  expect_err(
    b"\x1e\x00\x00\x00\x1f" + good[5:36].to_owned(),
    "ProtocolError(\"KEX_ECDH_INIT: Q_C must be 32 bytes, got 31\")",
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
  let short_q : @transport.KexEcdhReply = {
    k_s: b"",
    q_s: b"\x01",
    signature: b"",
  }
  expect_err(
    short_q.encode(),
    "ProtocolError(\"KEX_ECDH_REPLY: Q_S must be 32 bytes, got 1\")",
  )
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
    k_mpint=k_srv,
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
    k_mpint=k_cli,
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
  // Self-generated regression fixture for docs/06 M2 acceptance 2. Not yet
  // cross-checked against OpenSSH debug output.
  inspect(
    @hex.encode(h_cli[:]),
    content="718aad6c5e4911a8e2ec855eb5df023119c4cd79427aff85db7a4c6c34ea73a7",
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
  let keys = @transport.derive_session_keys(k[:], h[:], h[:])
  inspect(keys.c.length(), content="64")
  inspect(keys.d.length(), content="64")
  assert_eq(keys.c, @transport.derive_key(k[:], h[:], h[:], b'C', 64))
  assert_eq(keys.d, @transport.derive_key(k[:], h[:], h[:], b'D', 64))
  // Self-generated regression fixtures (not cross-checked against OpenSSH).
  inspect(
    @hex.encode(keys.c[:]),
    content="1091f669177fe84d7270066c93a3f23bbe319f8a99f976da59ea8f333b8ac1b5bdad53fe41e2e20056fcefbc38a5ad663f4bd1129cae946f55cbd14acc9611dd",
  )
  inspect(
    @hex.encode(keys.d[:]),
    content="5a03b03de4161e7804d37f562070a5dc46707d1dc876c9ab57e7a1162ad3853462911204727e125b7b9f84e2ee5474316e9089aeffe90f356ae8406953826219",
  )
  // Role mapping: client sends with C and receives with D; server mirrors.
  assert_eq(keys.send_key(Client), keys.c)
  assert_eq(keys.recv_key(Client), keys.d)
  assert_eq(keys.send_key(Server), keys.d)
  assert_eq(keys.recv_key(Server), keys.c)
}
