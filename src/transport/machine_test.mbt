// Sans-IO transport state machine: docs/06 M2 acceptance 1 (in-memory
// self-interop) and the docs/07 layer-2 pump, plus disconnect paths.

///|
/// Fixed, obviously-not-random inputs. Client scalar / server scalar are
/// the RFC 7748 section 6.1 Alice / Bob secrets; the host seed is RFC 8032
/// TEST 1.
fn client_config(
  ciphers? : Array[String]? = None,
) -> @transport.TransportConfig raise {
  {
    role: Client,
    ciphers,
    cookie: Bytes::make(16, b'\x11'),
    ephemeral_scalar: @hex.decode(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ),
    kem_random: Bytes::makei(64, i => (0xa0 + i).to_byte()),
    host_seed: None,
    fill: @transport.zero_padding,
    accept_host_key: _ => true,
  }
}

///|
fn server_config(
  ciphers? : Array[String]? = None,
) -> @transport.TransportConfig raise {
  {
    role: Server,
    ciphers,
    cookie: Bytes::make(16, b'\x22'),
    ephemeral_scalar: @hex.decode(
      "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ),
    kem_random: Bytes::makei(32, i => (0xb0 + i).to_byte()),
    host_seed: Some(
      @hex.decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      ),
    ),
    fill: @transport.zero_padding,
    accept_host_key: _ => true,
  }
}

///|
/// Pump bytes between two machines until neither has output. Returns the
/// events each side produced, in order.
fn pump(
  a : @transport.Transport,
  b : @transport.Transport,
) -> (Array[@transport.TransportEvent], Array[@transport.TransportEvent]) {
  let ea : Array[@transport.TransportEvent] = []
  let eb : Array[@transport.TransportEvent] = []
  for _ in 0..<50 {
    let out_a = a.take_outgoing()
    let out_b = b.take_outgoing()
    if out_a.length() == 0 && out_b.length() == 0 {
      break
    }
    if out_a.length() > 0 {
      eb.append(b.on_received(out_a[:]))
    }
    if out_b.length() > 0 {
      ea.append(a.on_received(out_b[:]))
    }
  }
  (ea, eb)
}

///|
fn events_hex(events : Array[@transport.TransportEvent]) -> Array[String] {
  events.map(e => {
    match e {
      Established(session_id~) =>
        "Established(" + @hex.encode(session_id[:]) + ")"
      Packet(payload~) => "Packet(" + @hex.encode(payload[:]) + ")"
      Disconnect(code~, description~, by_peer~) =>
        "Disconnect(\{code}, \{description}, by_peer=\{by_peer})"
    }
  })
}

///|
fn show_events(events : Array[@transport.TransportEvent]) -> String {
  events_hex(events).join(", ")
}

///|
test "self-interop: both sides reach Established with the same session_id" {
  let c = @transport.Transport::new(client_config())
  let s = @transport.Transport::new(server_config())
  let (ec, es) = pump(c, s)
  assert_eq(ec.length(), 1)
  assert_eq(es.length(), 1)
  guard ec[0] is Established(session_id=sid_c) else {
    fail("client: \{show_events(ec)}")
  }
  guard es[0] is Established(session_id=sid_s) else {
    fail("server: \{show_events(es)}")
  }
  assert_eq(sid_c, sid_s)
  assert_eq(sid_c.length(), 32)
  assert_eq(c.session_id(), Some(sid_c))
  assert_eq(s.session_id(), Some(sid_s))
  assert_true(c.is_established())
  assert_true(s.is_established())
  // strict kex negotiated on both sides (both markers present)
  assert_true(c.strict_kex())
  assert_true(s.strict_kex())
}

///|
test "self-interop: encrypted payloads survive round trips in both directions" {
  let c = @transport.Transport::new(client_config())
  let s = @transport.Transport::new(server_config())
  ignore(pump(c, s))
  // SERVICE_REQUEST is a next-layer message: the transport must hand it up.
  c.send_packet(@transport.encode_service_request("ssh-userauth")[:])
  let (_, es) = pump(c, s)
  debug_inspect(
    events_hex(es),
    content=(
      #|["Packet(050000000c7373682d7573657261757468)"]
    ),
  )
  s.send_packet(@transport.encode_service_accept("ssh-userauth")[:])
  let (ec, _) = pump(c, s)
  debug_inspect(
    events_hex(ec),
    content=(
      #|["Packet(060000000c7373682d7573657261757468)"]
    ),
  )
  // Several packets in a row exercise the sequence numbers.
  for i in 0..<5 {
    c.send_packet(
      b"\x05\x00\x00\x00\x01" + Bytes::make(1, (0x30 + i).to_byte()),
    )
  }
  let (_, es2) = pump(c, s)
  assert_eq(es2.length(), 5)
  for i in 0..<5 {
    guard es2[i] is Packet(payload~) else { fail("expected Packet") }
    assert_eq(payload[5], (0x30 + i).to_byte())
  }
}

///|
test "self-interop: exchange hash matches the kex fixture inputs" {
  // Recompute H by hand from the same inputs the two machines used. They
  // negotiate the ML-KEM hybrid, so the blobs are the hybrid's and K is
  // its `string`, not X25519's `mpint`.
  let c = @transport.Transport::new(client_config())
  let s = @transport.Transport::new(server_config())
  let (ec, _) = pump(c, s)
  guard ec[0] is Established(session_id~) else { fail("no Established") }
  let i_c = @transport.KexInit::for_role(
    Client,
    cookie=Bytes::make(16, b'\x11'),
  ).encode()
  let i_s = @transport.KexInit::for_role(
    Server,
    cookie=Bytes::make(16, b'\x22'),
  ).encode()
  let (q_c, state) = @transport.kex_client_init(
    @transport.MlKem768X25519,
    client_config().ephemeral_scalar[:],
    client_config().kem_random[:],
  )
  let (q_s, k_encoded) = @transport.kex_server_exchange(
    @transport.MlKem768X25519,
    server_config().ephemeral_scalar[:],
    server_config().kem_random[:],
    q_c[:],
  )
  // The client must reach the same K from the reply alone.
  assert_eq(
    @transport.kex_client_shared(@transport.MlKem768X25519, state, q_s[:]),
    k_encoded,
  )
  let k_s = @transport.encode_ed25519_host_key(
    @crypto.fixed_to_bytes(
      @crypto.ed25519_public_key(server_config().host_seed.unwrap()[:]),
    ),
  )
  let v = @ascii.encode(@transport.OUR_VERSION)
  let h = @transport.exchange_hash(
    v_c=v,
    v_s=v,
    i_c~,
    i_s~,
    k_s~,
    q_c~,
    q_s~,
    k_encoded~,
  )
  assert_eq(session_id, h)
}

///|
test "first outgoing bytes are the version line followed by a plaintext KEXINIT" {
  let c = @transport.Transport::new(client_config())
  let out = c.take_outgoing()
  let line = @transport.version_line()
  assert_eq(out[0:line.length()].to_owned(), line)
  match @transport.decode_packet(out[line.length():]) {
    Packet(payload~, consumed~) => {
      assert_eq(line.length() + consumed, out.length())
      let ki = @transport.KexInit::decode(payload[:])
      assert_eq(
        ki,
        @transport.KexInit::for_role(Client, cookie=Bytes::make(16, b'\x11')),
      )
    }
    NeedMoreData => fail("KEXINIT packet incomplete")
  }
  // Nothing more until the peer speaks.
  assert_eq(c.take_outgoing().length(), 0)
}

///|
/// Feed `data` to `t` and return the events, asserting exactly one
/// Disconnect with `code` came out, and that a DISCONNECT packet was
/// queued for the peer.
fn expect_disconnect(
  t : @transport.Transport,
  data : Bytes,
  code : UInt,
) -> String raise {
  let events = t.on_received(data[:])
  guard events.length() == 1 else { fail("events: \{show_events(events)}") }
  guard events[0] is Disconnect(code=got, description~, by_peer=false) else {
    fail("expected local Disconnect, got \{show_events(events)}")
  }
  assert_eq(got, code)
  assert_true(t.is_closed())
  // Outgoing ends with a DISCONNECT packet (plaintext before NEWKEYS).
  let out = t.take_outgoing()
  assert_true(out.length() > 0)
  // Further input is ignored once closed.
  assert_eq(t.on_received(b"junk"[:]).length(), 0)
  description
}

///|
test "disconnect: unsupported protocol version" {
  let c = @transport.Transport::new(client_config())
  ignore(c.take_outgoing())
  let desc = expect_disconnect(
    c,
    b"SSH-1.99-old\r\n",
    @transport.SSH_DISCONNECT_PROTOCOL_ERROR,
  )
  inspect(desc, content="unsupported protocol version: SSH-1.99-old")
}

///|
test "disconnect: peer KEXINIT without our algorithms" {
  let s = @transport.Transport::new(server_config())
  ignore(s.take_outgoing())
  let peer = {
    ..@transport.KexInit::for_role(Client, cookie=Bytes::make(16, b'\x33')),
    kex_algorithms: ["diffie-hellman-group14-sha256"],
  }
  let bytes = @transport.version_line() +
    @transport.encode_packet(peer.encode()[:], fill=@transport.zero_padding)
  ignore(
    expect_disconnect(s, bytes, @transport.SSH_DISCONNECT_KEY_EXCHANGE_FAILED),
  )
}

///|
test "disconnect: tampered server signature is rejected by the client" {
  let c = @transport.Transport::new(client_config())
  let s = @transport.Transport::new(server_config())
  // version + KEXINIT both ways, then client's ECDH_INIT to the server
  ignore(s.on_received(c.take_outgoing()[:]))
  ignore(c.on_received(s.take_outgoing()[:]))
  ignore(s.on_received(c.take_outgoing()[:]))
  // server output: ECDH_REPLY packet then NEWKEYS packet, both plaintext
  let out = s.take_outgoing()
  guard @transport.decode_packet(out[:]) is Packet(payload~, consumed~) else {
    fail("no reply packet")
  }
  let reply = @transport.KexEcdhReply::decode(payload[:])
  let sig = reply.signature.to_fixedarray()
  sig[sig.length() - 1] = sig[sig.length() - 1] ^ b'\x01'
  let tampered = { ..reply, signature: Bytes::from_iter(sig.iter()), }
  let bad = @transport.encode_packet(
      tampered.encode()[:],
      fill=@transport.zero_padding,
    ) +
    out[consumed:].to_owned()
  ignore(
    expect_disconnect(c, bad, @transport.SSH_DISCONNECT_KEY_EXCHANGE_FAILED),
  )
}

///|
test "disconnect: host key rejected by policy" {
  let cfg = { ..client_config(), accept_host_key: _ => false, }
  let c = @transport.Transport::new(cfg)
  let s = @transport.Transport::new(server_config())
  let (ec, _) = pump(c, s)
  guard ec[0] is Disconnect(code~, by_peer=false, ..) else {
    fail("expected Disconnect, got \{show_events(ec)}")
  }
  assert_eq(code, @transport.SSH_DISCONNECT_KEY_EXCHANGE_FAILED)
}

///|
test "disconnect: strict kex forbids IGNORE during the key exchange" {
  let s = @transport.Transport::new(server_config())
  ignore(s.take_outgoing())
  let bytes = @transport.version_line() +
    @transport.encode_packet(
      @transport.KexInit::for_role(Client, cookie=Bytes::make(16, b'\x33')).encode()[:],
      fill=@transport.zero_padding,
    ) +
    @transport.encode_packet(
      b"\x02\x00\x00\x00\x00"[:],
      fill=@transport.zero_padding,
    )
  ignore(expect_disconnect(s, bytes, @transport.SSH_DISCONNECT_PROTOCOL_ERROR))
}

///|
test "non-strict peer: IGNORE during kex is skipped and seqnums carry over" {
  // A client without the strict marker, driven by hand against our server.
  let s = @transport.Transport::new(server_config())
  let peer_ki = {
    ..@transport.KexInit::for_role(Client, cookie=Bytes::make(16, b'\x33')),
    kex_algorithms: ["curve25519-sha256"],
  }
  let scalar = client_config().ephemeral_scalar
  let bytes = @transport.version_line() +
    @transport.encode_packet(peer_ki.encode()[:], fill=@transport.zero_padding) +
    @transport.encode_packet(
      b"\x02\x00\x00\x00\x00"[:],
      fill=@transport.zero_padding,
    ) +
    @transport.encode_packet(
      ({ q_c: @transport.ecdh_public(scalar[:]), } : @transport.KexEcdhInit).encode()[:],
      fill=@transport.zero_padding,
    )
  let s_out0 = s.take_outgoing()
  assert_eq(s.on_received(bytes[:]).length(), 0)
  assert_false(s.strict_kex())
  // Server sent: version, KEXINIT (seq 0), ECDH_REPLY (seq 1), NEWKEYS (seq 2).
  // Without strict kex its next (encrypted) packet uses seq 3; ours would be
  // KEXINIT(0), IGNORE(1), ECDH_INIT(2), NEWKEYS(3) -> first encrypted seq 4.
  let out = s.take_outgoing()
  let line_len = @transport.version_line().length()
  let mut off = 0
  let mut reply_payload = b""
  // skip KEXINIT in s_out0, then parse ECDH_REPLY and NEWKEYS from out
  ignore(s_out0[line_len:])
  guard @transport.decode_packet(out[:]) is Packet(payload~, consumed~) else {
    fail("no reply")
  }
  reply_payload = payload
  off = consumed
  guard @transport.decode_packet(out[off:]) is Packet(payload=nk, consumed=c2) else {
    fail("no newkeys")
  }
  assert_eq(nk, b"\x15")
  assert_eq(off + c2, out.length())
  let reply = @transport.KexEcdhReply::decode(reply_payload[:])
  // Compute the keys as the peer would.
  let k = @transport.shared_secret(scalar[:], reply.q_s[:])
  let v = @ascii.encode(@transport.OUR_VERSION)
  let h = @transport.exchange_hash(
    v_c=v,
    v_s=v,
    i_c=peer_ki.encode(),
    i_s=@transport.KexInit::for_role(Server, cookie=Bytes::make(16, b'\x22')).encode(),
    k_s=reply.k_s,
    q_c=@transport.ecdh_public(scalar[:]),
    q_s=reply.q_s,
    k_encoded=@transport.shared_secret_mpint(k[:]),
  )
  let keys = @transport.derive_session_keys(
    ChaCha20Poly1305,
    @transport.shared_secret_mpint(k[:])[:],
    h[:],
    h[:],
  )
  // Peer sends NEWKEYS (plaintext seq 3), then an encrypted SERVICE_REQUEST
  // with seq 4 (non-strict: counters continue).
  let newkeys = @transport.encode_packet(
    b"\x15"[:],
    fill=@transport.zero_padding,
  )
  let ev = s.on_received(newkeys[:])
  guard ev.length() == 1 && ev[0] is Established(..) else {
    fail("expected Established, got \{show_events(ev)}")
  }
  let enc_req = @transport.seal_packet(
    @transport.RecordKey::new(keys.send_keys(Client).enc[:]),
    4,
    @transport.encode_service_request("ssh-userauth")[:],
    fill=@transport.zero_padding,
  )
  debug_inspect(
    events_hex(s.on_received(enc_req[:])),
    content=(
      #|["Packet(050000000c7373682d7573657261757468)"]
    ),
  )
  // And the server's first encrypted packet must use seq 3.
  s.send_packet(b"\x06\x00\x00\x00\x00"[:])
  let enc = s.take_outgoing()
  guard @transport.open_packet(
      @transport.RecordKey::new(keys.recv_keys(Client).enc[:]),
      3,
      enc[:],
    )
    is Packet(payload~, ..) else {
    fail("could not open with seq 3")
  }
  assert_eq(payload, b"\x06\x00\x00\x00\x00")
}

///|
test "disconnect: corrupted ciphertext after NEWKEYS is a MAC error" {
  let c = @transport.Transport::new(client_config())
  let s = @transport.Transport::new(server_config())
  ignore(pump(c, s))
  c.send_packet(b"\x05\x00\x00\x00\x00"[:])
  let enc = c.take_outgoing().to_fixedarray()
  enc[enc.length() - 1] = enc[enc.length() - 1] ^ b'\x80'
  let ev = s.on_received(Bytes::from_iter(enc.iter())[:])
  guard ev.length() == 1 && ev[0] is Disconnect(code~, by_peer=false, ..) else {
    fail("expected Disconnect, got \{show_events(ev)}")
  }
  assert_eq(code, @transport.SSH_DISCONNECT_MAC_ERROR)
  // The DISCONNECT we queued is encrypted and readable by the (uncorrupted) client.
  let ec = c.on_received(s.take_outgoing()[:])
  guard ec.length() == 1 && ec[0] is Disconnect(code=pc, by_peer=true, ..) else {
    fail("client should see the peer's DISCONNECT, got \{show_events(ec)}")
  }
  assert_eq(pc, @transport.SSH_DISCONNECT_MAC_ERROR)
  assert_true(c.is_closed())
}

///|
test "disconnect: KEXINIT after the handshake (rekey) is refused" {
  let c = @transport.Transport::new(client_config())
  let s = @transport.Transport::new(server_config())
  ignore(pump(c, s))
  c.send_packet(
    @transport.KexInit::for_role(Client, cookie=Bytes::make(16, b'\x44')).encode()[:],
  )
  let ev = s.on_received(c.take_outgoing()[:])
  guard ev.length() == 1 &&
    ev[0] is Disconnect(code~, description~, by_peer=false) else {
    fail("expected Disconnect, got \{show_events(ev)}")
  }
  assert_eq(code, @transport.SSH_DISCONNECT_PROTOCOL_ERROR)
  inspect(description, content="rekeying is not supported")
}

///|
test "established: IGNORE, DEBUG, UNIMPLEMENTED and EXT_INFO are swallowed" {
  let c = @transport.Transport::new(client_config())
  let s = @transport.Transport::new(server_config())
  ignore(pump(c, s))
  c.send_packet(b"\x02\x00\x00\x00\x00"[:])
  c.send_packet(b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"[:])
  c.send_packet(b"\x03\x00\x00\x00\x07"[:])
  c.send_packet(b"\x07\x00\x00\x00\x00"[:])
  c.send_packet(b"\x05\x00\x00\x00\x00"[:])
  let (_, es) = pump(c, s)
  debug_inspect(
    events_hex(es),
    content=(
      #|["Packet(0500000000)"]
    ),
  )
}

///|
test "local disconnect: queues an encrypted DISCONNECT the peer reports" {
  let c = @transport.Transport::new(client_config())
  let s = @transport.Transport::new(server_config())
  ignore(pump(c, s))
  c.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, "bye")
  assert_true(c.is_closed())
  let (_, es) = pump(c, s)
  debug_inspect(
    events_hex(es),
    content=(
      #|["Disconnect(2, bye, by_peer=true)"]
    ),
  )
  assert_true(s.is_closed())
}

///|
test "fuzz: garbage never crashes, always ends in a Disconnect" {
  // Deterministic LCG so the test is reproducible.
  let mut x = 12345U
  fn next() -> Byte {
    x = x * 1103515245U + 12345U
    ((x >> 16) & 0xffU).to_byte()
  }
  for round in 0..<40 {
    let s = @transport.Transport::new(server_config())
    ignore(s.take_outgoing())
    let mut prefix = b""
    if round % 2 == 0 {
      prefix = @transport.version_line()
    }
    let junk = Bytes::makei(1 + round * 7, _ => next())
    let mut saw_disconnect = false
    for ev in s.on_received((prefix + junk)[:]) {
      if ev is Disconnect(..) {
        saw_disconnect = true
      }
    }
    // Either it disconnected or it is still waiting for more bytes.
    assert_true(saw_disconnect || !s.is_closed())
  }
}

///|
test "disconnect: strict kex requires KEXINIT to be the peer's first packet" {
  let s = @transport.Transport::new(server_config())
  ignore(s.take_outgoing())
  let bytes = @transport.version_line() +
    @transport.encode_packet(
      b"\x02\x00\x00\x00\x00"[:],
      fill=@transport.zero_padding,
    ) +
    @transport.encode_packet(
      @transport.KexInit::for_role(Client, cookie=Bytes::make(16, b'\x33')).encode()[:],
      fill=@transport.zero_padding,
    )
  let desc = expect_disconnect(
    s,
    bytes,
    @transport.SSH_DISCONNECT_PROTOCOL_ERROR,
  )
  inspect(desc, content="KEXINIT was not the first packet")
}

///|
test "non-strict peer: IGNORE before KEXINIT is tolerated" {
  let s = @transport.Transport::new(server_config())
  ignore(s.take_outgoing())
  let peer_ki = {
    ..@transport.KexInit::for_role(Client, cookie=Bytes::make(16, b'\x33')),
    kex_algorithms: ["curve25519-sha256"],
  }
  let bytes = @transport.version_line() +
    @transport.encode_packet(
      b"\x02\x00\x00\x00\x00"[:],
      fill=@transport.zero_padding,
    ) +
    @transport.encode_packet(peer_ki.encode()[:], fill=@transport.zero_padding)
  assert_eq(s.on_received(bytes[:]).length(), 0)
  assert_false(s.is_closed())
  assert_false(s.strict_kex())
}

///|
test "send_packet and disconnect after close are no-ops" {
  let c = @transport.Transport::new(client_config())
  let s = @transport.Transport::new(server_config())
  ignore(pump(c, s))
  c.disconnect(@transport.SSH_DISCONNECT_BY_APPLICATION, "bye")
  ignore(c.take_outgoing())
  c.send_packet(b"\x05\x00\x00\x00\x00"[:])
  c.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, "again")
  assert_eq(c.take_outgoing().length(), 0)
}

///|
test "self-interop: the whole handshake and traffic over aes128-ctr" {
  let only_ctr = Some([@transport.CIPHER_AES128_CTR])
  let c = @transport.Transport::new(client_config(ciphers=only_ctr))
  let s = @transport.Transport::new(server_config(ciphers=only_ctr))
  let (ec, es) = pump(c, s)
  guard ec[0] is Established(session_id=sid_c) else {
    fail("client: \{show_events(ec)}")
  }
  guard es[0] is Established(session_id=sid_s) else {
    fail("server: \{show_events(es)}")
  }
  assert_eq(sid_c, sid_s)
  // Traffic both ways, several packets deep: CTR keeps one counter per
  // direction running across packets, so a second packet that restarted
  // the keystream would decrypt to garbage here.
  for i in 0..<5 {
    c.send_packet(
      b"\x05\x00\x00\x00\x01" + Bytes::make(1, (0x30 + i).to_byte()),
    )
    s.send_packet(
      b"\x06\x00\x00\x00\x01" + Bytes::make(1, (0x40 + i).to_byte()),
    )
  }
  let (ec2, es2) = pump(c, s)
  assert_eq(es2.length(), 5)
  assert_eq(ec2.length(), 5)
  for i in 0..<5 {
    guard es2[i] is Packet(payload=to_server) else { fail("expected Packet") }
    guard ec2[i] is Packet(payload=to_client) else { fail("expected Packet") }
    assert_eq(to_server[5], (0x30 + i).to_byte())
    assert_eq(to_client[5], (0x40 + i).to_byte())
  }
}

///|
test "self-interop: a client with no cipher in common is a key exchange failure" {
  let c = @transport.Transport::new(
    client_config(ciphers=Some([@transport.CIPHER_AES128_CTR])),
  )
  let s = @transport.Transport::new(
    server_config(ciphers=Some([@transport.CIPHER_CHACHA20_POLY1305])),
  )
  let (_, es) = pump(c, s)
  guard es[0] is Disconnect(code~, description~, by_peer=false) else {
    fail("server: \{show_events(es)}")
  }
  assert_eq(code, @transport.SSH_DISCONNECT_KEY_EXCHANGE_FAILED)
  assert_true(description.contains("no common cipher"))
}

///|
test "disconnect: corrupted aes128-ctr ciphertext is a MAC error" {
  let only_ctr = Some([@transport.CIPHER_AES128_CTR])
  let c = @transport.Transport::new(client_config(ciphers=only_ctr))
  let s = @transport.Transport::new(server_config(ciphers=only_ctr))
  ignore(pump(c, s))
  c.send_packet(@transport.encode_service_request("ssh-userauth")[:])
  let pkt = c.take_outgoing()
  // Flip a bit in the MAC, which is never part of the framing.
  let bad = Bytes::makei(pkt.length(), i => {
    if i == pkt.length() - 1 {
      pkt[i] ^ b'\x01'
    } else {
      pkt[i]
    }
  })
  let es = s.on_received(bad[:])
  guard es[0] is Disconnect(code~, by_peer=false, ..) else {
    fail("server: \{show_events(es)}")
  }
  assert_eq(code, @transport.SSH_DISCONNECT_MAC_ERROR)
}
