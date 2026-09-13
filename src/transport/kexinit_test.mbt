// SSH_MSG_KEXINIT codec, RFC 4253 section 7.1 / docs/02 section 3.

///|
test "message numbers match RFC 4250 / docs/02 section 8" {
  inspect(@transport.SSH_MSG_DISCONNECT.to_int(), content="1")
  inspect(@transport.SSH_MSG_IGNORE.to_int(), content="2")
  inspect(@transport.SSH_MSG_UNIMPLEMENTED.to_int(), content="3")
  inspect(@transport.SSH_MSG_DEBUG.to_int(), content="4")
  inspect(@transport.SSH_MSG_SERVICE_REQUEST.to_int(), content="5")
  inspect(@transport.SSH_MSG_SERVICE_ACCEPT.to_int(), content="6")
  inspect(@transport.SSH_MSG_EXT_INFO.to_int(), content="7")
  inspect(@transport.SSH_MSG_KEXINIT.to_int(), content="20")
  inspect(@transport.SSH_MSG_NEWKEYS.to_int(), content="21")
  inspect(@transport.SSH_MSG_KEX_ECDH_INIT.to_int(), content="30")
  inspect(@transport.SSH_MSG_KEX_ECDH_REPLY.to_int(), content="31")
  inspect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, content="2")
  inspect(@transport.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, content="3")
  inspect(@transport.SSH_DISCONNECT_MAC_ERROR, content="5")
  inspect(@transport.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, content="7")
  inspect(
    @transport.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
    content="14",
  )
}

///|
test "KexInit::for_role: byte-exact client payload (oracle: python struct)" {
  let cookie = Bytes::make(16, b'\x11')
  let ki = @transport.KexInit::for_role(Client, cookie~)
  let payload = ki.encode()
  assert_eq(payload.length(), 214)
  assert_eq(payload[0], @transport.SSH_MSG_KEXINIT)
  inspect(
    @wire.hex(payload[:]),
    content=(
      #|14111111111111111111111111111111110000004b637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c6b65782d7374726963742d632d763030406f70656e7373682e636f6d0000000b7373682d656432353531390000001d63686163686132302d706f6c7931333035406f70656e7373682e636f6d0000001d63686163686132302d706f6c7931333035406f70656e7373682e636f6d0000000000000000000000046e6f6e65000000046e6f6e6500000000000000000000000000
    ),
  )
}

///|
test "KexInit::for_role: server differs from client only in the strict-kex marker" {
  let cookie = Bytes::make(16, b'\x11')
  let c = @transport.KexInit::for_role(Client, cookie~)
  let s = @transport.KexInit::for_role(Server, cookie~)
  debug_inspect(
    c.kex_algorithms,
    content=(
      #|[
      #|  "curve25519-sha256",
      #|  "curve25519-sha256@libssh.org",
      #|  "kex-strict-c-v00@openssh.com",
      #|]
    ),
  )
  debug_inspect(
    s.kex_algorithms,
    content=(
      #|[
      #|  "curve25519-sha256",
      #|  "curve25519-sha256@libssh.org",
      #|  "kex-strict-s-v00@openssh.com",
      #|]
    ),
  )
  debug_inspect(s.server_host_key_algorithms, content="[\"ssh-ed25519\"]")
  debug_inspect(
    s.encryption_client_to_server,
    content="[\"chacha20-poly1305@openssh.com\"]",
  )
  debug_inspect(
    s.encryption_server_to_client,
    content="[\"chacha20-poly1305@openssh.com\"]",
  )
  // MAC lists are empty: the AEAD cipher makes the MAC implicit (docs/02 section 3).
  debug_inspect(s.mac_client_to_server, content="[]")
  debug_inspect(s.mac_server_to_client, content="[]")
  debug_inspect(s.compression_client_to_server, content="[\"none\"]")
  debug_inspect(s.compression_server_to_client, content="[\"none\"]")
  debug_inspect(s.languages_client_to_server, content="[]")
  debug_inspect(s.languages_server_to_client, content="[]")
  inspect(s.first_kex_packet_follows, content="false")
  inspect(s.reserved, content="0")
  assert_eq(s.cookie, cookie)
}

///|
test "KexInit: encode/decode round-trip with multi-name lists" {
  let ki : @transport.KexInit = {
    cookie: Bytes::makei(16, i => i.to_byte()),
    kex_algorithms: ["curve25519-sha256", "diffie-hellman-group14-sha256"],
    server_host_key_algorithms: ["ssh-ed25519", "rsa-sha2-512"],
    encryption_client_to_server: ["chacha20-poly1305@openssh.com", "aes128-ctr"],
    encryption_server_to_client: ["aes256-ctr"],
    mac_client_to_server: ["hmac-sha2-256"],
    mac_server_to_client: [],
    compression_client_to_server: ["none", "zlib@openssh.com"],
    compression_server_to_client: ["none"],
    languages_client_to_server: [],
    languages_server_to_client: ["en-US"],
    first_kex_packet_follows: true,
    reserved: 0,
  }
  let payload = ki.encode()
  let back = @transport.KexInit::decode(payload[:])
  assert_eq(back, ki)
  // Encoding is deterministic and stable.
  assert_eq(back.encode(), payload)
}

///|
test "KexInit::decode: rejects wrong message number, truncation, trailing bytes" {
  fn expect_err(buf : Bytes, want : String) -> Unit raise {
    try @transport.KexInit::decode(buf[:]) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected KexInit::decode to raise")
    }
  }
  let good = @transport.KexInit::for_role(
    Server,
    cookie=Bytes::make(16, b'\x00'),
  ).encode()
  expect_err(b"", "ProtocolError(\"KEXINIT: ShortRead(need=1, have=0)\")")
  expect_err(
    b"\x15" + good[1:].to_owned(),
    "ProtocolError(\"KEXINIT: expected message 20, got 21\")",
  )
  expect_err(
    good[0:40].to_owned(),
    "ProtocolError(\"KEXINIT: ShortRead(need=75, have=19)\")",
  )
  expect_err(good + b"\x00", "ProtocolError(\"KEXINIT: 1 trailing byte(s)\")")
}
