// The client-side userauth state machine: docs/04 Part A "Auth state
// machines", docs/01 `AuthEvent`.

///|
fn test_client(
  probe_none? : Bool = false,
  query_first? : Bool = true,
  key? : @crypto.Ed25519KeyPair? = None,
  password? : String? = None,
  user? : String = "alice",
) -> @auth.AuthClient {
  @auth.AuthClient::new({
    user,
    session_id: session_id(),
    probe_none,
    key,
    password,
    query_first,
  })
}

///|
fn client_events(c : @auth.AuthClient, payload : Bytes) -> Array[String] {
  c.on_payload(payload[:]).map(e => Repr(e).to_string())
}

///|
test "client: the first request is a none probe when asked for one" {
  let c = test_client(probe_none=true, password=Some("hunter2"))
  let out = c.take_outgoing()
  assert_eq(out.length(), 1)
  let req = @auth.decode_userauth_request(out[0][:])
  inspect(req.auth_method.name(), content="none")
  inspect(req.user, content="alice")
  inspect(req.service, content="ssh-connection")
}

///|
test "client: without a probe it goes straight to the first method" {
  let c = test_client(password=Some("hunter2"))
  let out = c.take_outgoing()
  assert_eq(out.length(), 1)
  let req = @auth.decode_userauth_request(out[0][:])
  inspect(req.auth_method.name(), content="password")
}

///|
test "client: publickey is tried before password" {
  let c = test_client(key=Some(key_pair()), password=Some("hunter2"))
  let out = c.take_outgoing()
  let req = @auth.decode_userauth_request(out[0][:])
  inspect(req.auth_method.name(), content="publickey")
  assert_true(req.auth_method is PublicKeyQuery(_))
}

///|
test "client: query_first=false signs straight away" {
  let c = test_client(key=Some(key_pair()), query_first=false)
  let out = c.take_outgoing()
  let req = @auth.decode_userauth_request(out[0][:])
  assert_true(req.auth_method is PublicKeySigned(_))
}

///|
test "client: PK_OK moves the publickey flow into the signature phase" {
  let c = test_client(key=Some(key_pair()))
  ignore(c.take_outgoing())
  let pk_ok = @auth.encode_userauth_pk_ok("ssh-ed25519", key_blob()[:])
  debug_inspect(client_events(c, pk_ok), content="[]")
  let out = c.take_outgoing()
  assert_eq(out.length(), 1)
  let req = @auth.decode_userauth_request(out[0][:])
  guard req.auth_method is PublicKeySigned(algorithm~, blob~, signature~) else {
    fail("expected the authentication form")
  }
  inspect(algorithm, content="ssh-ed25519")
  assert_eq(blob, key_blob())
  // The signature must verify over our own session id.
  let data = @auth.publickey_signed_data(
    session_id()[:],
    "alice",
    "ssh-connection",
    "ssh-ed25519",
    blob[:],
  )
  let raw = @auth.decode_ed25519_signature_blob(signature[:])
  assert_true(
    @crypto.ed25519_verify(
      @auth.decode_ed25519_public_key_blob(blob[:])[:],
      data[:],
      raw[:],
    ),
  )
}

///|
test "client: an unexpected PK_OK is a protocol violation" {
  let c = test_client(password=Some("hunter2"))
  ignore(c.take_outgoing())
  let pk_ok = @auth.encode_userauth_pk_ok("ssh-ed25519", key_blob()[:])
  let events = client_events(c, pk_ok)
  assert_eq(events.length(), 1)
  assert_true(events[0].contains("ProtocolViolation"))
}

///|
test "client: SUCCESS ends it, later messages are ignored" {
  let c = test_client(password=Some("hunter2"))
  ignore(c.take_outgoing())
  debug_inspect(
    client_events(c, @auth.encode_userauth_success()),
    content=(
      #|["Success"]
    ),
  )
  assert_true(c.is_authenticated())
  debug_inspect(
    client_events(c, @auth.encode_userauth_failure(["password"], false)),
    content="[]",
  )
}

///|
test "client: FAILURE advances to the next method, then gives up" {
  let c = test_client(key=Some(key_pair()), password=Some("hunter2"))
  ignore(c.take_outgoing())
  let failure = @auth.encode_userauth_failure(["publickey", "password"], false)
  let first = client_events(c, failure)
  assert_eq(first.length(), 1)
  assert_true(first[0].contains("Failure"))
  let out = c.take_outgoing()
  assert_eq(out.length(), 1)
  inspect(
    @auth.decode_userauth_request(out[0][:]).auth_method.name(),
    content="password",
  )
  let second = client_events(c, failure)
  assert_eq(second.length(), 2)
  assert_true(second[1].contains("GiveUp"))
  assert_true(c.is_done())
  assert_false(c.is_authenticated())
  debug_inspect(c.take_outgoing(), content="[]")
}

///|
test "client: a banner is reported and does not change the state" {
  let c = test_client(password=Some("hunter2"))
  ignore(c.take_outgoing())
  debug_inspect(
    client_events(c, @auth.encode_userauth_banner("hello\n", "")),
    content=(
      #|["Banner(\"hello\\n\")"]
    ),
  )
  assert_false(c.is_done())
}

///|
test "client: partial success is a give-up, we have no second factor" {
  let c = test_client(password=Some("hunter2"))
  ignore(c.take_outgoing())
  let events = client_events(
    c,
    @auth.encode_userauth_failure(["publickey"], true),
  )
  assert_eq(events.length(), 1)
  assert_true(events[0].contains("GiveUp"))
  assert_true(c.is_done())
}

///|
test "client: a client with no credentials gives up immediately" {
  let c = test_client()
  debug_inspect(c.take_outgoing(), content="[]")
  assert_true(c.is_done())
}

///|
test "client: garbage from the server is reported, never a crash" {
  let garbage : Array[Bytes] = [b"", b"\x34\x00", b"\x63", b"\x33\x00"]
  for payload in garbage {
    let c = test_client(password=Some("hunter2"))
    ignore(c.take_outgoing())
    let events = client_events(c, payload)
    assert_eq(events.length(), 1)
    assert_true(events[0].contains("ProtocolViolation"))
    assert_false(c.is_authenticated())
  }
}
