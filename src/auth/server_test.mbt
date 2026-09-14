// The server-side userauth state machine: docs/04 Part A "Auth state
// machines", docs/06 M3.

///|
/// A server that knows `alice`'s password and authorizes the fixture key
/// for `alice` only.
fn test_server(
  max_failures? : Int = 6,
  banner? : String? = None,
) -> @auth.AuthServer raise {
  let authorized = key_blob()
  @auth.AuthServer::new({
    session_id: session_id(),
    check_password: (user, password) => user == "alice" && password == "hunter2",
    authorize_public_key: (user, blob) => user == "alice" && blob == authorized,
    banner,
    max_failures,
  })
}

///|
/// Feed one request payload and return `(events, replies)` as text.
fn step(
  s : @auth.AuthServer,
  payload : Bytes,
) -> (Array[String], Array[String]) {
  let events = s.on_payload(payload[:]).map(e => Repr(e).to_string())
  let replies = s.take_outgoing().map(p => @hex.encode(p[:]))
  (events, replies)
}

///|
fn request(user : String, auth_method : @auth.AuthMethod) -> Bytes {
  @auth.encode_userauth_request({
    user,
    service: "ssh-connection",
    auth_method,
  })
}

///|
/// The reply's message number, or -1 when there is no single reply.
fn reply_number(s : @auth.AuthServer) -> Int {
  let out = s.take_outgoing()
  if out.length() != 1 {
    return -1
  }
  out[0][0].to_int()
}

///|
test "server: none probe is answered with the methods that can continue" {
  let s = test_server()
  let (events, replies) = step(s, request("alice", NoneAuth))
  assert_eq(events.length(), 1)
  assert_true(events[0].contains("auth_method=NoneAuth"))
  debug_inspect(
    replies,
    content=(
      #|["33000000127075626c69636b65792c70617373776f726400"]
    ),
  )
  assert_false(s.is_authenticated())
}

///|
test "server: a service other than ssh-connection is refused" {
  let s = test_server()
  let payload = @auth.encode_userauth_request({
    user: "alice",
    service: "ssh-userauth",
    auth_method: Password(password="hunter2"),
  })
  ignore(s.on_payload(payload[:]))
  assert_eq(reply_number(s), 51)
  assert_false(s.is_authenticated())
}

///|
test "server: correct password authenticates, wrong one fails" {
  let s = test_server()
  let (events, _) = step(s, request("alice", Password(password="hunter2")))
  assert_eq(events.length(), 2)
  assert_true(events[1] == "Authenticated(user=\"alice\")")
  assert_true(s.is_authenticated())
  debug_inspect(s.user(), content="Some(\"alice\")")
  let bad = test_server()
  ignore(bad.on_payload(request("alice", Password(password="nope"))[:]))
  assert_eq(reply_number(bad), 51)
  assert_false(bad.is_authenticated())
  assert_eq(bad.failure_count(), 1)
}

///|
test "server: the password-change variant is refused" {
  let s = test_server()
  ignore(
    s.on_payload(
      request("alice", PasswordChange(password="hunter2", new_password="x"))[:],
    ),
  )
  assert_eq(reply_number(s), 51)
  assert_false(s.is_authenticated())
}

///|
test "server: an unimplemented method is refused, not a protocol error" {
  let s = test_server()
  let (events, _) = step(s, request("alice", Unknown("keyboard-interactive")))
  assert_eq(events.length(), 1)
  assert_true(events[0].contains("Unknown(\"keyboard-interactive\")"))
  assert_eq(s.failure_count(), 1)
}

///|
test "server: publickey query answers PK_OK only for an authorized key" {
  let s = test_server()
  let blob = key_blob()
  ignore(
    s.on_payload(
      request("alice", PublicKeyQuery(algorithm="ssh-ed25519", blob~))[:],
    ),
  )
  let out = s.take_outgoing()
  assert_eq(out.length(), 1)
  let (algorithm, echoed) = @auth.decode_userauth_pk_ok(out[0][:])
  inspect(algorithm, content="ssh-ed25519")
  assert_eq(echoed, blob)
  // Same key, a user it is not authorized for.
  ignore(
    s.on_payload(
      request("bob", PublicKeyQuery(algorithm="ssh-ed25519", blob~))[:],
    ),
  )
  assert_eq(reply_number(s), 51)
}

///|
/// Build an authentication-form publickey request signed by `pair` over
/// `sid`, presenting `blob` as the public key.
fn signed_request(
  user : String,
  pair : @crypto.Ed25519KeyPair,
  blob : Bytes,
  sid : Bytes,
) -> Bytes {
  let data = @auth.publickey_signed_data(
    sid[:],
    user,
    "ssh-connection",
    "ssh-ed25519",
    blob[:],
  )
  let signature = @auth.encode_ed25519_signature_blob(
    @crypto.fixed_to_bytes(pair.sign(data[:]))[:],
  )
  request("alice", PublicKeySigned(algorithm="ssh-ed25519", blob~, signature~))
}

///|
test "server: a valid publickey signature authenticates" {
  let s = test_server()
  let (events, _) = step(
    s,
    signed_request("alice", key_pair(), key_blob(), session_id()),
  )
  assert_true(events[1] == "Authenticated(user=\"alice\")")
  assert_true(s.is_authenticated())
}

///|
test "server: a signature made under a different session id is refused" {
  let s = test_server()
  ignore(
    s.on_payload(
      signed_request("alice", key_pair(), key_blob(), Bytes::make(32, b'\x99'))[:],
    ),
  )
  assert_eq(reply_number(s), 51)
  assert_false(s.is_authenticated())
}

///|
test "server: an unauthorized key and a wrong-key signature are refused" {
  let other = other_pair()
  let other_blob = @auth.encode_ed25519_public_key_blob(other.public()[:])
  // Key not in authorized_keys at all.
  let s = test_server()
  ignore(
    s.on_payload(signed_request("alice", other, other_blob, session_id())[:]),
  )
  assert_eq(reply_number(s), 51)
  // Authorized key in the blob, but signed by a different key.
  let s2 = test_server()
  ignore(
    s2.on_payload(signed_request("alice", other, key_blob(), session_id())[:]),
  )
  assert_eq(reply_number(s2), 51)
  assert_false(s2.is_authenticated())
}

///|
test "server: a tampered signature is refused" {
  let s = test_server()
  let payload = signed_request("alice", key_pair(), key_blob(), session_id())
  let bytes = payload.to_array()
  bytes[payload.length() - 1] = bytes[payload.length() - 1] ^ b'\x01'
  ignore(s.on_payload(Bytes::from_iter(bytes.iter())[:]))
  assert_eq(reply_number(s), 51)
  assert_false(s.is_authenticated())
}

///|
test "server: the algorithm name and the blob's algorithm must agree" {
  let s = test_server()
  let blob = key_blob()
  // Outer algorithm we do not implement.
  ignore(
    s.on_payload(
      request("alice", PublicKeyQuery(algorithm="rsa-sha2-512", blob~))[:],
    ),
  )
  assert_eq(reply_number(s), 51)
  // Outer says ssh-ed25519, the blob says ssh-rsa.
  let rsa_blob = @hex.decode("000000077373682d7273610000000100")
  ignore(
    s.on_payload(
      request("alice", PublicKeyQuery(algorithm="ssh-ed25519", blob=rsa_blob))[:],
    ),
  )
  assert_eq(reply_number(s), 51)
}

///|
test "server: userauth messages after success are ignored" {
  let s = test_server()
  ignore(s.on_payload(request("alice", Password(password="hunter2"))[:]))
  ignore(s.take_outgoing())
  let (events, replies) = step(s, request("alice", Password(password="nope")))
  debug_inspect(events, content="[]")
  debug_inspect(replies, content="[]")
  assert_true(s.is_authenticated())
}

///|
test "server: the failure limit is reported as an event" {
  let s = test_server(max_failures=2)
  let (e1, _) = step(s, request("alice", Password(password="nope")))
  assert_eq(e1.length(), 1)
  let (e2, replies) = step(s, request("alice", Password(password="nope")))
  assert_true(e2[e2.length() - 1] == "TooManyFailures(user=\"alice\")")
  // Still a FAILURE on the wire; only the caller can disconnect.
  debug_inspect(
    replies,
    content=(
      #|["33000000127075626c69636b65792c70617373776f726400"]
    ),
  )
  // Past the limit the server keeps answering FAILURE.
  ignore(s.on_payload(request("alice", Password(password="nope"))[:]))
  assert_eq(reply_number(s), 51)
}

///|
test "server: a banner is queued before the first reply" {
  let s = test_server(banner=Some("toy-ssh\n"))
  let out = s.take_outgoing()
  assert_eq(out.length(), 1)
  let (message, _) = @auth.decode_userauth_banner(out[0][:])
  inspect(message, content="toy-ssh\n")
}

///|
test "server: garbage payloads are reported, never crash" {
  let garbage : Array[Bytes] = [
    b"", b"\x32", b"\x34", b"\x3c\x00", b"\x32\x00\x00\x00\xff", b"\x32\x00\x00\x00\x01a\x00\x00\x00\x01b",
  ]
  for payload in garbage {
    let s = test_server()
    let events = s.on_payload(payload[:])
    let replies = s.take_outgoing()
    // Either a FAILURE on the wire or a reported violation, never both
    // silence and a crash.
    assert_true(replies.length() == 1 || events.length() > 0)
    assert_false(s.is_authenticated())
  }
}
