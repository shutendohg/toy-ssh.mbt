// Userauth message codecs: docs/04 Part A, byte-exact fixtures.

///|
/// Assert that `f` raises an `AuthError` whose `Debug` form is `want`.
fn expect_err(f : () -> Unit raise, want : String) -> Unit raise {
  try f() catch {
    e => debug_inspect(e, content=want)
  } noraise {
    _ => fail("expected the decoder to raise")
  }
}

///|
test "encode USERAUTH_REQUEST none" {
  let payload = @auth.encode_userauth_request({
    user: "alice",
    service: "ssh-connection",
    auth_method: NoneAuth,
  })
  inspect(
    @hex.encode(payload[:]),
    content="3200000005616c6963650000000e7373682d636f6e6e656374696f6e000000046e6f6e65",
  )
}

///|
test "encode USERAUTH_REQUEST password" {
  let payload = @auth.encode_userauth_request({
    user: "alice",
    service: "ssh-connection",
    auth_method: Password(password="hunter2"),
  })
  inspect(
    @hex.encode(payload[:]),
    content="3200000005616c6963650000000e7373682d636f6e6e656374696f6e0000000870617373776f7264000000000768756e74657232",
  )
}

///|
test "encode USERAUTH_REQUEST publickey query and authentication forms" {
  let blob = key_blob()
  let query = @auth.encode_userauth_request({
    user: "alice",
    service: "ssh-connection",
    auth_method: PublicKeyQuery(algorithm="ssh-ed25519", blob~),
  })
  inspect(
    @hex.encode(query[:]),
    content="3200000005616c6963650000000e7373682d636f6e6e656374696f6e000000097075626c69636b6579000000000b7373682d65643235353139000000330000000b7373682d65643235353139000000205327249c998e5c6526bb29aaf2c3547e710734f9f86ad7c339d37ba14f40e7a7",
  )
  let signature = @auth.encode_ed25519_signature_blob(
    Bytes::make(64, b'\xab')[:],
  )
  let auth = @auth.encode_userauth_request({
    user: "alice",
    service: "ssh-connection",
    auth_method: PublicKeySigned(algorithm="ssh-ed25519", blob~, signature~),
  })
  inspect(
    @hex.encode(auth[:]),
    content="3200000005616c6963650000000e7373682d636f6e6e656374696f6e000000097075626c69636b6579010000000b7373682d65643235353139000000330000000b7373682d65643235353139000000205327249c998e5c6526bb29aaf2c3547e710734f9f86ad7c339d37ba14f40e7a7000000530000000b7373682d6564323535313900000040abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab",
  )
}

///|
test "decode USERAUTH_REQUEST round-trips every method" {
  let blob = key_blob()
  let signature = @auth.encode_ed25519_signature_blob(
    Bytes::make(64, b'\xab')[:],
  )
  let methods : Array[@auth.AuthMethod] = [
    NoneAuth,
    Password(password="hunter2"),
    PublicKeyQuery(algorithm="ssh-ed25519", blob~),
    PublicKeySigned(algorithm="ssh-ed25519", blob~, signature~),
  ]
  for auth_method in methods {
    let req : @auth.AuthRequest = {
      user: "alice",
      service: "ssh-connection",
      auth_method,
    }
    let back = @auth.decode_userauth_request(
      @auth.encode_userauth_request(req)[:],
    )
    assert_eq(back, req)
  }
}

///|
test "decode USERAUTH_REQUEST password-change variant" {
  let payload = @hex.decode(
    "3200000005616c6963650000000e7373682d636f6e6e656374696f6e0000000870617373776f726401000000036f6c64000000036e6577",
  )
  let req = @auth.decode_userauth_request(payload[:])
  debug_inspect(
    req.auth_method,
    content=(
      #|PasswordChange(password="old", new_password="new")
    ),
  )
}

///|
test "decode USERAUTH_REQUEST keeps an unknown method as data" {
  let payload = @hex.decode(
    "3200000005616c6963650000000e7373682d636f6e6e656374696f6e000000146b6579626f6172642d696e7465726163746976650000000000",
  )
  let req = @auth.decode_userauth_request(payload[:])
  debug_inspect(
    req.auth_method,
    content=(
      #|Unknown("keyboard-interactive")
    ),
  )
}

///|
test "decode USERAUTH_REQUEST rejects trailing bytes and the wrong number" {
  let trailing = @hex.decode(
    "3200000005616c6963650000000e7373682d636f6e6e656374696f6e000000046e6f6e6500",
  )
  expect_err(
    () => ignore(@auth.decode_userauth_request(trailing[:])),
    "AuthError(\"USERAUTH_REQUEST: 1 trailing byte(s)\")",
  )
  expect_err(
    () => ignore(@auth.decode_userauth_request(b"\x34"[:])),
    "AuthError(\"USERAUTH_REQUEST: expected message 50, got 52\")",
  )
}

///|
test "USERAUTH_FAILURE codec" {
  let payload = @auth.encode_userauth_failure(["publickey", "password"], false)
  inspect(
    @hex.encode(payload[:]),
    content="33000000127075626c69636b65792c70617373776f726400",
  )
  let (methods, partial) = @auth.decode_userauth_failure(payload[:])
  debug_inspect(methods, content="[\"publickey\", \"password\"]")
  assert_false(partial)
  expect_err(
    () => {
      ignore(@auth.decode_userauth_failure(b"\x33\x00\x00\x00\x00\x00\x00"[:]))
    },
    "AuthError(\"USERAUTH_FAILURE: 1 trailing byte(s)\")",
  )
}

///|
test "USERAUTH_SUCCESS codec" {
  inspect(@hex.encode(@auth.encode_userauth_success()[:]), content="34")
  @auth.decode_userauth_success(b"\x34"[:])
  expect_err(
    () => @auth.decode_userauth_success(b"\x34\x00"[:]),
    "AuthError(\"USERAUTH_SUCCESS: 1 trailing byte(s)\")",
  )
}

///|
test "USERAUTH_BANNER codec" {
  let payload = @auth.encode_userauth_banner("toy-ssh\n", "")
  inspect(@hex.encode(payload[:]), content="3500000008746f792d7373680a00000000")
  let (message, language) = @auth.decode_userauth_banner(payload[:])
  inspect(message, content="toy-ssh\n")
  inspect(language, content="")
}

///|
test "USERAUTH_PK_OK codec" {
  let blob = key_blob()
  let payload = @auth.encode_userauth_pk_ok("ssh-ed25519", blob[:])
  inspect(
    @hex.encode(payload[:]),
    content="3c0000000b7373682d65643235353139000000330000000b7373682d65643235353139000000205327249c998e5c6526bb29aaf2c3547e710734f9f86ad7c339d37ba14f40e7a7",
  )
  let (algorithm, back) = @auth.decode_userauth_pk_ok(payload[:])
  inspect(algorithm, content="ssh-ed25519")
  assert_eq(back, blob)
}

///|
test "ssh-ed25519 public key blob codec" {
  let public = @hex.decode(
    "5327249c998e5c6526bb29aaf2c3547e710734f9f86ad7c339d37ba14f40e7a7",
  )
  let blob = @auth.encode_ed25519_public_key_blob(public[:])
  inspect(@hex.encode(blob[:]), content=KEY_BLOB_HEX)
  assert_eq(@auth.decode_ed25519_public_key_blob(blob[:]), public)
  let rsa = @hex.decode("000000077373682d7273610000000100")
  expect_err(
    () => ignore(@auth.decode_ed25519_public_key_blob(rsa[:])),
    "AuthError(\"public key blob: expected ssh-ed25519, got ssh-rsa\")",
  )
  let short = @hex.decode("0000000b7373682d65643235353139000000020000")
  expect_err(
    () => ignore(@auth.decode_ed25519_public_key_blob(short[:])),
    "AuthError(\"public key blob: key must be 32 bytes, got 2\")",
  )
}

///|
test "publickey signed data matches the pinned fixture" {
  let session_id = @hex.decode(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  )
  let blob = key_blob()
  let signed = @auth.publickey_signed_data(
    session_id[:],
    "alice",
    "ssh-connection",
    "ssh-ed25519",
    blob[:],
  )
  inspect(
    @hex.encode(signed[:]),
    content="000000200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f203200000005616c6963650000000e7373682d636f6e6e656374696f6e000000097075626c69636b6579010000000b7373682d65643235353139000000330000000b7373682d65643235353139000000205327249c998e5c6526bb29aaf2c3547e710734f9f86ad7c339d37ba14f40e7a7",
  )
}

///|
test "signed data is string(session_id) || request without the signature field" {
  let session_id = Bytes::make(32, b'\x07')
  let blob = key_blob()
  let signature = @auth.encode_ed25519_signature_blob(
    Bytes::make(64, b'\xcd')[:],
  )
  let request = @auth.encode_userauth_request({
    user: "bob",
    service: "ssh-connection",
    auth_method: PublicKeySigned(algorithm="ssh-ed25519", blob~, signature~),
  })
  // Strip the trailing `string signature` field: 4 length bytes + body.
  let stripped = request[0:request.length() - 4 - signature.length()]
  let expected = @wire.Writer::new()
  expected.write_string(session_id[:])
  expected.write_raw(stripped)
  assert_eq(
    @auth.publickey_signed_data(
      session_id[:],
      "bob",
      "ssh-connection",
      "ssh-ed25519",
      blob[:],
    ),
    expected.to_bytes(),
  )
}
