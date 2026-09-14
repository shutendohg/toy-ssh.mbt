///|
/// Codecs for the five userauth messages of docs/04 Part A, plus the
/// `ssh-ed25519` key/signature blobs and the publickey signed-data blob.

///|
/// The method-specific tail of an `SSH_MSG_USERAUTH_REQUEST`. One decoder
/// handles every shape so the server can simply match; a method we do not
/// implement decodes to `Unknown` (a peer offering `keyboard-interactive`
/// is normal traffic, not a protocol violation) and the server answers
/// FAILURE.
pub(all) enum AuthMethod {
  /// `none`: the client's probe for the list of methods that can continue.
  NoneAuth
  /// `password` with `boolean FALSE`.
  Password(password~ : String)
  /// `password` with `boolean TRUE`: the password-change request. We never
  /// send it and always answer FAILURE, but it must decode.
  PasswordChange(password~ : String, new_password~ : String)
  /// `publickey` query phase (`boolean FALSE`, no signature).
  PublicKeyQuery(algorithm~ : String, blob~ : Bytes)
  /// `publickey` authentication phase (`boolean TRUE`, with signature).
  PublicKeySigned(algorithm~ : String, blob~ : Bytes, signature~ : Bytes)
  /// A method name we do not implement. The method-specific fields are not
  /// decoded (their shape is unknown) and are discarded.
  Unknown(String)
} derive(Debug, Eq)

///|
/// The method name as it appears on the wire.
pub fn AuthMethod::name(self : AuthMethod) -> String {
  match self {
    NoneAuth => METHOD_NONE
    Password(_) | PasswordChange(_) => METHOD_PASSWORD
    PublicKeyQuery(_) | PublicKeySigned(_) => METHOD_PUBLICKEY
    Unknown(name) => name
  }
}

///|
/// A decoded `SSH_MSG_USERAUTH_REQUEST`.
pub(all) struct AuthRequest {
  user : String
  service : String
  auth_method : AuthMethod
} derive(Debug, Eq)

///|
/// `byte(50) || string user || string service || string method || tail`.
pub fn encode_userauth_request(req : AuthRequest) -> Bytes {
  let w = @wire.Writer::new()
  w.write_byte(SSH_MSG_USERAUTH_REQUEST)
  w.write_str(req.user)
  w.write_str(req.service)
  w.write_str(req.auth_method.name())
  match req.auth_method {
    NoneAuth | Unknown(_) => ()
    Password(password~) => {
      w.write_boolean(false)
      w.write_str(password)
    }
    PasswordChange(password~, new_password~) => {
      w.write_boolean(true)
      w.write_str(password)
      w.write_str(new_password)
    }
    PublicKeyQuery(algorithm~, blob~) => {
      w.write_boolean(false)
      w.write_str(algorithm)
      w.write_string(blob[:])
    }
    PublicKeySigned(algorithm~, blob~, signature~) => {
      w.write_boolean(true)
      w.write_str(algorithm)
      w.write_string(blob[:])
      w.write_string(signature[:])
    }
  }
  w.to_bytes()
}

///|
/// Decode an `SSH_MSG_USERAUTH_REQUEST`. The whole payload must be
/// consumed, except for an `Unknown` method whose tail we cannot parse.
pub fn decode_userauth_request(
  payload : BytesView,
) -> AuthRequest raise AuthError {
  let ctx = "USERAUTH_REQUEST"
  let r = expect_message(payload, SSH_MSG_USERAUTH_REQUEST, ctx)
  let (user, service, name) = (r.read_str(), r.read_str(), r.read_str()) catch {
    e => raise wire_error(ctx, e)
  }
  let auth_method = read_method(r, name, ctx)
  // An unknown method's fields have an unknown shape, so there is nothing
  // to consume and nothing to check.
  if !(auth_method is Unknown(_)) {
    expect_end(r, ctx)
  }
  { user, service, auth_method, }
}

///|
fn read_method(
  r : @wire.Reader,
  name : String,
  ctx : String,
) -> AuthMethod raise AuthError {
  if name == METHOD_NONE {
    return NoneAuth
  }
  if name == METHOD_PASSWORD {
    return read_password_method(r) catch { e => raise wire_error(ctx, e) }
  }
  if name == METHOD_PUBLICKEY {
    return read_publickey_method(r) catch { e => raise wire_error(ctx, e) }
  }
  Unknown(name)
}

///|
fn read_password_method(r : @wire.Reader) -> AuthMethod raise @wire.WireError {
  let change = r.read_boolean()
  let password = r.read_str()
  if change {
    PasswordChange(password~, new_password=r.read_str())
  } else {
    Password(password~)
  }
}

///|
fn read_publickey_method(r : @wire.Reader) -> AuthMethod raise @wire.WireError {
  let signed = r.read_boolean()
  let algorithm = r.read_str()
  let blob = r.read_string().to_owned()
  if signed {
    PublicKeySigned(algorithm~, blob~, signature=r.read_string().to_owned())
  } else {
    PublicKeyQuery(algorithm~, blob~)
  }
}

///|
/// `byte(51) || name-list methods || boolean partial_success`. `methods`
/// must hold printable ASCII names without commas (RFC 4251 §5); ours are
/// the `METHOD_*` constants.
pub fn encode_userauth_failure(
  methods : Array[String],
  partial : Bool,
) -> Bytes {
  let w = @wire.Writer::new()
  w.write_byte(SSH_MSG_USERAUTH_FAILURE)
  w.write_str(methods.join(","))
  w.write_boolean(partial)
  w.to_bytes()
}

///|
/// Decode an `SSH_MSG_USERAUTH_FAILURE` into `(methods, partial_success)`.
pub fn decode_userauth_failure(
  payload : BytesView,
) -> (Array[String], Bool) raise AuthError {
  let ctx = "USERAUTH_FAILURE"
  let r = expect_message(payload, SSH_MSG_USERAUTH_FAILURE, ctx)
  let out = (r.read_name_list(), r.read_boolean()) catch {
    e => raise wire_error(ctx, e)
  }
  expect_end(r, ctx)
  out
}

///|
/// `byte(52)`.
pub fn encode_userauth_success() -> Bytes {
  b"\x34"
}

///|
/// Check that `payload` is exactly `SSH_MSG_USERAUTH_SUCCESS`.
pub fn decode_userauth_success(payload : BytesView) -> Unit raise AuthError {
  let ctx = "USERAUTH_SUCCESS"
  let r = expect_message(payload, SSH_MSG_USERAUTH_SUCCESS, ctx)
  expect_end(r, ctx)
}

///|
/// `byte(53) || string message || string language_tag`.
pub fn encode_userauth_banner(message : String, language : String) -> Bytes {
  let w = @wire.Writer::new()
  w.write_byte(SSH_MSG_USERAUTH_BANNER)
  w.write_str(message)
  w.write_str(language)
  w.to_bytes()
}

///|
/// Decode an `SSH_MSG_USERAUTH_BANNER` into `(message, language_tag)`.
pub fn decode_userauth_banner(
  payload : BytesView,
) -> (String, String) raise AuthError {
  let ctx = "USERAUTH_BANNER"
  let r = expect_message(payload, SSH_MSG_USERAUTH_BANNER, ctx)
  let out = (r.read_str(), r.read_str()) catch { e => raise wire_error(ctx, e) }
  expect_end(r, ctx)
  out
}

///|
/// `byte(60) || string algorithm || string public_key_blob`.
pub fn encode_userauth_pk_ok(algorithm : String, blob : BytesView) -> Bytes {
  let w = @wire.Writer::new()
  w.write_byte(SSH_MSG_USERAUTH_PK_OK)
  w.write_str(algorithm)
  w.write_string(blob)
  w.to_bytes()
}

///|
/// Decode an `SSH_MSG_USERAUTH_PK_OK` into `(algorithm, public_key_blob)`.
pub fn decode_userauth_pk_ok(
  payload : BytesView,
) -> (String, Bytes) raise AuthError {
  let ctx = "USERAUTH_PK_OK"
  let r = expect_message(payload, SSH_MSG_USERAUTH_PK_OK, ctx)
  let (algorithm, blob) = (r.read_str(), r.read_string()) catch {
    e => raise wire_error(ctx, e)
  }
  expect_end(r, ctx)
  (algorithm, blob.to_owned())
}

// ---------------------------------------------------------------------------
// ssh-ed25519 blobs (docs/02 section 5, RFC 8709)
// ---------------------------------------------------------------------------

///|
const ED25519_KEY_LEN : Int = 32

///|
const ED25519_SIG_LEN : Int = 64

///|
/// `string "ssh-ed25519" || string public_key`. A wrong length is a
/// programmer error (the key is ours) and aborts.
pub fn encode_ed25519_public_key_blob(public : BytesView) -> Bytes {
  guard public.length() == ED25519_KEY_LEN else {
    abort("public key blob: Ed25519 public key must be 32 bytes")
  }
  encode_ed25519_blob(public)
}

///|
/// `string "ssh-ed25519" || string signature`. A wrong length is a
/// programmer error (the signature is ours) and aborts.
pub fn encode_ed25519_signature_blob(signature : BytesView) -> Bytes {
  guard signature.length() == ED25519_SIG_LEN else {
    abort("signature blob: Ed25519 signature must be 64 bytes")
  }
  encode_ed25519_blob(signature)
}

///|
fn encode_ed25519_blob(body : BytesView) -> Bytes {
  let w = @wire.Writer::new(size_hint=16 + 4 + body.length())
  w.write_named_blob(PUBLICKEY_ALGORITHM, body)
  w.to_bytes()
}

///|
/// Extract the 32-byte Ed25519 public key from an `ssh-ed25519` blob.
pub fn decode_ed25519_public_key_blob(
  blob : BytesView,
) -> Bytes raise AuthError {
  decode_ed25519_blob(blob, "public key blob", "key", ED25519_KEY_LEN)
}

///|
/// Extract the 64-byte Ed25519 signature from an `ssh-ed25519` blob.
pub fn decode_ed25519_signature_blob(blob : BytesView) -> Bytes raise AuthError {
  decode_ed25519_blob(blob, "signature blob", "signature", ED25519_SIG_LEN)
}

///|
fn decode_ed25519_blob(
  blob : BytesView,
  ctx : String,
  what : String,
  want_len : Int,
) -> Bytes raise AuthError {
  let r = @wire.Reader::new(blob)
  let (name, body) = r.read_named_blob() catch { e => raise wire_error(ctx, e) }
  if name != PUBLICKEY_ALGORITHM {
    raise AuthError("\{ctx}: expected \{PUBLICKEY_ALGORITHM}, got \{name}")
  }
  if body.length() != want_len {
    raise AuthError(
      "\{ctx}: \{what} must be \{want_len} bytes, got \{body.length()}",
    )
  }
  expect_end(r, ctx)
  body.to_owned()
}

// ---------------------------------------------------------------------------
// The publickey signed data (RFC 4252 section 7, docs/04)
// ---------------------------------------------------------------------------

///|
/// The exact byte sequence a `publickey` signature is computed over:
///
/// ```
/// string    session_id
/// byte      50
/// string    user_name
/// string    service_name
/// string    "publickey"
/// boolean   TRUE
/// string    public_key_algorithm_name
/// string    public_key_blob
/// ```
///
/// i.e. `string(session_id)` prepended to the authentication-form request
/// payload up to and including the public key blob, **without** the
/// trailing signature field. Getting this layout wrong is the #1 publickey
/// interop bug, so it is pinned by a fixture test.
pub fn publickey_signed_data(
  session_id : BytesView,
  user : String,
  service : String,
  algorithm : String,
  public_key_blob : BytesView,
) -> Bytes {
  let w = @wire.Writer::new(
    size_hint=64 + session_id.length() + public_key_blob.length(),
  )
  w.write_string(session_id)
  w.write_byte(SSH_MSG_USERAUTH_REQUEST)
  w.write_str(user)
  w.write_str(service)
  w.write_str(METHOD_PUBLICKEY)
  w.write_boolean(true)
  w.write_str(algorithm)
  w.write_string(public_key_blob)
  w.to_bytes()
}
