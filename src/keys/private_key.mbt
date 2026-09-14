///|
/// The `openssh-key-v1` private key container, unencrypted only (docs/05
/// section 2; authoritative source: OpenSSH `PROTOCOL.key`). Sans-IO: the
/// caller reads the file and passes its whole text in.

///|
/// `AUTH_MAGIC`: the 14 ASCII characters plus a trailing NUL, 15 bytes.
let auth_magic : Bytes = b"openssh-key-v1\x00"

///|
/// Padding block size when `ciphername == "none"` (docs/05 section 2).
let none_block_size : Int = 8

///|
let pem_begin : String = "-----BEGIN OPENSSH PRIVATE KEY-----"

///|
let pem_end : String = "-----END OPENSSH PRIVATE KEY-----"

///|
/// A parsed, unencrypted Ed25519 private key file.
///
/// It holds a `@crypto.Ed25519KeyPair` rather than a bare seed: every
/// caller (the server signing the exchange hash, the client signing a
/// `publickey` request) needs the public key A and signs more than once,
/// and the key pair caches the seed expansion that deriving A costs. The
/// seed is still reachable via `key.seed()` for anything that needs the
/// raw RFC 8032 secret.
pub(all) struct PrivateKey {
  key : @crypto.Ed25519KeyPair
  comment : String
}

///|
/// The public half as a `PublicKey`, carrying the file's comment — this is
/// what you would write to a `.pub` file or hand to `fingerprint`.
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  { public: self.key.public(), comment: self.comment, }
}

///|
/// Parse a whole `-----BEGIN OPENSSH PRIVATE KEY-----` PEM text.
///
/// Validates, in order: the PEM guards; the 15-byte `AUTH_MAGIC`;
/// `ciphername`/`kdfname`/`kdfoptions` (unencrypted only);
/// `number_of_keys == 1`; `checkint1 == checkint2`; the inner key type; the
/// 32-byte public key and the 64-byte `seed || A` private field; that the
/// outer blob, the inner public key, the private field's trailing A and
/// `ed25519_public_key(seed)` all agree; the `1,2,3,…` padding with block
/// size 8; and that nothing trails the container.
pub fn parse_openssh_private_key(pem : String) -> PrivateKey raise KeyError {
  let ctx = "private key"
  let container = decode_pem_body(pem, ctx)
  let r = @wire.Reader::new(container[:])
  let magic = r.read_bytes(auth_magic.length()) catch {
    e => raise wire_error(ctx, e)
  }
  if magic.to_owned() != auth_magic {
    raise BadFormat("\{ctx}: bad AUTH_MAGIC (not an openssh-key-v1 file)")
  }
  let ciphername = r.read_str() catch { e => raise wire_error(ctx, e) }
  let kdfname = r.read_str() catch { e => raise wire_error(ctx, e) }
  let kdfoptions = r.read_string() catch { e => raise wire_error(ctx, e) }
  if ciphername != "none" || kdfname != "none" || kdfoptions.length() != 0 {
    raise Unsupported(
      "\{ctx}: encrypted keys not supported; re-generate with `-N ''` or decrypt first",
    )
  }
  let number_of_keys = r.read_uint32() catch { e => raise wire_error(ctx, e) }
  if number_of_keys != 1 {
    raise Unsupported(
      "\{ctx}: expected exactly 1 key in the file, got \{number_of_keys}",
    )
  }
  let public_blob = r.read_string() catch { e => raise wire_error(ctx, e) }
  let outer_public = decode_public_key_blob(public_blob) catch {
    BadFormat(m) => raise BadFormat("\{ctx}: outer \{m}")
    Unsupported(m) => raise Unsupported("\{ctx}: outer \{m}")
  }
  let section = r.read_string() catch { e => raise wire_error(ctx, e) }
  if !r.is_at_end() {
    raise BadFormat("\{ctx}: \{r.remaining()} trailing byte(s) after the key")
  }
  parse_inner_section(section, outer_public, ctx)
}

///|
/// Parse the `encrypted_section` (plaintext, since `ciphername == "none"`)
/// and check it against the container's public key blob.
fn parse_inner_section(
  section : BytesView,
  outer_public : Bytes,
  ctx : String,
) -> PrivateKey raise KeyError {
  if section.length() % none_block_size != 0 {
    raise BadFormat(
      "\{ctx}: inner section length \{section.length()} is not a multiple of the block size \{none_block_size}",
    )
  }
  let r = @wire.Reader::new(section)
  let checkint1 = r.read_uint32() catch { e => raise wire_error(ctx, e) }
  let checkint2 = r.read_uint32() catch { e => raise wire_error(ctx, e) }
  if checkint1 != checkint2 {
    raise BadFormat(
      "\{ctx}: checkint mismatch (corrupt file, or it is actually encrypted)",
    )
  }
  let key_type = r.read_str() catch { e => raise wire_error(ctx, e) }
  if key_type != ed25519_algorithm {
    raise Unsupported(
      "\{ctx}: expected key type \{Repr(ed25519_algorithm)}, got \{Repr(key_type)}",
    )
  }
  let inner_public = r.read_string() catch { e => raise wire_error(ctx, e) }
  if inner_public.length() != ed25519_key_len {
    raise BadFormat(
      "\{ctx}: inner public key must be \{ed25519_key_len} bytes, got \{inner_public.length()}",
    )
  }
  let private_field = r.read_string() catch { e => raise wire_error(ctx, e) }
  if private_field.length() != 2 * ed25519_key_len {
    raise BadFormat(
      "\{ctx}: private key field must be \{2 * ed25519_key_len} bytes, got \{private_field.length()}",
    )
  }
  let comment = r.read_str() catch { e => raise wire_error(ctx, e) }
  check_padding(r, ctx)
  if inner_public.to_owned() != outer_public {
    raise BadFormat(
      "\{ctx}: outer public key blob disagrees with the inner public key",
    )
  }
  // The Ed25519 private field is seed(32) || A(32); the trailing A must be
  // the inner public key, and the seed must actually derive it (docs/05).
  let seed = private_field[0:ed25519_key_len]
  let tail = private_field[ed25519_key_len:]
  if tail.to_owned() != inner_public.to_owned() {
    raise BadFormat(
      "\{ctx}: private key field's trailing A disagrees with the public key",
    )
  }
  let derived = @crypto.fixed_to_bytes(@crypto.ed25519_public_key(seed))
  if derived != inner_public.to_owned() {
    raise BadFormat(
      "\{ctx}: ed25519_public_key(seed) does not match A (corrupt file)",
    )
  }
  { key: @crypto.Ed25519KeyPair::from_seed(seed), comment, }
}

///|
/// The trailing padding must be `1,2,3,…` and shorter than one block — a
/// cheap corruption check (docs/05 section 2).
fn check_padding(r : @wire.Reader, ctx : String) -> Unit raise KeyError {
  let n = r.remaining()
  if n >= none_block_size {
    raise BadFormat(
      "\{ctx}: \{n} padding byte(s) is more than the block size \{none_block_size}",
    )
  }
  for i in 0..<n {
    let got = r.read_byte() catch { e => raise wire_error(ctx, e) }
    let want = (i + 1).to_byte()
    if got != want {
      raise BadFormat(
        "\{ctx}: bad padding byte at offset \{i}: expected \{want.to_int()}, got \{got.to_int()}",
      )
    }
  }
}

///|
/// Strip the PEM guard lines and decode the base64 body. Line endings and
/// indentation inside the body are ignored.
fn decode_pem_body(pem : String, ctx : String) -> Bytes raise KeyError {
  let body = StringBuilder()
  let mut seen_begin = false
  let mut seen_end = false
  for raw in pem.split("\n") {
    let line = raw.trim(char_set=" \t\r\n")
    if line == pem_begin {
      seen_begin = true
      continue
    }
    if line == pem_end {
      seen_end = true
      break
    }
    if seen_begin {
      body.write_string(line.to_owned())
    }
  }
  if !seen_begin {
    raise BadFormat("\{ctx}: missing \{Repr(pem_begin)} line")
  }
  if !seen_end {
    raise BadFormat("\{ctx}: missing \{Repr(pem_end)} line")
  }
  @base64.decode(body.to_string(), ignore_whitespace=true) catch {
    _ => raise BadFormat("\{ctx}: malformed base64 body")
  }
}
