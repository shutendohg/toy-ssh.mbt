///|
/// On-disk key formats: the `ssh-ed25519` public key blob and line, the
/// `authorized_keys` file, and the OpenSSH fingerprint (docs/05 sections 1
/// and 3). Everything here is Ed25519-only and sans-IO: the caller reads
/// the file and hands us its contents as text.
///
/// `keys` sits below `transport` in the dependency order, so the blob
/// codec is implemented here rather than reused from `transport`.

///|
/// A key file or a peer-supplied line is never trusted input, so every
/// rejection is a `raise`, never an `abort` (docs/01 "Error handling
/// policy"). `BadFormat` means "this is not a well-formed X"; `Unsupported`
/// means "well-formed, but the toy deliberately does not handle it" — the
/// distinction is what lets a binary print "regenerate your key" instead
/// of "corrupt file".
pub(all) suberror KeyError {
  BadFormat(String)
  Unsupported(String)
} derive(Debug, Eq)

///|
/// The only public key algorithm the toy knows.
pub let ed25519_algorithm : String = "ssh-ed25519"

///|
/// Length of an Ed25519 public key A, and of the seed (RFC 8032's secret
/// key).
pub let ed25519_key_len : Int = 32

///|
/// Wrap a `WireError` raised while decoding `ctx` into a `BadFormat`.
fn wire_error(ctx : String, e : @wire.WireError) -> KeyError {
  BadFormat("\{ctx}: \{Repr(e)}")
}

// ---------------------------------------------------------------------------
// Public key blob (docs/05 section 1)
// ---------------------------------------------------------------------------

///|
/// Encode the `ssh-ed25519` public key blob: `string "ssh-ed25519" ||
/// string A`. The key is ours by the time we format it, so a wrong length
/// is a programmer error and aborts.
pub fn encode_public_key_blob(public : BytesView) -> Bytes {
  guard public.length() == ed25519_key_len else {
    abort("encode_public_key_blob: Ed25519 public key must be 32 bytes")
  }
  let w = @wire.Writer::new(size_hint=51)
  w.write_named_blob(ed25519_algorithm, public)
  w.to_bytes()
}

///|
/// Extract the 32-byte Ed25519 public key A from a public key blob,
/// rejecting a foreign algorithm name, a wrong key length and any trailing
/// bytes.
pub fn decode_public_key_blob(blob : BytesView) -> Bytes raise KeyError {
  let ctx = "public key blob"
  let r = @wire.Reader::new(blob)
  let (algorithm, key) = r.read_named_blob() catch {
    e => raise wire_error(ctx, e)
  }
  if algorithm != ed25519_algorithm {
    raise BadFormat(
      "\{ctx}: expected algorithm \{Repr(ed25519_algorithm)}, got \{Repr(algorithm)}",
    )
  }
  if key.length() != ed25519_key_len {
    raise BadFormat(
      "\{ctx}: Ed25519 key must be \{ed25519_key_len} bytes, got \{key.length()}",
    )
  }
  if !r.is_at_end() {
    raise BadFormat("\{ctx}: \{r.remaining()} trailing byte(s)")
  }
  key.to_owned()
}

// ---------------------------------------------------------------------------
// Public key line (docs/05 section 1)
// ---------------------------------------------------------------------------

///|
/// One `ssh-ed25519 <base64> [comment]` line: the 32-byte public key A and
/// the free-form comment (empty when the line had none). The algorithm is
/// not a field because only `ssh-ed25519` ever parses.
pub(all) struct PublicKey {
  public : Bytes
  comment : String
} derive(Debug, Eq)

///|
/// The `ssh-ed25519` blob for this key.
pub fn PublicKey::blob(self : PublicKey) -> Bytes {
  encode_public_key_blob(self.public[:])
}

///|
/// Format the key back as a public key line. Round-trips
/// `parse_public_key_line`; the trailing space is omitted when there is no
/// comment, matching `ssh-keygen -y`.
pub fn PublicKey::format(self : PublicKey) -> String {
  let text = "\{ed25519_algorithm} \{@base64.encode(self.blob()[:])}"
  if self.comment == "" {
    text
  } else {
    "\{text} \{self.comment}"
  }
}

///|
/// OpenSSH `SHA256:...` fingerprint of this key.
pub fn PublicKey::fingerprint(self : PublicKey) -> String {
  fingerprint(self.blob()[:])
}

///|
/// Parse one public key line: `ssh-ed25519 <base64-of-blob> [comment]`.
/// The comment is everything after the base64 field, so internal spaces
/// survive. Rejects a foreign type, malformed base64, a blob whose inner
/// algorithm name disagrees with the text type, a wrong key length, and a
/// missing base64 field.
///
/// An options prefix (`restrict ...`, `command="..." ...`) is *not*
/// supported and shows up as a foreign type, which is a rejection: docs/05
/// allows a toy to refuse lines with options, and refusing loudly is the
/// safe direction for an authorization file.
pub fn parse_public_key_line(line : String) -> PublicKey raise KeyError {
  parse_public_key_fields(line, "public key line")
}

///|
/// Shared body of `parse_public_key_line`, with the error context as a
/// parameter so `known_hosts` can reuse the type/base64/blob checks.
fn parse_public_key_fields(
  line : String,
  ctx : String,
) -> PublicKey raise KeyError {
  let rest = line.trim(char_set=" \t\r\n")
  if rest.length() == 0 {
    raise BadFormat("\{ctx}: empty")
  }
  let (type_name, after_type) = split_field(rest)
  if type_name != ed25519_algorithm {
    raise Unsupported(
      "\{ctx}: expected type \{Repr(ed25519_algorithm)}, got \{Repr(type_name)}",
    )
  }
  let (b64, comment) = split_field(after_type)
  if b64 == "" {
    raise BadFormat("\{ctx}: missing base64 key")
  }
  let blob = @base64.decode(b64) catch {
    _ => raise BadFormat("\{ctx}: malformed base64")
  }
  { public: decode_public_key_blob(blob[:]), comment: comment.to_owned(), }
}

///|
/// Split off the first whitespace-delimited field, returning it and the
/// remainder with its leading whitespace removed. The remainder is `""`
/// when there was only one field.
fn split_field(s : StringView) -> (String, StringView) {
  let chars = s.to_array()
  let mut n = 0
  while n < chars.length() && !is_space(chars[n]) {
    n = n + 1
  }
  // Char count to code-unit offset: a comment may hold non-ASCII text.
  let cut = match s.offset_of_nth_char(n) {
    Some(o) => o
    None => s.length()
  }
  (
    s.view(end_offset=cut).to_owned(),
    s.view(start_offset=cut).trim_start(char_set=" \t"),
  )
}

///|
/// Whitespace as a key file uses it: spaces, tabs and stray line endings.
fn is_space(c : Char) -> Bool {
  c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

///|
/// Iterate the significant lines of a key file body: blank lines and lines
/// whose first non-blank character is `#` are skipped, and each remaining
/// line is yielded trimmed together with its 1-based line number.
fn significant_lines(body : String) -> Array[(Int, String)] {
  let out = []
  for i, line in body.split("\n").collect() {
    let trimmed = line.trim(char_set=" \t\r\n")
    if trimmed.length() == 0 || trimmed.has_prefix("#") {
      continue
    }
    out.push((i + 1, trimmed.to_owned()))
  }
  out
}

// ---------------------------------------------------------------------------
// authorized_keys (docs/05 section 1)
// ---------------------------------------------------------------------------

///|
/// Parse a whole `authorized_keys` body, skipping blank lines and `#`
/// comments.
///
/// **A single bad line fails the whole parse**, with the 1-based line
/// number in the message. The alternative — reporting per line and
/// continuing — means a typo silently drops an entry, which either locks
/// the owner out or (if the file is rewritten from the parse) lets someone
/// in. The caller should refuse to authenticate anyone rather than
/// authorize against a file it could not fully read.
pub fn parse_authorized_keys(body : String) -> Array[PublicKey] raise KeyError {
  let entries = []
  for numbered in significant_lines(body) {
    let (n, line) = numbered
    entries.push(
      parse_public_key_line(line) catch {
        BadFormat(m) => raise BadFormat("authorized_keys line \{n}: \{m}")
        Unsupported(m) => raise Unsupported("authorized_keys line \{n}: \{m}")
      },
    )
  }
  entries
}

///|
/// Is `public` (a raw 32-byte Ed25519 A) one of `entries`? Comparison is on
/// the raw bytes, never the base64 text (docs/05 section 1). A key of the
/// wrong length is simply not authorized — this is an authorization
/// predicate, so it never raises and never aborts.
pub fn is_authorized(
  entries : ArrayView[PublicKey],
  public : BytesView,
) -> Bool {
  if public.length() != ed25519_key_len {
    return false
  }
  let want = public.to_owned()
  for e in entries {
    if e.public == want {
      return true
    }
  }
  false
}

// ---------------------------------------------------------------------------
// Fingerprint (docs/05 section 3)
// ---------------------------------------------------------------------------

///|
/// OpenSSH-style fingerprint of a public key blob: `SHA256:` followed by
/// the base64 of `sha256(blob)` **without** padding.
pub fn fingerprint(blob : BytesView) -> String {
  let digest = @crypto.fixed_to_bytes(@xcrypto.sha256(blob.to_owned()))
  "SHA256:\{@base64.encode(digest[:], padding=false)}"
}
