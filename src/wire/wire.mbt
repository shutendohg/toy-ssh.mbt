///|
/// SSH wire-type codec (RFC 4251 section 5). No SSH semantics live here.
///
/// All multi-byte integers are big-endian. `Writer` appends to a growable
/// buffer; `Reader` is a cursor over a `BytesView` that raises `WireError`
/// on truncated or invalid input (callers turn that into a protocol-error
/// disconnect, see docs/01 "Error handling policy").

///|
/// Decoding failure. `ShortRead` carries how many bytes were needed versus
/// how many were left; `Invalid` covers well-formed-but-illegal encodings.
pub(all) suberror WireError {
  ShortRead(need~ : Int, have~ : Int)
  Invalid(String)
} derive(Debug, Eq)

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

///|
/// Growable output buffer for SSH wire types.
pub struct Writer {
  buf : @buffer.Buffer
}

///|
pub fn Writer::new(size_hint? : Int = 64) -> Writer {
  { buf: @buffer.Buffer(size_hint~), }
}

///|
/// Number of bytes written so far.
pub fn Writer::length(self : Writer) -> Int {
  self.buf.length()
}

///|
pub fn Writer::to_bytes(self : Writer) -> Bytes {
  self.buf.to_bytes()
}

///|
/// Append raw bytes with no framing.
pub fn Writer::write_raw(self : Writer, data : BytesView) -> Unit {
  self.buf.write_bytesview(data)
}

///|
pub fn Writer::write_byte(self : Writer, b : Byte) -> Unit {
  self.buf.write_byte(b)
}

///|
/// `boolean`: one byte, written as 0 or 1.
pub fn Writer::write_boolean(self : Writer, v : Bool) -> Unit {
  self.buf.write_byte(if v { b'\x01' } else { b'\x00' })
}

///|
pub fn Writer::write_uint32(self : Writer, v : UInt) -> Unit {
  self.buf.write_uint_be(v)
}

///|
pub fn Writer::write_uint64(self : Writer, v : UInt64) -> Unit {
  self.buf.write_uint64_be(v)
}

///|
/// `string`: uint32 length prefix followed by the raw bytes (binary-safe).
pub fn Writer::write_string(self : Writer, data : BytesView) -> Unit {
  self.write_uint32(data.length().reinterpret_as_uint())
  self.buf.write_bytesview(data)
}

///|
/// `string` holding UTF-8 text (SSH uses this for names and messages).
pub fn Writer::write_str(self : Writer, s : String) -> Unit {
  let tmp = @buffer.Buffer(size_hint=s.length())
  tmp.write_string_utf8(s)
  self.write_string(tmp.to_bytes()[:])
}

///|
/// `mpint` of a non-negative integer given as a big-endian magnitude.
/// Leading zero bytes are stripped; a 0x00 sign byte is prepended when the
/// top bit of the first significant byte is set; zero encodes as "".
pub fn Writer::write_mpint(self : Writer, magnitude : BytesView) -> Unit {
  let mut start = 0
  while start < magnitude.length() && magnitude[start] == b'\x00' {
    start = start + 1
  }
  let body = magnitude[start:]
  let needs_sign_byte = body.length() > 0 && (body[0] & b'\x80') != b'\x00'
  let len = body.length() + (if needs_sign_byte { 1 } else { 0 })
  self.write_uint32(len.reinterpret_as_uint())
  if needs_sign_byte {
    self.buf.write_byte(b'\x00')
  }
  self.buf.write_bytesview(body)
}

///|
/// A `string name || string body` pair: the shape shared by every SSH
/// public key blob, signature blob and key-file entry (RFC 4253 section
/// 6.6, RFC 8709). Only the encoding lives here; which names and body
/// lengths are acceptable is policy for the layer that calls this.
pub fn Writer::write_named_blob(
  self : Writer,
  name : String,
  body : BytesView,
) -> Unit {
  self.write_str(name)
  self.write_string(body)
}

///|
/// `name-list`: comma-separated ASCII names, order significant. Each name
/// must be non-empty printable US-ASCII without commas (RFC 4251 section
/// 5); anything else would not round-trip through `read_name_list`.
pub fn Writer::write_name_list(
  self : Writer,
  names : Array[String],
) -> Unit raise WireError {
  let tmp = @buffer.Buffer()
  for i, name in names {
    if name.length() == 0 {
      raise Invalid("empty name in name-list")
    }
    for c in name {
      if !is_name_char(c.to_int()) {
        raise Invalid("name-list entry is not a printable ASCII name")
      }
    }
    if i > 0 {
      tmp.write_byte(b',')
    }
    tmp.write_string_utf8(name)
  }
  self.write_string(tmp.to_bytes()[:])
}

///|
/// Printable US-ASCII excluding space and comma: what a name-list entry
/// may contain (RFC 4251 section 5).
fn is_name_char(c : Int) -> Bool {
  c > 0x20 && c < 0x7f && c != ','.to_int()
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

///|
/// Cursor over an immutable byte view. Every `read_*` advances the cursor
/// and raises `WireError::ShortRead` if fewer bytes remain than needed.
pub struct Reader {
  data : BytesView
  mut pos : Int
}

///|
pub fn Reader::new(data : BytesView) -> Reader {
  { data, pos: 0, }
}

///|
pub fn Reader::remaining(self : Reader) -> Int {
  self.data.length() - self.pos
}

///|
pub fn Reader::is_at_end(self : Reader) -> Bool {
  self.pos >= self.data.length()
}

///|
/// Take `n` raw bytes as a view (no copy).
pub fn Reader::read_bytes(self : Reader, n : Int) -> BytesView raise WireError {
  if n < 0 {
    raise Invalid("negative length")
  }
  let have = self.remaining()
  if have < n {
    raise ShortRead(need=n, have~)
  }
  let out = self.data[self.pos:self.pos + n]
  self.pos = self.pos + n
  out
}

///|
pub fn Reader::read_byte(self : Reader) -> Byte raise WireError {
  self.read_bytes(1)[0]
}

///|
/// `boolean`: any nonzero byte is true (RFC 4251 section 5).
pub fn Reader::read_boolean(self : Reader) -> Bool raise WireError {
  self.read_byte() != b'\x00'
}

///|
pub fn Reader::read_uint32(self : Reader) -> UInt raise WireError {
  let v = self.read_bytes(4)
  (v[0].to_uint() << 24) |
  (v[1].to_uint() << 16) |
  (v[2].to_uint() << 8) |
  v[3].to_uint()
}

///|
pub fn Reader::read_uint64(self : Reader) -> UInt64 raise WireError {
  let hi = self.read_uint32().to_uint64()
  let lo = self.read_uint32().to_uint64()
  (hi << 32) | lo
}

///|
/// `string`: returns the raw bytes as a view into the input.
pub fn Reader::read_string(self : Reader) -> BytesView raise WireError {
  let len = self.read_uint32()
  // A length above Int range cannot fit in any packet we accept anyway.
  if len > 0x7fffffffU {
    raise Invalid("string length out of range")
  }
  self.read_bytes(len.reinterpret_as_int())
}

///|
/// `string` decoded as UTF-8 text (SSH uses this for names and messages).
/// Malformed UTF-8 is an `Invalid` encoding, not a crash.
pub fn Reader::read_str(self : Reader) -> String raise WireError {
  let raw = self.read_string()
  @utf8.decode(raw) catch {
    _ => raise Invalid("string is not valid UTF-8")
  }
}

///|
/// `mpint`: returns the big-endian magnitude with any sign byte stripped.
/// Negative values are rejected (SSH never uses them for our suite).
pub fn Reader::read_mpint(self : Reader) -> Bytes raise WireError {
  let body = self.read_string()
  if body.length() == 0 {
    return b""
  }
  if (body[0] & b'\x80') != b'\x00' {
    raise Invalid("negative mpint")
  }
  if body[0] == b'\x00' {
    if body.length() == 1 || (body[1] & b'\x80') == b'\x00' {
      raise Invalid("mpint has unnecessary leading zero")
    }
    return body[1:].to_owned()
  }
  body.to_owned()
}

///|
/// `name-list`: splits on commas. An empty string yields an empty list;
/// otherwise every name must be non-empty printable US-ASCII (RFC 4251
/// section 5), so `",a"`, `"a,,b"` and `"a b"` are all `Invalid`.
pub fn Reader::read_name_list(self : Reader) -> Array[String] raise WireError {
  let body = self.read_string()
  let names : Array[String] = []
  if body.length() == 0 {
    return names
  }
  let cur = StringBuilder()
  fn flush() -> Unit raise WireError {
    if cur.is_empty() {
      raise Invalid("empty name in name-list")
    }
    names.push(cur.to_string())
    cur.reset()
  }
  for b in body {
    if b == b',' {
      flush()
    } else if !is_name_char(b.to_int()) {
      raise Invalid("name-list entry is not a printable ASCII name")
    } else {
      cur.write_char(b.to_char())
    }
  }
  flush()
  names
}

///|
/// Read a `string name || string body` pair (see `write_named_blob`). The
/// cursor is left where the body ends, so the caller decides whether
/// trailing bytes are an error and what an acceptable name and body length
/// are.
pub fn Reader::read_named_blob(
  self : Reader,
) -> (String, BytesView) raise WireError {
  let name = self.read_str()
  let body = self.read_string()
  (name, body)
}
