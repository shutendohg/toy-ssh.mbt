///|
/// Lowercase hex of a byte view. Used by tests across packages to state
/// byte fixtures compactly (the Debug repr of Bytes is one byte per line).
pub fn hex(data : BytesView) -> String {
  let digits = b"0123456789abcdef"
  let sb = StringBuilder(size_hint=data.length() * 2)
  for b in data {
    sb.write_char(digits[(b.to_int() >> 4) & 0xf].to_char())
    sb.write_char(digits[b.to_int() & 0xf].to_char())
  }
  sb.to_string()
}
