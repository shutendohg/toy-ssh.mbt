///|
/// Hex helpers, used by tests to paste RFC vectors verbatim.
pub fn hex_encode(data : BytesView) -> String {
  let digits = b"0123456789abcdef"
  let buf = StringBuilder()
  for b in data {
    buf.write_char(digits[(b.to_int() >> 4) & 0xf].to_char())
    buf.write_char(digits[b.to_int() & 0xf].to_char())
  }
  buf.to_string()
}

///|
fn hex_digit(c : Char) -> Int {
  match c {
    '0'..='9' => c.to_int() - '0'.to_int()
    'a'..='f' => c.to_int() - 'a'.to_int() + 10
    'A'..='F' => c.to_int() - 'A'.to_int() + 10
    _ => abort("invalid hex digit")
  }
}

///|
pub fn hex_decode(s : String) -> Bytes {
  let chars = s.to_array()
  guard chars.length() % 2 == 0 else { abort("odd-length hex string") }
  let out : Array[Byte] = Array::make(chars.length() / 2, b'\x00')
  for i in 0..<(chars.length() / 2) {
    let hi = hex_digit(chars[2 * i])
    let lo = hex_digit(chars[2 * i + 1])
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(out)
}
