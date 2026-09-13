///|
/// Identification string exchange, RFC 4253 section 4.2 / docs/02 section 1.

///|
/// Our identification string without the CRLF terminator. This exact byte
/// string is `V_C` / `V_S` in the exchange hash.
pub const OUR_VERSION : String = "SSH-2.0-toyssh_0.1"

///|
/// Maximum identification line length including CRLF (RFC 4253 section 4.2).
pub const MAX_VERSION_LINE : Int = 255

///|
/// Our version line as sent on the wire: banner + CRLF.
pub fn version_line() -> Bytes {
  let w = @wire.Writer::new()
  w.write_raw(@ascii.encode(OUR_VERSION)[:])
  w.write_raw(b"\r\n")
  w.to_bytes()
}

///|
/// Result of scanning a receive buffer for the peer's identification line.
pub(all) enum VersionParse {
  /// No complete identification line yet; call again with more input.
  NeedMoreData
  /// Peer version found. `version` excludes CR/LF (feed it to the exchange
  /// hash as-is); `consumed` counts every byte through the terminator,
  /// including any skipped pre-banner lines.
  Version(version~ : Bytes, consumed~ : Int)
} derive(Debug, Eq)

///|
/// Scan `buf` for the peer's `SSH-2.0-...` line. Lines not starting with
/// `SSH-` are skipped (servers may send a banner before the version line).
/// Both CRLF and bare LF terminate a line; a trailing CR is stripped.
/// Raises `ProtocolError` if any line exceeds 255 bytes, the protocol
/// version is not 2.0, or the identification line holds bytes outside
/// printable US-ASCII (RFC 4253 section 4.2).
pub fn parse_version(buf : BytesView) -> VersionParse raise ProtocolError {
  let mut line_start = 0
  for i in 0..<buf.length() {
    if i - line_start + 1 > MAX_VERSION_LINE {
      raise ProtocolError("identification line too long")
    }
    if buf[i] != b'\n' {
      continue
    }
    let mut line_end = i
    if line_end > line_start && buf[line_end - 1] == b'\r' {
      line_end = line_end - 1
    }
    let line = buf[line_start:line_end]
    if line.has_prefix(b"SSH-") {
      for b in line {
        if b < b'\x20' || b > b'\x7e' {
          raise ProtocolError("identification line is not printable ASCII")
        }
      }
      if !line.has_prefix(b"SSH-2.0-") {
        raise ProtocolError(
          "unsupported protocol version: " + @ascii.decode_lossy(line),
        )
      }
      return Version(version=line.to_owned(), consumed=i + 1)
    }
    line_start = i + 1
  }
  // No terminator yet. A partial line that is already at the cap can never
  // become valid, so fail early instead of buffering without bound.
  if buf.length() - line_start >= MAX_VERSION_LINE {
    raise ProtocolError("identification line too long")
  }
  NeedMoreData
}
