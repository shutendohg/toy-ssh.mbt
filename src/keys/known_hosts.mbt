///|
/// `known_hosts` parsing and host key lookup (docs/05 section 3). This
/// package only answers "what does the file say about this host?" — the
/// trust-on-first-use *policy* (auto-accept and append, or prompt) belongs
/// to the binary, which is also the only thing allowed to touch the file.

///|
/// One `known_hosts` line: the host patterns it covers and the 32-byte
/// Ed25519 public key A. Hashed patterns (`|1|...`) never appear here —
/// they are rejected at parse time.
pub(all) struct KnownHost {
  hosts : Array[String]
  public : Bytes
} derive(Debug, Eq)

///|
/// What the file says about a host we are about to connect to.
pub(all) enum HostKeyStatus {
  /// No line covers this host: trust-on-first-use territory.
  Unknown
  /// A line covers this host and the presented key matches it.
  Trusted
  /// A line covers this host with a *different* key — OpenSSH's "REMOTE
  /// HOST IDENTIFICATION HAS CHANGED". The stored key comes along so the
  /// caller can print its fingerprint. Never silently accept this.
  Changed(Bytes)
} derive(Debug, Eq)

///|
/// The `known_hosts` host pattern for a connection: bare `hostname` on the
/// default port, `[hostname]:port` otherwise (docs/05 section 3).
pub fn host_pattern(host : String, port : Int) -> String {
  if port == 22 {
    host
  } else {
    "[\{host}]:\{port}"
  }
}

///|
/// Format a line to append to `known_hosts` for one host pattern (build it
/// with `host_pattern`). No trailing newline: the caller decides how to
/// join it to the file.
pub fn format_known_hosts_line(pattern : String, public : BytesView) -> String {
  "\{pattern} \{ed25519_algorithm} \{@base64.encode(encode_public_key_blob(public)[:])}"
}

///|
/// Parse a whole `known_hosts` body, skipping blank lines and `#`
/// comments. Like `parse_authorized_keys`, one bad line fails the whole
/// parse with its 1-based line number: a `known_hosts` file we only
/// half-understand would silently downgrade a changed host key to
/// "unknown", which is the one outcome we must never produce.
///
/// Hashed host patterns (`|1|...`) are rejected explicitly — the toy does
/// not implement them, and treating them as opaque host names would make
/// every hashed entry silently unmatchable.
pub fn parse_known_hosts(body : String) -> Array[KnownHost] raise KeyError {
  let entries = []
  for numbered in significant_lines(body) {
    let (n, line) = numbered
    let ctx = "known_hosts line \{n}"
    if line.has_prefix("|") {
      raise Unsupported(
        "\{ctx}: hashed host patterns (|1|...) are not supported",
      )
    }
    let (patterns, rest) = split_field(line[:])
    if rest.length() == 0 {
      raise BadFormat("\{ctx}: expected <host> \{ed25519_algorithm} <base64>")
    }
    let hosts = []
    for pattern in patterns.split(",") {
      if pattern.length() == 0 {
        raise BadFormat("\{ctx}: empty host pattern")
      }
      hosts.push(pattern.to_owned())
    }
    // Reuse the type / base64 / blob checks; a known_hosts line has no
    // comment field, so anything after the base64 is ignored the way
    // OpenSSH ignores a trailing marker.
    let key = parse_public_key_fields(rest.to_owned(), ctx) catch {
      BadFormat(m) =>
        raise BadFormat(
          if m == "\{ctx}: missing base64 key" {
            "\{ctx}: expected <host> \{ed25519_algorithm} <base64>"
          } else {
            m
          },
        )
      e => raise e
    }
    entries.push({ hosts, public: key.public, })
  }
  entries
}

///|
/// Look the connection's host pattern up in a parsed `known_hosts` and say
/// whether the presented key is unknown, trusted, or changed. `presented`
/// is the raw 32-byte A (decode a `K_S` blob with
/// `decode_public_key_blob` first).
///
/// A presented key of the wrong length raises rather than answering
/// `Unknown`: a malformed host key must not be able to masquerade as a
/// first-time connection.
pub fn check_known_host(
  entries : ArrayView[KnownHost],
  pattern : String,
  presented : BytesView,
) -> HostKeyStatus raise KeyError {
  if presented.length() != ed25519_key_len {
    raise BadFormat(
      "known_hosts: presented Ed25519 key must be \{ed25519_key_len} bytes, got \{presented.length()}",
    )
  }
  let want = presented.to_owned()
  let mut stored : Bytes? = None
  for e in entries {
    if e.hosts.contains(pattern) {
      if e.public == want {
        // OpenSSH accepts as soon as any line for this host matches,
        // even when other lines hold different keys.
        return Trusted
      }
      if stored is None {
        stored = Some(e.public)
      }
    }
  }
  match stored {
    Some(key) => Changed(key)
    None => Unknown
  }
}
