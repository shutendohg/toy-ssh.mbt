// RFC 4253 section 4.2 identification string exchange (docs/02 section 1).

///|
test "version_line: our banner terminated by CRLF" {
  inspect(@transport.OUR_VERSION, content="SSH-2.0-toyssh_0.1")
  inspect(
    @hex.encode(@transport.version_line()[:]),
    content="5353482d322e302d746f797373685f302e310d0a",
  )
  assert_eq(@transport.version_line(), b"SSH-2.0-toyssh_0.1\r\n")
}

///|
test "parse_version: extracts the raw version without CRLF and reports consumed" {
  let buf = b"SSH-2.0-OpenSSH_9.9 comment\r\n\x00\x00\x00\x0c"
  match @transport.parse_version(buf[:]) {
    Version(version~, consumed~) => {
      assert_eq(version, b"SSH-2.0-OpenSSH_9.9 comment")
      assert_eq(consumed, 29)
    }
    NeedMoreData => fail("expected a complete version line")
  }
}

///|
test "parse_version: tolerates a bare LF terminator" {
  match @transport.parse_version(b"SSH-2.0-x\n"[:]) {
    Version(version~, consumed~) => {
      assert_eq(version, b"SSH-2.0-x")
      assert_eq(consumed, 10)
    }
    NeedMoreData => fail("expected a complete version line")
  }
}

///|
test "parse_version: skips pre-banner lines that do not start with SSH-" {
  let buf = b"Welcome to the toy box\r\n\r\nSSH-2.0-toyssh_0.1\r\n"
  match @transport.parse_version(buf[:]) {
    Version(version~, consumed~) => {
      assert_eq(version, b"SSH-2.0-toyssh_0.1")
      assert_eq(consumed, buf.length())
    }
    NeedMoreData => fail("expected a complete version line")
  }
}

///|
test "parse_version: NeedMoreData until the terminator arrives" {
  debug_inspect(@transport.parse_version(b""[:]), content="NeedMoreData")
  debug_inspect(
    @transport.parse_version(b"SSH-2.0-abc"[:]),
    content="NeedMoreData",
  )
  debug_inspect(
    @transport.parse_version(b"SSH-2.0-abc\r"[:]),
    content="NeedMoreData",
  )
  debug_inspect(
    @transport.parse_version(b"banner\r\nSSH-2.0-abc"[:]),
    content="NeedMoreData",
  )
}

///|
test "parse_version: rejects lines longer than 255 bytes including CRLF" {
  fn expect_err(buf : Bytes, want : String) -> Unit raise {
    try @transport.parse_version(buf[:]) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_version to raise")
    }
  }
  // 253 chars + CRLF = 255: accepted
  let ok = b"SSH-2.0-" + Bytes::make(245, b'x') + b"\r\n"
  assert_eq(ok.length(), 255)
  match @transport.parse_version(ok[:]) {
    Version(consumed~, ..) => assert_eq(consumed, 255)
    NeedMoreData => fail("expected a complete version line")
  }
  // 254 chars + CRLF = 256: rejected
  let long = b"SSH-2.0-" + Bytes::make(246, b'x') + b"\r\n"
  expect_err(long, "ProtocolError(\"identification line too long\")")
  // Even without a terminator, 256 buffered bytes cannot be a valid line.
  expect_err(
    Bytes::make(256, b'x'),
    "ProtocolError(\"identification line too long\")",
  )
  // A too-long pre-banner line is rejected too.
  expect_err(
    Bytes::make(254, b'x') + b"\r\nSSH-2.0-x\r\n",
    "ProtocolError(\"identification line too long\")",
  )
}

///|
test "parse_version: rejects unsupported protocol versions" {
  try @transport.parse_version(b"SSH-1.5-old\r\n"[:]) catch {
    e =>
      debug_inspect(
        e,
        content="ProtocolError(\"unsupported protocol version: SSH-1.5-old\")",
      )
  } noraise {
    _ => fail("expected parse_version to raise")
  }
}

///|
test "parse_version: rejects non-printable bytes in the identification line" {
  for buf in [b"SSH-2.0-toy\xffssh\r\n", b"SSH-2.0-toy\x01ssh\r\n"] {
    try @transport.parse_version(buf[:]) catch {
      e =>
        debug_inspect(
          e,
          content="ProtocolError(\"identification line is not printable ASCII\")",
        )
    } noraise {
      _ => fail("expected parse_version to raise")
    }
  }
}
