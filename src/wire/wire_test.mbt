// Fixtures from RFC 4251 section 5 and docs/06 M0 TDD order.

///|
test "hex helper" {
  inspect(@wire.hex(b"\x00\xff\x10"[:]), content="00ff10")
  inspect(@wire.hex(b""[:]), content="")
}

///|
test "writer: byte / boolean / uint32 / uint64 fixed fixtures" {
  let w = @wire.Writer::new()
  w.write_byte(b'\x2a')
  w.write_boolean(true)
  w.write_boolean(false)
  w.write_uint32(1)
  w.write_uint64(0x0102030405060708UL)
  inspect(@wire.hex(w.to_bytes()[:]), content="2a0100000000010102030405060708")
}

///|
test "writer: string is uint32 length prefix plus raw bytes" {
  let w = @wire.Writer::new()
  w.write_string(b"abc")
  w.write_string(b"")
  w.write_str("ssh-ed25519")
  inspect(
    @wire.hex(w.to_bytes()[:]),
    content="00000003616263" +
      "00000000" +
      "0000000b" +
      "7373682d65643235353139",
  )
}

///|
test "writer: mpint fixtures from RFC 4251 section 5" {
  fn enc(m : Bytes) -> String {
    let w = @wire.Writer::new()
    w.write_mpint(m[:])
    @wire.hex(w.to_bytes()[:])
  }
  // zero -> empty string
  inspect(enc(b""), content="00000000")
  // leading zero bytes in the magnitude are stripped
  inspect(enc(b"\x00\x00"), content="00000000")
  // 0x80 -> 00 80 (sign byte added because the high bit is set)
  inspect(enc(b"\x80"), content="000000020080")
  // 0x9a378f9b2e332a7 -> 08 09 a3 78 f9 b2 e3 32 a7
  inspect(
    enc(b"\x09\xa3\x78\xf9\xb2\xe3\x32\xa7"),
    content="0000000809a378f9b2e332a7",
  )
  // leading zeros stripped, then sign byte re-added: 00 00 80 -> 00 80
  inspect(enc(b"\x00\x00\x80"), content="000000020080")
}

///|
test "writer: name-list fixtures from RFC 4251 section 5" {
  let w = @wire.Writer::new()
  w.write_name_list([])
  w.write_name_list(["zlib"])
  w.write_name_list(["zlib", "none"])
  inspect(
    @wire.hex(w.to_bytes()[:]),
    content="00000000" +
      "00000004" +
      "7a6c6962" +
      "00000009" +
      "7a6c69622c6e6f6e65",
  )
}

///|
test "reader: scalar round-trip" {
  let w = @wire.Writer::new()
  w.write_byte(b'\x2a')
  w.write_boolean(true)
  w.write_boolean(false)
  w.write_uint32(0xdeadbeef)
  w.write_uint64(0xffffffffffffffffUL)
  let r = @wire.Reader::new(w.to_bytes()[:])
  inspect(r.read_byte().to_int(), content="42")
  inspect(r.read_boolean(), content="true")
  inspect(r.read_boolean(), content="false")
  inspect(r.read_uint32(), content="3735928559")
  inspect(r.read_uint64(), content="18446744073709551615")
  inspect(r.remaining(), content="0")
  inspect(r.is_at_end(), content="true")
}

///|
test "reader: boolean treats any nonzero byte as true" {
  let r = @wire.Reader::new(b"\x07"[:])
  inspect(r.read_boolean(), content="true")
}

///|
test "reader: string / mpint / name-list round-trip" {
  let w = @wire.Writer::new()
  w.write_string(b"\x00\xff")
  w.write_str("ssh-userauth")
  w.write_mpint(b"\x80")
  w.write_mpint(b"")
  w.write_name_list(["curve25519-sha256", "kex-strict-c-v00@openssh.com"])
  w.write_name_list([])
  let r = @wire.Reader::new(w.to_bytes()[:])
  inspect(@wire.hex(r.read_string()), content="00ff")
  inspect(r.read_str(), content="ssh-userauth")
  inspect(@wire.hex(r.read_mpint()[:]), content="80")
  inspect(@wire.hex(r.read_mpint()[:]), content="")
  debug_inspect(
    r.read_name_list(),
    content=(
      #|["curve25519-sha256", "kex-strict-c-v00@openssh.com"]
    ),
  )
  debug_inspect(r.read_name_list(), content="[]")
  inspect(r.is_at_end(), content="true")
}

///|
test "reader: raises on short reads" {
  let r = @wire.Reader::new(b"\x00\x00\x00"[:])
  try r.read_uint32() catch {
    e => debug_inspect(e, content="ShortRead(need=4, have=3)")
  } noraise {
    _ => fail("expected read_uint32 to raise")
  }
  let r2 = @wire.Reader::new(b"\x00\x00\x00\x05ab"[:])
  try r2.read_string() catch {
    e => debug_inspect(e, content="ShortRead(need=5, have=2)")
  } noraise {
    _ => fail("expected read_string to raise")
  }
  let r3 = @wire.Reader::new(b""[:])
  try r3.read_byte() catch {
    e => debug_inspect(e, content="ShortRead(need=1, have=0)")
  } noraise {
    _ => fail("expected read_byte to raise")
  }
}

///|
test "reader: rejects negative and non-minimal mpint" {
  let r = @wire.Reader::new(b"\x00\x00\x00\x01\x80"[:])
  try r.read_mpint() catch {
    e => debug_inspect(e, content="Invalid(\"negative mpint\")")
  } noraise {
    _ => fail("expected read_mpint to raise")
  }
  let r2 = @wire.Reader::new(b"\x00\x00\x00\x02\x00\x01"[:])
  try r2.read_mpint() catch {
    e =>
      debug_inspect(
        e,
        content="Invalid(\"mpint has unnecessary leading zero\")",
      )
  } noraise {
    _ => fail("expected read_mpint to raise")
  }
}

///|
test "reader: read_bytes slices raw bytes" {
  let r = @wire.Reader::new(b"abcdef"[:])
  inspect(@wire.hex(r.read_bytes(2)), content="6162")
  inspect(@wire.hex(r.read_bytes(4)), content="63646566")
  try r.read_bytes(1) catch {
    e => debug_inspect(e, content="ShortRead(need=1, have=0)")
  } noraise {
    _ => fail("expected read_bytes to raise")
  }
}
