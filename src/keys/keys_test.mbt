// Fixtures for docs/05. The private key below was produced by a real
// `ssh-keygen -t ed25519 -N '' -C 'toy-ssh keys test fixture'` run; it is
// embedded here rather than stored as a key file so the repository never
// ships something that looks like a usable private key.

///|
/// The unencrypted `openssh-key-v1` fixture, PEM text exactly as
/// `ssh-keygen` wrote it (70-column base64 wrapping included).
let fixture_pem : String =
  #|-----BEGIN OPENSSH PRIVATE KEY-----
  #|b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
  #|QyNTUxOQAAACBTJyScmY5cZSa7Karyw1R+cQc0+fhq18M503uhT0DnpwAAAKBNbW1/TW1t
  #|fwAAAAtzc2gtZWQyNTUxOQAAACBTJyScmY5cZSa7Karyw1R+cQc0+fhq18M503uhT0Dnpw
  #|AAAEBHactotRMkgPSkW7Fg1KeGQMAFXrDKRJU4xbO2yZtyfFMnJJyZjlxlJrspqvLDVH5x
  #|BzT5+GrXwznTe6FPQOenAAAAGXRveS1zc2gga2V5cyB0ZXN0IGZpeHR1cmUBAgME
  #|-----END OPENSSH PRIVATE KEY-----

///|
/// The matching `.pub` line.
let fixture_pub_line : String = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFMnJJyZjlxlJrspqvLDVH5xBzT5+GrXwznTe6FPQOen toy-ssh keys test fixture"

///|
let fixture_a_hex : String = "5327249c998e5c6526bb29aaf2c3547e710734f9f86ad7c339d37ba14f40e7a7"

///|
let fixture_seed_hex : String = "4769cb68b5132480f4a45bb160d4a78640c0055eb0ca449538c5b3b6c99b727c"

///|
let fixture_blob_hex : String = "0000000b7373682d65643235353139000000205327249c998e5c6526bb29aaf2c3547e710734f9f86ad7c339d37ba14f40e7a7"

///|
let fixture_fingerprint : String = "SHA256:KoPcOPub4kMnJIOai9Hnz0MJU65QpbUuCqydSYNOJdw"

///|
/// A second, unrelated Ed25519 public key (derived from an all-`0x01` seed)
/// used as the "other" key in authorized_keys / known_hosts tests.
fn other_public() -> Bytes {
  @crypto.fixed_to_bytes(
    @crypto.ed25519_public_key(Bytes::make(32, b'\x01')[:]),
  )
}

// ---------------------------------------------------------------------------
// Public key blob and line (docs/05 section 1)
// ---------------------------------------------------------------------------

///|
test "public key blob: encode and decode round-trip against the fixture" {
  let a = @hex.decode(fixture_a_hex)
  let blob = @keys.encode_public_key_blob(a[:])
  inspect(@hex.encode(blob[:]), content=fixture_blob_hex)
  assert_eq(@keys.decode_public_key_blob(blob[:]), a)
}

///|
test "public key blob: rejects a foreign algorithm, a wrong key length and trailing bytes" {
  fn expect_err(blob : Bytes, want : String) -> Unit raise {
    try @keys.decode_public_key_blob(blob[:]) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected decode_public_key_blob to raise")
    }
  }

  let w = @wire.Writer::new()
  w.write_str("ssh-rsa")
  w.write_string(Bytes::make(32, b'\x00')[:])
  expect_err(
    w.to_bytes(),
    "BadFormat(\"public key blob: expected algorithm \\\"ssh-ed25519\\\", got \\\"ssh-rsa\\\"\")",
  )
  let w = @wire.Writer::new()
  w.write_str("ssh-ed25519")
  w.write_string(Bytes::make(31, b'\x00')[:])
  expect_err(
    w.to_bytes(),
    "BadFormat(\"public key blob: Ed25519 key must be 32 bytes, got 31\")",
  )
  let w = @wire.Writer::new()
  w.write_str("ssh-ed25519")
  w.write_string(Bytes::make(32, b'\x00')[:])
  w.write_byte(b'\x00')
  expect_err(w.to_bytes(), "BadFormat(\"public key blob: 1 trailing byte(s)\")")
  expect_err(b"", "BadFormat(\"public key blob: ShortRead(need=4, have=0)\")")
}

///|
test "public key line: parses the fixture and formats back to the same text" {
  let key = @keys.parse_public_key_line(fixture_pub_line)
  inspect(@hex.encode(key.public[:]), content=fixture_a_hex)
  inspect(key.comment, content="toy-ssh keys test fixture")
  inspect(key.format(), content=fixture_pub_line)
  inspect(key.fingerprint(), content=fixture_fingerprint)
}

///|
test "public key line: a missing comment is allowed and round-trips" {
  let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFMnJJyZjlxlJrspqvLDVH5xBzT5+GrXwznTe6FPQOen"
  let key = @keys.parse_public_key_line(line)
  inspect(key.comment, content="")
  inspect(key.format(), content=line)
}

///|
test "public key line: the comment keeps its internal spaces" {
  let key = @keys.parse_public_key_line(
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFMnJJyZjlxlJrspqvLDVH5xBzT5+GrXwznTe6FPQOen a b  c",
  )
  inspect(key.comment, content="a b  c")
}

///|
test "public key line: rejects a foreign type, bad base64, a type/blob mismatch and missing fields" {
  fn expect_err(line : String, want : String) -> Unit raise {
    try @keys.parse_public_key_line(line) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_public_key_line to raise")
    }
  }

  expect_err(
    "ssh-rsa AAAAB3NzaC1yc2E=", "Unsupported(\"public key line: expected type \\\"ssh-ed25519\\\", got \\\"ssh-rsa\\\"\")",
  )
  expect_err(
    "ssh-ed25519", "BadFormat(\"public key line: missing base64 key\")",
  )
  expect_err("", "BadFormat(\"public key line: empty\")")
  expect_err(
    "ssh-ed25519 not_base64!!", "BadFormat(\"public key line: malformed base64\")",
  )
  // A blob whose inner algorithm name disagrees with the text type.
  let w = @wire.Writer::new()
  w.write_str("ssh-dss")
  w.write_string(@hex.decode(fixture_a_hex)[:])
  let text = "ssh-ed25519 " + @base64.encode(w.to_bytes()[:])
  expect_err(
    text, "BadFormat(\"public key blob: expected algorithm \\\"ssh-ed25519\\\", got \\\"ssh-dss\\\"\")",
  )
}

// ---------------------------------------------------------------------------
// authorized_keys (docs/05 section 1)
// ---------------------------------------------------------------------------

///|
test "authorized_keys: skips blanks and comments, keeps both keys, answers the predicate" {
  let other = @keys.PublicKey::{ public: other_public(), comment: "second", }
  let body = "# a leading comment\n" +
    "\n" +
    fixture_pub_line +
    "\n" +
    "   \n" +
    "  # an indented comment\n" +
    other.format() +
    "\n"
  let entries = @keys.parse_authorized_keys(body)
  assert_eq(entries.length(), 2)
  inspect(@hex.encode(entries[0].public[:]), content=fixture_a_hex)
  inspect(entries[0].comment, content="toy-ssh keys test fixture")
  inspect(entries[1].comment, content="second")
  assert_true(@keys.is_authorized(entries[:], @hex.decode(fixture_a_hex)[:]))
  assert_true(@keys.is_authorized(entries[:], other_public()[:]))
  assert_false(@keys.is_authorized(entries[:], Bytes::make(32, b'\x00')[:]))
  // A key of the wrong length is never authorized (and never aborts).
  assert_false(@keys.is_authorized(entries[:], b""[:]))
}

///|
test "authorized_keys: an empty body has no entries and authorizes nobody" {
  let entries = @keys.parse_authorized_keys("\n# nothing here\n")
  assert_eq(entries.length(), 0)
  assert_false(@keys.is_authorized(entries[:], @hex.decode(fixture_a_hex)[:]))
}

///|
test "authorized_keys: one bad line fails the whole file, naming the line number" {
  fn expect_err(body : String, want : String) -> Unit raise {
    try @keys.parse_authorized_keys(body) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_authorized_keys to raise")
    }
  }

  // An options prefix is rejected rather than silently skipped: an
  // unparsable authorization line must never read as "not authorized".
  expect_err(
    "restrict " + fixture_pub_line + "\n",
    "Unsupported(\"authorized_keys line 1: public key line: expected type \\\"ssh-ed25519\\\", got \\\"restrict\\\"\")",
  )
  expect_err(
    fixture_pub_line + "\nssh-ed25519 !!!\n",
    "BadFormat(\"authorized_keys line 2: public key line: malformed base64\")",
  )
}

// ---------------------------------------------------------------------------
// openssh-key-v1 private key (docs/05 section 2)
// ---------------------------------------------------------------------------

///|
/// Assemble an `openssh-key-v1` inner (for cipher "none": plaintext)
/// section. Defaults reproduce the fixture; every parameter exists so a
/// test can break exactly one field.
fn build_inner(
  checkint1? : UInt = 0x4d6d6d7f,
  checkint2? : UInt = 0x4d6d6d7f,
  key_type? : String = "ssh-ed25519",
  public? : Bytes = @hex.decode(fixture_a_hex),
  private_field? : Bytes = b"",
  comment? : String = "toy-ssh keys test fixture",
  padding? : Bytes,
) -> Bytes raise {
  let secret = if private_field.length() == 0 {
    let w = @wire.Writer::new(size_hint=64)
    w.write_raw(@hex.decode(fixture_seed_hex)[:])
    w.write_raw(@hex.decode(fixture_a_hex)[:])
    w.to_bytes()
  } else {
    private_field
  }
  let w = @wire.Writer::new(size_hint=192)
  w.write_uint32(checkint1)
  w.write_uint32(checkint2)
  w.write_str(key_type)
  w.write_string(public[:])
  w.write_string(secret[:])
  w.write_str(comment)
  match padding {
    Some(p) => w.write_raw(p[:])
    None => {
      let n = (8 - w.length() % 8) % 8
      for i in 0..<n {
        w.write_byte((i + 1).to_byte())
      }
    }
  }
  w.to_bytes()
}

///|
/// Assemble a whole `openssh-key-v1` container and wrap it in PEM guards.
/// Defaults reproduce the fixture.
fn build_pem(
  magic? : Bytes = b"openssh-key-v1\x00",
  ciphername? : String = "none",
  kdfname? : String = "none",
  kdfoptions? : Bytes = b"",
  number_of_keys? : UInt = 1,
  public_blob? : Bytes,
  inner? : Bytes,
  trailer? : Bytes = b"",
) -> String raise {
  let blob = match public_blob {
    Some(b) => b
    None => @hex.decode(fixture_blob_hex)
  }
  let section = match inner {
    Some(b) => b
    None => build_inner()
  }
  let w = @wire.Writer::new(size_hint=256)
  w.write_raw(magic[:])
  w.write_str(ciphername)
  w.write_str(kdfname)
  w.write_string(kdfoptions[:])
  w.write_uint32(number_of_keys)
  w.write_string(blob[:])
  w.write_string(section[:])
  w.write_raw(trailer[:])
  pem_wrap(w.to_bytes())
}

///|
/// Wrap raw container bytes in the `OPENSSH PRIVATE KEY` PEM guards.
fn pem_wrap(container : Bytes) -> String {
  "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
  @base64.encode(container[:]) +
  "\n-----END OPENSSH PRIVATE KEY-----\n"
}

///|
/// The fixture's own container bytes, for mutation-based negative tests.
fn fixture_container() -> Bytes raise {
  let body = StringBuilder()
  for line in fixture_pem.split("\n") {
    if line.has_prefix("-----") {
      continue
    }
    body.write_string(line.to_owned())
  }
  @base64.decode(body.to_string())
}

///|
test "private key: the test builder reproduces the real ssh-keygen container byte for byte" {
  // If this fails, the negative tests below are testing a straw man.
  let rebuilt = build_pem()
  let container = fixture_container()
  assert_eq(rebuilt, pem_wrap(container))
}

///|
test "private key: parses the fixture and cross-checks it against the .pub line" {
  let parsed = @keys.parse_openssh_private_key(fixture_pem)
  inspect(@hex.encode(parsed.key.seed()[:]), content=fixture_seed_hex)
  inspect(@hex.encode(parsed.key.public()[:]), content=fixture_a_hex)
  inspect(parsed.comment, content="toy-ssh keys test fixture")
  // docs/05 section 2: re-derive A from the seed and match the .pub file.
  let derived = @crypto.fixed_to_bytes(
    @crypto.ed25519_public_key(parsed.key.seed()[:]),
  )
  assert_eq(derived, @hex.decode(fixture_a_hex))
  assert_eq(derived, @keys.parse_public_key_line(fixture_pub_line).public)
  inspect(
    @keys.fingerprint(parsed.public_key().blob()[:]),
    content=fixture_fingerprint,
  )
}

///|
test "private key: the parsed key produces a signature that verifies under A" {
  let parsed = @keys.parse_openssh_private_key(fixture_pem)
  let msg = b"toy-ssh keys signature test"
  let sig = @crypto.fixed_to_bytes(parsed.key.sign(msg[:]))
  assert_true(@crypto.ed25519_verify(parsed.key.public()[:], msg[:], sig[:]))
  assert_false(@crypto.ed25519_verify(other_public()[:], msg[:], sig[:]))
}

///|
test "private key: accepts unwrapped, CRLF and whitespace-padded PEM text" {
  let one_line = "-----BEGIN OPENSSH PRIVATE KEY-----\r\n" +
    @base64.encode(fixture_container()[:]) +
    "\r\n-----END OPENSSH PRIVATE KEY-----\r\n"
  let parsed = @keys.parse_openssh_private_key(one_line)
  inspect(@hex.encode(parsed.key.seed()[:]), content=fixture_seed_hex)
}

///|
test "private key: rejects missing or swapped PEM guard lines" {
  fn expect_err(pem : String, want : String) -> Unit raise {
    try @keys.parse_openssh_private_key(pem) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_openssh_private_key to raise")
    }
  }

  expect_err(
    "not a pem file at all\n", "BadFormat(\"private key: missing \\\"-----BEGIN OPENSSH PRIVATE KEY-----\\\" line\")",
  )
  expect_err(
    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n", "BadFormat(\"private key: missing \\\"-----END OPENSSH PRIVATE KEY-----\\\" line\")",
  )
}

///|
test "private key: rejects a corrupt magic, a truncated body and trailing bytes" {
  fn expect_err(pem : String, want : String) -> Unit raise {
    try @keys.parse_openssh_private_key(pem) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_openssh_private_key to raise")
    }
  }

  expect_err(
    build_pem(magic=b"Openssh-key-v1\x00"),
    "BadFormat(\"private key: bad AUTH_MAGIC (not an openssh-key-v1 file)\")",
  )
  // The magic without its trailing NUL is *not* caught by the magic check:
  // the missing NUL aliases the first byte of the `ciphername` length
  // prefix, so the 15 bytes still read as "openssh-key-v1\\0" and the file
  // is rejected one field later. Still a rejection, just a different
  // message - assert the behaviour rather than pretend otherwise.
  expect_err(
    build_pem(magic=b"openssh-key-v1"),
    "BadFormat(\"private key: ShortRead(need=1134, have=238)\")",
  )
  // Truncate the base64 body: the container ends mid-field.
  let container = fixture_container()
  expect_err(
    pem_wrap(container[0:container.length() - 40].to_owned()),
    "BadFormat(\"private key: ShortRead(need=160, have=120)\")",
  )
  expect_err(
    build_pem(trailer=b"\x00"),
    "BadFormat(\"private key: 1 trailing byte(s) after the key\")",
  )
  expect_err(
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn!!\n-----END OPENSSH PRIVATE KEY-----\n",
    "BadFormat(\"private key: malformed base64 body\")",
  )
}

///|
test "private key: refuses encrypted keys with an actionable message" {
  fn expect_err(pem : String, want : String) -> Unit raise {
    try @keys.parse_openssh_private_key(pem) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_openssh_private_key to raise")
    }
  }

  let want = "Unsupported(\"private key: encrypted keys not supported; re-generate with `-N ''` or decrypt first\")"
  expect_err(build_pem(ciphername="aes256-ctr"), want)
  expect_err(build_pem(kdfname="bcrypt"), want)
  expect_err(build_pem(kdfoptions=b"\x00\x01"), want)
}

///|
test "private key: rejects a multi-key container, mismatched checkints, a foreign inner type" {
  fn expect_err(pem : String, want : String) -> Unit raise {
    try @keys.parse_openssh_private_key(pem) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_openssh_private_key to raise")
    }
  }

  expect_err(
    build_pem(number_of_keys=2),
    "Unsupported(\"private key: expected exactly 1 key in the file, got 2\")",
  )
  expect_err(
    build_pem(inner=build_inner(checkint2=0x4d6d6d80)),
    "BadFormat(\"private key: checkint mismatch (corrupt file, or it is actually encrypted)\")",
  )
  expect_err(
    build_pem(inner=build_inner(key_type="ssh-rsa")),
    "Unsupported(\"private key: expected key type \\\"ssh-ed25519\\\", got \\\"ssh-rsa\\\"\")",
  )
}

///|
test "private key: rejects wrong field lengths and a public key that disagrees" {
  fn expect_err(pem : String, want : String) -> Unit raise {
    try @keys.parse_openssh_private_key(pem) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_openssh_private_key to raise")
    }
  }

  let seed = @hex.decode(fixture_seed_hex)
  let a = @hex.decode(fixture_a_hex)
  expect_err(
    build_pem(inner=build_inner(public=Bytes::make(31, b'\x00'))),
    "BadFormat(\"private key: inner public key must be 32 bytes, got 31\")",
  )
  expect_err(
    build_pem(inner=build_inner(private_field=Bytes::make(63, b'\x00'))),
    "BadFormat(\"private key: private key field must be 64 bytes, got 63\")",
  )
  // The outer public key blob must agree with the inner public key.
  expect_err(
    build_pem(public_blob=@keys.encode_public_key_blob(other_public()[:])),
    "BadFormat(\"private key: outer public key blob disagrees with the inner public key\")",
  )
  // seed || A where the trailing A is not the inner public key.
  let bad_tail = @wire.Writer::new(size_hint=64)
  bad_tail.write_raw(seed[:])
  bad_tail.write_raw(other_public()[:])
  expect_err(
    build_pem(inner=build_inner(private_field=bad_tail.to_bytes())),
    "BadFormat(\"private key: private key field's trailing A disagrees with the public key\")",
  )
  // seed || A consistent with itself but not the seed's real public key.
  let wrong_seed = @wire.Writer::new(size_hint=64)
  wrong_seed.write_raw(Bytes::make(32, b'\x02')[:])
  wrong_seed.write_raw(a[:])
  expect_err(
    build_pem(inner=build_inner(private_field=wrong_seed.to_bytes())),
    "BadFormat(\"private key: ed25519_public_key(seed) does not match A (corrupt file)\")",
  )
}

///|
test "private key: rejects broken padding and a non-block-multiple section" {
  fn expect_err(pem : String, want : String) -> Unit raise {
    try @keys.parse_openssh_private_key(pem) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_openssh_private_key to raise")
    }
  }

  expect_err(
    build_pem(inner=build_inner(padding=b"\x01\x02\x03\x05")),
    "BadFormat(\"private key: bad padding byte at offset 3: expected 4, got 5\")",
  )
  expect_err(
    build_pem(inner=build_inner(padding=b"\x01\x02\x03")),
    "BadFormat(\"private key: inner section length 159 is not a multiple of the block size 8\")",
  )
  // Padding longer than a block: the section is block-aligned but OpenSSH
  // never emits 8+ padding bytes for this layout.
  expect_err(
    build_pem(
      inner=build_inner(
        padding=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
      ),
    ),
    "BadFormat(\"private key: 12 padding byte(s) is more than the block size 8\")",
  )
}

// ---------------------------------------------------------------------------
// known_hosts and TOFU (docs/05 section 3)
// ---------------------------------------------------------------------------

///|
test "known_hosts: host pattern is bare for port 22 and bracketed otherwise" {
  inspect(@keys.host_pattern("example.com", 22), content="example.com")
  inspect(@keys.host_pattern("example.com", 2222), content="[example.com]:2222")
  inspect(@keys.host_pattern("127.0.0.1", 22), content="127.0.0.1")
  inspect(@keys.host_pattern("127.0.0.1", 22022), content="[127.0.0.1]:22022")
}

///|
test "known_hosts: parses multi-host lines, skipping blanks and comments" {
  let a = @hex.decode(fixture_a_hex)
  let body = "# known hosts for the toy\n" +
    "\n" +
    "example.com,[example.com]:2222 ssh-ed25519 " +
    @base64.encode(@keys.encode_public_key_blob(a[:])[:]) +
    "\n" +
    @keys.format_known_hosts_line("[other.test]:2022", other_public()[:]) +
    "\n"
  let entries = @keys.parse_known_hosts(body)
  assert_eq(entries.length(), 2)
  debug_inspect(
    entries[0].hosts,
    content="[\"example.com\", \"[example.com]:2222\"]",
  )
  inspect(@hex.encode(entries[0].public[:]), content=fixture_a_hex)
  debug_inspect(entries[1].hosts, content="[\"[other.test]:2022\"]")
}

///|
test "known_hosts: the appended line is a single newline-free entry" {
  inspect(
    @keys.format_known_hosts_line(
      "[example.com]:2222",
      @hex.decode(fixture_a_hex)[:],
    ),
    content="[example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFMnJJyZjlxlJrspqvLDVH5xBzT5+GrXwznTe6FPQOen",
  )
  // The formatted line parses back to the same entry.
  let entries = @keys.parse_known_hosts(
    @keys.format_known_hosts_line("example.com", @hex.decode(fixture_a_hex)[:]),
  )
  assert_eq(entries.length(), 1)
  inspect(@hex.encode(entries[0].public[:]), content=fixture_a_hex)
}

///|
test "known_hosts: lookup returns unknown, trusted and changed" {
  let a = @hex.decode(fixture_a_hex)
  let other = other_public()
  let body = "example.com,[example.com]:2222 ssh-ed25519 " +
    @base64.encode(@keys.encode_public_key_blob(a[:])[:]) +
    "\n"
  let entries = @keys.parse_known_hosts(body)
  debug_inspect(
    @keys.check_known_host(entries[:], "example.com", a[:]),
    content="Trusted",
  )
  debug_inspect(
    @keys.check_known_host(entries[:], "[example.com]:2222", a[:]),
    content="Trusted",
  )
  debug_inspect(
    @keys.check_known_host(entries[:], "other.test", a[:]),
    content="Unknown",
  )
  // Port 22 and port 2222 are different host patterns, so a bare
  // "example.com" entry does not cover "[example.com]:9999".
  debug_inspect(
    @keys.check_known_host(entries[:], "[example.com]:9999", a[:]),
    content="Unknown",
  )
  // REMOTE HOST IDENTIFICATION HAS CHANGED: the stored key comes back so
  // the binary can print its fingerprint.
  match @keys.check_known_host(entries[:], "example.com", other[:]) {
    Changed(stored) => assert_eq(stored, a)
    got => fail("expected Changed, got \{Repr(got)}")
  }
}

///|
test "known_hosts: rejects hashed host patterns and malformed lines" {
  fn expect_err(body : String, want : String) -> Unit raise {
    try @keys.parse_known_hosts(body) catch {
      e => debug_inspect(e, content=want)
    } noraise {
      _ => fail("expected parse_known_hosts to raise")
    }
  }

  let good = @keys.format_known_hosts_line(
    "example.com",
    @hex.decode(fixture_a_hex)[:],
  )
  expect_err(
    "|1|F1E1+abc=|def= ssh-ed25519 AAAA\n", "Unsupported(\"known_hosts line 1: hashed host patterns (|1|...) are not supported\")",
  )
  // A line for another key type is skipped rather than failing the file
  // (see "other key types are skipped, markers are refused"); only the
  // Ed25519 entry survives.
  inspect(
    @keys.parse_known_hosts(good + "\nexample.com ssh-rsa AAAAB3NzaC1yc2E=\n").length(),
    content="1",
  )
  expect_err(
    "example.com ssh-ed25519\n", "BadFormat(\"known_hosts line 1: expected <host> ssh-ed25519 <base64>\")",
  )
  expect_err(
    "example.com ssh-ed25519 !!!\n", "BadFormat(\"known_hosts line 1: malformed base64\")",
  )
  expect_err(
    ",example.com ssh-ed25519 " +
    @base64.encode(
      @keys.encode_public_key_blob(@hex.decode(fixture_a_hex)[:])[:],
    ) +
    "\n",
    "BadFormat(\"known_hosts line 1: empty host pattern\")",
  )
}

///|
test "known_hosts: an empty file knows no hosts" {
  let entries = @keys.parse_known_hosts("\n\n# only comments\n")
  assert_eq(entries.length(), 0)
  debug_inspect(
    @keys.check_known_host(
      entries[:],
      "example.com",
      @hex.decode(fixture_a_hex)[:],
    ),
    content="Unknown",
  )
}

///|
test "known_hosts: a presented key of the wrong length is rejected, not silently trusted" {
  let entries = @keys.parse_known_hosts(
    @keys.format_known_hosts_line("example.com", @hex.decode(fixture_a_hex)[:]),
  )
  try @keys.check_known_host(entries[:], "example.com", b"\x00"[:]) catch {
    e =>
      debug_inspect(
        e,
        content="BadFormat(\"known_hosts: presented Ed25519 key must be 32 bytes, got 1\")",
      )
  } noraise {
    _ => fail("expected check_known_host to raise")
  }
}

// ---------------------------------------------------------------------------
// Fingerprint (docs/05 section 3)
// ---------------------------------------------------------------------------

///|
test "fingerprint: OpenSSH style SHA256 of the blob, base64 without padding" {
  let blob = @hex.decode(fixture_blob_hex)
  inspect(@keys.fingerprint(blob[:]), content=fixture_fingerprint)
  // No '=' padding, ever.
  assert_false(@keys.fingerprint(blob[:]).has_suffix("="))
  inspect(
    @keys.fingerprint(@keys.encode_public_key_blob(other_public()[:])[:]),
    content="SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8",
  )
}

///|
test "known_hosts: wildcard and negated patterns are refused, not left unmatchable" {
  // Matching is literal, so a pattern we cannot evaluate must fail the
  // file. Leaving it in would make the entry silently unmatchable, and the
  // client's trust-on-first-use would then accept any key for that host.
  let b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIFMnJJyZjlxlJrspqvLDVH5xBzT5+GrXwznTe6FPQOen"
  for pattern in ["*.example.com", "192.168.1.?", "!badhost", "host,*.other"] {
    try @keys.parse_known_hosts("\{pattern} ssh-ed25519 \{b64}\n") catch {
      Unsupported(_) => ()
      e => fail("expected Unsupported for \{pattern}, got \{Repr(e)}")
    } noraise {
      _ => fail("expected parse_known_hosts to refuse \{pattern}")
    }
  }
  // A plain pattern still parses.
  let ok = @keys.parse_known_hosts("[127.0.0.1]:2200 ssh-ed25519 \{b64}\n")
  inspect(ok.length(), content="1")
}

///|
test "known_hosts: other key types are skipped, markers are refused" {
  let b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIFMnJJyZjlxlJrspqvLDVH5xBzT5+GrXwznTe6FPQOen"
  // A real known_hosts holds other algorithms for unrelated hosts, and for
  // the same host. Skipping them is what OpenSSH does and cannot hide a
  // changed Ed25519 key: a host with only an RSA entry reads as unknown.
  let body =
    #|other.example ssh-rsa AAAAB3NzaC1yc2EAAAA
    #|[127.0.0.1]:2200 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY
    #|[127.0.0.1]:2200 ssh-ed25519 REPLACED
    #|
  let entries = @keys.parse_known_hosts(body.replace(old="REPLACED", new=b64))
  inspect(entries.length(), content="1")
  debug_inspect(
    @keys.check_known_host(
      entries[:],
      "[127.0.0.1]:2200",
      @hex.decode(
        "5327249c998e5c6526bb29aaf2c3547e710734f9f86ad7c339d37ba14f40e7a7",
      )[:],
    ),
    content="Trusted",
  )
  // A host whose only entry is another algorithm is unknown, not trusted.
  let rsa_only = @keys.parse_known_hosts("only.example ssh-rsa AAAAB3Nz\n")
  inspect(rsa_only.length(), content="0")
  // Markers must not be skipped: silently dropping @revoked would let a
  // revoked key through as a first-time connection.
  for marker in ["@revoked", "@cert-authority"] {
    try
      @keys.parse_known_hosts("\{marker} h.example ssh-ed25519 \{b64}\n")
    catch {
      Unsupported(_) => ()
      e => fail("expected Unsupported for \{marker}, got \{Repr(e)}")
    } noraise {
      _ => fail("expected parse_known_hosts to refuse \{marker}")
    }
  }
  // A malformed ssh-ed25519 line still fails the file.
  try @keys.parse_known_hosts("h.example ssh-ed25519 not_base64!!\n") catch {
    BadFormat(_) => ()
    e => fail("expected BadFormat, got \{Repr(e)}")
  } noraise {
    _ => fail("expected parse_known_hosts to refuse a bad base64 key")
  }
}
