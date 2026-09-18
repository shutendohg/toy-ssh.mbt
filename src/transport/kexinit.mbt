///|
/// SSH_MSG_KEXINIT payload, RFC 4253 section 7.1 / docs/02 section 3.
/// `encode()` yields the full payload starting at the message byte; that
/// exact byte string is `I_C` / `I_S` in the exchange hash, so keep it.

///|
pub(all) struct KexInit {
  cookie : Bytes
  kex_algorithms : Array[String]
  server_host_key_algorithms : Array[String]
  encryption_client_to_server : Array[String]
  encryption_server_to_client : Array[String]
  mac_client_to_server : Array[String]
  mac_server_to_client : Array[String]
  compression_client_to_server : Array[String]
  compression_server_to_client : Array[String]
  languages_client_to_server : Array[String]
  languages_server_to_client : Array[String]
  first_kex_packet_follows : Bool
  reserved : UInt
} derive(Debug, Eq)

///|
/// The algorithms we advertise (docs/00, docs/02 section 3, docs/06 M5).
/// The kex list carries the role-specific strict-kex marker. The AEAD
/// cipher stays first; `aes128-ctr` + `hmac-sha2-256` is the fallback a
/// peer has to ask for, and the MAC lists exist only for it.
pub const KEX_MLKEM768X25519_SHA256 : String = "mlkem768x25519-sha256"

///|
pub const KEX_CURVE25519_SHA256 : String = "curve25519-sha256"

///|
pub const KEX_CURVE25519_SHA256_LIBSSH : String = "curve25519-sha256@libssh.org"

///|
pub const KEX_STRICT_CLIENT : String = "kex-strict-c-v00@openssh.com"

///|
pub const KEX_STRICT_SERVER : String = "kex-strict-s-v00@openssh.com"

///|
pub const HOSTKEY_ED25519 : String = "ssh-ed25519"

///|
pub const CIPHER_CHACHA20_POLY1305 : String = "chacha20-poly1305@openssh.com"

///|
pub const CIPHER_AES128_CTR : String = "aes128-ctr"

///|
pub const MAC_HMAC_SHA2_256 : String = "hmac-sha2-256"

///|
pub const COMPRESSION_NONE : String = "none"

///|
/// The KEXINIT we advertise for `role`. `cookie` must be 16 random bytes;
/// it is a parameter so this codec stays free of randomness. `ciphers`
/// replaces the cipher lists when given, which is how a caller pins one
/// suite (docs/07 interop runs both of them).
pub fn KexInit::for_role(
  role : Role,
  cookie~ : Bytes,
  ciphers? : Array[String]? = None,
) -> KexInit {
  guard cookie.length() == 16 else { abort("KEXINIT cookie must be 16 bytes") }
  let strict = match role {
    Client => KEX_STRICT_CLIENT
    Server => KEX_STRICT_SERVER
  }
  let ciphers = match ciphers {
    Some(list) => {
      guard list.length() > 0 else { abort("KEXINIT: empty cipher list") }
      list
    }
    None => [CIPHER_CHACHA20_POLY1305, CIPHER_AES128_CTR]
  }
  {
    cookie,
    kex_algorithms: [
      // Post-quantum first, as OpenSSH does: a hybrid exchange should be
      // the default rather than something a peer has to ask for.
      KEX_MLKEM768X25519_SHA256,
      KEX_CURVE25519_SHA256,
      KEX_CURVE25519_SHA256_LIBSSH,
      strict,
    ],
    server_host_key_algorithms: [HOSTKEY_ED25519],
    encryption_client_to_server: ciphers,
    encryption_server_to_client: ciphers,
    // Only the second cipher needs one; an AEAD peer ignores these lists.
    mac_client_to_server: [MAC_HMAC_SHA2_256],
    mac_server_to_client: [MAC_HMAC_SHA2_256],
    compression_client_to_server: [COMPRESSION_NONE],
    compression_server_to_client: [COMPRESSION_NONE],
    languages_client_to_server: [],
    languages_server_to_client: [],
    first_kex_packet_follows: false,
    reserved: 0,
  }
}

///|
/// Full KEXINIT payload: message byte, cookie, ten name-lists, boolean,
/// reserved uint32.
pub fn KexInit::encode(self : KexInit) -> Bytes raise ProtocolError {
  self.encode_kexinit() catch {
    e => raise wire_error("KEXINIT", e)
  }
}

///|
fn KexInit::encode_kexinit(self : KexInit) -> Bytes raise @wire.WireError {
  let w = @wire.Writer::new(size_hint=256)
  w.write_byte(SSH_MSG_KEXINIT)
  w.write_raw(self.cookie[:])
  w.write_name_list(self.kex_algorithms)
  w.write_name_list(self.server_host_key_algorithms)
  w.write_name_list(self.encryption_client_to_server)
  w.write_name_list(self.encryption_server_to_client)
  w.write_name_list(self.mac_client_to_server)
  w.write_name_list(self.mac_server_to_client)
  w.write_name_list(self.compression_client_to_server)
  w.write_name_list(self.compression_server_to_client)
  w.write_name_list(self.languages_client_to_server)
  w.write_name_list(self.languages_server_to_client)
  w.write_boolean(self.first_kex_packet_follows)
  w.write_uint32(self.reserved)
  w.to_bytes()
}

///|
/// Parse a KEXINIT payload (message byte through reserved uint32). The
/// whole payload must be consumed; wire-level failures are wrapped in
/// `ProtocolError` per docs/01.
pub fn KexInit::decode(payload : BytesView) -> KexInit raise ProtocolError {
  let ctx = "KEXINIT"
  let r = expect_message(payload, SSH_MSG_KEXINIT, ctx)
  let ki = read_kexinit_fields(r) catch { e => raise wire_error(ctx, e) }
  expect_end(r, ctx)
  ki
}

///|
/// Reads everything after the message byte.
fn read_kexinit_fields(r : @wire.Reader) -> KexInit raise @wire.WireError {
  {
    cookie: r.read_bytes(16).to_owned(),
    kex_algorithms: r.read_name_list(),
    server_host_key_algorithms: r.read_name_list(),
    encryption_client_to_server: r.read_name_list(),
    encryption_server_to_client: r.read_name_list(),
    mac_client_to_server: r.read_name_list(),
    mac_server_to_client: r.read_name_list(),
    compression_client_to_server: r.read_name_list(),
    compression_server_to_client: r.read_name_list(),
    languages_client_to_server: r.read_name_list(),
    languages_server_to_client: r.read_name_list(),
    first_kex_packet_follows: r.read_boolean(),
    reserved: r.read_uint32(),
  }
}
