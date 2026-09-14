///|
/// Toy SSH server, M3 scope: key exchange, then `publickey` and `password`
/// user authentication. Once a user is authenticated the connection ends,
/// because the connection protocol (channels, exec, shell) is M4.
///
/// ```
/// server [--listen 127.0.0.1:2222]
///        (--host-key <openssh-key-v1 file> | --host-seed-hex <64 hex>)
///        [--authorized-keys <user>:<file>]... [--passwords <file>]
/// ```
///
/// `--authorized-keys` is per user and may be repeated, because a key must
/// authorize one account rather than any name the client claims. M3 has no
/// per-user behaviour yet, but M4 runs commands, so the scoping belongs
/// here before it can be relied on.
///
/// The passwords file is plaintext `user:password` lines. That is insecure
/// and exists only because this is a toy.
///
/// Toy code. Never use for real security.

///|
/// Print a usage error and exit 2. Generic in its return type so it can
/// stand where a value is expected; it never returns.
fn[T] usage_error(message : String) -> T {
  println(message)
  @sys.exit(2)
  abort(message)
}

///|
/// What the server was told on the command line.
struct ServerOptions {
  listen : String
  host_key_path : String?
  host_seed_hex : String?
  /// `user` -> `authorized_keys` path. A key authorizes only the user it
  /// was configured for.
  authorized_keys_paths : Array[(String, String)]
  passwords_path : String?
}

///|
async fn main {
  let opts = parse_args(@env.args())
  let host_seed = load_host_seed(opts)
  // Read the policy files once at startup: a connection handler cannot do
  // IO (the transport callbacks are synchronous).
  let authorized : Map[String, Array[@keys.PublicKey]] = Map([])
  for pair in opts.authorized_keys_paths {
    let (user, path) = pair
    let entries = @keys.parse_authorized_keys(@net.read_text_file(path))
    match authorized.get(user) {
      Some(existing) => existing.append(entries)
      None => authorized[user] = entries
    }
  }
  let passwords = match opts.passwords_path {
    Some(path) => parse_passwords(@net.read_text_file(path))
    None => Map([])
  }
  @net.log(
    "toy-ssh server: \{authorized.length()} user(s) with keys, \{passwords.length()} password entr(ies)",
  )
  for user, entries in authorized {
    for entry in entries {
      @net.log(
        "toy-ssh server: \{user} authorized \{entry.fingerprint()} \{entry.comment}",
      )
    }
  }
  let server = @socket.TcpServer(
    @socket.Addr::parse(opts.listen),
    reuse_addr=true,
  )
  @net.log("toy-ssh server: listening on \{server.addr}")
  server.run_forever(allow_failure=true) <| ((conn, peer) => {
    defer conn.close()
    @net.log("[\{peer}] connected")
    serve(conn, peer, host_seed, authorized, passwords)
    @net.log("[\{peer}] closed")
  })
}

///|
/// Run one connection: transport handshake, then userauth.
async fn serve(
  conn : @socket.Tcp,
  peer : @socket.Addr,
  host_seed : Bytes,
  authorized : Map[String, Array[@keys.PublicKey]],
  passwords : Map[String, String],
) -> Unit {
  let t = @transport.Transport::new(@net.server_config(host_seed~))
  // Created on Established, when the session id exists.
  let mut auth : @auth.AuthServer? = None
  @net.run(conn, t, (t, ev) => {
    match ev {
      Established(session_id~) => {
        @net.log(
          "[\{peer}] established, session id \{@hex.encode(session_id[:])}",
        )
        auth = Some(
          @auth.AuthServer::new({
            session_id,
            check_password: (user, password) => {
              match passwords.get(user) {
                Some(want) => password == want
                None => false
              }
            },
            authorize_public_key: (user, blob) => {
              // Scoped to the user: a key listed for one account must not
              // authenticate another.
              guard authorized.get(user) is Some(entries) else { return false }
              let public = @keys.decode_public_key_blob(blob[:]) catch {
                _ => return false
              }
              @keys.is_authorized(entries[:], public[:])
            },
            banner: Some(
              "toy-ssh server: authentication is a toy, do not trust it\n",
            ),
            max_failures: 6,
          }),
        )
      }
      Packet(payload~) => handle_packet(t, peer, auth, payload)
      Disconnect(code~, description~, by_peer~) =>
        @net.log(
          "[\{peer}] disconnect code=\{code} \"\{description}\" by_peer=\{by_peer}",
        )
    }
  })
}

///|
/// One decrypted payload from the peer: the service request, then
/// everything the userauth layer owns.
async fn handle_packet(
  t : @transport.Transport,
  peer : @socket.Addr,
  auth : @auth.AuthServer?,
  payload : Bytes,
) -> Unit {
  guard payload.length() > 0 else { return }
  guard auth is Some(auth) else {
    // Cannot happen: packets only arrive after Established.
    abort("packet before the session id existed")
  }
  if payload[0] == @transport.SSH_MSG_SERVICE_REQUEST {
    let service = @transport.decode_service_request(payload[:]) catch {
      e => {
        t.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, "\{Repr(e)}")
        return
      }
    }
    if service == @transport.SERVICE_USERAUTH {
      @net.log("[\{peer}] service request \{service}: accepted")
      t.send_packet(@transport.encode_service_accept(service)[:])
    } else {
      @net.log("[\{peer}] service request \{service}: refused")
      t.disconnect(
        @transport.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
        "service not available",
      )
    }
    return
  }
  if auth.is_authenticated() {
    // The connection protocol is M4; say so instead of going silent.
    @net.log(
      "[\{peer}] message \{payload[0].to_int()} after authentication: the connection protocol is M4",
    )
    t.disconnect(
      @transport.SSH_DISCONNECT_BY_APPLICATION,
      "toy-ssh: the connection protocol is not implemented yet (M4)",
    )
    return
  }
  for ev in auth.on_payload(payload[:]) {
    match ev {
      Request(user~, service~, auth_method~) =>
        @net.log(
          "[\{peer}] userauth request user=\{user} service=\{service} method=\{auth_method.name()}",
        )
      Authenticated(user~) => @net.log("[\{peer}] authenticated \{user}")
      TooManyFailures(user~) => {
        @net.log("[\{peer}] too many failures for \{user}, disconnecting")
        t.disconnect(
          @transport.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
          "too many authentication failures",
        )
      }
      ProtocolViolation(msg) => {
        @net.log("[\{peer}] userauth protocol violation: \{msg}")
        t.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, msg)
      }
    }
  }
  for out in auth.take_outgoing() {
    t.send_packet(out[:])
  }
}

///|
/// The host key, from an `openssh-key-v1` file or a raw hex seed.
async fn load_host_seed(opts : ServerOptions) -> Bytes {
  match (opts.host_key_path, opts.host_seed_hex) {
    (Some(path), _) => {
      let key = @keys.parse_openssh_private_key(@net.read_text_file(path))
      @net.log(
        "toy-ssh server: host key \{key.public_key().fingerprint()} from \{path}",
      )
      key.key.seed()
    }
    (None, Some(h)) => {
      let seed = @hex.decode(h) catch {
        _ => usage_error("--host-seed-hex must be 64 hex digits")
      }
      if seed.length() != 32 {
        usage_error("--host-seed-hex must be 64 hex digits")
      }
      seed
    }
    (None, None) =>
      usage_error("one of --host-key or --host-seed-hex is required")
  }
}

///|
/// `USER:FILE` for `--authorized-keys`. The separator is the first colon,
/// so a path may contain one.
fn split_user_path(value : String) -> (String, String) {
  let chars = value.to_array()
  let mut at = -1
  for n, c in chars {
    if c == ':' && at < 0 {
      at = n
    }
  }
  if at <= 0 || at == chars.length() - 1 {
    usage_error("--authorized-keys needs USER:FILE, got \{value}")
  }
  (
    String::from_array(chars[0:at].to_owned()),
    String::from_array(chars[at + 1:].to_owned()),
  )
}

///|
/// `user:password` per line; blank lines and `#` comments are skipped.
/// A password is everything after the first colon, so it may contain one.
/// Plaintext passwords in a file are insecure; this is a toy.
fn parse_passwords(body : String) -> Map[String, String] {
  let out : Map[String, String] = Map([])
  for i, line in body.split("\n").collect() {
    let trimmed = line.trim(char_set=" \t\r\n")
    if trimmed.length() == 0 || trimmed.has_prefix("#") {
      continue
    }
    let chars = trimmed.to_array()
    let mut at = -1
    for n, c in chars {
      if c == ':' && at < 0 {
        at = n
      }
    }
    if at <= 0 {
      usage_error(
        "passwords file line \{i + 1}: expected user:password, got \{trimmed}",
      )
    }
    let user = String::from_array(chars[0:at].to_owned())
    let password = String::from_array(chars[at + 1:].to_owned())
    if password.length() == 0 {
      // An empty password would match a client that sends none.
      usage_error("passwords file line \{i + 1}: empty password for \{user}")
    }
    out[user] = password
  }
  out
}

///|
fn parse_args(args : Array[String]) -> ServerOptions {
  let mut listen = "127.0.0.1:2222"
  let mut host_key_path : String? = None
  let mut host_seed_hex : String? = None
  let authorized_keys_paths : Array[(String, String)] = []
  let mut passwords_path : String? = None
  let mut i = 1
  while i < args.length() {
    let flag = args[i]
    if flag == "--help" {
      println(
        "usage: server [--listen ADDR] (--host-key FILE | --host-seed-hex HEX) [--authorized-keys USER:FILE]... [--passwords FILE]",
      )
      @sys.exit(0)
    }
    guard i + 1 < args.length() else { usage_error("\{flag} needs a value") }
    let value = args[i + 1]
    match flag {
      "--listen" => listen = value
      "--host-key" => host_key_path = Some(value)
      "--host-seed-hex" => host_seed_hex = Some(value)
      "--authorized-keys" => authorized_keys_paths.push(split_user_path(value))
      "--passwords" => passwords_path = Some(value)
      _ => usage_error("unknown argument: \{flag}")
    }
    i = i + 2
  }
  {
    listen,
    host_key_path,
    host_seed_hex,
    authorized_keys_paths,
    passwords_path,
  }
}
