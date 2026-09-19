///|
/// Toy SSH server: key exchange, `publickey` and `password` user
/// authentication, then one `session` channel running `exec` or a non-PTY
/// `shell`, plus optional `direct-tcpip` forwarding.
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
/// `--allow-tcp-forwarding` honours `direct-tcpip` channels (what `ssh -L`
/// opens). It is off by default: with it on, anyone who authenticates can
/// make this process connect anywhere it can reach.
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
/// What we advertise for the session channel: a 2 MiB window and a 32 KiB
/// maximum packet, the sizes docs/04 Part B suggests.
const CHANNEL_WINDOW : UInt = 2097152

///|
const CHANNEL_MAX_PACKET : UInt = 32768

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
  /// Whether `direct-tcpip` channels are honoured. Off unless asked for:
  /// a server that dials anywhere an authenticated peer names is a relay
  /// into whatever network it sits in.
  allow_tcp_forwarding : Bool
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
    // Each connection owns a task group: the socket reader and writer, and
    // the child process's output pumps, all live in it.
    @async.with_task_group(group => {
      serve(
        group,
        conn,
        peer,
        host_seed,
        authorized,
        passwords,
        allow_forward=opts.allow_tcp_forwarding,
      )
    })
    @net.log("[\{peer}] closed")
  })
}

///|
/// Run one connection: transport handshake, userauth, then one session
/// channel.
async fn[X] serve(
  group : @async.TaskGroup[X],
  conn : @socket.Tcp,
  peer : @socket.Addr,
  host_seed : Bytes,
  authorized : Map[String, Array[@keys.PublicKey]],
  passwords : Map[String, String],
  allow_forward~ : Bool,
) -> Unit {
  let t = @transport.Transport::new(@net.server_config(host_seed~))
  let c = @net.Conn::new(conn, t)
  // Created on Established, when the session id exists.
  let mut auth : @auth.AuthServer? = None
  // Created once the user is authenticated and opens a channel.
  let state : ConnState = {
    session: None,
    children: Map([]),
    forwards: Map([]),
    ptys: Map([]),
    allow_forward,
  }
  c.run(group, (c, ev) => {
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
      Packet(payload~) =>
        if auth is Some(a) && a.is_authenticated() {
          handle_connection(group, c, peer, a, state, payload)
        } else {
          handle_userauth(c, peer, auth, payload)
        }
      Disconnect(code~, description~, by_peer~) =>
        @net.log(
          "[\{peer}] disconnect code=\{code} \"\{description}\" by_peer=\{by_peer}",
        )
    }
  })
  // The read side is done. A command still running, or a forwarded
  // connection still open, would otherwise keep this connection's task
  // group — and the socket — alive: `sleep 3600` outlived its client by an
  // hour.
  for _, ch in state.children {
    @net.log("[\{peer}] peer gone, stopping pid \{ch.pid()}")
    ch.close_stdin()
    ch.cancel()
  }
  for _, fwd in state.forwards {
    fwd.close()
  }
  for channel, entry in state.ptys {
    let (pty, _) = entry
    if !state.children.contains(channel) {
      pty.close()
    }
  }
}

///|
/// Everything one authenticated connection owns, keyed by our channel id.
/// A connection can now have several channels at once: one session and any
/// number of forwards.
struct ConnState {
  mut session : @connection.ServerSession?
  children : Map[UInt, @net.Child]
  forwards : Map[UInt, @net.Forward]
  /// Terminals asked for with `pty-req` and not yet handed to a command,
  /// plus the `TERM` that came with each.
  ptys : Map[UInt, (@net.Pty, String)]
  allow_forward : Bool
}

///|
/// One decrypted payload before the user is authenticated: the service
/// request, then everything the userauth layer owns.
async fn handle_userauth(
  c : @net.Conn,
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
        c.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, "\{Repr(e)}")
        return
      }
    }
    if service == @transport.SERVICE_USERAUTH {
      @net.log("[\{peer}] service request \{service}: accepted")
      c.send(@transport.encode_service_accept(service)[:])
    } else {
      @net.log("[\{peer}] service request \{service}: refused")
      c.disconnect(
        @transport.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
        "service not available",
      )
    }
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
        c.disconnect(
          @transport.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
          "too many authentication failures",
        )
      }
      ProtocolViolation(msg) => {
        @net.log("[\{peer}] userauth protocol violation: \{msg}")
        c.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, msg)
      }
    }
  }
  for out in auth.take_outgoing() {
    c.send(out[:])
  }
}

///|
/// One decrypted payload after authentication: the connection protocol.
/// Channels are created lazily, as the peer opens them.
async fn[X] handle_connection(
  group : @async.TaskGroup[X],
  c : @net.Conn,
  peer : @socket.Addr,
  auth : @auth.AuthServer,
  state : ConnState,
  payload : Bytes,
) -> Unit {
  let s = match state.session {
    Some(s) => s
    None => {
      let s = @connection.ServerSession::new(
        window_size=CHANNEL_WINDOW,
        max_packet_size=CHANNEL_MAX_PACKET,
        allow_forward=state.allow_forward,
      )
      state.session = Some(s)
      s
    }
  }
  let events = s.on_payload(payload[:]) catch {
    ConnectionError(msg) => {
      @net.log("[\{peer}] connection protocol error: \{msg}")
      c.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, msg)
      return
    }
  }
  for ev in events {
    match ev {
      ExecRequest(channel~, command~) => {
        @net.log(
          "[\{peer}] exec \{Repr(command)} as \{auth.user().unwrap_or("?")}",
        )
        state.children[channel] = start_child(
          group,
          c,
          peer,
          s,
          state,
          channel,
          Some(command),
        )
      }
      ShellRequest(channel~, pty~) => {
        @net.log(
          "[\{peer}] shell as \{auth.user().unwrap_or("?")}\{if pty { " on a terminal" } else { "" }}",
        )
        state.children[channel] = start_child(
          group,
          c,
          peer,
          s,
          state,
          channel,
          None,
        )
      }
      PtyRequest(channel~, term~, cols~, rows~, width_px~, height_px~, ..) => {
        // Allocated now, handed to the command when it starts. A failure
        // here is the peer's to know about: the request was accepted, so
        // the session would otherwise run without the terminal it asked
        // for.
        let pty = @net.open_pty() catch {
          e => {
            @net.log("[\{peer}] pty-req failed: \{Repr(e)}")
            s.close_channel(channel~)
            flush(c, s)
            continue
          }
        }
        pty.set_window_size(cols~, rows~, width_px~, height_px~)
        @net.log(
          "[\{peer}] pty \{pty.slave_path()} \{cols}x\{rows} TERM=\{term}",
        )
        state.ptys[channel] = (pty, term)
      }
      WindowChange(channel~, cols~, rows~, width_px~, height_px~) =>
        match state.ptys.get(channel) {
          Some((pty, _)) =>
            pty.set_window_size(cols~, rows~, width_px~, height_px~)
          None => ()
        }
      ForwardRequest(channel~, host~, port~) =>
        // In its own task: the connect can take as long as the network
        // does, and `Conn::run` awaits this handler, so connecting here
        // would freeze every other channel on the connection.
        group.spawn_bg(
          () => start_forward(group, c, peer, s, state, channel, host, port),
          no_wait=true,
        )
      Stdin(channel~, data~) =>
        match (state.children.get(channel), state.forwards.get(channel)) {
          (Some(ch), _) => ch.write_stdin(data[:])
          (_, Some(fwd)) => fwd.write(data[:])
          // Data before a request: nothing is running to receive it.
          _ => ()
        }
      StdinEof(channel~) =>
        match state.children.get(channel) {
          Some(ch) => ch.close_stdin()
          // A forward has no half-close to pass on (see net/forward.mbt);
          // the target learns about it when the channel closes.
          None => ()
        }
      Closed(channel~) => {
        @net.log("[\{peer}] channel \{channel} closed")
        match state.forwards.get(channel) {
          Some(fwd) => {
            fwd.close()
            state.forwards.remove(channel)
          }
          None => ()
        }
        // A pty that never got a command (the peer asked for one and then
        // closed) is ours to close; one handed to a command is closed by
        // that command's pump.
        match state.ptys.get(channel) {
          Some((pty, _)) => {
            if !state.children.contains(channel) {
              pty.close()
            }
            state.ptys.remove(channel)
          }
          None => ()
        }
        match state.children.get(channel) {
          Some(ch) => {
            // Cancel, not just close stdin: the channel is gone, so
            // nothing can carry the command's output any more, and a
            // command that ignores its stdin (`sleep 3600`) would
            // otherwise keep this connection's task group alive long
            // after the peer hung up.
            ch.close_stdin()
            ch.cancel()
            state.children.remove(channel)
          }
          None => ()
        }
      }
    }
  }
  flush(c, s)
}

///|
/// Connect out for a `direct-tcpip` channel and relay it. The channel is
/// confirmed only once the connection stands, so a refused target reaches
/// the peer as a CHANNEL_OPEN_FAILURE rather than as a channel that
/// immediately closes.
async fn[X] start_forward(
  group : @async.TaskGroup[X],
  c : @net.Conn,
  peer : @socket.Addr,
  s : @connection.ServerSession,
  state : ConnState,
  channel : UInt,
  host : String,
  port : UInt,
) -> Unit {
  @net.log("[\{peer}] direct-tcpip to \{host}:\{port}")
  let fwd = @net.connect_forward(
    group,
    host~,
    port=port.reinterpret_as_int(),
    // Backpressure: the queue only drains as fast as the peer grants
    // window credit, so without this a fast target and a slow peer put
    // the whole transfer in memory.
    () => s.queued_bytes(channel~),
    chunk => {
      s.send_data(channel~, chunk[:])
      flush(c, s)
    },
    () => {
      // The target hung up: end our half of the channel.
      s.send_eof(channel~)
      s.close_channel(channel~)
      flush(c, s)
    },
  ) catch {
    e => {
      @net.log("[\{peer}] direct-tcpip to \{host}:\{port} failed: \{Repr(e)}")
      s.forward_failed(channel~, description="connect failed")
      flush(c, s)
      return
    }
  }
  state.forwards[channel] = fwd
  s.forward_connected(channel~)
  flush(c, s)
}

///|
/// Spawn the command and, in a third task, wait for it and report its exit
/// status. The output pumps queue channel data through the session; the
/// connection's writer task is what actually puts it on the socket.
async fn[X] start_child(
  group : @async.TaskGroup[X],
  c : @net.Conn,
  peer : @socket.Addr,
  s : @connection.ServerSession,
  state : ConnState,
  channel : UInt,
  command : String?,
) -> @net.Child {
  let child = match state.ptys.get(channel) {
    // A terminal merges the two output streams, so there is one pump and
    // no EXTENDED_DATA on a pty session.
    Some((pty, term)) =>
      @net.spawn_session_pty(
        group,
        command,
        pty,
        term~,
        () => s.queued_bytes(channel~),
        chunk => {
          s.send_data(channel~, chunk[:])
          flush(c, s)
        },
      )
    None => spawn_piped(group, c, s, command, channel)
  }
  group.spawn_bg(() => {
    let status = child.wait()
    // A child killed by a signal reports a negative value, which is not a
    // valid exit status; report it the way a shell does.
    let code = if status < 0 { 128 - status } else { status }
    @net.log("[\{peer}] pid \{child.pid()} exited with \{status}")
    s.finish(channel~, exit_status=code.reinterpret_as_uint())
    flush(c, s)
  })
  child
}

///|
/// The plain, pipe-backed session: stdout and stderr stay apart.
async fn[X] spawn_piped(
  group : @async.TaskGroup[X],
  c : @net.Conn,
  s : @connection.ServerSession,
  command : String?,
  channel : UInt,
) -> @net.Child {
  @net.spawn_session(
    group,
    command,
    chunk => {
      s.send_data(channel~, chunk[:])
      flush(c, s)
    },
    chunk => {
      s.send_stderr(channel~, chunk[:])
      flush(c, s)
    },
  )
}

///|
/// Hand whatever the session has queued to the connection's writer.
fn flush(c : @net.Conn, s : @connection.ServerSession) -> Unit {
  for out in s.take_outgoing() {
    c.send(out[:])
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
  let mut allow_tcp_forwarding = false
  let mut i = 1
  while i < args.length() {
    let flag = args[i]
    if flag == "--help" {
      println(
        "usage: server [--listen ADDR] (--host-key FILE | --host-seed-hex HEX) [--authorized-keys USER:FILE]... [--passwords FILE] [--allow-tcp-forwarding]",
      )
      @sys.exit(0)
    }
    if flag == "--allow-tcp-forwarding" {
      allow_tcp_forwarding = true
      i = i + 1
      continue
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
    allow_tcp_forwarding,
  }
}
