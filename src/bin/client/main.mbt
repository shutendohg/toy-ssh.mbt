///|
/// Toy SSH client: key exchange with a known_hosts check, `publickey` or
/// `password` authentication, then one `session` channel that runs a
/// command (`exec`) or the remote login shell.
///
/// ```
/// client [-p PORT] [-i KEYFILE] [--known-hosts FILE] [--password PW]
///        [--strict-host-key-checking] [USER@]HOST [COMMAND]
/// ```
///
/// With a COMMAND the client runs it and exits with its status, like
/// `ssh host command`. Without one it asks for the remote shell and pipes
/// this process's standard input to it (no PTY, so no line editing).
/// The command's standard output goes to ours verbatim; diagnostics go to
/// standard error.
///
/// Host keys are trusted on first use and appended to the known_hosts file
/// unless `--strict-host-key-checking` is given. A changed host key is
/// always refused.
///
/// Toy code. Never use for real security.

///|
struct ClientOptions {
  user : String
  host : String
  port : Int
  key_path : String?
  known_hosts_path : String
  password : String?
  /// Refuse an unknown host key instead of trusting it on first use.
  strict : Bool
  /// The command to run, or `None` to ask for the remote shell.
  command : String?
}

///|
/// How many unsent standard-input bytes we let pile up before we stop
/// reading. One window's worth: the queue cannot drain faster than the
/// peer grants credit anyway.
const STDIN_QUEUE_LIMIT : Int = 2097152

///|
/// What we advertise for the session channel (docs/04 Part B).
const CHANNEL_WINDOW : UInt = 2097152

///|
const CHANNEL_MAX_PACKET : UInt = 32768

///|
/// Print a usage error and exit 2. Generic in its return type so it can
/// stand where a value is expected; it never returns.
fn[T] usage_error(message : String) -> T {
  println(message)
  @sys.exit(2)
  abort(message)
}

///|
async fn main {
  let opts = parse_args(@env.args())
  let key = match opts.key_path {
    Some(path) => {
      let parsed = @keys.parse_openssh_private_key(@net.read_text_file(path))
      @net.log(
        "toy-ssh client: identity \{parsed.public_key().fingerprint()} from \{path}",
      )
      Some(parsed.key)
    }
    None => None
  }
  if key is None && opts.password is None {
    usage_error("no credentials: pass -i KEYFILE or --password PW")
  }
  // known_hosts is read before connecting: the host key callback is
  // synchronous and cannot do IO.
  let known = if @net.file_exists(opts.known_hosts_path) {
    @keys.parse_known_hosts(@net.read_text_file(opts.known_hosts_path))
  } else {
    []
  }
  let pattern = @keys.host_pattern(opts.host, opts.port)
  // Set when we trust a new host key and should append it after the
  // handshake (appending is IO, so it cannot happen in the callback).
  let mut learned : Bytes? = None
  let mut host_key_error = ""
  // The host key callback runs inside the sans-IO transport, so it cannot
  // write to stderr itself; it queues lines that the async side drains.
  let pending : Array[String] = []
  let accept_host_key = (k_s : Bytes) => {
    let public = @keys.decode_public_key_blob(k_s[:]) catch {
      e => {
        host_key_error = "unparsable host key: \{Repr(e)}"
        return false
      }
    }
    let status = @keys.check_known_host(known[:], pattern, public[:]) catch {
      e => {
        host_key_error = "known_hosts: \{Repr(e)}"
        return false
      }
    }
    match status {
      Trusted => {
        pending.push(
          "toy-ssh client: host key \{@keys.fingerprint(k_s[:])} matches \{opts.known_hosts_path}",
        )
        true
      }
      Changed(stored) => {
        pending.push(
          "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
        )
        pending.push(
          "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
        )
        pending.push(
          "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
        )
        pending.push(
          "The host key for \{pattern} does not match the stored one.",
        )
        pending.push(
          "  stored:    \{@keys.fingerprint(@keys.encode_public_key_blob(stored[:])[:])}",
        )
        pending.push("  presented: \{@keys.fingerprint(k_s[:])}")
        pending.push(
          "Remove the offending line from \{opts.known_hosts_path} if this is expected.",
        )
        host_key_error = "host key for \{pattern} has changed"
        false
      }
      Unknown =>
        if opts.strict {
          pending.push(
            "toy-ssh client: host \{pattern} is not in \{opts.known_hosts_path}",
          )
          host_key_error = "unknown host key for \{pattern}"
          false
        } else {
          // Trust on first use. Insecure by construction: nothing proves
          // this key belongs to the host.
          pending.push(
            "toy-ssh client: trusting new host key \{@keys.fingerprint(k_s[:])} for \{pattern}",
          )
          learned = Some(public)
          true
        }
    }
  }
  async fn drain() -> Unit {
    for line in pending {
      @net.log(line)
    }
    pending.clear()
  }

  let addr = @socket.Addr::resolve(opts.host, port=opts.port)
  let conn = @socket.Tcp::connect(addr)
  defer conn.close()
  @net.log("toy-ssh client: connected to \{addr}")
  let t = @transport.Transport::new(@net.client_config(accept_host_key~))
  let c = @net.Conn::new(conn, t)
  let mut auth : @auth.AuthClient? = None
  let mut authenticated = false
  let mut session : @connection.ClientSession? = None
  let mut exit_status : UInt? = None
  @async.with_task_group(group => {
    c.run(group, (c, ev) => {
      // Flush anything the synchronous host key callback queued.
      drain()
      match ev {
        Established(session_id~) => {
          @net.log(
            "toy-ssh client: established, session id \{@hex.encode(session_id[:])}",
          )
          auth = Some(
            @auth.AuthClient::new({
              user: opts.user,
              session_id,
              probe_none: true,
              key,
              password: opts.password,
              query_first: true,
            }),
          )
          c.send(
            @transport.encode_service_request(@transport.SERVICE_USERAUTH)[:],
          )
        }
        Packet(payload~) =>
          if session is Some(s) {
            run_session(c, s, payload)
            if s.is_closed() {
              exit_status = s.exit_status()
              c.disconnect(
                @transport.SSH_DISCONNECT_BY_APPLICATION,
                "toy-ssh: session finished",
              )
            }
          } else {
            match auth {
              Some(auth) => {
                handle_userauth(c, opts, auth, payload, () => {
                  authenticated = true
                })
                if authenticated {
                  // Authentication done: open the session and run.
                  let s = @connection.ClientSession::new(
                    window_size=CHANNEL_WINDOW,
                    max_packet_size=CHANNEL_MAX_PACKET,
                  )
                  match opts.command {
                    Some(command) => s.request_exec(command)
                    None => s.request_shell()
                  }
                  session = Some(s)
                  for out in s.take_outgoing() {
                    c.send(out[:])
                  }
                  // Forward our own standard input, the way `ssh` does, so
                  // a remote shell (or `cat`) has something to read.
                  // `no_wait` because the read blocks on a terminal that
                  // never reaches end of file: the session ending must not
                  // wait for it.
                  group.spawn_bg(no_wait=true, () => pump_stdin(c, s))
                } else if auth.is_done() {
                  c.disconnect(
                    @transport.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                    "no more authentication methods",
                  )
                }
              }
              None => ()
            }
          }
        Disconnect(code~, description~, by_peer~) =>
          @net.log(
            "toy-ssh client: disconnect code=\{code} \"\{description}\" by_peer=\{by_peer}",
          )
      }
    })
  })
  drain()
  if learned is Some(public) && authenticated {
    // Only remember a host we actually finished talking to.
    @net.append_line(
      opts.known_hosts_path,
      @keys.format_known_hosts_line(pattern, public[:]),
    )
    @net.log("toy-ssh client: added \{pattern} to \{opts.known_hosts_path}")
  }
  match exit_status {
    // Exit with the remote command's status, the way `ssh` does.
    Some(code) => @sys.exit(code.reinterpret_as_int())
    None => ()
  }
  if host_key_error != "" {
    @net.log("toy-ssh client: host key check failed: \{host_key_error}")
  }
  if authenticated {
    @net.log("toy-ssh client: the session ended without an exit status")
    @sys.exit(255)
  }
  @sys.exit(1)
}

///|
/// Drive the userauth exchange for one payload. `on_success` is called when
/// the server accepts.
async fn handle_userauth(
  c : @net.Conn,
  opts : ClientOptions,
  auth : @auth.AuthClient,
  payload : Bytes,
  on_success : () -> Unit,
) -> Unit {
  if payload.length() > 0 && payload[0] == @transport.SSH_MSG_SERVICE_ACCEPT {
    let service = @transport.decode_service_accept(payload[:]) catch {
      e => {
        c.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, "\{Repr(e)}")
        return
      }
    }
    @net.log("toy-ssh client: service accept \{service}")
  } else {
    for aev in auth.on_payload(payload[:]) {
      match aev {
        Banner(text) =>
          @net.log("toy-ssh client: banner: \{text.trim(char_set="\r\n")}")
        Success => {
          @net.log("toy-ssh client: authenticated as \{opts.user}")
          on_success()
        }
        Failure(methods~, partial~) =>
          @net.log(
            "toy-ssh client: authentication failed, server offers [\{methods.join(", ")}] partial=\{partial}",
          )
        GiveUp(why) => @net.log("toy-ssh client: giving up: \{why}")
        ProtocolViolation(msg) => {
          @net.log("toy-ssh client: protocol violation: \{msg}")
          c.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, msg)
        }
      }
    }
  }
  for out in auth.take_outgoing() {
    c.send(out[:])
  }
}

///|
/// Copy this process's standard input into the session until end of file,
/// then tell the peer we are done sending.
async fn pump_stdin(c : @net.Conn, s : @connection.ClientSession) -> Unit {
  let buf = FixedArray::make(16384, b'\x00')
  while true {
    // Backpressure: without this, `client host 'sleep 60' < big-file`
    // reads the whole file into the send queue, because the queue only
    // drains as fast as the peer grants window credit.
    while s.queued_bytes() > STDIN_QUEUE_LIMIT {
      @async.sleep(10)
    }
    let n = @stdio.stdin.read(buf)
    if n == 0 {
      break
    }
    s.send_stdin(Bytes::makei(n, i => buf[i])[:])
    for out in s.take_outgoing() {
      c.send(out[:])
    }
  }
  s.send_eof()
  for out in s.take_outgoing() {
    c.send(out[:])
  }
}

///|
/// Drive the session channel for one payload: the command's output goes to
/// our own standard output and standard error, byte for byte.
async fn run_session(
  c : @net.Conn,
  s : @connection.ClientSession,
  payload : Bytes,
) -> Unit {
  let events = s.on_payload(payload[:]) catch {
    ConnectionError(msg) => {
      @net.log("toy-ssh client: connection protocol error: \{msg}")
      c.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, msg)
      return
    }
  }
  for ev in events {
    match ev {
      Stdout(data) => @stdio.stdout.write(data)
      Stderr(data) => @stdio.stderr.write(data)
      ExitStatus(code) => @net.log("toy-ssh client: exit status \{code}")
      Eof => ()
      Closed => @net.log("toy-ssh client: channel closed")
      OpenFailed(reason~, description~) =>
        @net.log(
          "toy-ssh client: the server refused the session (\{reason}): \{description}",
        )
    }
  }
  for out in s.take_outgoing() {
    c.send(out[:])
  }
}

///|
fn parse_args(args : Array[String]) -> ClientOptions {
  let mut port = 22
  let mut key_path : String? = None
  let mut known_hosts_path = "./toy_known_hosts"
  let mut password : String? = None
  let mut strict = false
  let mut target : String? = None
  let mut command : String? = None
  let mut i = 1
  while i < args.length() {
    let flag = args[i]
    match flag {
      "--help" => {
        println(
          "usage: client [-p PORT] [-i KEYFILE] [--known-hosts FILE] [--password PW] [--strict-host-key-checking] [USER@]HOST [COMMAND]",
        )
        @sys.exit(0)
      }
      "--strict-host-key-checking" => {
        strict = true
        i = i + 1
        continue
      }
      _ => ()
    }
    if !flag.has_prefix("-") {
      if target is None {
        target = Some(flag)
        i = i + 1
        continue
      }
      // Everything from here on is the command, joined with spaces the way
      // `ssh` does, so `client host echo hello` works and a leading `-`
      // inside the command is not mistaken for a flag.
      let words = []
      while i < args.length() {
        words.push(args[i])
        i = i + 1
      }
      command = Some(words.join(" "))
      continue
    }
    guard i + 1 < args.length() else { usage_error("\{flag} needs a value") }
    let value = args[i + 1]
    match flag {
      "-p" => port = parse_port(value)
      "-i" => key_path = Some(value)
      "--known-hosts" => known_hosts_path = value
      "--password" => password = Some(value)
      _ => usage_error("unknown argument: \{flag}")
    }
    i = i + 2
  }
  guard target is Some(target) else { usage_error("expected [USER@]HOST") }
  let (user, host) = split_target(target)
  { user, host, port, key_path, known_hosts_path, password, strict, command, }
}

///|
/// `user@host` or a bare `host` (then the user must come from elsewhere;
/// for a toy, refuse rather than guess an identity).
fn split_target(target : String) -> (String, String) {
  let chars = target.to_array()
  let mut at = -1
  for n, c in chars {
    if c == '@' && at < 0 {
      at = n
    }
  }
  if at <= 0 || at == chars.length() - 1 {
    usage_error("expected USER@HOST, got \{target}")
  }
  (
    String::from_array(chars[0:at].to_owned()),
    String::from_array(chars[at + 1:].to_owned()),
  )
}

///|
fn parse_port(value : String) -> Int {
  // Parsed by hand: `moonbitlang/core/strconv` is empty in this toolchain
  // (moon 0.1.20260904), so there is no library integer parser to call.
  let chars = value.to_array()
  if chars.length() == 0 || chars.length() > 5 {
    usage_error("-p needs a number between 1 and 65535, got \{value}")
  }
  let mut n = 0
  for c in chars {
    if c < '0' || c > '9' {
      usage_error("-p needs a number, got \{value}")
    }
    n = n * 10 + (c.to_int() - '0'.to_int())
  }
  if n <= 0 || n > 65535 {
    usage_error("-p must be between 1 and 65535, got \{value}")
  }
  n
}
