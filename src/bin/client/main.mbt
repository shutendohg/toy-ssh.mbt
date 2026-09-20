///|
/// Toy SSH client: key exchange with a known_hosts check, `publickey` or
/// `password` authentication, then one `session` channel that runs a
/// command (`exec`) or the remote login shell.
///
/// ```
/// client [-p PORT] [-i KEYFILE] [--known-hosts FILE] [--password PW]
///        [--strict-host-key-checking] [-c CIPHER] [-t] [-T]
///        [USER@]HOST [COMMAND]
/// ```
///
/// With a COMMAND the client runs it and exits with its status, like
/// `ssh host command`. Without one it asks for the remote shell and pipes
/// this process's standard input to it. The command's standard output goes
/// to ours verbatim; diagnostics go to standard error.
///
/// A shell gets a terminal when this process has one, the way `ssh` does:
/// the client asks for `pty-req`, puts its own terminal into raw mode so
/// that echo, line editing and `^C` become the remote end's business, and
/// reports every resize with `window-change`. `-T` asks for no terminal
/// (pipes, no line editing); `-t` asks for one even without a local
/// terminal to mirror.
///
/// `-c` pins one cipher (`chacha20-poly1305@openssh.com` or `aes128-ctr`)
/// instead of offering both, which is how the docs/07 interop runs exercise
/// each suite.
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
  /// The only cipher to offer, or `None` for our default preference.
  cipher : String?
  /// `-t` / `-T`. `None` means "decide from the request and the terminal":
  /// a shell run from a terminal gets one, everything else does not.
  pty : Bool?
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
/// How often the client re-reads its terminal size to notice a resize.
/// `moonbitlang/async` routes only the cancellation signals (SIGINT,
/// SIGTERM, SIGHUP), so SIGWINCH has nowhere to arrive; a C handler would
/// still have to be polled to reach async code, and the runtime reserves
/// the right to change the signal mask. Asking the kernel is one ioctl.
const WINCH_POLL_MS : Int = 200

///|
/// What a forced `-t` reports when there is no local terminal to measure.
/// The RFC's own example is 80x24.
const DEFAULT_COLS : UInt = 80

///|
const DEFAULT_ROWS : UInt = 24

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
  let ciphers = match opts.cipher {
    Some(name) => Some([name])
    None => None
  }
  let t = @transport.Transport::new(
    @net.client_config(accept_host_key~, ciphers~),
  )
  let c = @net.Conn::new(conn, t)
  let mut auth : @auth.AuthClient? = None
  let mut authenticated = false
  let mut session : @connection.ClientSession? = None
  let mut exit_status : UInt? = None
  // Set while our own terminal is in raw mode. Every path out of `main`
  // has to put it back: a client that exits raw leaves a shell with no
  // echo and no line editing.
  let mut raw : @net.RawTerminal? = None
  fn restore_terminal() -> Unit {
    if raw is Some(terminal) {
      terminal.restore()
    }
  }

  // Covers the paths that leave `main` by raising — a refused host key, a
  // dropped connection. `@sys.exit` does not run defers, so the ordinary
  // paths below call `restore_terminal` themselves.
  defer restore_terminal()
  @async.with_task_group(group => {
    c.run(group, (c, ev) => {
      // Flush anything the synchronous host key callback queued.
      drain()
      match ev {
        Established(session_id~) => {
          @net.log(
            "toy-ssh client: established, session id \{@hex.encode(session_id[:])}",
          )
          if c.transport().negotiated() is Some(n) {
            @net.log("toy-ssh client: \{n.summary()}")
          }
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
                  if wanted_pty(opts) is Some(pty) {
                    s.request_pty(pty)
                    // Raw from here on: echo, line editing and the signal
                    // characters are the remote terminal's business now,
                    // and `^C` has to travel as a byte.
                    raw = @net.enter_raw_mode()
                    if raw is None && @net.stdin_is_terminal() {
                      @net.log(
                        "toy-ssh client: could not switch the terminal to raw mode; expect doubled echo",
                      )
                    }
                    group.spawn_bg(no_wait=true, () => watch_window_size(c, s))
                  }
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
  // Before anything that exits, and before the shell prompt this process
  // returns to.
  restore_terminal()
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
        Failure(refused~, methods~, partial~) =>
          // The opening `none` probe is a question, not an attempt: every
          // server refuses it, and calling that "authentication failed"
          // sent the reader hunting for a problem that was not there.
          if refused == @auth.METHOD_NONE {
            @net.log("toy-ssh client: server accepts [\{methods.join(", ")}]")
          } else {
            @net.log(
              "toy-ssh client: \{refused} was refused, still offered [\{methods.join(", ")}] partial=\{partial}",
            )
          }
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
/// The terminal to ask the server for, or `None` for a session on pipes.
///
/// Without `-t` or `-T` this mirrors `ssh`: a shell started from a
/// terminal gets one, a command or a redirected standard input does not.
/// `-t` forces the request even with nothing local to measure, which is
/// how `client -t host 'stty size'` is checked.
fn wanted_pty(opts : ClientOptions) -> @connection.PtyParams? {
  let asked = match opts.pty {
    Some(explicit) => explicit
    None => opts.command is None && @net.stdin_is_terminal()
  }
  guard asked else { return None }
  let size = @net.terminal_size()
  Some({
    term: @net.terminal_type(),
    cols: match size {
      Some(s) => s.cols
      None => DEFAULT_COLS
    },
    rows: match size {
      Some(s) => s.rows
      None => DEFAULT_ROWS
    },
    width_px: match size {
      Some(s) => s.width_px
      None => 0
    },
    height_px: match size {
      Some(s) => s.height_px
      None => 0
    },
    // No modes: the local terminal is raw, so the remote end should use
    // its own defaults rather than be told to copy ours (docs/04 —
    // the server accepts the string and ignores it either way).
    modes: b"\x00",
  })
}

///|
/// Report every resize with `window-change`, so that a full-screen
/// program on the other end redraws at the new size.
///
/// Polled rather than driven by SIGWINCH: see `WINCH_POLL_MS`.
async fn watch_window_size(
  c : @net.Conn,
  s : @connection.ClientSession,
) -> Unit {
  let mut last = @net.terminal_size()
  while !s.is_closed() {
    @async.sleep(WINCH_POLL_MS)
    let now = @net.terminal_size()
    if now == last {
      continue
    }
    // `last` only moves once the peer has actually been told. The channel
    // is not running for the first two and a half round trips (open,
    // pty-req, then the shell), and a resize in that window used to be
    // recorded as the new `last` while `send_window_change` dropped it —
    // after which every later poll compared equal and the remote program
    // stayed at the size `pty-req` carried until the next resize.
    guard now is Some(size) else { continue }
    if !s.is_running() {
      continue
    }
    last = now
    s.send_window_change(
      cols=size.cols,
      rows=size.rows,
      width_px=size.width_px,
      height_px=size.height_px,
    )
    for out in s.take_outgoing() {
      c.send(out[:])
    }
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
      // Not a protocol error: RFC 4254 section 6.2 lets a restricted or
      // pty-starved server say no this way. Say what happened instead of
      // accusing it of a violation on the wire.
      PtyRefused =>
        @net.log(
          "toy-ssh client: the server would not give us a terminal; try -T for a session without one",
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
  let mut cipher : String? = None
  let mut pty : Bool? = None
  let mut i = 1
  while i < args.length() {
    let flag = args[i]
    // Everything after the host is the command, joined with spaces the
    // way `ssh` does, whatever it looks like: `client host echo hello`
    // works, and `client host -T` runs `-T` remotely rather than being
    // read as our own flag.
    if target is Some(_) {
      let words = []
      while i < args.length() {
        words.push(args[i])
        i = i + 1
      }
      command = Some(words.join(" "))
      continue
    }
    match flag {
      "--help" => {
        println(
          "usage: client [-p PORT] [-i KEYFILE] [--known-hosts FILE] [--password PW] [--strict-host-key-checking] [-c CIPHER] [-t] [-T] [USER@]HOST [COMMAND]",
        )
        @sys.exit(0)
      }
      "--strict-host-key-checking" => {
        strict = true
        i = i + 1
        continue
      }
      // Last one wins, so `-t -T` means `-T`, as with `ssh`.
      "-t" => {
        pty = Some(true)
        i = i + 1
        continue
      }
      "-T" => {
        pty = Some(false)
        i = i + 1
        continue
      }
      _ => ()
    }
    if !flag.has_prefix("-") {
      target = Some(flag)
      i = i + 1
      continue
    }
    guard i + 1 < args.length() else { usage_error("\{flag} needs a value") }
    let value = args[i + 1]
    match flag {
      "-p" => port = parse_port(value)
      "-i" => key_path = Some(value)
      "--known-hosts" => known_hosts_path = value
      "--password" => password = Some(value)
      "-c" =>
        if value == @transport.CIPHER_CHACHA20_POLY1305 ||
          value == @transport.CIPHER_AES128_CTR {
          cipher = Some(value)
        } else {
          usage_error(
            "unknown cipher: \{value} (\{@transport.CIPHER_CHACHA20_POLY1305} or \{@transport.CIPHER_AES128_CTR})",
          )
        }
      _ => usage_error("unknown argument: \{flag}")
    }
    i = i + 2
  }
  guard target is Some(target) else { usage_error("expected [USER@]HOST") }
  let (user, host) = split_target(target)
  {
    user,
    host,
    port,
    key_path,
    known_hosts_path,
    password,
    strict,
    command,
    cipher,
    pty,
  }
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
