///|
/// The IO adapter (docs/01 "The IO adapter"). This is the only package
/// that touches sockets, files or randomness. It pumps bytes between a
/// `@socket.Tcp` and a sans-IO `@transport.Transport` and hands events
/// to a callback.
///
/// Toy code. Never use for real security.

///|
/// `n` bytes from `/dev/urandom`. Opened per call; the toy does not keep a
/// long-lived handle.
pub async fn random_bytes(n : Int) -> Bytes {
  let f = @fs.open("/dev/urandom", mode=ReadOnly)
  defer f.close()
  f.read_exactly_at(n, position=0)
}

///|
/// Write one diagnostic line to standard error, immediately.
///
/// `println` goes through C stdio, which is fully buffered when standard
/// output is a file or a pipe: a long-running server would show nothing
/// until it exited. Diagnostics also belong on standard error so that a
/// remote command's output can own standard output verbatim.
///
/// Encoded as UTF-8, not ASCII: log lines carry peer-controlled text (a
/// user name from USERAUTH_REQUEST, a server banner, a DISCONNECT
/// description), and `@ascii.encode` *panics* above 0x7f — which no
/// `catch` can contain, so one packet would kill the process.
pub async fn log(line : String) -> Unit {
  @stdio.stderr.write(@utf8.encode(line + "\n"))
}

///|
/// Whole-file text read. Key files, `authorized_keys` and `known_hosts`
/// are all small enough to slurp; the parsers in `keys/` work on the text.
pub async fn read_text_file(path : String) -> String {
  @fs.read_file(path).text()
}

///|
/// Append `text` to a file, creating it if needed. Used for the client's
/// trust-on-first-use known_hosts update.
pub async fn append_text_file(path : String, text : String) -> Unit {
  @fs.write_file(
    path,
    @utf8.encode(text),
    append=true,
    create_mode=OpenOrCreate,
  )
}

///|
/// Append `line` as its own line, adding a leading newline when the file
/// does not already end with one.
///
/// A hand-edited or third-party-written file may lack a final newline;
/// appending straight onto it would splice two entries into one corrupt
/// line, which the strict parsers then refuse for good.
pub async fn append_line(path : String, line : String) -> Unit {
  let existing = if @fs.exists(path) { read_text_file(path) } else { "" }
  let prefix = if existing.length() > 0 && !existing.has_suffix("\n") {
    "\n"
  } else {
    ""
  }
  append_text_file(path, prefix + line + "\n")
}

///|
/// Whether `path` exists.
pub async fn file_exists(path : String) -> Bool {
  @fs.exists(path)
}

///|
/// Random padding filler for production packets (RFC 4253 section 6:
/// padding SHOULD be random). Uses a per-call chacha8 generator seeded from
/// `seed` so the synchronous `fill` callback needs no IO.
fn random_fill(seed : Bytes) -> (Int) -> Bytes {
  let rng = @random.Rand::chacha8(seed~)
  n => Bytes::makei(n, _ => rng.uint(limit=256).to_byte())
}

///|
/// A client `TransportConfig` with fresh randomness.
pub async fn client_config(
  accept_host_key~ : (Bytes) -> Bool,
  ciphers? : Array[String]? = None,
) -> @transport.TransportConfig {
  // 16 cookie, 32 X25519 scalar, 32 padding seed, 64 ML-KEM key pair seed.
  let r = random_bytes(16 + 32 + 32 + 64)
  {
    role: Client,
    cookie: r[0:16].to_owned(),
    ephemeral_scalar: r[16:48].to_owned(),
    kem_random: r[80:144].to_owned(),
    host_seed: None,
    ciphers,
    fill: random_fill(r[48:80].to_owned()),
    accept_host_key,
  }
}

///|
/// A server `TransportConfig` with fresh randomness and the given 32-byte
/// Ed25519 host key seed.
pub async fn server_config(
  host_seed~ : Bytes,
  ciphers? : Array[String]? = None,
) -> @transport.TransportConfig {
  // 16 cookie, 32 X25519 scalar, 32 padding seed, 32 ML-KEM message.
  let r = random_bytes(16 + 32 + 32 + 32)
  {
    role: Server,
    cookie: r[0:16].to_owned(),
    ephemeral_scalar: r[16:48].to_owned(),
    kem_random: r[80:112].to_owned(),
    host_seed: Some(host_seed),
    ciphers,
    fill: random_fill(r[48:80].to_owned()),
    accept_host_key: _ => true,
  }
}

///|
/// One connection: a transport plus the socket it runs over, driven by two
/// tasks — one reads the socket and dispatches events, one owns every
/// write.
///
/// Two tasks are needed because a `session` channel has two independent
/// sources of outgoing traffic: the peer's packets (answered from the read
/// loop) and a child process's output (produced by its own pump). Only the
/// writer task ever touches the socket's write side, which is what
/// `moonbitlang/async` requires; everyone else queues through the
/// transport and wakes the writer.
pub struct Conn {
  socket : @socket.Tcp
  transport : @transport.Transport
  /// Counts pending flushes. A semaphore rather than a condition variable
  /// because `release` before `acquire` still counts, so a wake-up cannot
  /// be lost and the writer cannot park with bytes queued.
  wake : @semaphore.Semaphore
  mut stopped : Bool
}

///|
pub fn Conn::new(
  socket : @socket.Tcp,
  transport : @transport.Transport,
) -> Conn {
  {
    socket,
    transport,
    wake: @semaphore.Semaphore(1024, initial_value=0),
    stopped: false,
  }
}

///|
/// The transport, for state queries such as `session_id`.
pub fn Conn::transport(self : Conn) -> @transport.Transport {
  self.transport
}

///|
/// Queue an encrypted payload for the peer and wake the writer. Safe from
/// any task.
pub fn Conn::send(self : Conn, payload : BytesView) -> Unit {
  self.transport.send_packet(payload)
  self.notify()
}

///|
/// Wake the writer, unless it has already gone. The semaphore aborts once
/// its value reaches its size, so releasing with no consumer left would
/// eventually kill the process rather than just the connection.
fn Conn::notify(self : Conn) -> Unit {
  if self.stopped {
    return
  }
  self.wake.release()
}

///|
/// Disconnect on our own initiative, making sure the DISCONNECT is
/// actually written before the connection winds down.
pub fn Conn::disconnect(self : Conn, code : UInt, description : String) -> Unit {
  self.transport.disconnect(code, description)
  self.notify()
}

///|
/// Ask the read loop to finish, without sending anything.
pub fn Conn::stop(self : Conn) -> Unit {
  self.stopped = true
  self.wake.release()
}

///|
/// Run the connection: spawn the writer into `group`, then read until the
/// transport closes or the peer hangs up. Returns once the read side is
/// done; the writer flushes what is left and exits.
pub async fn[X] Conn::run(
  self : Conn,
  group : @async.TaskGroup[X],
  on_event : async (Conn, @transport.TransportEvent) -> Unit,
) -> Unit {
  // Kept as a task we wait on: returning before the writer has flushed
  // would let the caller close the socket with the last packet — usually a
  // DISCONNECT — still queued.
  let writer = group.spawn(() => self.write_loop())
  let buf = FixedArray::make(16384, b'\x00')
  // The version line and our KEXINIT are queued by `Transport::new`.
  self.wake.release()
  while !self.stopped && !self.transport.is_closed() {
    let n = self.socket.read(buf)
    if n == 0 {
      break
    }
    let chunk = Bytes::makei(n, i => buf[i])
    for ev in self.transport.on_received(chunk[:]) {
      on_event(self, ev)
      // A handler may have closed the transport; the rest of the batch is
      // moot then (the transport itself already stopped producing events).
      if self.transport.is_closed() && !(ev is Disconnect(..)) {
        break
      }
    }
    self.wake.release()
  }
  // Let the writer flush anything still queued, then wait for it to exit.
  self.stopped = true
  self.wake.release()
  writer.wait()
}

///|
/// The only task that writes the socket.
async fn Conn::write_loop(self : Conn) -> Unit {
  while true {
    self.wake.acquire()
    let out = self.transport.take_outgoing()
    if out.length() > 0 {
      self.socket.write(out) catch {
        // The peer is gone. Say so before leaving, so nothing keeps
        // waking a writer that no longer exists.
        _ => {
          self.stopped = true
          break
        }
      }
    }
    if self.stopped {
      break
    }
  }
}
