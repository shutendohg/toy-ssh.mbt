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
pub async fn log(line : String) -> Unit {
  @stdio.stderr.write(@ascii.encode(line + "\n"))
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
    @ascii.encode(text),
    append=true,
    create_mode=OpenOrCreate,
  )
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
) -> @transport.TransportConfig {
  let r = random_bytes(16 + 32 + 32)
  {
    role: Client,
    cookie: r[0:16].to_owned(),
    ephemeral_scalar: r[16:48].to_owned(),
    host_seed: None,
    fill: random_fill(r[48:80].to_owned()),
    accept_host_key,
  }
}

///|
/// A server `TransportConfig` with fresh randomness and the given 32-byte
/// Ed25519 host key seed.
pub async fn server_config(host_seed~ : Bytes) -> @transport.TransportConfig {
  let r = random_bytes(16 + 32 + 32)
  {
    role: Server,
    cookie: r[0:16].to_owned(),
    ephemeral_scalar: r[16:48].to_owned(),
    host_seed: Some(host_seed),
    fill: random_fill(r[48:80].to_owned()),
    accept_host_key: _ => true,
  }
}

///|
/// Drive `t` over `conn` until the transport closes or the peer hangs up:
/// write whatever is queued, read, feed, dispatch events, repeat. A single
/// task owns both directions of the socket, which satisfies the
/// one-reader / one-writer rule of `moonbitlang/async`.
pub async fn run(
  conn : @socket.Tcp,
  t : @transport.Transport,
  on_event : async (@transport.Transport, @transport.TransportEvent) -> Unit,
) -> Unit {
  let buf = FixedArray::make(16384, b'\x00')
  flush(conn, t)
  while !t.is_closed() {
    let n = conn.read(buf)
    if n == 0 {
      break
    }
    let chunk = Bytes::makei(n, i => buf[i])
    for ev in t.on_received(chunk[:]) {
      on_event(t, ev)
      // A handler may have closed the transport; the rest of the batch is
      // moot then (the transport itself already stopped producing events).
      if t.is_closed() && !(ev is Disconnect(..)) {
        break
      }
    }
    flush(conn, t)
  }
}

///|
async fn flush(conn : @socket.Tcp, t : @transport.Transport) -> Unit {
  let out = t.take_outgoing()
  if out.length() > 0 {
    conn.write(out)
  }
}
