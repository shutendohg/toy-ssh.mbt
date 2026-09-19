///|
/// Outbound TCP connections for `direct-tcpip` channels (RFC 4254 section
/// 7.2, docs/06 M5). Part of the IO adapter: `connection/` decides what a
/// forwarded channel means and stays sans-IO, while this is the only place
/// that dials out on a peer's behalf.
///
/// Toy code. Never use for real security. A server with forwarding enabled
/// will connect anywhere an authenticated peer names, including addresses
/// only reachable from where the server runs — which is exactly what
/// OpenSSH's `AllowTcpForwarding no` exists to prevent. It is off unless
/// the operator turns it on.

///|
/// Read buffer size for the forwarded socket. The connection layer
/// re-frames each chunk against the peer's window and maximum packet size.
const FORWARD_CHUNK : Int = 16384

///|
/// How many unsent bytes we let pile up for one forwarded channel before
/// the pump stops reading. One window's worth, the same rule the client
/// applies to its own standard input.
const FORWARD_QUEUE_LIMIT : Int = 2097152

///|
/// One forwarded connection: the socket, plus the task reading from it.
///
/// Only the pump task reads the socket and only the connection's event
/// loop writes it, which keeps the one-reader / one-writer rule of
/// `moonbitlang/async`.
pub struct Forward {
  socket : @socket.Tcp
  /// Shared with the pump task, which has to see our close to tell it
  /// apart from the target hanging up.
  closed : Ref[Bool]
  pump : @async.Task[Unit]
}

///|
/// Connect to `host`:`port` and start relaying. `on_chunk` gets each
/// non-empty chunk as it arrives; `on_eof` is called once, when the target
/// closes its side or the socket fails.
///
/// Raises when the connection cannot be made (refused, unknown host,
/// unreachable): the caller answers that with a CHANNEL_OPEN_FAILURE
/// rather than opening a channel that goes nowhere.
///
/// The pump joins `group` with `no_wait=true`: a forwarded connection can
/// stay open for as long as the peer likes, and the SSH connection's task
/// group must not wait on it after the channel is gone.
pub async fn[X] connect_forward(
  group : @async.TaskGroup[X],
  host~ : String,
  port~ : Int,
  /// Unsent bytes already queued for this channel; the pump pauses while
  /// they exceed `FORWARD_QUEUE_LIMIT`.
  queued_bytes : () -> Int,
  on_chunk : async (Bytes) -> Unit,
  on_eof : async () -> Unit,
) -> Forward {
  let socket = @socket.Tcp::connect_to_host(host, port~)
  let closed = Ref(false)
  let pump = group.spawn(
    () => {
      let buf = FixedArray::make(FORWARD_CHUNK, b'\x00')
      // A read on a socket we closed ourselves fails; that is the normal
      // way this task ends, so it is an exit rather than an error.
      while !closed.val {
        // Stop reading while the channel's send queue is already a
        // window deep: it drains only as fast as the peer grants credit,
        // and a fast target would otherwise be buffered in full.
        while !closed.val && queued_bytes() > FORWARD_QUEUE_LIMIT {
          @async.sleep(10)
        }
        if closed.val {
          break
        }
        let n = socket.read(buf) catch { _ => break }
        if n == 0 {
          break
        }
        on_chunk(Bytes::makei(n, i => buf[i]))
      }
      if !closed.val {
        on_eof()
      }
    },
    no_wait=true,
  )
  { socket, closed, pump, }
}

///|
/// Send `data` to the target.
///
/// Errors are swallowed the way `Child::write_stdin` swallows them: a peer
/// that keeps sending after the target hung up is ordinary, and the
/// channel teardown that follows is driven by the read side, not by this
/// failure.
///
/// Toy limitation: this is awaited on the connection's read loop, so a
/// target that stops reading long enough to fill its socket buffer stalls
/// every channel on that SSH connection until the write completes. The
/// fix is a per-forward writer task with its own queue, the way `Conn`
/// owns the socket's write side; `Child::write_stdin` has the same shape
/// and the same caveat.
pub async fn Forward::write(self : Forward, data : BytesView) -> Unit {
  if self.closed.val || data.length() == 0 {
    return
  }
  self.socket.write(data.to_owned()) catch {
    _ => ()
  }
}

///|
/// Close the forwarded connection and let its pump finish.
///
/// There is no half-close here: `moonbitlang/async` exposes no shutdown,
/// so a peer's CHANNEL_EOF cannot be turned into a FIN on the target
/// socket. A protocol that waits for one (HTTP/1.0 without a length, say)
/// will not see it — a toy limitation, noted in docs/04.
pub fn Forward::close(self : Forward) -> Unit {
  if self.closed.val {
    return
  }
  self.closed.val = true
  self.socket.close()
}

///|
/// Wait for the pump to finish. Used by tests; the server does not need
/// it, because the pump exits on its own when either side closes.
pub async fn Forward::wait(self : Forward) -> Unit {
  self.pump.wait() catch {
    _ => ()
  }
}
