///|
/// Child processes for a `session` channel (docs/04 Part B "Minimal shell
/// semantics"). Part of the IO adapter: this is the only place that spawns
/// an OS process, so `connection/` stays sans-IO and testable in memory.
///
/// Toy code. Never use for real security. The command string an `exec`
/// request carries is handed straight to `/bin/sh -c`, exactly as OpenSSH's
/// sshd does after authentication — there is no sandbox of any kind here.

///|
/// Read buffer size for the child's stdout/stderr pumps. A chunk handed to a
/// callback is at most this large; the connection layer re-frames it against
/// the peer's window and `maximum_packet_size` anyway.
const CHILD_CHUNK : Int = 16384

///|
/// A spawned child process with its standard streams wired to the caller.
///
/// Created by `spawn_session`. Its stdout/stderr pumps run as tasks in the
/// task group passed there, so the `Child` itself owns only the write side
/// of the child's standard input, which satisfies the one-reader /
/// one-writer rule of `moonbitlang/async`: each pipe has exactly one task
/// touching it.
pub struct Child {
  proc : @process.Process
  stdin : @process.WriteToProcess
  stdin_closed : Ref[Bool]
}

///|
/// The login shell to run for a `shell` request: `$SHELL`, else `/bin/sh`.
fn login_shell() -> String {
  match @env.get_env_var("SHELL") {
    Some(sh) if sh.length() > 0 => sh
    _ => "/bin/sh"
  }
}

///|
/// Copy everything from one of the child's output pipes into `on_chunk`,
/// one read at a time, until the pipe reaches end of file.
///
/// The chunk is the exact bytes read, never decoded: a remote command's
/// output is arbitrary binary (`cat /bin/ls` is a legitimate `exec`), and
/// `@utf8.decode`/`@ascii.encode` would corrupt or kill it.
async fn pump(
  r : @process.ReadFromProcess,
  on_chunk : async (Bytes) -> Unit,
) -> Unit {
  defer r.close()
  let buf = FixedArray::make(CHILD_CHUNK, b'\x00')
  while true {
    let n = r.read(buf)
    if n == 0 {
      break
    }
    on_chunk(Bytes::makei(n, i => buf[i]))
  }
}

///|
/// Spawn a child for an SSH `session` channel.
///
/// `command` is `Some(cmd)` for an `exec` request — run it through a shell
/// (`sh -c cmd`) so that `echo hello; exit 3` behaves as a user expects —
/// or `None` for a `shell` request, which runs the login shell
/// (`$SHELL`, else `/bin/sh`) with no PTY.
///
/// `on_stdout` and `on_stderr` are called with each chunk as it arrives;
/// the spawned reader tasks live in `group`. They are called with a
/// non-empty `Bytes` and are never called again after the stream ends.
///
/// Three tasks join `group`: the two reader pumps and the process waiter
/// that `@process.spawn` adds. All three finish on their own once the child
/// exits and closes its pipes, so `group` completes without extra help; the
/// caller does not need `Child::wait` for that. Cancelling `group` runs
/// `@process.spawn`'s default cancel handler, `graceful_cancel(timeout=5000)`
/// — SIGTERM, then SIGKILL five seconds later — which is what a dropped SSH
/// connection should do to the command it started. `no_wait` is deliberately
/// left off for the same reason: a connection's task group must not be
/// considered finished while the command it is proxying still runs.
pub async fn[X] spawn_session(
  group : @async.TaskGroup[X],
  command : String?,
  on_stdout : async (Bytes) -> Unit,
  on_stderr : async (Bytes) -> Unit,
) -> Child {
  let (cmd, args) = match command {
    Some(c) => ("/bin/sh", ["-c", c])
    None => (login_shell(), [])
  }
  // The child's ends of these three pipes are closed by `spawn` once the
  // child has started, which is what lets the pumps below observe EOF.
  let (child_stdin, our_stdin) = @process.write_to_process()
  let (our_stdout, child_stdout) = @process.read_from_process()
  let (our_stderr, child_stderr) = @process.read_from_process()
  let proc = @process.spawn(
    group,
    cmd,
    args,
    stdin=child_stdin,
    stdout=child_stdout,
    stderr=child_stderr,
  )
  group.spawn_bg(() => pump(our_stdout, on_stdout))
  group.spawn_bg(() => pump(our_stderr, on_stderr))
  { proc, stdin: our_stdin, stdin_closed: Ref(false) }
}

///|
/// Write `data` to the child's standard input.
///
/// Errors are swallowed, not raised. A client that keeps sending
/// `SSH_MSG_CHANNEL_DATA` after the command finished is completely normal
/// (`ssh host 'true' < big-file`), and the child's end of the pipe is gone by
/// then, so the write fails with `EPIPE`. Failing the connection over that
/// would be wrong, and so would dying: `moonbitlang/async` ignores `SIGPIPE`
/// for us, so the failure arrives as a catchable error rather than a signal.
/// A write after `close_stdin` is a no-op — the handle is closed, and using
/// it again would be a use-after-close.
///
/// Swallowing every error is safe with respect to cancellation: cancellation
/// is sticky in `moonbitlang/async` (the coroutine keeps its `cancelled`
/// flag, and the next suspension point raises `Cancelled` again), so a
/// cancel that lands inside this write is re-delivered immediately after.
pub async fn Child::write_stdin(self : Child, data : BytesView) -> Unit {
  if self.stdin_closed.val {
    return
  }
  self.stdin.write(data) catch {
    _ => ()
  }
}

///|
/// Close the child's standard input (the peer sent EOF). Idempotent.
///
/// The flag guards against closing the underlying handle twice, which the
/// peer can trigger by sending `SSH_MSG_CHANNEL_EOF` followed by
/// `SSH_MSG_CHANNEL_CLOSE`.
pub fn Child::close_stdin(self : Child) -> Unit {
  if self.stdin_closed.val {
    return
  }
  self.stdin_closed.val = true
  self.stdin.close()
}

///|
/// Wait for the child to exit and return its exit status.
///
/// This is the value for the `exit-status` channel request (docs/04 Part B
/// "Closing & exit status"). It is idempotent: a second call returns the
/// same status. A child killed by a signal reports the negated signal
/// number, which is not a valid `exit-status`; the connection layer decides
/// what to report, since `exit-signal` is out of scope.
pub async fn Child::wait(self : Child) -> Int {
  self.proc.wait()
}

///|
/// The child's process id, for logs.
pub fn Child::pid(self : Child) -> Int {
  self.proc.pid
}
