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
/// How many unsent bytes may pile up for a channel before a pump stops
/// reading. One window's worth, as elsewhere.
const CHILD_QUEUE_LIMIT : Int = 2097152

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
  /// Where the peer's input goes: a pipe for a plain session, the
  /// terminal's master side when the peer asked for a pty.
  stdin : ChildStdin
  stdin_closed : Ref[Bool]
  /// Set when the connection gives up on this child, so a pump waiting
  /// for window credit that will never come can stop.
  stopped : Ref[Bool]
  /// The two output pumps. `wait` joins them first, so it means "the
  /// command finished *and* all of its output has been handed over".
  pumps : Array[@async.Task[Unit]]
}

///|
/// The two shapes a child's standard input can have.
enum ChildStdin {
  Pipe(@process.WriteToProcess)
  /// A pty: writing to the master is what the terminal sees as typing,
  /// and there is no separate handle to close — the pty is closed as a
  /// whole when the session ends.
  Terminal(Pty)
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
/// Three tasks join `group`: the two reader pumps (joined by `wait`) and the process waiter
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
  let pumps = [
    group.spawn(() => pump(our_stdout, on_stdout)),
    group.spawn(() => pump(our_stderr, on_stderr)),
  ]
  {
    proc,
    stdin: Pipe(our_stdin),
    stdin_closed: Ref(false),
    stopped: Ref(false),
    pumps,
  }
}

///|
/// Spawn a child for a `session` channel that asked for a terminal
/// (`pty-req`, docs/06 M5).
///
/// The child opens the terminal itself, in a `sh` wrapper that redirects
/// its own three streams and then `exec`s the real command. The obvious
/// alternative — `@process.redirect_from_file` / `redirect_to_file` on the
/// slave path — opens the terminal in **this** process and without
/// `O_NOCTTY` (the library adds only `O_CLOEXEC`), which would make the
/// peer's pty the controlling terminal of a server that is a session
/// leader with none: a daemonized one. The peer could then signal the
/// server by typing. In the child the open is harmless, because the child
/// is not a session leader.
///
/// Everything that reaches the wrapper does so through the environment,
/// never through the script text, so a command or a path cannot break out
/// of it.
///
/// `on_output` gets everything the terminal produces — a pty merges
/// stdout and stderr by construction, which is why there is one callback
/// here and two in `spawn_session`.
///
/// `queued_bytes` is the channel's unsent backlog: the pump pauses while
/// it is a window deep, the same rule the forwarding pump follows.
///
/// Toy limitation: the child is not made a session leader with this pty
/// as its controlling terminal (that needs a hook between fork and exec,
/// which the process API does not expose), so a shell will say it has no
/// job control. Interactive editing, prompts and `tty` all work.
pub async fn[X] spawn_session_pty(
  group : @async.TaskGroup[X],
  command : String?,
  pty : Pty,
  term~ : String,
  queued_bytes : () -> Int,
  on_output : async (Bytes) -> Unit,
) -> Child {
  let env = {
    "TERM": term,
    "TOY_SSH_TTY": pty.slave_path(),
    "TOY_SSH_SHELL": login_shell(),
    "TOY_SSH_CMD": match command {
      Some(c) => c
      None => ""
    },
  }
  let proc = @process.spawn(
    group,
    "/bin/sh",
    ["-c", PTY_WRAPPER],
    extra_env=env,
  )
  // Our own slave handle stays open until the child has exited (see
  // `Child::wait`): the child has not opened the terminal yet when
  // `spawn` returns, and a master with no slave attached fails reads
  // outright rather than waiting.
  let stopped = Ref(false)
  let pumps = [
    group.spawn(() => pump_terminal(pty, stopped, queued_bytes, on_output)),
  ]
  { proc, stdin: Terminal(pty), stdin_closed: Ref(false), stopped, pumps, }
}

///|
/// The script the child runs: attach to the terminal, then become the
/// command. Everything variable comes from the environment.
const PTY_WRAPPER : String = "exec 0<\"$TOY_SSH_TTY\" 1>\"$TOY_SSH_TTY\" 2>&1; " +
  "if [ -n \"$TOY_SSH_CMD\" ]; then exec /bin/sh -c \"$TOY_SSH_CMD\"; " +
  "else exec \"$TOY_SSH_SHELL\"; fi"

///|
/// Copy everything the terminal produces into `on_output`, until the
/// child closes its end or the connection gives up on it.
async fn pump_terminal(
  pty : Pty,
  stopped : Ref[Bool],
  queued_bytes : () -> Int,
  on_output : async (Bytes) -> Unit,
) -> Unit {
  let buf = FixedArray::make(CHILD_CHUNK, b'\x00')
  while !stopped.val {
    // The escape hatch matters: when a peer vanishes mid-transfer its
    // queue never drains, and without `stopped` this loop would spin for
    // the life of the process, holding the connection's task group — and
    // its socket — open. What sets it is `Child::cancel`, which the
    // connection's teardown always reaches once the read side is done;
    // that is also what frees a pump parked here while `Child::wait`
    // waits to join it.
    while !stopped.val && queued_bytes() > CHILD_QUEUE_LIMIT {
      @async.sleep(10)
    }
    if stopped.val {
      break
    }
    // Once the child exits, the master has no slave left: that surfaces
    // as end of file on Linux and as an error on macOS, and both mean the
    // same thing here.
    let n = pty.master().read(buf) catch { _ => break }
    if n == 0 {
      break
    }
    on_output(Bytes::makei(n, i => buf[i]))
  }
  pty.close()
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
  match self.stdin {
    Pipe(w) => w.write(data) catch { _ => () }
    Terminal(pty) => pty.master().write(data.to_owned()) catch { _ => () }
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
  match self.stdin {
    Pipe(w) => w.close()
    // Closing the master would kill the terminal the command is still
    // using. A pty has no half-close, so the command learns about the
    // peer's EOF only when the session ends — the same limitation
    // `direct-tcpip` has (docs/04).
    Terminal(_) => ()
  }
}

///|
/// Wait for the child to finish: the output pumps reach end of file and
/// the process is reaped. Returns its exit status.
///
/// The pumps are joined **first**, and that ordering is the point. A child
/// is reaped the moment it exits, while its pipes may still hold unread
/// output; reporting the exit status then would put `exit-status`, EOF and
/// CLOSE ahead of the tail of the command's output, and the peer would
/// either lose it or reject it as data for a closed channel.
///
/// This is the value for the `exit-status` channel request (docs/04 Part B
/// "Closing & exit status"). A child killed by a signal reports the negated
/// signal number, which is not a valid `exit-status`; the connection layer
/// decides what to report, since `exit-signal` is out of scope.
pub async fn Child::wait(self : Child) -> Int {
  match self.stdin {
    // A terminal is the other way round from a pipe, and this is the one
    // place the slave is released. The pump cannot see end of file while
    // we still hold a slave descriptor, and closing the master does not
    // interrupt a read already in flight — so the process is reaped
    // first, dropping our slave then is what wakes the pump, and joining
    // it afterwards still means "all output handed over".
    Terminal(pty) => {
      let status = self.proc.wait()
      pty.release_slave()
      for pump in self.pumps {
        pump.wait()
      }
      status
    }
    Pipe(_) => {
      for pump in self.pumps {
        pump.wait()
      }
      self.proc.wait()
    }
  }
}

///|
/// Kill the child: SIGTERM, then SIGKILL after the grace period that
/// `@process.spawn`'s default cancel handler applies. Used when the peer
/// disconnects, so a `sleep 3600` does not outlive its connection.
pub fn Child::cancel(self : Child) -> Unit {
  self.stopped.val = true
  self.proc.cancel()
}

///|
/// The child's process id, for logs.
pub fn Child::pid(self : Child) -> Int {
  self.proc.pid
}
