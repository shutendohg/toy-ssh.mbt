// Child processes for a session channel (docs/04 Part B). These spawn real
// processes and so need to run outside a write-restricted sandbox.

///|
/// Run `command` to completion, collecting stdout and stderr.
async fn run_collect(command : String?) -> (Int, Bytes, Bytes) {
  let out = @buffer.Buffer(size_hint=256)
  let err = @buffer.Buffer(size_hint=64)
  let status = @async.with_task_group(group => {
    let child = @net.spawn_session(
      group,
      command,
      chunk => out.write_bytes(chunk),
      chunk => err.write_bytes(chunk),
    )
    child.close_stdin()
    child.wait()
  })
  (status, out.to_bytes(), err.to_bytes())
}

///|
async test "exec: stdout and a zero status" {
  let (status, out, err) = run_collect(Some("echo hello"))
  inspect(status, content="0")
  assert_eq(out, b"hello\n")
  inspect(err.length(), content="0")
}

///|
async test "exec: the command's exit status is reported" {
  // The shape of docs/06 M4 acceptance 2.
  let (status, out, _) = run_collect(Some("echo hello; exit 3"))
  inspect(status, content="3")
  assert_eq(out, b"hello\n")
}

///|
async test "exec: stdout and stderr stay separate" {
  let (status, out, err) = run_collect(Some("echo out; echo err >&2"))
  inspect(status, content="0")
  assert_eq(out, b"out\n")
  assert_eq(err, b"err\n")
}

///|
async test "exec: output is binary-safe" {
  // A remote command may emit anything; nothing may decode it as text.
  let (status, out, _) = run_collect(Some("printf '\\377\\376\\000A'"))
  inspect(status, content="0")
  inspect(@hex.encode(out[:]), content="fffe0041")
}

///|
async test "exec: a large output arrives complete" {
  // Catches a pump that assumes the whole stream fits one read.
  let (status, out, _) = run_collect(Some("seq 1 20000"))
  inspect(status, content="0")
  let mut lines = 0
  for b in out {
    if b == b'\n' {
      lines = lines + 1
    }
  }
  inspect(lines, content="20000")
  inspect(out.length(), content="108894")
}

///|
async test "exec: standard input is delivered in order" {
  let out = @buffer.Buffer(size_hint=64)
  let status = @async.with_task_group(group => {
    let child = @net.spawn_session(
      group,
      Some("cat"),
      chunk => out.write_bytes(chunk),
      _ => (),
    )
    child.write_stdin(b"first\n")
    child.write_stdin(b"second\n")
    child.close_stdin()
    child.wait()
  })
  inspect(status, content="0")
  assert_eq(out.to_bytes(), b"first\nsecond\n")
}

///|
async test "shell: the login shell runs commands from standard input" {
  let out = @buffer.Buffer(size_hint=64)
  let status = @async.with_task_group(group => {
    let child = @net.spawn_session(
      group,
      None,
      chunk => out.write_bytes(chunk),
      _ => (),
    )
    child.write_stdin(b"echo shell-ok\n")
    child.close_stdin()
    child.wait()
  })
  inspect(status, content="0")
  assert_eq(out.to_bytes(), b"shell-ok\n")
}

///|
async test "writing after the child exited is ignored, and close_stdin is idempotent" {
  // A client that keeps sending standard input after the command finished
  // is normal (`ssh host true < big-file`); the write must not fail the
  // connection, and it must not kill this process with SIGPIPE.
  let status = @async.with_task_group(group => {
    let child = @net.spawn_session(group, Some("true"), _ => (), _ => ())
    let status = child.wait()
    child.write_stdin(b"ignored")
    child.close_stdin()
    child.close_stdin()
    child.write_stdin(b"also ignored")
    status
  })
  inspect(status, content="0")
}

///|
async test "pid is reported for logs" {
  @async.with_task_group(group => {
    let child = @net.spawn_session(group, Some("true"), _ => (), _ => ())
    assert_true(child.pid() > 0)
    ignore(child.wait())
  })
}

///|
async test "wait returns only after every byte of output has been delivered" {
  // The child is reaped as soon as it exits, while its pipe may still hold
  // unread output. If `wait` returned then, the caller would report the
  // exit status and close the channel before the tail arrived.
  let out = @buffer.Buffer(size_hint=400000)
  @async.with_task_group(group => {
    let child = @net.spawn_session(
      group,
      Some("seq 1 50000; exit 7"),
      chunk => out.write_bytes(chunk),
      _ => (),
    )
    child.close_stdin()
    let status = child.wait()
    // Checked here, not after the group finishes: this is the contract the
    // server relies on before it sends exit-status, EOF and CLOSE.
    assert_eq(status, 7)
    let mut lines = 0
    for b in out.to_bytes() {
      if b == b'\n' {
        lines = lines + 1
      }
    }
    assert_eq(lines, 50000)
  })
}

///|
/// The local-terminal FFI links and marshals correctly. What it reports
/// depends on how the tests were started, so the test asserts the
/// invariants rather than a fixed size: a size is only ever reported for
/// a terminal, and a reported size is never zero (a terminal nobody has
/// sized answers `TIOCGWINSZ` with zeroes, and a `pty-req` carrying 0x0
/// makes a remote full-screen program draw into nothing).
test "local terminal: a reported size means a terminal, and is never zero" {
  match @net.terminal_size() {
    Some(size) => {
      assert_true(@net.stdin_is_terminal())
      assert_true(size.cols > 0)
      assert_true(size.rows > 0)
    }
    None => ()
  }
}

///|
test "local terminal: TERM is never reported as empty" {
  assert_true(@net.terminal_type() != "")
}
