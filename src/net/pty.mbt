///|
/// Pseudo-terminals for `pty-req` (RFC 4254 section 6.2, docs/06 M5).
///
/// This is the only C FFI in the project. `moonbitlang/async` has no PTY
/// support, but it does not need to: the master side is opened as an
/// ordinary file (`/dev/ptmx`), so the runtime owns the handle and reads
/// it the way it reads anything else. Only `grantpt` / `unlockpt` /
/// `ptsname`, which have no equivalent outside C, and the window-size
/// ioctl are ours.
///
/// The child gets the slave by path, through `@process.redirect_*`, so no
/// raw descriptor is ever handed to the process API.
///
/// Toy code. Never use for real security.

///|
/// Longest slave path we accept. Real ones are `/dev/ttysNNN` or
/// `/dev/pts/N`.
const PTY_NAME_MAX : Int = 128

///|
#borrow(buf)
extern "C" fn pty_slave_name_ffi(
  fd : Int,
  buf : FixedArray[Byte],
  buf_len : Int,
) -> Int = "toy_ssh_pty_slave_name"

///|
#borrow(path)
extern "C" fn open_pty_slave_ffi(path : Bytes) -> Int = "toy_ssh_open_pty_slave"

///|
extern "C" fn set_winsize_ffi(
  fd : Int,
  cols : Int,
  rows : Int,
  xpixels : Int,
  ypixels : Int,
) -> Int = "toy_ssh_set_winsize"

///|
/// `close(2)`, for the slave descriptor. It is a plain fd rather than a
/// handle the async runtime knows about, so nothing else will close it.
extern "C" fn close_ffi(fd : Int) -> Int = "close"

///|
/// An allocated pseudo-terminal: the master we read and write, and the
/// path of the slave the child will open as its standard streams.
pub struct Pty {
  master : @fs.File
  slave_path : String
  /// Our own descriptor for the slave, held only until the child has
  /// opened its end. It exists because a master with no slave attached fails
  /// reads outright (EIO on macOS) instead of waiting, so a pump started
  /// before the child would fall out of its loop immediately.
  ///
  /// It must be dropped once the child is running (`release_slave`): with
  /// it open the master never reaches end of file, and a read already in
  /// flight is not interrupted by closing the handle — the pump would
  /// hang for the life of the process.
  mut slave : Int?
}

///|
/// Allocate a pseudo-terminal. Raises when the system refuses — no free
/// pty, or `/dev/ptmx` out of reach, which is what a sandbox does.
pub async fn open_pty() -> Pty {
  let master = @fs.open("/dev/ptmx", mode=ReadWrite)
  let buf = FixedArray::make(PTY_NAME_MAX, b'\x00')
  let len = pty_slave_name_ffi(master.fd(), buf, PTY_NAME_MAX)
  if len <= 0 {
    master.close()
    fail("pty: could not unlock a pseudo-terminal")
  }
  let name_bytes = Bytes::makei(len, i => buf[i])
  let slave_path = @utf8.decode(name_bytes[:]) catch {
    _ => {
      master.close()
      fail("pty: the slave path is not text")
    }
  }
  // Opened through C for one reason: O_NOCTTY. We never read or write
  // this descriptor — it exists so that the master always has a slave
  // attached — so a raw fd is all it needs to be.
  let slave = open_pty_slave_ffi(@utf8.encode(slave_path + "\u0000"))
  if slave < 0 {
    master.close()
    fail("pty: could not open \{slave_path}")
  }
  { master, slave_path, slave: Some(slave), }
}

///|
/// The master end, for reading the terminal's output and writing its
/// input.
pub fn Pty::master(self : Pty) -> @fs.File {
  self.master
}

///|
/// The slave's path, which the child opens as its standard streams.
pub fn Pty::slave_path(self : Pty) -> String {
  self.slave_path
}

///|
/// Set the terminal's window size, as `pty-req` and `window-change`
/// report it. Failures are ignored: a resize the kernel refuses is not
/// worth dropping a connection over.
pub fn Pty::set_window_size(
  self : Pty,
  cols~ : UInt,
  rows~ : UInt,
  width_px~ : UInt,
  height_px~ : UInt,
) -> Unit {
  ignore(
    set_winsize_ffi(
      self.master.fd(),
      cols.reinterpret_as_int(),
      rows.reinterpret_as_int(),
      width_px.reinterpret_as_int(),
      height_px.reinterpret_as_int(),
    ),
  )
}

///|
/// Drop our handle on the slave, once the child has opened its own.
/// After this the master reaches end of file when the child exits, which
/// is what stops the pump that relays its output.
pub fn Pty::release_slave(self : Pty) -> Unit {
  match self.slave {
    Some(fd) => {
      ignore(close_ffi(fd))
      self.slave = None
    }
    None => ()
  }
}

///|
/// Close the pty. Call `release_slave` first if a child was started: a
/// read already in flight on the master is not interrupted by this.
pub fn Pty::close(self : Pty) -> Unit {
  self.release_slave()
  self.master.close()
}

// ---------------------------------------------------------------------------
// The local terminal (client side)
// ---------------------------------------------------------------------------

///|
/// Room for a `struct termios`, which is 60 bytes on both platforms we
/// build for. The C side checks the length rather than trusting it.
const TERMIOS_MAX : Int = 128

///|
/// Standard input. A client asks for a remote terminal only when its own
/// is one, so this is the descriptor it reports the size of and puts into
/// raw mode.
const STDIN_FD : Int = 0

///|
/// Standard error, where diagnostics go. Raw mode is a property of the
/// terminal, so whether a diagnostic needs a carriage return depends on
/// whether it lands on that same terminal rather than in a file.
const STDERR_FD : Int = 2

///|
/// How many numbers `terminal_size` asks the kernel for.
const WINSIZE_FIELDS : Int = 4

///|
extern "C" fn isatty_ffi(fd : Int) -> Int = "toy_ssh_isatty"

///|
#borrow(out)
extern "C" fn get_winsize_ffi(
  fd : Int,
  out : FixedArray[Int],
  out_len : Int,
) -> Int = "toy_ssh_get_winsize"

///|
#borrow(saved)
extern "C" fn term_raw_ffi(
  fd : Int,
  saved : FixedArray[Byte],
  saved_len : Int,
) -> Int = "toy_ssh_term_raw"

///|
#borrow(saved)
extern "C" fn term_restore_ffi(
  fd : Int,
  saved : FixedArray[Byte],
  saved_len : Int,
) -> Int = "toy_ssh_term_restore"

///|
/// A terminal's size in characters and, when the terminal reports them,
/// pixels. `pty-req` and `window-change` carry exactly these four.
pub struct WindowSize {
  cols : UInt
  rows : UInt
  width_px : UInt
  height_px : UInt
} derive(Eq, Debug)

///|
/// True when this process's standard input is a terminal. A client
/// without one has nothing to put into raw mode and no size to report, so
/// it asks for no remote terminal either.
pub fn stdin_is_terminal() -> Bool {
  // POSIX says non-zero, not 1.
  isatty_ffi(STDIN_FD) != 0
}

///|
/// The terminal type to report, from `TERM`. `vt100` is the fallback the
/// RFC's own example uses; sending an empty string makes remote programs
/// fail in ways that look like our bug.
pub fn terminal_type() -> String {
  match @env.get_env_var("TERM") {
    Some(term) if term != "" => term
    _ => "vt100"
  }
}

///|
/// The size of this process's terminal, or `None` when it has none, the
/// kernel will not say, or the terminal has never been sized (which it
/// reports as zero by zero -- see the C side).
pub fn terminal_size() -> WindowSize? {
  let out = FixedArray::make(WINSIZE_FIELDS, 0)
  if get_winsize_ffi(STDIN_FD, out, WINSIZE_FIELDS) != 0 {
    return None
  }
  Some({
    cols: out[0].reinterpret_as_uint(),
    rows: out[1].reinterpret_as_uint(),
    width_px: out[2].reinterpret_as_uint(),
    height_px: out[3].reinterpret_as_uint(),
  })
}

///|
/// The saved settings of a terminal that is currently in raw mode.
/// `restore` puts them back and is safe to call more than once, because
/// every exit path has to go through it — a client that dies with the
/// terminal still raw leaves the user with no echo.
pub struct RawTerminal {
  saved : FixedArray[Byte]
  mut raw : Bool
}

///|
/// True while `enter_raw_mode` is in effect. Process-wide because it is a
/// property of the terminal, not of any one handle on it: `log` reads it
/// to end its lines the way a raw terminal needs.
let raw_mode : Ref[Bool] = Ref(false)

///|
/// Whether this process's terminal is currently in raw mode.
pub fn terminal_is_raw() -> Bool {
  raw_mode.val
}

///|
/// Whether a diagnostic line needs a carriage return as well as a line
/// feed: only when it lands on the very terminal that is in raw mode.
/// Redirect standard error to a file and the raw flag says nothing about
/// it, so the file would collect a stray CR on every line.
pub fn log_needs_crlf() -> Bool {
  raw_mode.val && isatty_ffi(STDERR_FD) != 0
}

///|
/// Put this process's terminal into raw mode, so that echo, line editing
/// and the signal characters all become the remote end's business and
/// `^C` travels as a byte. `None` when there is no terminal or the
/// settings could not be changed.
pub fn enter_raw_mode() -> RawTerminal? {
  let saved = FixedArray::make(TERMIOS_MAX, b'\x00')
  if term_raw_ffi(STDIN_FD, saved, TERMIOS_MAX) != 0 {
    return None
  }
  raw_mode.val = true
  Some({ saved, raw: true, })
}

///|
/// Put the terminal back the way it was. Does nothing after the first
/// call.
pub fn RawTerminal::restore(self : RawTerminal) -> Unit {
  if self.raw {
    self.raw = false
    raw_mode.val = false
    ignore(term_restore_ffi(STDIN_FD, self.saved, TERMIOS_MAX))
  }
}
