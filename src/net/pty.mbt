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
