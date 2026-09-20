// PTY allocation for `pty-req` (docs/04 Part B, docs/06 M5).
//
// Plain POSIX (`posix_openpt` / `grantpt` / `unlockpt` / `ptsname`) rather
// than `openpty(3)`, which lives in <util.h> on macOS and <pty.h> on Linux
// and needs -lutil on older glibc. These four are in libc everywhere we
// build.
//
// Toy code. Never use for real security.

// glibc hides `posix_openpt`, `grantpt`, `unlockpt` and `ptsname` behind a
// feature-test macro. Without it gcc assumes they return `int`, and the
// truncated `ptsname` pointer segfaults the moment it is dereferenced --
// which is exactly how this was found, on Linux CI, after a clean macOS
// build (Apple's headers declare all four by default).
#if defined(__linux__)
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

// Unlocks the pseudo-terminal behind an already-open /dev/ptmx `fd` and
// writes the slave's path into `buf`. Returns its length, or -1.
//
// The master is opened by the async library (so the runtime owns the
// handle and can read it without blocking); only these three calls, which
// have no portable equivalent outside C, happen here.
int32_t toy_ssh_pty_slave_name(int32_t fd, uint8_t *buf, int32_t buf_len) {
  if (grantpt((int)fd) < 0 || unlockpt((int)fd) < 0) {
    return -1;
  }
  char *name = ptsname((int)fd);
  if (name == NULL) {
    return -1;
  }
  size_t len = strlen(name);
  if (len >= (size_t)buf_len) {
    return -1;
  }
  memcpy(buf, name, len);
  return (int32_t)len;
}

// Sets the window size of the terminal behind `fd`.
int32_t toy_ssh_set_winsize(int32_t fd, int32_t cols, int32_t rows,
                            int32_t xpixels, int32_t ypixels) {
  struct winsize ws;
  ws.ws_col = (unsigned short)cols;
  ws.ws_row = (unsigned short)rows;
  ws.ws_xpixel = (unsigned short)xpixels;
  ws.ws_ypixel = (unsigned short)ypixels;
  return (int32_t)ioctl((int)fd, TIOCSWINSZ, &ws);
}

// Opens the pty slave at `path` with O_NOCTTY, and returns the descriptor
// or -1.
//
// O_NOCTTY is the point of doing this in C: the public file API has no
// flag for it, and opening a terminal without it makes that terminal the
// controlling terminal of a process that is a session leader and has none
// yet — which is exactly how a daemonized server starts. A peer could
// then send signals to the server itself by typing them.
int32_t toy_ssh_open_pty_slave(const char *path) {
  return (int32_t)open(path, O_RDWR | O_NOCTTY);
}

// ---------------------------------------------------------------------------
// The local terminal, for a client that asks for a remote one
// ---------------------------------------------------------------------------

// Is `fd` a terminal? A client only asks for a remote pty when its own
// standard input is one; a pipe has no size to report and no modes to
// save.
int32_t toy_ssh_isatty(int32_t fd) { return (int32_t)isatty((int)fd); }

// Reads the window size of the terminal behind `fd` into
// `out = {cols, rows, xpixels, ypixels}`. Returns 0, or -1.
//
// `out_len` is checked rather than assumed, like the `saved_len` of the
// two calls below: a shorter array would otherwise be written past its
// end with no diagnostic.
//
// A size of zero is reported as failure, not as a size. `TIOCGWINSZ`
// succeeds with `ws_col == ws_row == 0` on a terminal nobody has sized --
// a bare `posix_openpt` pty, some CI harnesses, some serial lines -- and
// a `pty-req` carrying 0x0 makes a remote full-screen program draw into
// nothing.
int32_t toy_ssh_get_winsize(int32_t fd, int32_t *out, int32_t out_len) {
  struct winsize ws;
  if (out_len < 4) {
    return -1;
  }
  if (ioctl((int)fd, TIOCGWINSZ, &ws) < 0) {
    return -1;
  }
  if (ws.ws_col == 0 || ws.ws_row == 0) {
    return -1;
  }
  out[0] = (int32_t)ws.ws_col;
  out[1] = (int32_t)ws.ws_row;
  out[2] = (int32_t)ws.ws_xpixel;
  out[3] = (int32_t)ws.ws_ypixel;
  return 0;
}

// Saves the current terminal settings of `fd` into `saved` and puts the
// terminal into raw mode. Returns 0, or -1 (including when `saved` is too
// small to hold a `struct termios`, which is checked rather than assumed:
// its size differs between macOS and Linux).
//
// Raw mode is what makes the remote end responsible for echo, line
// editing and the signal characters: `^C` has to travel to the remote
// shell as a byte instead of killing the client.
int32_t toy_ssh_term_raw(int32_t fd, uint8_t *saved, int32_t saved_len) {
  struct termios tio;
  if ((size_t)saved_len < sizeof(struct termios)) {
    return -1;
  }
  if (tcgetattr((int)fd, &tio) < 0) {
    return -1;
  }
  memcpy(saved, &tio, sizeof(struct termios));
  cfmakeraw(&tio);
  if (tcsetattr((int)fd, TCSADRAIN, &tio) < 0) {
    return -1;
  }
  return 0;
}

// Puts back the settings `toy_ssh_term_raw` saved. Returns 0, or -1.
int32_t toy_ssh_term_restore(int32_t fd, const uint8_t *saved,
                             int32_t saved_len) {
  struct termios tio;
  if ((size_t)saved_len < sizeof(struct termios)) {
    return -1;
  }
  memcpy(&tio, saved, sizeof(struct termios));
  return (int32_t)tcsetattr((int)fd, TCSADRAIN, &tio);
}
