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
