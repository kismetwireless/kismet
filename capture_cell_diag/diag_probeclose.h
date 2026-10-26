/* diag_probeclose.h - close a scan PROBE fd without waiting on output the
 * device never took.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Both capture sources identify a modem by writing "AT\r\n" to candidate
 * ttys. On a USB serial function that never reads its OUT endpoint -- an
 * NMEA-only interface is the measured case -- those bytes stay queued in an
 * in-flight URB, and the LAST close() of the tty then blocks in
 * tty_wait_until_sent() for the port's closing_wait: 30 s by default. Measured
 * on a Foxconn T99W175 NMEA tty (interface ff/00/00, streaming $GPGGA):
 *
 *     after the AT write     TIOCOUTQ = 4, and it stays 4
 *     plain close()          30,910 ms
 *     tcflush(TCOFLUSH)      30,623 ms  -- the bytes are in a URB, not in the
 *                                          tty buffer the flush discards
 *     closing_wait = NONE    2 ms
 *
 * 30 s is exactly Kismet's per-command timeout, so a cellat source whose
 * open-time IMEI scan reaches that port first fails to launch ("Command did
 * not complete"), and a celldiag source starts 30 s late. Descriptors
 * cannot pre-screen the port: on these compositions the NMEA and AT functions
 * are both class ff/00/00. The first reliable signal comes AFTER the write:
 * output still unsent once the AT deadline has passed.
 *
 * So diag_probe_close() does an ordinary close() unless TIOCOUTQ reports
 * unsent output, and only then avoids the wait:
 *
 *   1. With CAP_SYS_ADMIN (TIOCSSERIAL may change closing_wait): set NONE for
 *      this close -- the kernel kills the stuck URB at once -- then restore the
 *      port's original value on a fresh open. closing_wait is a property of the
 *      PORT, not of our fd; leaving it at NONE would change close semantics for
 *      the port's real owner (gpsd on an NMEA tty).
 *   2. Without it: hand the close() to a detached thread, so the scan moves on
 *      while the kernel waits. The thread's fd keeps the probe's flock until the
 *      close completes, which makes every concurrent scanner skip that port
 *      instead of paying for it again. The fd is marked FD_CLOEXEC first: an fd
 *      still closing on another thread when the process forks and execs a
 *      child would otherwise survive the exec and hold the port open for the
 *      child's whole life.
 *
 *      Under Kismet, path 2 is THE path, not a fallback. Both capture
 *      helpers call cf_drop_most_caps() at startup and keep only CAP_NET_ADMIN
 *      and CAP_NET_RAW, even when the server runs as root -- so TIOCSSERIAL is
 *      refused and every in-Kismet probe of a stuck port closes "detached"
 *      (once; the other sources find the port still claimed and skip it).
 *      Path 1 is what a standalone, still-privileged caller gets.
 *
 * A healthy AT port has TIOCOUTQ == 0 by the time it has answered, and a non-tty
 * transport (MHI /dev/mhi_DUN, /dev/wwan*) fails TIOCOUTQ; both take the plain
 * close, so the change is invisible to every port that behaves.
 *
 * Pure libc + pthreads, no Kismet link, so it unit-tests standalone. The
 * syscalls sit behind an ops table because no fd a test can build reproduces
 * the stuck state: a pty hands written bytes straight to the master's input,
 * so its TIOCOUTQ reads 0 however much is unread (and TIOCGSERIAL is ENOTTY).
 */
#ifndef DIAG_PROBECLOSE_H
#define DIAG_PROBECLOSE_H

#include <stddef.h>
#include <sys/types.h>
#include <termios.h>

#ifdef __cplusplus
extern "C" {
#endif

/* How diag_probe_close() released the fd. */
typedef enum {
    DIAG_PROBECLOSE_PLAIN = 0,          /* nothing unsent, or not a tty: close() */
    DIAG_PROBECLOSE_NOWAIT,             /* unsent: closed with closing_wait NONE, restored */
    DIAG_PROBECLOSE_NOWAIT_UNRESTORED,  /* as NOWAIT, but the restore failed */
    DIAG_PROBECLOSE_DETACHED,           /* unsent, closing_wait not settable: closing on a thread */
    DIAG_PROBECLOSE_BLOCKED,            /* unsent, and no thread could be started: close() blocked */
} diag_probeclose_how_t;

/* The syscalls the decision reads and acts through. Each returns 0 on success
 * and -1 on failure, like the calls it wraps. */
typedef struct {
    int (*outq)(int fd, int *pending);                     /* TIOCOUTQ */
    int (*get_closing_wait)(int fd, unsigned short *cw);   /* TIOCGSERIAL */
    int (*set_closing_wait)(int fd, unsigned short cw);    /* TIOCSSERIAL */
    int (*reopen)(const char *path);                       /* returns an fd, or -1 */
    int (*close_now)(int fd);                              /* close() */
    int (*close_detached)(int fd);                         /* 0 once a thread owns fd */
} diag_probeclose_ops_t;

/* The real syscalls. */
extern const diag_probeclose_ops_t diag_probeclose_sys;

/* Close a probe fd opened on `path`, never blocking on output the device has
 * not taken. `path` is needed only for the restore open of path 1 above and may
 * be NULL, in which case a changed closing_wait is reported UNRESTORED. The fd
 * is always released (or owned by a closing thread) when this returns. */
diag_probeclose_how_t diag_probe_close(int fd, const char *path);
diag_probeclose_how_t diag_probe_close_with(const diag_probeclose_ops_t *ops,
                                            int fd, const char *path);

/* ---------------------------------------------------------------------------
 * The OPEN half: a probe open() that cannot block the scan either.
 *
 * DETACHED above moves the 30 s off the prober -- but the tty is still in its
 * final close for those 30 s, and Linux's tty_open() does not fail an open of a
 * tty in that state -- it retries it (-EAGAIN from the reopen path) until the
 * close completes. O_NONBLOCK does not stop it. So the NEXT
 * open() of that tty blocks instead: a sibling source's scan, or the same
 * helper's own rescan. Measured on the T99W175 NMEA tty:
 *
 *     second open() while a first fd with 4 unsent bytes is closing   30,107 ms
 *     the same open with nothing unsent (control, before and after)       1 ms
 *
 * and in Kismet it shows up as `cellat AT rescan slow ports: ttyUSB18:29828ms`,
 * which costs a cellat source Kismet's whole 30 s command deadline.
 *
 * diag_probe_open() runs the open() on a worker thread and waits at most
 * deadline_ms for it. A healthy port's open returns in well under that -- every
 * modem port on a test host opened in <= 31.6 ms, the slowest being the first
 * open of an MHI channel -- so the deadline only ever fires on a stuck tty.
 *
 * When it fires, the call returns -1 with errno ETIMEDOUT and the worker keeps
 * waiting on its own. If the open eventually succeeds, the WORKER closes that fd:
 * nothing was ever written to it, so that close has nothing to wait on. The fd is
 * opened O_CLOEXEC (added to `flags` here, always), so a late fd can never be
 * inherited by an exec'd child -- the same hazard the detached close guards
 * against.
 *
 * A timed-out open is NOT a busy port (errno is ETIMEDOUT, not EWOULDBLOCK), so
 * it never triggers the busy-port rescan on its own. A stuck tty is by
 * construction not an AT port -- an AT port reads what it is sent -- so skipping
 * it never loses the target.
 *
 * deadline_ms <= 0, or no thread available: a plain inline open(), as before.
 * --------------------------------------------------------------------------- */

/* The scan deadline for one probe open(). ~30x the slowest healthy open measured,
 * and ~30x shorter than the stuck case. */
#define DIAG_PROBE_OPEN_DEADLINE_MS 1000

/* The syscall the open half acts through; open(2)'s contract. */
typedef int (*diag_probe_open_fn)(const char *path, int flags);

/* Open `path` with `flags | O_CLOEXEC`, waiting at most deadline_ms. Returns the
 * fd, or -1 with errno set by open(), or -1 with errno ETIMEDOUT when open() had
 * not returned by the deadline. */
int diag_probe_open(const char *path, int flags, int deadline_ms);
int diag_probe_open_with(diag_probe_open_fn fn, const char *path, int flags,
                         int deadline_ms);

/* Short operator label: "plain", "nowait", "nowait-unrestored", "detached",
 * "blocked". Static, never NULL. For messages only; never parsed. */
const char *diag_probeclose_label(diag_probeclose_how_t how);

/* Append "<basename(port)>(<label>)" to a comma-separated list in buf, for a
 * one-line scan summary. Truncates rather than overflows: an entry that does
 * not fit whole is dropped, and buf always stays NUL-terminated. */
void diag_probeclose_note(char *buf, size_t bufsz, const char *port,
                          diag_probeclose_how_t how);

/* The same, with a caller-chosen label -- for the scan's list of ports whose
 * open() hit its deadline, which is not a close and has no `how`. */
void diag_probeclose_note_label(char *buf, size_t bufsz, const char *port,
                                const char *label);

/* ---------------------------------------------------------------------------
 * The TERMIOS half: a probe leaves the port's line settings exactly as
 * it found them.
 *
 * A probe open sets 115200 raw 8N1 so it can speak AT. On Linux those settings
 * belong to the TTY, not to the fd, so they outlive the probe and every other
 * reader of the port inherits them. A GNSS receiver read by str2str at 460800
 * (a reader that takes no flock, so the port claim cannot protect it) is left
 * at 115200 by one scan and from then on reads only line noise.
 *
 * So the probe open records the termios it FOUND (keep), and diag_probe_close()
 * puts it back (restore) before it releases the fd -- every probe close in both
 * scanners goes through it, so none can forget. The restore is TCSANOW, never
 * TCSADRAIN: a port that never took the probe's "AT\r\n" (the NMEA tty above)
 * would hold a draining tcsetattr() forever, the very wait diag_probe_close
 * exists to avoid.
 *
 * What it cannot undo: the probe's tcflush() and its "AT\r\n" have already
 * happened, and a reader that does not flock loses ~one exchange of bytes. The
 * scan's admission rule (diag_portadmit.h) is what keeps a non-modem
 * port from being opened at all; this half covers the ports it does admit.
 *
 * Indexed by fd number, like at_serial.inc's late-OK table: one probe fd at a
 * time per scanning thread, and a fd past the table is simply not restored
 * (left as the probe set it). keep() on a reused fd number replaces the entry.
 * --------------------------------------------------------------------------- */

/* Remember `orig` as the termios `fd`'s port had before the probe changed it. */
void diag_probe_termios_keep(int fd, const struct termios *orig);

/* Forget what keep() recorded for `fd`: the fd is not (or no longer) a probe
 * whose settings should be put back -- a non-tty, or a port kept for use. */
void diag_probe_termios_forget(int fd);

/* Put back what keep() recorded for `fd`, TCSANOW, and forget it. Returns 1 if
 * a recorded termios was written back, 0 if nothing was recorded or the write
 * failed. Called by diag_probe_close() before it releases the fd. */
int diag_probe_termios_restore(int fd);

/* ---------------------------------------------------------------------------
 * The input drain: tcflush(TCIFLUSH) for a node that is not a tty.
 *
 * Both scanners flush a port's input before each AT exchange, so a reply
 * another process left unread is not taken as the answer to the next command.
 * tcflush() alone does not do that on an AT node that is not a real tty. A
 * mainline /dev/wwan0at0 fails it with ENOTTY. An out-of-tree MHI UCI node
 * (/dev/mhi_DUN) is worse: it answers the termios ioctls, so isatty() is true
 * and TCFLSH reports success, but the replies it holds -- kept across a
 * close, for the next opener -- survive. Undrained, an RM520N-GL's AT+CGMI
 * and AT+CGMM answers left by an earlier prober read as AT+CGSN's reply and
 * its retry, and the modem does not identify on that open.
 *
 * So this calls tcflush(fd, TCIFLUSH) on a tty, then, on any fd, reads and
 * discards what is still waiting -- poll() with a zero timeout before every
 * read, so it never blocks -- and returns that count (0 after a flush that
 * worked). It stops at DIAG_PROBE_DRAIN_MAX bytes, so a node that streams
 * cannot hold the caller. Returns -1 for an invalid fd.
 * --------------------------------------------------------------------------- */
#define DIAG_PROBE_DRAIN_MAX 16384
ssize_t diag_probe_drain_input(int fd);

#ifdef __cplusplus
}
#endif

#endif /* DIAG_PROBECLOSE_H */
