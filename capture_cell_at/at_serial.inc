/* at_serial.inc - shared AT-over-serial core for capture_cell_at.
 *
 * Textually #included (not separately compiled) by:
 *   - capture_cell_at.c        (the Kismet capture binary)
 *   - cellat_serial_probe.c    (standalone hardware probe, no Kismet)
 *   - test_at_serial.c         (socketpair selftest, `make check`)
 *
 * The functions stay `static` so each including TU gets its own copy — no
 * external linkage, so no symbol-collision risk against the Kismet framework
 * library, and capture_cell_at.c compiles byte-identically to when these
 * definitions lived inline. This is the AT-side analogue of the DIAG side's
 * separately-compiled diag_capture.c core (which powers celldiag_probe).
 *
 * The transport-agnostic bits (mirroring the DIAG side):
 *   - serial_open() skips termios on a non-tty (MHI /dev/mhi_DUN, inline
 *     /dev/wwan*): those are raw byte pipes, not terminals.
 *   - at_command_log() gets its per-read timeout from poll(), not tty VTIME,
 *     so a non-tty AT port still times out instead of blocking forever.
 *
 * at_command_log() can also report WHEN inside the exchange things happened
 * (at_timing_t below), so a record can separate host TX cost, modem
 * think-time and response transfer time instead of one collapsed duration.
 */
#ifndef AT_SERIAL_INC
#define AT_SERIAL_INC

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
/* stdio for the unsupported-baud refusal below. This file is textually
 * #included, so both current includers already have it -- named here anyway,
 * because "the includer happens to provide it" is how a new includer breaks. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/time.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* The bounded probe open lives with the probe close in the shared module both scanners link -- every includer of this file links
 * diag_probeclose.c (and -pthread) for it. */
#include "../capture_cell_diag/diag_probeclose.h"

/* Write an ISO 8601 timestamp + direction tag + message to the transcript fd.
 * direction: "TX" for commands sent, "RX" for responses received.
 * Safe to call with fd < 0 (no-op). */
static void transcript_write(int fd, const char *direction, const char *data, int len) {
    if (fd < 0 || !data)
        return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    gmtime_r(&tv.tv_sec, &tm);

    char header[64];
    int hlen = snprintf(header, sizeof(header),
                        "[%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ] %s: ",
                        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec,
                        (long)(tv.tv_usec / 1000), direction);

    /* Write header + data + newline atomically-ish */
    write(fd, header, hlen);
    if (len > 0)
        write(fd, data, len);
    else
        write(fd, data, strlen(data));
    write(fd, "\n", 1);
}

/* A final OK this fd may still owe. An info read that ended on the idle
 * gap read no terminator, and a modem that terminates LATE sends that
 * OK after the reader has moved on -- into the NEXT exchange, ahead of its
 * answer. The info form already refuses to end on such an OK; the ordinary form
 * would take it as its whole reply, so a capability probe that only checks for
 * OK would read "supported" off the previous command's OK.
 *
 * Indexed by fd, holding the gap that ended the read (0 = nothing owed). A fd
 * number past the table owes nothing (no late-OK handling for it). It is
 * cleared by the next exchange on the fd, whatever its form, and by
 * serial_open(): a new port on a reused fd number owes nothing. */
#define AT_LATE_OK_FDS 1024
static int at_late_ok_gap_ms[AT_LATE_OK_FDS];

static void at_late_ok_owe(int fd, int gap_ms) {
    if (fd >= 0 && fd < AT_LATE_OK_FDS)
        at_late_ok_gap_ms[fd] = gap_ms;
}

static int at_late_ok_take(int fd) {
    int gap_ms = 0;
    if (fd >= 0 && fd < AT_LATE_OK_FDS) {
        gap_ms = at_late_ok_gap_ms[fd];
        at_late_ok_gap_ms[fd] = 0;
    }
    return gap_ms;
}

/* -----------------------------------------------------------------------
 * Serial I/O via POSIX termios
 * ----------------------------------------------------------------------- */

static int serial_open(const char *path, int baudrate) {
    int fd;
    struct termios tty;
    speed_t speed;

    /* Bounded: a tty still in its final close -- a sibling scanner's
     * detached close of a port that never read its "AT\r\n" -- makes a
     * plain open() block for the port's 30 s closing_wait, O_NONBLOCK or not,
     * which would consume Kismet's whole 30 s command deadline. An open that
     * has not returned by the deadline fails with ETIMEDOUT. */
    fd = diag_probe_open(path, O_RDWR | O_NOCTTY | O_NONBLOCK,
                         DIAG_PROBE_OPEN_DEADLINE_MS);
    if (fd < 0)
        return -1;

    /* Claim the port exclusively.
     *
     * Every cellat process scans every suspected-modem serial port on the host
     * (diag_portadmit.h) to identify modems by IMEI, including ports owned by
     * another modem's capture process. Two processes on one port both write
     * AT+CGMR and both read the reply, and the kernel gives each chunk to
     * exactly one reader, so the reply is SPLIT between them rather than
     * duplicated: with byte-at-a-time reads, 'EG25GGBR07A08M2G' comes back as
     * 'G5GR70MG' (every odd character; the sibling ate the even ones). The
     * same split hits the AT+CGSN read that identify_modem() matches IMEIs on,
     * so a source can fail to open or bind a different port run-to-run.
     *
     * flock() is per open-file-description and is released automatically when
     * the last fd referring to that description is closed -- including on
     * crash -- so no stale lock can strand a port. A scanning pass simply skips
     * ports someone else holds, and a capture session holds its own port for
     * its lifetime. This is also the convention other serial tooling follows,
     * so the claim is mutually visible with non-Kismet users of the port.
     *
     * Non-tty AT transports (MHI /dev/mhi_DUN, inline /dev/wwan*) are locked
     * too: they are equally scannable and equally raceable, and flock() has no
     * tty dependency. So the claim goes here, ahead of the isatty() split. */
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        /* Keep flock's EWOULDBLOCK across the close: it is how a scan tells a
         * port another process is probing RIGHT NOW from one that is simply
         * not a modem, and retries only the former. */
        int claim_errno = errno;
        close(fd);
        errno = claim_errno;
        return -1;
    }

    /* Clear O_NONBLOCK after open (we want blocking reads with timeout) */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    /* Non-tty AT transports -- an MHI char device (/dev/mhi_DUN on a PCIe modem
     * like the RM520N-GL / SDX6x under the OOT driver) or a /dev/wwan* port on
     * the inline driver -- are not terminals: tcgetattr() returns ENOTTY. They
     * are already raw byte pipes with no baud rate or line discipline to
     * configure, so skip termios entirely rather than failing the open. The AT
     * read loop's per-read timeout is provided by poll() (see at_command_log),
     * not tty VTIME, so a non-tty port still times out correctly. (Mirrors
     * the DIAG side.) */
    at_late_ok_take(fd);   /* a new port on this fd number owes nothing */
    if (!isatty(fd)) {
        diag_probe_termios_forget(fd);   /* no line settings to put back */
        return fd;
    }

    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(fd, &tty) != 0) {
        diag_probe_termios_forget(fd);
        close(fd);
        return -1;
    }

    /* Keep the port's settings AS FOUND, before anything below changes them.
     * A probe's close (diag_probe_close) writes them back: on Linux the 115200
     * raw set below belongs to the TTY, not to this fd, so without the restore
     * every other reader of the port inherits it -- a GNSS receiver read at
     * 460800 by a reader that takes no flock is left at 115200, reading line
     * noise. */
    diag_probe_termios_keep(fd, &tty);

    /* B460800 / B921600 do not exist on Darwin -- and unlike the
     * feature-test problem in diag_capture.c, no macro brings them back.
     * macOS's termios tops out at B230400; higher rates go through the
     * IOSSIOSPEED ioctl. Referenced unconditionally, they are a hard compile
     * error, which would break `make -f standalone.mk check` (the
     * framework-free selftest) on macOS.
     *
     * The `#ifdef` must NOT simply drop the arms. Falling through to
     * `default:` would run a 921600 modem at 115200 and report success, a
     * silent downgrade. An unsupported rate refuses the open and says which rate and which
     * platform. On Linux both constants exist, so nothing here changes. */
    switch (baudrate) {
        case 9600:   speed = B9600;   break;
        case 19200:  speed = B19200;  break;
        case 38400:  speed = B38400;  break;
        case 57600:  speed = B57600;  break;
#ifdef B460800
        case 460800: speed = B460800; break;
#endif
#ifdef B921600
        case 921600: speed = B921600; break;
#endif
        default:
#if !defined(B460800) || !defined(B921600)
            if (baudrate == 460800 || baudrate == 921600) {
                fprintf(stderr,
                        "serial_open(%s): %d baud has no termios constant on "
                        "this platform (macOS caps at B230400; higher rates "
                        "need IOSSIOSPEED). Refusing rather than silently "
                        "running at 115200.\n", path, baudrate);
                diag_probe_termios_forget(fd);   /* nothing was changed */
                close(fd);
                return -1;
            }
#endif
            speed = B115200;
            break;
    }

    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);

    /* 8N1, no flow control */
    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~CRTSCTS;
    tty.c_cflag |= CREAD | CLOCAL;

    /* Raw mode */
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY | IGNBRK | BRKINT | PARMRK |
                      ISTRIP | INLCR | IGNCR | ICRNL);
    tty.c_oflag &= ~OPOST;

    /* Read with 1 second timeout */
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 10;  /* 1 second in deciseconds */

    tcflush(fd, TCIOFLUSH);
    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        diag_probe_termios_forget(fd);   /* the settings were not changed */
        close(fd);
        return -1;
    }

    return fd;
}

/* serial_open(), waiting out a port another process holds the claim to.
 *
 * A claim refused with EWOULDBLOCK is retried every SERIAL_CLAIM_STEP_MS until
 * `budget_ms` has passed; every other failure returns at once, errno intact.
 * `*waited_ms` (may be NULL) is how long the claim was waited for: 0 when the
 * first open succeeded or failed for another reason. On a refusal that outlasts
 * the budget, the result is -1 with errno EWOULDBLOCK.
 *
 * For an open the caller has already decided on -- the port a scan found. A
 * SCAN must not use it: a scan skips a busy port and rescans, and
 * waiting on each busy port in turn would stack the waits. */
#define SERIAL_CLAIM_WAIT_MS 3000
#define SERIAL_CLAIM_STEP_MS 100

static int serial_open_claim(const char *path, int baudrate, int budget_ms,
                             long *waited_ms) {
    struct timespec t0, now;
    long waited = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int fd = serial_open(path, baudrate);
    while (fd < 0 && errno == EWOULDBLOCK && waited < budget_ms) {
        usleep(SERIAL_CLAIM_STEP_MS * 1000);
        fd = serial_open(path, baudrate);
        int open_errno = errno;
        clock_gettime(CLOCK_MONOTONIC, &now);
        waited = (long)(now.tv_sec - t0.tv_sec) * 1000L +
                 (long)(now.tv_nsec - t0.tv_nsec) / 1000000L;
        errno = open_errno;
    }
    if (waited_ms)
        *waited_ms = waited;
    return fd;
}

/* The close of a port KEPT for use, not a probe: its settings are the
 * source's own by now and are not written back, so the entry serial_open()
 * kept is dropped rather than left for a reused fd number. A PROBE
 * closes through diag_probe_close(), which restores them. */
static void serial_close(int *fd) {
    if (*fd >= 0) {
        diag_probe_termios_forget(*fd);
        close(*fd);
        *fd = -1;
    }
}

/* The inner instants of one AT exchange, host CLOCK_MONOTONIC ns --
 * the same clock as the atlog record's ts_mono_ns, so each interval is a plain
 * subtraction. 0 means the exchange never got there (CLOCK_MONOTONIC is seconds
 * past boot before any userland runs, so 0 is never a real reading).
 *
 *   tx_done_ns   the command's write() returned. That is the hand-off to the
 *                kernel, not the last bit on the wire. 0 if the write failed.
 *   first_rx_ns  the host read the first byte of the first line KEPT as
 *                response. The command echo (before ATE0) and the blank lines
 *                around a reply are not response, so they do not start it: an
 *                echo arrives before the modem has thought at all, and stamping
 *                it would read as zero think-time. An unsolicited line (a URC)
 *                that lands mid-exchange is kept as response today, so it
 *                starts it too. 0 if no line was kept.
 *   rx_done_ns   the host read the end of the terminal line (OK / ERROR /
 *                +CME ERROR). 0 if the exchange ended without one -- a timeout,
 *                an EOF, a read error -- so a caller can tell a completed
 *                exchange from one that ran out of time without parsing text.
 *
 * All three are when the HOST read the byte, not when it arrived: bytes that
 * land while the host is writing the transcript line are stamped when the loop
 * gets to them. One read() takes every byte already buffered, and they
 * all share that read's instant: first_rx_ns is the read that delivered the
 * first kept line's first byte, rx_done_ns the read that delivered the terminal
 * line. So a reply the modem sent in one burst reads as rx_done_ns ==
 * first_rx_ns -- zero transfer -- and the gap between them is almost all time
 * spent waiting for the modem's next bytes. (A byte-per-poll()+read() loop,
 * plus a VTIME refresh on a tty, costs ~5 us/byte on a pty, so a 3 KB
 * neighbour-cell reply would read as 13-18 ms of "transfer" with nothing on
 * the wire.) */
typedef struct {
    uint64_t tx_done_ns;
    uint64_t first_rx_ns;
    uint64_t rx_done_ns;
} at_timing_t;

/* Bytes asked of one read() in at_command_log(). A read returns what
 * is already buffered, up to this many, and never waits for more: poll() said
 * readable, and a tty is VMIN=0 (serial_open). So a reply the modem sent in
 * one burst costs one or a few reads instead of one per byte. */
#define AT_READ_CHUNK 4096

static uint64_t at_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Send an AT command and collect the full response.
 *
 * Reads until OK, ERROR, +CME ERROR, or timeout.  Returns the number
 * of bytes written to resp_buf (not including the NUL terminator),
 * or -1 on error.
 *
 * `timing` (may be NULL) receives the exchange's inner instants, see
 * at_timing_t. It is zeroed on entry, so a field the exchange never reached
 * reads 0 whatever the return value.
 *
 * Bytes that the read completing the terminal line delivered AFTER it are
 * dropped. On a tty that is what the next exchange's tcflush() would do to
 * them anyway. On a non-tty nothing flushes, and leaving them for the next
 * exchange would make it take a URC sent right after this OK as the start of
 * ITS reply, stamping its first_rx_ns before the modem had thought at all.
 * Bytes that arrive in a later read still wait in the kernel for the next
 * exchange.
 *
 * `info_idle_ms` > 0 is the INFO form, for a single-line info read
 * (AT+CGMR / +CGSN / +CGMI / +CGMM) only: once a value line has arrived, a
 * port silent for info_idle_ms also ends the exchange. Some firmware (a
 * Foxconn T99W175) never sends the final OK on these, so without the gap
 * every such read would run its whole deadline. A bare OK that arrives BEFORE any value line does
 * not end an info read -- it can be the previous exchange's late OK, ahead of
 * this one's answer -- the gap does. rx_done_ns stays 0 when the gap ended it:
 * no terminal line was read. 0 is the ordinary form.
 *
 * An info read the gap ended leaves the fd OWING a late OK (see
 * at_late_ok_gap_ms). The next exchange on the fd pays it: in the ordinary
 * form, a bare OK that is its first line is HELD rather than taken as the
 * reply. If anything follows it within the same gap, it was the previous
 * exchange's OK: it is dropped (the transcript records it as RX-LATE) and the
 * read goes on for this one's answer. If the port stays quiet, it was this
 * reply after all -- an echo-off modem answers ATE0 with nothing else -- and it
 * is returned, stamped with the read that delivered it. Either way the cost is
 * at most one gap, once; with nothing owed the ordinary form is unchanged.
 */
static int at_command_log_ex(int fd, const char *cmd, char *resp_buf,
                             size_t resp_max, int timeout_ms, int transcript_fd,
                             at_timing_t *timing, int info_idle_ms) {
    char line_buf[1024];
    ssize_t n;
    size_t resp_len = 0;
    size_t line_pos = 0;
    uint64_t line_t0 = 0;       /* when the current line's first byte was read */
    struct timeval deadline, now_tv;
    int have_value = 0;         /* info form: a value line has been kept */
    int early_ok = 0;           /* info form: a bare OK came before any value */
    int kept = 0;               /* a line has been kept as response */
    int held = 0;               /* a leading bare OK is being held */
    int hold_spent = 0;         /* the one owed OK has been held */
    int gap_ended = 0;          /* info form: the idle gap ended the read */
    uint64_t held_t0 = 0, held_t_read = 0;

    if (timing)
        memset(timing, 0, sizeof(*timing));

    if (fd < 0)
        return -1;

    /* What the fd owes is paid by THIS exchange, whatever its form. The
     * info form has its own rule for an early OK, so only the ordinary form
     * holds one. */
    int owed_gap_ms = at_late_ok_take(fd);
    int hold_gap_ms = (info_idle_ms > 0) ? 0 : owed_gap_ms;

    /* A non-tty AT transport (MHI /dev/mhi_DUN, inline /dev/wwan*) has no line
     * discipline; termios calls ENOTTY-noop on it and the per-read timeout comes
     * from poll() below rather than VTIME. */
    int is_tty = isatty(fd);

    /* Drop input waiting from before this exchange, so a reply another
     * process left unread is not this one: tcflush() on a tty, then a bounded
     * read -- an MHI UCI node passes isatty() and ignores the flush. */
    diag_probe_drain_input(fd);

    /* On a tty, set VTIME once for the exchange: poll()
     * below bounds every wait, so VTIME is only a backstop for a read that
     * finds nothing after poll() said readable. Refreshing it before every
     * read would cost a tcgetattr+tcsetattr pair per read. Done before the
     * write, so its cost is host
     * TX time, not modem think-time. */
    if (is_tty) {
        struct termios tty;
        if (tcgetattr(fd, &tty) == 0) {
            int vtime = (timeout_ms >= 1000) ? 10 : (timeout_ms / 100);
            if (vtime < 1) vtime = 1;
            tty.c_cc[VTIME] = vtime;
            tcsetattr(fd, TCSANOW, &tty);
        }
    }

    /* Send command */
    size_t cmd_len = strlen(cmd);
    char *send_buf = malloc(cmd_len + 3);
    if (!send_buf)
        return -1;
    snprintf(send_buf, cmd_len + 3, "%s\r\n", cmd);

    ssize_t written = write(fd, send_buf, strlen(send_buf));
    free(send_buf);
    if (written < 0)
        return -1;
    if (timing)
        timing->tx_done_ns = at_mono_ns();

    transcript_write(transcript_fd, "TX", cmd, 0);

    /* Calculate deadline */
    gettimeofday(&deadline, NULL);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_usec += (timeout_ms % 1000) * 1000;
    if (deadline.tv_usec >= 1000000) {
        deadline.tv_sec++;
        deadline.tv_usec -= 1000000;
    }

    resp_buf[0] = '\0';

    while (1) {
        gettimeofday(&now_tv, NULL);
        if (now_tv.tv_sec > deadline.tv_sec ||
            (now_tv.tv_sec == deadline.tv_sec &&
             now_tv.tv_usec >= deadline.tv_usec))
            break;

        /* Set read timeout to remaining time, max 1s */
        long remaining_ms = (deadline.tv_sec - now_tv.tv_sec) * 1000 +
                            (deadline.tv_usec - now_tv.tv_usec) / 1000;
        if (remaining_ms <= 0)
            break;

        /* Per-read timeout is provided by poll() for both tty and non-tty
         * transports (VTIME is only a backstop, set once above). */
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int wait_ms = remaining_ms > 1000 ? 1000 : (int)remaining_ms;
        /* Info form: after a value (or a bare early OK), wait only the
         * idle gap -- a poll() that finds nothing in it is the end of the reply. */
        int idle_armed = info_idle_ms > 0 && (have_value || early_ok);
        if (idle_armed && wait_ms > info_idle_ms)
            wait_ms = info_idle_ms;
        /* A held OK is the reply unless something follows it in the gap. */
        if (held && wait_ms > hold_gap_ms)
            wait_ms = hold_gap_ms;
        int pr = poll(&pfd, 1, wait_ms);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (pr == 0) {
            if (idle_armed) {
                gap_ended = 1;     /* the port went quiet after the answer */
                break;
            }
            if (held)
                break;             /* nothing followed the held OK */
            continue;              /* timeout: re-check deadline at loop top */
        }

        char rbuf[AT_READ_CHUNK];
        n = read(fd, rbuf, sizeof(rbuf));
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            /* poll readable + read()==0 == EOF. On a non-tty that's a genuine
             * device disconnect -- return what we have instead of busy-spinning
             * poll-readable until the deadline. On a tty preserve the old
             * treat-as-timeout behavior. */
            if (!is_tty)
                break;
            continue;
        }

        /* One read, one instant: every byte this read delivered was read by
         * the host at the same moment. */
        uint64_t t_read = timing ? at_mono_ns() : 0;
        int done = 0;

        for (ssize_t i = 0; i < n; i++) {
            char c = rbuf[i];

            /* Build line */
            if (c == '\n' || c == '\r') {
                if (line_pos == 0)
                    continue;  /* skip empty lines */

                line_buf[line_pos] = '\0';

                /* A line after the held OK -- even this command's echo,
                 * which a modem sends before it has answered anything -- means
                 * the held OK was the previous exchange's. */
                if (held) {
                    held = 0;
                    transcript_write(transcript_fd, "RX-LATE", "OK", 2);
                }

                /* Skip echo of the command */
                if (strncmp(line_buf, cmd, strlen(cmd)) == 0) {
                    line_pos = 0;
                    continue;
                }

                /* The fd owes a late OK, and this bare OK is the first
                 * line of the reply. Hold it; the gap decides whose it is. */
                if (hold_gap_ms > 0 && !kept && !hold_spent &&
                    strcmp(line_buf, "OK") == 0) {
                    held = 1;
                    hold_spent = 1;        /* one late OK is owed, not two */
                    held_t0 = line_t0;
                    held_t_read = t_read;
                    line_pos = 0;
                    continue;
                }
                kept = 1;

                /* The first line kept is where the response starts --
                 * stamped whether or not it fits resp_buf, since the modem
                 * sent it either way. */
                if (timing && timing->first_rx_ns == 0)
                    timing->first_rx_ns = line_t0;

                /* Append to response buffer */
                if (resp_len + line_pos + 2 < resp_max) {
                    if (resp_len > 0) {
                        resp_buf[resp_len++] = '\n';
                    }
                    memcpy(resp_buf + resp_len, line_buf, line_pos);
                    resp_len += line_pos;
                    resp_buf[resp_len] = '\0';
                }

                /* Check for terminal responses. The rest of this read, if
                 * any, is dropped -- see the function comment. */
                if (strcmp(line_buf, "OK") == 0 ||
                    strcmp(line_buf, "ERROR") == 0 ||
                    strncmp(line_buf, "+CME ERROR", 10) == 0) {
                    if (info_idle_ms > 0 && !have_value &&
                        strcmp(line_buf, "OK") == 0) {
                        /* Info form: possibly the previous exchange's late OK
                         * Keep reading; the idle gap ends it. */
                        early_ok = 1;
                        line_pos = 0;
                        continue;
                    }
                    if (timing)
                        timing->rx_done_ns = t_read;
                    done = 1;
                    break;
                }

                if (info_idle_ms > 0)
                    have_value = 1;
                line_pos = 0;
            } else {
                if (line_pos == 0)
                    line_t0 = t_read;   /* the read that brought the line's first byte */
                if (line_pos < sizeof(line_buf) - 1) {
                    line_buf[line_pos++] = c;
                }
            }
        }
        if (done)
            break;
    }

    /* Nothing followed the held OK, so it was this reply. It is the
     * first and the terminal line, read when the read that delivered it ran. */
    if (held) {
        if (resp_len + 2 + 2 < resp_max) {
            memcpy(resp_buf + resp_len, "OK", 2);
            resp_len += 2;
            resp_buf[resp_len] = '\0';
        }
        if (timing) {
            if (timing->first_rx_ns == 0)
                timing->first_rx_ns = held_t0;
            timing->rx_done_ns = held_t_read;
        }
    }

    /* An info read the gap ended read no terminator. A modem that
     * terminates late still owes one, and the next exchange must not end on it. */
    if (gap_ended)
        at_late_ok_owe(fd, info_idle_ms);

    transcript_write(transcript_fd, "RX", resp_buf, (int)resp_len);

    return (int)resp_len;
}

/* The ordinary form: reads until OK / ERROR / +CME ERROR / timeout. */
static int at_command_log(int fd, const char *cmd, char *resp_buf,
                          size_t resp_max, int timeout_ms, int transcript_fd,
                          at_timing_t *timing) {
    return at_command_log_ex(fd, cmd, resp_buf, resp_max, timeout_ms,
                             transcript_fd, timing, 0);
}

/* Original signature — no transcript, used during probe/identify before
 * the transcript file is opened. */
static int at_command(int fd, const char *cmd, char *resp_buf,
                      size_t resp_max, int timeout_ms) {
    return at_command_log(fd, cmd, resp_buf, resp_max, timeout_ms, -1, NULL);
}

/* A single-line info read (AT+CGMR / +CGSN / +CGMI / +CGMM) in the info form
 * (see at_command_log_ex): the reply also ends on `idle_ms` of silence
 * after its value. Never for a command whose answer may legitimately pause. */
static int at_info_command(int fd, const char *cmd, char *resp_buf,
                           size_t resp_max, int timeout_ms, int idle_ms) {
    return at_command_log_ex(fd, cmd, resp_buf, resp_max, timeout_ms, -1, NULL,
                             idle_ms);
}

#endif /* AT_SERIAL_INC */
