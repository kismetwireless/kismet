/* diag_capture.c - reusable DIAG capture core. See diag_capture.h. */
/* cfmakeraw / CRTSCTS / O_CLOEXEC are BSD/POSIX extensions gated behind a
 * feature-test macro under strict -std=c11; the Kismet build uses -std=gnu11
 * where they are visible by default. */
/* The selftest's pty (posix_openpt/grantpt/unlockpt/ptsname) needs
 * _XOPEN_SOURCE >= 600, which _DEFAULT_SOURCE alone does not imply. Gated on
 * the selftest macro so the production translation unit's feature set is
 * unchanged; _DEFAULT_SOURCE stays either way, so cfmakeraw/CRTSCTS/O_CLOEXEC
 * remain visible in both builds. */
/* The reasoning above is GLIBC-SPECIFIC, and on Darwin it inverts.
 * `_DEFAULT_SOURCE` is a glibc feature-test macro; Darwin's libc ignores it
 * entirely. There the BSD extensions come from `_DARWIN_C_SOURCE`, which is
 * the default ONLY while no strict macro is defined — so `_XOPEN_SOURCE 600`
 * switches them off and nothing switches them back: on Apple clang `B115200`
 * and `CRTSCTS` are undeclared and the selftest build fails.
 *
 * Only the selftest is affected (the macro is inside the `#ifdef`), but the
 * selftest is the one build that runs on a host that cannot `./configure`
 * this tree, and macOS is such a host.
 *
 * `_DARWIN_C_SOURCE` is unknown to glibc and inert there, so this is one
 * definition for both rather than an `#ifdef __APPLE__` at each call site. */
#ifdef DIAG_CAPTURE_SELFTEST
#define _XOPEN_SOURCE 600
#define _DARWIN_C_SOURCE
#endif
#define _DEFAULT_SOURCE
#include "diag_capture.h"
#include "diag_hdlc.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/file.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define DIAG_FLAG              0x7E
#define DIAG_CAPTURE_IDLE_TIMEOUTS 12   /* ~12 * VTIME (5s) = 60s of silence */

int diag_port_claim(int fd) {
    if (fd < 0)
        return -1;
    return flock(fd, LOCK_EX | LOCK_NB) == 0 ? 0 : -1;
}

/* Terminate whatever partial frame another writer left in the modem's HDLC
 * parser, before our first command. cellat's IMEI scan writes "AT\r\n"
 * into every port it can claim, DIAG nodes included (celldiag's own scan skips
 * them). The modem keeps those bytes as the head of a frame, glues our
 * first command onto them, and the CRC fails: the command is never answered.
 * On an EG25-G DIAG node, after one such probe the SPC unlock goes unanswered
 * until its 20 s deadline, while the same probe followed by one 0x7E leaves it
 * accepted. A lone flag is an empty frame
 * the modem discards, and diag_read_frame() skips one on the way back in.
 * Sent only once the claim is held, so a port another process owns is never
 * written to. Best effort: a transport that refuses this byte will refuse the
 * command after it too, and that one fails loudly. */
static void diag_capture_resync(int fd) {
    static const uint8_t flag = DIAG_FLAG;
    ssize_t w = write(fd, &flag, 1);
    (void)w;
}

int diag_capture_open(const char *port) {
    struct termios tio;
    int fd = open(port, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    /* Claim before configuring: a port another process is already reading must
     * fail here rather than have its byte stream split between us. Ahead of the
     * isatty() split below so non-tty DIAG transports (MHI /dev/mhi_DIAG,
     * /dev/diag) are covered too -- they are equally scannable and flock() has
     * no tty dependency. See diag_capture.h for the full rationale.
     *
     * Callers wanting to tolerate a momentary grab should use
     * diag_capture_open_retry(), whose retry semantics ("a dying
     * sibling helper still holding it during a rapid relaunch") are exactly the
     * right layer for a transiently locked port. */
    if (diag_port_claim(fd) != 0) {
        close(fd);
        return -1;
    }

    /* Serial DIAG ports (/dev/ttyUSBx) are terminals and need raw-mode line
     * discipline set up below. A non-tty DIAG transport -- an MHI char device
     * (/dev/mhi_DIAG on PCIe basebands like the RM520N-GL / SDX6x) or a
     * /dev/diag kernel node -- is already a raw byte pipe with no baud rate or
     * line discipline to configure; tcgetattr() returns ENOTTY on it. Skip
     * termios entirely rather than failing the open. The idle timeout that a
     * tty gets from VTIME is provided transport-agnostically by the poll() in
     * next_byte(), so a quiet non-tty port still bails instead of blocking
     * forever. */
    if (!isatty(fd)) {
        diag_capture_resync(fd);
        return fd;
    }

    if (tcgetattr(fd, &tio) != 0) {
        close(fd);
        return -1;
    }
    cfmakeraw(&tio);
    cfsetispeed(&tio, B115200);
    cfsetospeed(&tio, B115200);
    tio.c_cflag |= (CLOCAL | CREAD);
    tio.c_cflag &= ~CRTSCTS;
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 50;              /* 5.0s per-read timeout */
    if (tcsetattr(fd, TCSANOW, &tio) != 0) {
        close(fd);
        return -1;
    }
    tcflush(fd, TCIOFLUSH);
    diag_capture_resync(fd);   /* after the flush, or the flush would drop it */
    return fd;
}

/* True for an open() errno a rapid celldiag relaunch can hit *transiently*: the
 * DIAG port still held by a dying sibling helper, or briefly EACCES/EAGAIN while
 * the kernel tears the old holder down, or the char node momentarily gone during
 * USB/MHI re-enumeration (ENODEV), or an EINTR. A permanent misconfiguration --
 * a typo'd diagport= (ENOENT), no such device (ENXIO) -- is deliberately NOT in
 * this set, so a genuinely-wrong port still fails fast on the first attempt
 * instead of eating the whole retry budget. */
static int diag_open_errno_is_transient(int e) {
    return e == EBUSY || e == EACCES || e == EAGAIN ||
           e == ENODEV || e == EINTR;
}

int diag_capture_open_retry(const char *port, int attempts, int delay_ms) {
    int fd;
    int i;

    if (attempts < 1)
        attempts = 1;

    for (i = 0; i < attempts; i++) {
        fd = diag_capture_open(port);
        if (fd >= 0)
            return fd;
        /* Only wait out a transient grab, and only if we have a retry left; a
         * permanent failure returns immediately so a bad path is not slow. An
         * intermittent port hold by a dying sibling during a rapid relaunch is
         * absorbed here (the open succeeds on a later attempt) instead of
         * failing the source open -- which, on a single-source server, would
         * tear the whole server down via the capture framework's "Remote side
         * closed read pipe" path. */
        if (i + 1 < attempts && diag_open_errno_is_transient(errno)) {
            struct timespec ts = {
                .tv_sec = delay_ms / 1000,
                .tv_nsec = (long)(delay_ms % 1000) * 1000000L,
            };
            nanosleep(&ts, NULL);
            continue;
        }
        break;
    }
    return -1;
}

/* ~5.0s per-read timeout, mirroring the old tty VTIME=50. Applied via poll()
 * so a non-tty transport (MHI /dev/mhi_DIAG), which has no VTIME, gets the same
 * idle window instead of blocking indefinitely. DIAG_CAPTURE_IDLE_TIMEOUTS
 * consecutive timeouts still bound the total idle at ~60s. */
#define DIAG_CAPTURE_READ_TIMEOUT_MS 5000

/* Return the next raw byte from the buffered reader: 1 on byte (*b set),
 * 0 on read timeout (no data this interval), -1 on error/EOF.
 *
 * read() is gated on poll(): poll timing out is the idle tick (transport-
 * agnostic, so it works on a non-tty MHI node with no VTIME), while a poll
 * that reports the fd readable followed by read()==0 is a genuine EOF (peer
 * closed / device unplugged) and bails immediately -- on the old VTIME-only
 * path an unplugged tty's read()==0 was indistinguishable from an idle tick
 * and took the full ~60s idle window to surface. */
static int next_byte(int fd, diag_reader_t *r, uint8_t *b) {
    if (r->pos >= r->len) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        ssize_t n;
        int pr = poll(&pfd, 1, DIAG_CAPTURE_READ_TIMEOUT_MS);
        if (pr < 0)
            return (errno == EINTR) ? 0 : -1;
        if (pr == 0)
            return 0;                  /* idle timeout tick */
        n = read(fd, r->buf, sizeof(r->buf));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN)
                return 0;
            return -1;
        }
        if (n == 0)
            return -1;                 /* readable + 0 bytes = EOF */
        r->len = (size_t)n;
        r->pos = 0;
    }
    *b = r->buf[r->pos++];
    return 1;
}

int diag_read_frame(int fd, diag_reader_t *r,
                    uint8_t *out, size_t outcap, size_t *len) {
    uint8_t raw[2048];
    size_t rawlen = 0;
    int idle = 0;

    for (;;) {
        uint8_t b;
        int rc = next_byte(fd, r, &b);
        if (rc < 0)
            return -1;
        if (rc == 0) {
            if (++idle >= DIAG_CAPTURE_IDLE_TIMEOUTS)
                return -1;
            continue;
        }
        idle = 0;

        if (b == DIAG_FLAG) {
            size_t n;
            if (rawlen == 0)
                continue;              /* skip leading / back-to-back flags */
            n = diag_hdlc_unescape(raw, rawlen, out, outcap);
            rawlen = 0;
            if (n == 0)
                continue;              /* empty: skip */
            if (!diag_hdlc_check_crc(out, &n))
                continue;              /* partial (joined mid-frame) or corrupt: skip */
            *len = n;
            return 0;                  /* CRC-valid frame, any opcode */
        }

        if (rawlen >= sizeof(raw)) {
            rawlen = 0;                /* oversize: drop, resync */
            continue;
        }
        raw[rawlen++] = b;
    }
}

#ifdef DIAG_CAPTURE_SELFTEST
/* Build:
 *   cc -DDIAG_CAPTURE_SELFTEST -Wall -Wextra -Werror \
 *      diag_capture.c diag_hdlc.c -o /tmp/diag_capture_selftest && /tmp/diag_capture_selftest
 *
 * Exercises diag_read_frame() over a socketpair -- a NON-tty fd, the exact
 * transport class the isatty()/poll() handling serves (MHI /dev/mhi_DIAG
 * behaves the same: raw byte pipe, no line discipline, EOF on close). */
#include <stdio.h>
#include <stdlib.h>     /* posix_openpt/grantpt/unlockpt/ptsname -- test 4's pty */
#include <sys/socket.h>
#include <sys/stat.h>     /* mkfifo -- test 6's non-tty node */

static int fail;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        fail = 1;
    }
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        perror("socketpair");
        return 2;
    }

    /* A socketpair endpoint is not a terminal -- this is why the old
     * unconditional tcgetattr() in diag_capture_open() would reject the same
     * class of fd an MHI node presents. */
    check(!isatty(sv[0]) && !isatty(sv[1]), "socketpair endpoints are non-tty");

    /* 1. A complete built frame written to one end decodes at the other. The
     * leading lone 0x7E must be skipped (rawlen==0), then body accumulates to
     * the trailing 0x7E that diag_hdlc_build() appends. */
    {
        const uint8_t body[] = {0x00, 0xDE, 0xAD, 0xBE, 0xEF};
        uint8_t wire[64];
        size_t wlen = diag_hdlc_build(0x73, body, sizeof(body), wire, sizeof(wire));
        uint8_t lead = 0x7E;
        diag_reader_t r = {0};
        uint8_t out[64];
        size_t olen = 0;
        int rc;

        check(wlen > 0, "diag_hdlc_build produced a frame");
        check(write(sv[1], &lead, 1) == 1, "write leading flag");
        check(write(sv[1], wire, wlen) == (ssize_t)wlen, "write framed payload");

        rc = diag_read_frame(sv[0], &r, out, sizeof(out), &olen);
        /* Decoded frame is cmd || body (CRC stripped by diag_read_frame). */
        check(rc == 0, "diag_read_frame decodes a frame over a non-tty");
        check(olen == 1 + sizeof(body), "decoded length == cmd + body");
        check(olen >= 1 && out[0] == 0x73, "decoded opcode preserved");
        check(olen == 1 + sizeof(body) && memcmp(out + 1, body, sizeof(body)) == 0,
              "decoded body preserved");
    }

    /* 2. Closing the write end is a genuine EOF: poll reports the fd readable,
     * read() returns 0, and diag_read_frame() bails immediately with -1 rather
     * than spinning the full idle window. */
    {
        diag_reader_t r = {0};
        uint8_t out[64];
        size_t olen = 0;
        close(sv[1]);
        check(diag_read_frame(sv[0], &r, out, sizeof(out), &olen) == -1,
              "diag_read_frame returns -1 on EOF (write end closed)");
    }

    close(sv[0]);

    /* 3. diag_capture_open_retry. */
    {
        /* Transient-errno classifier: the grab/re-enum family retries; a bad
         * path (ENOENT) / no-device (ENXIO) fails fast. */
        check(diag_open_errno_is_transient(EBUSY), "EBUSY is transient");
        check(diag_open_errno_is_transient(EACCES), "EACCES is transient");
        check(diag_open_errno_is_transient(EAGAIN), "EAGAIN is transient");
        check(diag_open_errno_is_transient(ENODEV), "ENODEV is transient");
        check(!diag_open_errno_is_transient(ENOENT), "ENOENT is NOT transient");
        check(!diag_open_errno_is_transient(ENXIO), "ENXIO is NOT transient");

        /* A valid non-tty node opens on the first attempt. /dev/null is O_RDWR
         * openable and isatty()==false, so diag_capture_open returns its fd. */
        int fd = diag_capture_open_retry("/dev/null", 5, 200);
        check(fd >= 0, "retry opens /dev/null on the first attempt");
        if (fd >= 0)
            close(fd);

        /* A permanent failure (ENOENT) must fail FAST -- no retry sleeps eaten.
         * With attempts=5, delay=200ms a retrying-on-ENOENT bug would burn ~800ms;
         * the fast-fail path returns in well under that. */
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int bad = diag_capture_open_retry("/dev/celldiag_nonexistent_xyz", 5, 200);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        check(bad < 0, "retry fails on a nonexistent path");
        double elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                            (t1.tv_nsec - t0.tv_nsec) / 1e6;
        check(elapsed_ms < 100.0, "permanent failure fails fast (no retry sleeps)");
    }

    /* 4. Exclusive port claim (the celldiag half of the cellat port claim).
     *
     * Two processes reading one port do NOT each get a copy of the bytes -- the
     * kernel hands every byte to exactly one reader, so the stream is SPLIT.
     * On the AT side a sibling process can turn
     * 'EG25GGBR07A08M2G' into 'G5GR70MG' (every odd character). celldiag is
     * exposed to the same race from the other direction: cellat scans EVERY
     * port on the host looking for AT responders, and a DIAG port is one of the
     * ports it probes.
     *
     * flock() is advisory -- it only excludes other flock() users -- so the
     * claim is worthless unless BOTH binaries take it. diag_capture_open() must
     * therefore refuse a port another open-file-description holds, and must
     * release it on close so a skipped probe cannot strand the port. flock is
     * per-description, so one process suffices to prove it. */
    {
        int ptm = posix_openpt(O_RDWR | O_NOCTTY);
        if (ptm < 0 || grantpt(ptm) != 0 || unlockpt(ptm) != 0) {
            perror("posix_openpt");
            fail = 1;
        } else {
            const char *pts = ptsname(ptm);
            check(pts != NULL, "ptsname resolves the pty slave");
            if (pts) {
                int fd1 = diag_capture_open(pts);
                check(fd1 >= 0, "diag_capture_open claims a free port");

                int fd2 = diag_capture_open(pts);
                check(fd2 < 0,
                      "diag_capture_open REFUSES a port already claimed by another reader");
                if (fd2 >= 0)
                    close(fd2);   /* only reached while the bug is live */

                if (fd1 >= 0)
                    close(fd1);
                int fd3 = diag_capture_open(pts);
                check(fd3 >= 0, "port is claimable again once the holder closes it");
                if (fd3 >= 0)
                    close(fd3);
            }
            close(ptm);
        }
    }

    /* 5. The resync flag. A freshly claimed port is sent exactly one
     * lone 0x7E -- the "modem" end (the pty master) reads it and nothing else --
     * so junk a scanner left in the modem's HDLC parser cannot swallow our
     * first command. A port that is REFUSED (claimed elsewhere) gets nothing. */
    {
        int ptm = posix_openpt(O_RDWR | O_NOCTTY);
        if (ptm < 0 || grantpt(ptm) != 0 || unlockpt(ptm) != 0) {
            perror("posix_openpt");
            fail = 1;
        } else {
            const char *pts = ptsname(ptm);
            check(pts != NULL, "ptsname resolves the pty slave (resync)");
            if (pts) {
                int fd = diag_capture_open(pts);
                check(fd >= 0, "diag_capture_open opens the port (resync)");
                uint8_t got[8];
                ssize_t n = 0;
                struct pollfd p = { .fd = ptm, .events = POLLIN };
                if (poll(&p, 1, 1000) == 1)
                    n = read(ptm, got, sizeof(got));
                check(n == 1 && got[0] == DIAG_FLAG,
                      "an open sends exactly one lone 0x7E to the modem end");

                int refused = diag_capture_open(pts);
                check(refused < 0, "a second open of the claimed port is refused");
                if (refused >= 0)
                    close(refused);
                p.revents = 0;
                check(poll(&p, 1, 200) == 0,
                      "a REFUSED open writes nothing into the port");
                if (fd >= 0)
                    close(fd);
            }
            close(ptm);
        }
    }

    /* 6. The resync flag on a NON-tty node -- the path a PCIe modem's
     * /dev/mhi_DIAG takes, which returns before any termios work. A FIFO is a
     * non-tty node that can be opened by path; the test's own read end sees
     * what diag_capture_open() wrote. */
    {
        char fifo[] = "/tmp/diag_capture_selftest_fifoXXXXXX";
        int tmp = mkstemp(fifo);
        if (tmp >= 0) {
            close(tmp);
            unlink(fifo);
        }
        if (tmp < 0 || mkfifo(fifo, 0600) != 0) {
            perror("mkfifo");
            fail = 1;
        } else {
            int rd = open(fifo, O_RDONLY | O_NONBLOCK);
            check(rd >= 0, "open the FIFO's read end");
            int fd = diag_capture_open(fifo);
            check(fd >= 0 && !isatty(fd), "diag_capture_open opens a non-tty node");
            uint8_t got[8];
            ssize_t n = rd >= 0 ? read(rd, got, sizeof(got)) : -1;
            check(n == 1 && got[0] == DIAG_FLAG,
                  "a non-tty open sends exactly one lone 0x7E too");
            if (fd >= 0)
                close(fd);
            if (rd >= 0)
                close(rd);
            unlink(fifo);
        }
    }

    if (fail) {
        fprintf(stderr, "diag_capture selftest: FAILURES\n");
        return 1;
    }
    printf("diag_capture selftest: all passed\n");
    return 0;
}
#endif /* DIAG_CAPTURE_SELFTEST */
