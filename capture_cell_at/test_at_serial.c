/* test_at_serial.c - selftest for the AT-over-serial core (at_serial.inc).
 *
 * Build:
 *   cc -Wall -Wextra -Werror test_at_serial.c -o /tmp/test_at_serial \
 *      && /tmp/test_at_serial
 *
 * Drives at_command() over a socketpair -- a NON-tty fd, the exact transport
 * class that the isatty()/poll() read path supports (an MHI /dev/mhi_DUN behaves
 * the same: raw byte pipe, no line discipline, poll-driven timeout, EOF on
 * close). A fork()ed child plays a mock modem.
 */
/* _GNU_SOURCE rather than _XOPEN_SOURCE=600: posix_openpt() needs XOPEN, but
 * at_serial.inc needs CRTSCTS, which _XOPEN_SOURCE alone would hide. On glibc
 * _GNU_SOURCE enables both. Must precede every include.
 *
 * That reasoning is glibc-only. The file is also correct on Darwin, for a
 * different reason, and that reason is the rule for auditing any other file
 * here. `_GNU_SOURCE` is a glibc macro; Darwin's libc ignores it. It is also
 * not a STRICT macro, so Darwin's `_DARWIN_C_SOURCE` default stays on and both
 * symbols remain visible. Only a strict macro (`_XOPEN_SOURCE`,
 * `_POSIX_C_SOURCE`) switches that default off, which is what breaks a
 * selftest build on Darwin. */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>     /* posix_openpt/grantpt/unlockpt/ptsname -- test 3's PTY */
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include "at_serial.inc"

static int fail;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        fail = 1;
    }
}

static long elapsed_ms(struct timeval a, struct timeval b) {
    return (b.tv_sec - a.tv_sec) * 1000 + (b.tv_usec - a.tv_usec) / 1000;
}

/* Test 1: happy path -- a mock modem answers a command with a body + OK over a
 * non-tty socketpair; at_command must return the body (echo + terminal stripped). */
static void test_happy_path(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }

    check(!isatty(sv[0]) && !isatty(sv[1]), "socketpair endpoints are non-tty");

    pid_t pid = fork();
    if (pid == 0) {
        /* mock modem */
        close(sv[0]);
        char buf[256];
        (void)!read(sv[1], buf, sizeof(buf));               /* consume "ATI\r\n" */
        const char *reply = "ATI\r\nQuectel\r\nRM520N-GL\r\nOK\r\n";
        (void)!write(sv[1], reply, strlen(reply));
        usleep(50 * 1000);
        close(sv[1]);
        _exit(0);
    }
    close(sv[1]);

    char resp[256];
    int n = at_command(sv[0], "ATI", resp, sizeof(resp), 2000);
    check(n > 0, "at_command returns a response over a non-tty");
    check(strstr(resp, "Quectel") != NULL, "response body preserved (Quectel)");
    check(strstr(resp, "RM520N-GL") != NULL, "response body preserved (model)");
    check(strstr(resp, "OK") != NULL, "terminal OK line retained (pre-existing behavior)");
    check(strstr(resp, "ATI") == NULL, "command echo line is stripped");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* Test 2: timeout without hang -- the mock modem stays connected but silent for
 * 1s, then exits. at_command with a 200ms timeout must return via poll() well
 * before the child closes the fd. A regression (blocking read with no VTIME on a
 * non-tty) would instead block until the child's 1s exit (or forever). */
static void test_timeout_no_hang(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }

    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        char buf[256];
        (void)!read(sv[1], buf, sizeof(buf));   /* consume the command, send nothing */
        usleep(1000 * 1000);                    /* hold the fd open, silent, 1s */
        close(sv[1]);
        _exit(0);
    }
    close(sv[1]);

    char resp[64];
    struct timeval t0, t1;
    gettimeofday(&t0, NULL);
    int n = at_command(sv[0], "AT", resp, sizeof(resp), 200);
    gettimeofday(&t1, NULL);
    long ms = elapsed_ms(t0, t1);

    check(n >= 0, "at_command does not error on a silent non-tty port");
    check(ms < 700, "poll() times out the read (returned before the 1s child exit)");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* Test 3: exclusive port claim.
 *
 * Two cellat capture processes each scan EVERY /dev/ttyUSB* on the host,
 * including ports belonging to the other modem. Without an exclusive claim both
 * open the same port, both write AT+CGMR, and at_command_log's one-byte-at-a-time
 * read() splits the reply between them -- the kernel gives each byte to exactly
 * one reader, so 'EG25GGBR07A08M2G' can come back as 'G5GR70MG', every odd
 * character, the sibling process having eaten the even ones. The same race
 * corrupts the AT+CGSN IMEI read that identify_modem() matches on, so a source
 * can fail to open or bind a different port run-to-run.
 *
 * serial_open() must therefore refuse a port another open-file-description
 * already holds. flock() is per-description, so a second serial_open() of the
 * same path -- even from this one process -- must fail, and the claim must be
 * released when the holder closes.
 */
static void test_exclusive_claim(void) {
    int ptm = posix_openpt(O_RDWR | O_NOCTTY);
    if (ptm < 0 || grantpt(ptm) != 0 || unlockpt(ptm) != 0) {
        perror("posix_openpt");
        fail = 1;
        return;
    }
    const char *path = ptsname(ptm);
    if (!path) { perror("ptsname"); fail = 1; close(ptm); return; }

    int fd1 = serial_open(path, 115200);
    check(fd1 >= 0, "serial_open claims a free port");

    errno = 0;
    int fd2 = serial_open(path, 115200);
    int fd2_errno = errno;
    check(fd2 < 0, "serial_open REFUSES a port already claimed by another reader");
    if (fd2 >= 0)
        close(fd2);   /* only reached while the bug is live */
    /* ...and says WHY: a scan must tell "another process is probing this
     * port right now" from "no modem answers here". For a modem with ONE AT
     * node (/dev/mhi_DUN on a PCIe RM520N-GL) the busy port IS the target, and
     * a concurrent multi-source open that cannot tell the difference reports
     * the modem "not found". The errno must survive the close() of the refused
     * fd. */
    check(fd2_errno == EWOULDBLOCK,
          "the refusal reports EWOULDBLOCK (busy), not an unrelated errno");

    /* Releasing the claim must make the port available again -- a probing pass
     * that skipped a busy port must not poison it for the real open that
     * follows. */
    close(fd1);
    int fd3 = serial_open(path, 115200);
    check(fd3 >= 0, "port is claimable again once the holder closes it");
    if (fd3 >= 0)
        close(fd3);

    close(ptm);
}

/*
 * test 4: serial_open_claim() waits out a claim, boundedly
 *
 * cellat's scan identifies a modem, RELEASES the port, then opens it again for
 * ongoing use. A sibling source's scan can take the claim in between, and a
 * plain serial_open() is then refused EWOULDBLOCK: the source fails its launch
 * with "Resource temporarily unavailable". The claim is held
 * here by a forked child -- a real second process, as a sibling source is.
 */
static pid_t hold_claim(const char *path, long hold_ms) {
    int p[2];
    if (pipe(p) != 0)
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
        char ok = (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0) ? '1' : '0';
        (void)!write(p[1], &ok, 1);
        usleep((useconds_t)hold_ms * 1000);
        _exit(0);
    }
    close(p[1]);
    char ok = '0';
    (void)!read(p[0], &ok, 1);
    close(p[0]);
    return ok == '1' ? pid : -1;
}

static void test_claim_wait(void) {
    int ptm = posix_openpt(O_RDWR | O_NOCTTY);
    if (ptm < 0 || grantpt(ptm) != 0 || unlockpt(ptm) != 0) {
        perror("posix_openpt");
        fail = 1;
        return;
    }
    char path[128];
    snprintf(path, sizeof(path), "%s", ptsname(ptm));
    long waited = -1;

    /* A free port: no wait at all. */
    int fd = serial_open_claim(path, 115200, 3000, &waited);
    check(fd >= 0 && waited == 0, "a free port opens at once, waited_ms == 0");
    if (fd >= 0)
        close(fd);

    /* A sibling's probe: held 300 ms, then released. */
    pid_t holder = hold_claim(path, 300);
    check(holder > 0, "positive control: the child holds the claim");
    fd = serial_open(path, 115200);
    check(fd < 0 && errno == EWOULDBLOCK,
          "...and a plain serial_open() is refused EWOULDBLOCK");
    if (fd >= 0)
        close(fd);
    fd = serial_open_claim(path, 115200, 3000, &waited);
    check(fd >= 0, "serial_open_claim takes the port once the probe lets go");
    check(waited >= 150 && waited < 1500, "...after waiting roughly the hold");
    if (fd >= 0)
        close(fd);
    if (holder > 0)
        waitpid(holder, NULL, 0);

    /* A real conflict: held past the budget. Fails EWOULDBLOCK, bounded. */
    holder = hold_claim(path, 3000);
    struct timeval a, b;
    gettimeofday(&a, NULL);
    fd = serial_open_claim(path, 115200, 500, &waited);
    int claim_errno = errno;
    gettimeofday(&b, NULL);
    check(fd < 0 && claim_errno == EWOULDBLOCK,
          "a claim held past the budget still fails, errno EWOULDBLOCK");
    check(waited >= 500 && elapsed_ms(a, b) < 1500,
          "...after the budget, not the holder's 3 s");
    if (fd >= 0)
        close(fd);
    if (holder > 0) {
        kill(holder, SIGKILL);
        waitpid(holder, NULL, 0);
    }

    /* Any other failure is immediate: only a busy claim is waited on. */
    gettimeofday(&a, NULL);
    fd = serial_open_claim("/dev/does-not-exist-4751", 115200, 3000, &waited);
    claim_errno = errno;
    gettimeofday(&b, NULL);
    check(fd < 0 && claim_errno == ENOENT && waited == 0 && elapsed_ms(a, b) < 500,
          "a missing path fails at once with ENOENT, no wait");

    close(ptm);
}

/* ---- the exchange's inner instants ---- */

#define MS_NS 1000000ULL

/* A mock modem that ECHOES the command at once, thinks `think_ms`, sends the
 * body line, takes `xfer_ms` more, then sends `term` (NULL: never terminates,
 * holds the line open `hold_ms` instead). The echo is the point: a real modem
 * echoes before ATE0, and it arrives before any thinking has happened. */
static pid_t paced_modem(int fd, const char *echo, int think_ms,
                         const char *body, int xfer_ms, const char *term,
                         int hold_ms) {
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    char buf[256];
    (void)!read(fd, buf, sizeof(buf));
    if (echo)
        (void)!write(fd, echo, strlen(echo));
    usleep((useconds_t)think_ms * 1000);
    if (body)
        (void)!write(fd, body, strlen(body));
    usleep((useconds_t)xfer_ms * 1000);
    if (term)
        (void)!write(fd, term, strlen(term));
    usleep((useconds_t)hold_ms * 1000);
    close(fd);
    _exit(0);
}

/* Test 5: think-time and transfer time come out separately, and the echo does
 * not start the response. The positive control is the delays themselves: each
 * interval must be at least what the mock slept, and not wildly more. */
static void test_timing_splits_think_and_transfer(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], "AT+QENG\r\n", 150, "\r\n+QENG: 1\r\n", 100,
                            "\r\nOK\r\n", 50);
    close(sv[1]);

    at_timing_t tm;
    char resp[256];
    uint64_t t0 = at_mono_ns();
    int n = at_command_log(sv[0], "AT+QENG", resp, sizeof(resp), 2000, -1, &tm);
    uint64_t t1 = at_mono_ns();

    check(n > 0 && strstr(resp, "+QENG: 1") != NULL, "timed exchange still returns the body");
    check(tm.tx_done_ns != 0 && tm.first_rx_ns != 0 && tm.rx_done_ns != 0,
          "a completed exchange reports all three instants");
    check(t0 <= tm.tx_done_ns && tm.tx_done_ns <= tm.first_rx_ns &&
          tm.first_rx_ns <= tm.rx_done_ns && tm.rx_done_ns <= t1,
          "instants are ordered and inside the call");
    check(tm.tx_done_ns - t0 < 50 * MS_NS, "TX cost is small (no modem time in it)");
    check(tm.first_rx_ns - tm.tx_done_ns >= 140 * MS_NS,
          "think-time covers the modem's 150 ms -- the echo did NOT start the response");
    check(tm.first_rx_ns - tm.tx_done_ns < 600 * MS_NS, "think-time is not wildly over");
    check(tm.rx_done_ns - tm.first_rx_ns >= 90 * MS_NS,
          "transfer covers the 100 ms between the body and OK");
    check(tm.rx_done_ns - tm.first_rx_ns < 600 * MS_NS, "transfer is not wildly over");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* Test 6: a bare OK (ATE0) is both the first and the terminal line. */
static void test_timing_bare_ok(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], "ATE0\r\n", 80, NULL, 0, "\r\nOK\r\n", 50);
    close(sv[1]);

    at_timing_t tm;
    char resp[64];
    int n = at_command_log(sv[0], "ATE0", resp, sizeof(resp), 2000, -1, &tm);
    check(n >= 0 && strcmp(resp, "OK") == 0, "bare OK returned");
    check(tm.first_rx_ns != 0 && tm.rx_done_ns != 0, "bare OK: first_rx and rx_done set");
    check(tm.first_rx_ns - tm.tx_done_ns >= 70 * MS_NS, "bare OK: think-time is the 80 ms, not the echo");
    check(tm.rx_done_ns >= tm.first_rx_ns && tm.rx_done_ns - tm.first_rx_ns < 50 * MS_NS,
          "bare OK: one short line, transfer ~0");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* Test 7: a reply that never terminates. The body arrived, so first_rx is
 * set; no OK arrived, so rx_done stays 0 -- the record can say "incomplete"
 * without anyone parsing the text. Positive control: the same mock with a
 * terminator (test 5) does set rx_done. */
static void test_timing_timeout_has_no_rx_done(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], NULL, 20, "\r\n+COPS: (1,\"x\")\r\n", 0, NULL, 800);
    close(sv[1]);

    at_timing_t tm;
    char resp[128];
    int n = at_command_log(sv[0], "AT+COPS=?", resp, sizeof(resp), 300, -1, &tm);
    check(n > 0, "timed-out exchange keeps the partial body");
    check(tm.tx_done_ns != 0, "timeout: tx_done set");
    check(tm.first_rx_ns != 0, "timeout: first_rx set (a line did arrive)");
    check(tm.rx_done_ns == 0, "timeout: rx_done is 0 -- the reply never completed");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* Test 8: silence, and a write that fails. Silence: TX happened, nothing
 * else. A failed write (peer gone): nothing at all, including stale values the
 * caller left in the struct -- it is zeroed on entry. */
static void test_timing_silent_and_failed_write(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], NULL, 0, NULL, 0, NULL, 600);
    close(sv[1]);

    at_timing_t tm;
    char resp[64];
    (void)at_command_log(sv[0], "AT", resp, sizeof(resp), 200, -1, &tm);
    check(tm.tx_done_ns != 0 && tm.first_rx_ns == 0 && tm.rx_done_ns == 0,
          "silent modem: tx_done only");
    close(sv[0]);
    waitpid(pid, NULL, 0);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    close(sv[1]);                                   /* peer gone: write() fails EPIPE */
    tm.tx_done_ns = tm.first_rx_ns = tm.rx_done_ns = 12345;
    int n = at_command_log(sv[0], "AT", resp, sizeof(resp), 200, -1, &tm);
    check(n == -1, "failed write returns -1");
    check(tm.tx_done_ns == 0 && tm.first_rx_ns == 0 && tm.rx_done_ns == 0,
          "failed write: all three 0, caller's stale values cleared");
    close(sv[0]);

    tm.tx_done_ns = tm.first_rx_ns = tm.rx_done_ns = 12345;
    n = at_command_log(-1, "AT", resp, sizeof(resp), 200, -1, &tm);
    check(n == -1 && tm.tx_done_ns == 0 && tm.first_rx_ns == 0 && tm.rx_done_ns == 0,
          "fd < 0: -1 and all three 0");
}

/* ---- chunked reads ---- */

/* Test 9: a reply the modem sent in ONE write comes back in one read(), so its
 * first and terminal lines share that read's instant -- zero transfer. ~3 KB,
 * the size of a full neighbour-cell dump: read a byte at a time, a pty spends
 * 13-18 ms on it with nothing on the wire, and all of it reads as "transfer". */
static void test_timing_burst_reply_reads_as_zero_transfer(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    static char burst[3400];
    size_t len = 0;
    const char *line =
        "\r\n+QENG: \"neighbourcell intra\",\"LTE\",66536,221,-96,-11,-56,14,0,-,29,-,-,-,-";
    for (int i = 0; i < 40; i++)
        len += (size_t)snprintf(burst + len, sizeof(burst) - len, "%s", line);
    snprintf(burst + len, sizeof(burst) - len, "\r\n\r\nOK\r\n");
    pid_t pid = paced_modem(sv[1], NULL, 20, NULL, 0, burst, 300);
    close(sv[1]);

    at_timing_t tm;
    static char resp[4096];
    int n = at_command_log(sv[0], "AT+QENG=\"neighbourcell\"", resp, sizeof(resp),
                           2000, -1, &tm);
    uint64_t t1 = at_mono_ns();
    check(n > 2900 && strcmp(resp + n - 3, "\nOK") == 0,
          "burst: the whole ~3 KB reply came back, OK last");
    check(tm.first_rx_ns != 0 && tm.rx_done_ns != 0, "burst: first_rx and rx_done set");
    check(tm.rx_done_ns == tm.first_rx_ns,
          "burst: one read, one instant -- rx_done == first_rx (zero transfer)");
    /* The mock holds the line open 300 ms after OK: the call must return AT
     * the terminal line, not when the line goes quiet or the deadline hits. */
    check(tm.rx_done_ns != 0 && t1 - tm.rx_done_ns < 100 * MS_NS,
          "burst: the call returns at OK, not when the line goes quiet");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* A mock modem for two exchanges: answers the first command with `reply1` in
 * one write, then the second with `reply2` after `gap_ms`. */
static pid_t two_reply_modem(int fd, const char *reply1, int gap_ms, const char *reply2) {
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    char buf[256];
    (void)!read(fd, buf, sizeof(buf));
    (void)!write(fd, reply1, strlen(reply1));
    (void)!read(fd, buf, sizeof(buf));
    usleep((useconds_t)gap_ms * 1000);
    (void)!write(fd, reply2, strlen(reply2));
    usleep(50 * 1000);
    close(fd);
    _exit(0);
}

/* Test 10: a URC the modem sent right after OK, in the same write, is not the
 * NEXT exchange's reply. The read that completed OK delivered it too, and it is
 * dropped with the rest of that read. On a tty the next exchange's tcflush()
 * drops it; on a non-tty nothing flushes, so a reader that left it buffered
 * would hand it to the next command as its own first line and stamp first_rx
 * on it before the modem had thought at all. */
static void test_urc_after_ok_is_not_the_next_reply(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = two_reply_modem(sv[1], "\r\nOK\r\n\r\n+QIND: SMS DONE\r\n", 60, "\r\nOK\r\n");
    close(sv[1]);

    char resp[256];
    at_timing_t tm;
    int n = at_command_log(sv[0], "AT+CFUN?", resp, sizeof(resp), 2000, -1, NULL);
    check(n >= 0 && strcmp(resp, "OK") == 0, "URC after OK: the first reply is just OK");
    n = at_command_log(sv[0], "AT", resp, sizeof(resp), 2000, -1, &tm);
    check(n >= 0 && strcmp(resp, "OK") == 0,
          "URC after OK: the next reply is its own OK, not the leftover URC");
    check(tm.first_rx_ns != 0 && tm.first_rx_ns - tm.tx_done_ns >= 50 * MS_NS,
          "URC after OK: the next reply's think-time is the modem's 60 ms, not a leftover");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* Test 11: a line that arrives in two reads is stamped by the FIRST one --
 * first_rx_ns is when the response's first byte was read, not when its line
 * was completed 120 ms later. */
static void test_timing_split_line_keeps_the_first_reads_instant(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], NULL, 20, "\r\n+QENG: part", 120, "one\r\n\r\nOK\r\n", 50);
    close(sv[1]);

    at_timing_t tm;
    char resp[256];
    int n = at_command_log(sv[0], "AT+QENG", resp, sizeof(resp), 2000, -1, &tm);
    check(n > 0 && strstr(resp, "+QENG: partone") != NULL,
          "split line: the two reads join into one line");
    check(tm.first_rx_ns != 0 && tm.first_rx_ns - tm.tx_done_ns < 100 * MS_NS,
          "split line: first_rx is the first read (~20 ms), not the line's completion (~140 ms)");
    check(tm.rx_done_ns - tm.first_rx_ns >= 100 * MS_NS,
          "split line: transfer covers the 120 ms between the two halves");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* ---- the info form ---- */

/* The T99W175 shape: echo, the value ~50 ms later, then NOTHING. The info form
 * returns on the idle gap with the value; rx_done_ns stays 0 because no
 * terminal line was read. */
static void test_info_unterminated_value_ends_on_the_gap(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], "AT+CGMR\r\r\n", 50,
                            "T99W175.F0.1.0.0.9.GC.004\r\n", 0, NULL, 2000);
    close(sv[1]);

    at_timing_t tm;
    char resp[256];
    struct timeval a, b;
    gettimeofday(&a, NULL);
    int n = at_command_log_ex(sv[0], "AT+CGMR", resp, sizeof(resp), 3000, -1, &tm, 200);
    gettimeofday(&b, NULL);

    check(n > 0 && strstr(resp, "T99W175.F0.1.0.0.9.GC.004") != NULL,
          "info form: the unterminated value is returned");
    check(elapsed_ms(a, b) < 700, "info form: ends on the 200 ms gap, not the 3 s deadline");
    check(elapsed_ms(a, b) >= 200, "info form: waited out the gap after the value");
    check(tm.first_rx_ns != 0 && tm.rx_done_ns == 0,
          "info form: no terminal line read -> rx_done_ns stays 0");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* The ORDINARY form is unchanged: the same unterminated reply runs to its
 * deadline. */
static void test_ordinary_form_still_waits_for_a_terminator(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], "AT+CGMR\r\r\n", 50,
                            "T99W175.F0.1.0.0.9.GC.004\r\n", 0, NULL, 2000);
    close(sv[1]);

    char resp[256];
    struct timeval a, b;
    gettimeofday(&a, NULL);
    int n = at_command(sv[0], "AT+CGMR", resp, sizeof(resp), 900);
    gettimeofday(&b, NULL);

    check(n > 0 && strstr(resp, "T99W175") != NULL, "ordinary form: value collected");
    check(elapsed_ms(a, b) >= 850, "ordinary form: waited its whole 900 ms deadline");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* A LATE OK from the previous exchange arrives ahead of this one's answer. The
 * info form must not end on it: it keeps reading, takes the value, and ends on
 * the real OK after it. */
static void test_info_late_ok_is_not_the_end_of_the_reply(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], NULL, 0, "\r\nOK\r\n", 100,
                            "\r\nQUALCOMM\r\nOK\r\n", 300);
    close(sv[1]);

    at_timing_t tm;
    char resp[256];
    struct timeval a, b;
    gettimeofday(&a, NULL);
    int n = at_command_log_ex(sv[0], "AT+CGMI", resp, sizeof(resp), 3000, -1, &tm, 200);
    gettimeofday(&b, NULL);

    check(n > 0 && strstr(resp, "QUALCOMM") != NULL,
          "info form: a stray OK before the value did not end the read");
    check(tm.rx_done_ns != 0, "info form: ended on the REAL OK, after the value");
    check(elapsed_ms(a, b) < 700, "info form: and promptly");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* An info reply that is only OK (no value) still ends -- on the gap, at a cost
 * of the gap, never the deadline. */
static void test_info_ok_only_reply_ends_on_the_gap(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], NULL, 30, NULL, 0, "\r\nOK\r\n", 1500);
    close(sv[1]);

    char resp[256];
    struct timeval a, b;
    gettimeofday(&a, NULL);
    int n = at_info_command(sv[0], "AT+CGMM", resp, sizeof(resp), 3000, 200);
    gettimeofday(&b, NULL);

    check(n > 0 && strcmp(resp, "OK") == 0, "info form: an OK-only reply reads as OK");
    check(elapsed_ms(a, b) < 700, "info form: an OK-only reply costs the gap, not the deadline");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* A modem that terminates promptly is read exactly as the ordinary form reads
 * it: value + OK, ended on the OK (rx_done_ns set), no gap waited. */
static void test_info_terminated_reply_is_read_as_before(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = paced_modem(sv[1], "AT+CGSN\r\r\n", 20, "\r\n860000000000000\r\n", 5,
                            "\r\nOK\r\n", 1500);
    close(sv[1]);

    at_timing_t tm;
    char resp[256];
    struct timeval a, b;
    gettimeofday(&a, NULL);
    int n = at_command_log_ex(sv[0], "AT+CGSN", resp, sizeof(resp), 3000, -1, &tm, 200);
    gettimeofday(&b, NULL);

    check(n > 0 && strstr(resp, "860000000000000") != NULL && strstr(resp, "OK") != NULL,
          "info form: a terminated reply keeps value and OK");
    check(tm.rx_done_ns != 0, "info form: a terminated reply ends on its OK");
    check(elapsed_ms(a, b) < 180, "info form: a terminated reply waits no gap");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* ---- a late OK after a gap-ended info read ---- */

/* Two exchanges. The first is an info read: the modem sends `value1` and,
 * if late_ok_ms >= 0, its final OK `late_ok_ms` later -- past the 200 ms gap,
 * so it lands AFTER the reader has sent the next command. The second command
 * is answered `think_ms` after the modem reads it, with `reply2`. */
static pid_t late_ok_modem(int fd, const char *value1, int late_ok_ms,
                           int think_ms, const char *reply2) {
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    char buf[256];
    (void)!read(fd, buf, sizeof(buf));
    (void)!write(fd, value1, strlen(value1));
    if (late_ok_ms >= 0) {
        usleep((useconds_t)late_ok_ms * 1000);
        (void)!write(fd, "\r\nOK\r\n", 6);
    }
    (void)!read(fd, buf, sizeof(buf));
    usleep((useconds_t)think_ms * 1000);
    (void)!write(fd, reply2, strlen(reply2));
    usleep(1500 * 1000);
    close(fd);
    _exit(0);
}

/* The shape: detect_vendor's AT+CGMI ends on the gap, its OK arrives
 * ~150 ms into the next exchange, and the next exchange is ORDINARY. It must
 * not end on that OK: it takes its own answer, and the late OK is not in it. */
static void test_late_ok_does_not_end_the_next_ordinary_read(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = late_ok_modem(sv[1], "\r\nQuectel\r\n", 350, 100,
                              "\r\n+QENG: \"servingcell\",\"NOCONN\"\r\n\r\nOK\r\n");
    close(sv[1]);

    char resp[256];
    int n = at_info_command(sv[0], "AT+CGMI", resp, sizeof(resp), 3000, 200);
    check(n > 0 && strstr(resp, "Quectel") != NULL, "late OK: the info read took its value");

    at_timing_t tm;
    n = at_command_log(sv[0], "AT+QENG=\"servingcell\"", resp, sizeof(resp), 3000, -1, &tm);
    check(n > 0 && strstr(resp, "+QENG:") != NULL,
          "late OK: the next ORDINARY read did not end on the previous exchange's OK");
    check(strncmp(resp, "+QENG:", 6) == 0,
          "late OK: the previous exchange's OK is not part of this reply");
    check(tm.rx_done_ns != 0, "late OK: the reply ended on its OWN OK");
    check(tm.first_rx_ns != 0 && tm.first_rx_ns - tm.tx_done_ns >= 200 * MS_NS,
          "late OK: first_rx is the real answer (~230 ms), not the late OK (~130 ms)");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* The same, where the next reply is ONLY an OK (ATE0 on an echo-off modem):
 * the late OK is dropped and the reply ends on the second, real OK. */
static void test_late_ok_then_a_bare_ok_reply(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = late_ok_modem(sv[1], "\r\nQuectel\r\n", 350, 100, "\r\nOK\r\n");
    close(sv[1]);

    char resp[256];
    (void)at_info_command(sv[0], "AT+CGMI", resp, sizeof(resp), 3000, 200);

    at_timing_t tm;
    int n = at_command_log(sv[0], "ATE0", resp, sizeof(resp), 3000, -1, &tm);
    check(n >= 0 && strcmp(resp, "OK") == 0, "late OK + bare OK: the reply reads as one OK");
    check(tm.rx_done_ns != 0 && tm.rx_done_ns - tm.tx_done_ns >= 200 * MS_NS,
          "late OK + bare OK: ended on the real OK (~230 ms), not the late one (~130 ms)");
    /* One late OK is owed, not two: the real OK ends the read when it is read,
     * it is not held for a second gap. */
    check(at_mono_ns() - tm.rx_done_ns < 100 * MS_NS,
          "late OK + bare OK: returned AT the real OK, not a second gap after it");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* No late OK ever comes (the T99W175 never terminates an info reply): the
 * next ordinary read's own bare OK is still its answer. Holding it costs the
 * gap, once -- never the deadline. */
static void test_no_late_ok_the_next_bare_ok_costs_only_the_gap(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = late_ok_modem(sv[1], "\r\nQUALCOMM\r\n", -1, 20, "\r\nOK\r\n");
    close(sv[1]);

    char resp[256];
    (void)at_info_command(sv[0], "AT+CGMI", resp, sizeof(resp), 3000, 200);

    at_timing_t tm;
    struct timeval a, b;
    gettimeofday(&a, NULL);
    int n = at_command_log(sv[0], "ATE0", resp, sizeof(resp), 3000, -1, &tm);
    gettimeofday(&b, NULL);
    check(n >= 0 && strcmp(resp, "OK") == 0, "no late OK: the bare OK is the reply");
    check(elapsed_ms(a, b) < 700, "no late OK: it costs the gap, not the 3 s deadline");
    check(tm.first_rx_ns != 0 && tm.rx_done_ns != 0 &&
          tm.rx_done_ns - tm.tx_done_ns < 150 * MS_NS,
          "no late OK: rx_done is when the OK was READ (~20 ms), not when the gap closed");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* Only a GAP-ended info read owes a late OK. After one that ended on its own
 * OK, the next bare-OK reply ends at once. */
static void test_a_terminated_info_read_owes_nothing(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    pid_t pid = late_ok_modem(sv[1], "\r\nQuectel\r\n\r\nOK\r\n", -1, 20, "\r\nOK\r\n");
    close(sv[1]);

    char resp[256];
    (void)at_info_command(sv[0], "AT+CGMI", resp, sizeof(resp), 3000, 200);

    struct timeval a, b;
    gettimeofday(&a, NULL);
    int n = at_command(sv[0], "ATE0", resp, sizeof(resp), 3000);
    gettimeofday(&b, NULL);
    check(n >= 0 && strcmp(resp, "OK") == 0, "terminated info read: the next OK is the reply");
    check(elapsed_ms(a, b) < 150, "terminated info read: the next OK ends it at once (no gap)");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

/* What a fd owes belongs to the PORT it was open on. A port closed after a
 * gap-ended info read and a new open that gets the same fd number back owe
 * nothing: serial_open() clears it. On a PTY, since serial_open() refuses
 * anything else; a plain (unclaimed) slave fd keeps the pty alive across the
 * close and is opened first, so the claimed fd number is the one reused. */
static void test_a_reopened_port_owes_nothing(void) {
    int ptm = posix_openpt(O_RDWR | O_NOCTTY);
    if (ptm < 0 || grantpt(ptm) != 0 || unlockpt(ptm) != 0) {
        perror("posix_openpt");
        fail = 1;
        return;
    }
    const char *path = ptsname(ptm);
    int keep = path ? open(path, O_RDWR | O_NOCTTY) : -1;
    int fd = keep >= 0 ? serial_open(path, 115200) : -1;
    if (fd < 0) { perror("reopen setup"); fail = 1; close(ptm); return; }

    pid_t pid = fork();
    if (pid == 0) {
        /* The child's copies of the slave fds share their open file
         * descriptions -- and the claimed one's flock -- so they must go, or
         * the parent's reopen is refused as busy. */
        close(fd);
        close(keep);
        char buf[256];
        (void)!read(ptm, buf, sizeof(buf));              /* AT+CGMI */
        (void)!write(ptm, "\r\nQuectel\r\n", 11);         /* ...and no OK */
        (void)!read(ptm, buf, sizeof(buf));              /* ATE0 */
        usleep(20 * 1000);
        (void)!write(ptm, "\r\nOK\r\n", 6);
        usleep(1000 * 1000);
        _exit(0);
    }

    char resp[256];
    (void)at_info_command(fd, "AT+CGMI", resp, sizeof(resp), 3000, 200);
    int old_fd = fd;
    close(fd);
    fd = serial_open(path, 115200);
    check(fd == old_fd, "reopen: the new open reused the fd number (else this proves nothing)");

    struct timeval a, b;
    gettimeofday(&a, NULL);
    int n = at_command(fd, "ATE0", resp, sizeof(resp), 3000);
    gettimeofday(&b, NULL);
    check(n >= 0 && strcmp(resp, "OK") == 0, "reopen: the bare OK is the reply");
    check(elapsed_ms(a, b) < 150, "reopen: a fresh port holds nothing (no gap waited)");

    if (fd >= 0)
        close(fd);
    close(keep);
    kill(pid, SIGKILL);     /* a failed reopen never sent ATE0: do not wait on it */
    waitpid(pid, NULL, 0);
    close(ptm);
}

/* A reply another process left unread on a non-tty node -- an ATI answer still
 * in an MHI pipe when this port is opened -- is not the next command's answer.
 * On a tty the exchange's tcflush() drops it; a non-tty node is drained. Not
 * covered by the same-read URC drop (test 10) or the late-OK hold: neither
 * reply came from an exchange of this fd. */
static void test_stale_reply_on_a_nontty_is_not_the_next_answer(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); fail = 1; return; }
    const char *stale = "\r\nQuectel\r\nRM520N-GL\r\n\r\nOK\r\n";
    (void)!write(sv[1], stale, strlen(stale));   /* waiting before the exchange */

    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        char buf[256];
        (void)!read(sv[1], buf, sizeof(buf));    /* consume "AT+CGSN\r\n" */
        usleep(30 * 1000);
        const char *reply = "\r\n860000000000000\r\n\r\nOK\r\n";
        (void)!write(sv[1], reply, strlen(reply));
        usleep(50 * 1000);
        close(sv[1]);
        _exit(0);
    }
    close(sv[1]);

    char resp[256];
    int n = at_info_command(sv[0], "AT+CGSN", resp, sizeof(resp), 2000, 200);
    check(n > 0 && strncmp(resp, "860000000000000", 15) == 0,
          "stale reply: the answer is the IMEI, not the leftover 'Quectel'");
    check(strstr(resp, "Quectel") == NULL && strstr(resp, "RM520N-GL") == NULL,
          "stale reply: no leftover line rides in the answer");

    close(sv[0]);
    waitpid(pid, NULL, 0);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);   /* writing to a closed peer must not kill us */

    test_happy_path();
    test_timeout_no_hang();
    test_exclusive_claim();
    test_claim_wait();
    test_timing_splits_think_and_transfer();
    test_timing_bare_ok();
    test_timing_timeout_has_no_rx_done();
    test_timing_silent_and_failed_write();
    test_timing_burst_reply_reads_as_zero_transfer();
    test_urc_after_ok_is_not_the_next_reply();
    test_timing_split_line_keeps_the_first_reads_instant();
    test_info_unterminated_value_ends_on_the_gap();
    test_ordinary_form_still_waits_for_a_terminator();
    test_info_late_ok_is_not_the_end_of_the_reply();
    test_info_ok_only_reply_ends_on_the_gap();
    test_info_terminated_reply_is_read_as_before();
    test_late_ok_does_not_end_the_next_ordinary_read();
    test_late_ok_then_a_bare_ok_reply();
    test_no_late_ok_the_next_bare_ok_costs_only_the_gap();
    test_a_terminated_info_read_owes_nothing();
    test_a_reopened_port_owes_nothing();
    test_stale_reply_on_a_nontty_is_not_the_next_answer();

    if (fail) {
        fprintf(stderr, "test_at_serial: FAILURES\n");
        return 1;
    }
    printf("test_at_serial: all passed\n");
    return 0;
}
