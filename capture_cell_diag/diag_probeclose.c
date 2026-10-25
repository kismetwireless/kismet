/* diag_probeclose.c - close a scan PROBE fd without waiting on output the
 * device never took. See diag_probeclose.h for the measurement.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* The selftest's termios half drives a pty (posix_openpt/grantpt/unlockpt/
 * ptsname), which glibc declares only under an XSI feature macro. Scoped to the
 * selftest build so the shipping objects compile exactly as before; macOS
 * declares them by default. */
#if defined(DIAG_PROBECLOSE_SELFTEST) && defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/serial.h>
#endif

#include "diag_probeclose.h"

/* ASYNC_CLOSING_WAIT_NONE: "do not wait for output to drain at close". Spelled
 * here so the module builds where <linux/serial.h> does not exist (the
 * framework-free selftests also build on macOS); pinned to the kernel's
 * value where it does. */
#define PROBECLOSE_WAIT_NONE 65535
#if defined(__linux__) && defined(ASYNC_CLOSING_WAIT_NONE)
_Static_assert(ASYNC_CLOSING_WAIT_NONE == PROBECLOSE_WAIT_NONE,
               "closing_wait NONE sentinel disagrees with <linux/serial.h>");
#endif

/* -----------------------------------------------------------------------
 * The real syscalls
 * ----------------------------------------------------------------------- */

static int sys_outq(int fd, int *pending) {
#ifdef TIOCOUTQ
    int n = 0;
    if (ioctl(fd, TIOCOUTQ, &n) != 0)
        return -1;
    *pending = n;
    return 0;
#else
    (void)fd; (void)pending;
    return -1;
#endif
}

static int sys_get_closing_wait(int fd, unsigned short *cw) {
#if defined(__linux__) && defined(TIOCGSERIAL)
    struct serial_struct ss;
    memset(&ss, 0, sizeof(ss));
    if (ioctl(fd, TIOCGSERIAL, &ss) != 0)
        return -1;
    *cw = ss.closing_wait;
    return 0;
#else
    (void)fd; (void)cw;
    return -1;
#endif
}

static int sys_set_closing_wait(int fd, unsigned short cw) {
#if defined(__linux__) && defined(TIOCGSERIAL) && defined(TIOCSSERIAL)
    /* TIOCSSERIAL takes the whole struct: read it back and change one field,
     * so every other port setting is written back as it was. */
    struct serial_struct ss;
    memset(&ss, 0, sizeof(ss));
    if (ioctl(fd, TIOCGSERIAL, &ss) != 0)
        return -1;
    ss.closing_wait = cw;
    return ioctl(fd, TIOCSSERIAL, &ss) == 0 ? 0 : -1;
#else
    (void)fd; (void)cw;
    return -1;
#endif
}

static int sys_reopen(const char *path) {
    return open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
}

static int sys_close_now(int fd) {
    return close(fd);
}

static void *probeclose_thread(void *arg) {
    close((int)(intptr_t)arg);
    return NULL;
}

static int sys_close_detached(int fd) {
    /* FD_CLOEXEC before the handoff: this fd may still be open when the process
     * forks and execs a child, and without it the child would inherit the
     * probe's port and hold it (flock and all) for its whole life. */
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0)
        fcntl(fd, F_SETFD, fl | FD_CLOEXEC);

    pthread_attr_t attr;
    pthread_t th;
    if (pthread_attr_init(&attr) != 0)
        return -1;
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&th, &attr, probeclose_thread, (void *)(intptr_t)fd);
    pthread_attr_destroy(&attr);
    return rc == 0 ? 0 : -1;
}

const diag_probeclose_ops_t diag_probeclose_sys = {
    sys_outq,
    sys_get_closing_wait,
    sys_set_closing_wait,
    sys_reopen,
    sys_close_now,
    sys_close_detached,
};

/* -----------------------------------------------------------------------
 * The decision
 * ----------------------------------------------------------------------- */

diag_probeclose_how_t diag_probe_close_with(const diag_probeclose_ops_t *ops,
                                            int fd, const char *path) {
    /* The device took everything it was sent (or this is no tty at all): the
     * close cannot wait on anything, so it is the close it always was. */
    int pending = 0;
    if (ops->outq(fd, &pending) != 0 || pending <= 0) {
        ops->close_now(fd);
        return DIAG_PROBECLOSE_PLAIN;
    }

    unsigned short orig = 0;
    if (ops->get_closing_wait(fd, &orig) == 0) {
        /* Already NONE -- quite possibly a concurrent scanner of this same port
         * between its close and its restore. Close, and write nothing: storing
         * NONE as "the original" is how a transient change becomes permanent. */
        if (orig == PROBECLOSE_WAIT_NONE) {
            ops->close_now(fd);
            return DIAG_PROBECLOSE_NOWAIT;
        }
        if (ops->set_closing_wait(fd, PROBECLOSE_WAIT_NONE) == 0) {
            ops->close_now(fd);
            if (!path)
                return DIAG_PROBECLOSE_NOWAIT_UNRESTORED;
            int rfd = ops->reopen(path);
            if (rfd < 0)
                return DIAG_PROBECLOSE_NOWAIT_UNRESTORED;
            /* Put back only what is still ours: if the port no longer reads
             * NONE, someone else has set it since, and their value wins. */
            diag_probeclose_how_t how = DIAG_PROBECLOSE_NOWAIT;
            unsigned short now = 0;
            if (ops->get_closing_wait(rfd, &now) != 0)
                how = DIAG_PROBECLOSE_NOWAIT_UNRESTORED;
            else if (now == PROBECLOSE_WAIT_NONE &&
                     ops->set_closing_wait(rfd, orig) != 0)
                how = DIAG_PROBECLOSE_NOWAIT_UNRESTORED;
            ops->close_now(rfd);
            return how;
        }
    }

    /* closing_wait is not ours to change (no CAP_SYS_ADMIN, or no
     * serial_struct): the kernel will wait, but the scan does not have to. */
    if (ops->close_detached(fd) == 0)
        return DIAG_PROBECLOSE_DETACHED;

    /* No thread either. Releasing the fd is not optional, so block -- and say
     * so, rather than report a close that did not avoid the wait. */
    ops->close_now(fd);
    return DIAG_PROBECLOSE_BLOCKED;
}

/* The termios half: see diag_probeclose.h. */
#define PROBE_TERMIOS_FDS 1024
static struct termios g_probe_termios[PROBE_TERMIOS_FDS];
static unsigned char g_probe_termios_kept[PROBE_TERMIOS_FDS];

void diag_probe_termios_keep(int fd, const struct termios *orig) {
    if (fd < 0 || fd >= PROBE_TERMIOS_FDS || orig == NULL)
        return;
    g_probe_termios[fd] = *orig;
    g_probe_termios_kept[fd] = 1;
}

void diag_probe_termios_forget(int fd) {
    if (fd >= 0 && fd < PROBE_TERMIOS_FDS)
        g_probe_termios_kept[fd] = 0;
}

int diag_probe_termios_restore(int fd) {
    if (fd < 0 || fd >= PROBE_TERMIOS_FDS || !g_probe_termios_kept[fd])
        return 0;
    g_probe_termios_kept[fd] = 0;
    /* TCSANOW: TCSADRAIN would wait for the probe's unsent "AT\r\n", which a
     * port that never reads it never drains. */
    return tcsetattr(fd, TCSANOW, &g_probe_termios[fd]) == 0 ? 1 : 0;
}

/* The input drain: see diag_probeclose.h. */
ssize_t diag_probe_drain_input(int fd) {
    if (fd < 0)
        return -1;
    /* The flush first, where the node takes it; then the read either way,
     * because an MHI UCI node accepts TCFLSH and discards nothing. After a
     * flush that worked the read finds nothing and costs one poll(). */
    if (isatty(fd))
        tcflush(fd, TCIFLUSH);
    char scratch[1024];
    ssize_t total = 0;
    while (total < DIAG_PROBE_DRAIN_MAX) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN))
            break;
        ssize_t n = read(fd, scratch, sizeof(scratch));
        if (n <= 0)
            break;   /* 0: the peer is gone; <0: nothing more to take */
        total += n;
    }
    return total;
}

diag_probeclose_how_t diag_probe_close(int fd, const char *path) {
    /* The port's own line settings go back BEFORE the fd is released: after
     * the close there is no fd left to write them through. */
    diag_probe_termios_restore(fd);
    return diag_probe_close_with(&diag_probeclose_sys, fd, path);
}

/* -----------------------------------------------------------------------
 * The open half -- see diag_probeclose.h
 * ----------------------------------------------------------------------- */

/* One open() in flight. Both the caller and the worker hold a reference; the
 * one that drops the last frees it, so neither side can free it under the other
 * -- the caller may give up long before the worker's open() returns. */
typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int refs;
    int done;
    int fd;
    int err;
    int flags;
    diag_probe_open_fn fn;
    char path[];
} probe_open_job_t;

/* Drop one reference. Called with j->mu held; returns with it released. */
static void probe_open_put(probe_open_job_t *j) {
    int last = --j->refs == 0;
    pthread_mutex_unlock(&j->mu);
    if (last) {
        pthread_cond_destroy(&j->cv);
        pthread_mutex_destroy(&j->mu);
        free(j);
    }
}

static void *probe_open_thread(void *arg) {
    probe_open_job_t *j = arg;
    int fd = j->fn(j->path, j->flags);
    int err = errno;
    int orphan = -1;

    pthread_mutex_lock(&j->mu);
    if (j->refs < 2) {
        /* The caller hit its deadline and left: nobody will ever read this fd,
         * so it is ours to release. Nothing was written to it, so this close has
         * nothing to wait on. */
        orphan = fd;
    } else {
        j->fd = fd;
        j->err = err;
        j->done = 1;
        pthread_cond_signal(&j->cv);
    }
    probe_open_put(j);

    if (orphan >= 0)
        close(orphan);
    return NULL;
}

static int sys_open(const char *path, int flags) {
    return open(path, flags);
}

int diag_probe_open_with(diag_probe_open_fn fn, const char *path, int flags,
                         int deadline_ms) {
    flags |= O_CLOEXEC;
    if (deadline_ms <= 0 || !path)
        return fn(path, flags);

    size_t plen = strlen(path);
    probe_open_job_t *j = calloc(1, sizeof(*j) + plen + 1);
    if (!j)
        return fn(path, flags);
    memcpy(j->path, path, plen + 1);
    j->fn = fn;
    j->flags = flags;
    j->fd = -1;
    j->refs = 2;

    /* Wait on the MONOTONIC clock where the platform allows it, so a host clock
     * step cannot stretch or collapse the deadline. macOS has no
     * pthread_condattr_setclock; its framework-free selftest build uses
     * the realtime clock instead. */
    clockid_t clk = CLOCK_REALTIME;
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
#if defined(__linux__)
    if (pthread_condattr_setclock(&ca, CLOCK_MONOTONIC) == 0)
        clk = CLOCK_MONOTONIC;
#endif
    pthread_mutex_init(&j->mu, NULL);
    pthread_cond_init(&j->cv, &ca);
    pthread_condattr_destroy(&ca);

    pthread_attr_t attr;
    pthread_t th;
    int started = pthread_attr_init(&attr) == 0;
    if (started) {
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        started = pthread_create(&th, &attr, probe_open_thread, j) == 0;
        pthread_attr_destroy(&attr);
    }
    if (!started) {
        /* No thread: the open is not optional, so do it inline, as before. */
        pthread_cond_destroy(&j->cv);
        pthread_mutex_destroy(&j->mu);
        free(j);
        return fn(path, flags);
    }

    struct timespec until;
    clock_gettime(clk, &until);
    until.tv_sec += deadline_ms / 1000;
    until.tv_nsec += (long)(deadline_ms % 1000) * 1000000L;
    if (until.tv_nsec >= 1000000000L) {
        until.tv_sec++;
        until.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&j->mu);
    while (!j->done) {
        if (pthread_cond_timedwait(&j->cv, &j->mu, &until) == ETIMEDOUT)
            break;
    }
    /* Re-read under the lock: a result that landed as the wait timed out is
     * still ours to take. */
    int fd = j->done ? j->fd : -1;
    int err = j->done ? j->err : ETIMEDOUT;
    probe_open_put(j);

    if (fd < 0)
        errno = err;
    return fd;
}

int diag_probe_open(const char *path, int flags, int deadline_ms) {
    return diag_probe_open_with(sys_open, path, flags, deadline_ms);
}

const char *diag_probeclose_label(diag_probeclose_how_t how) {
    switch (how) {
        case DIAG_PROBECLOSE_PLAIN:             return "plain";
        case DIAG_PROBECLOSE_NOWAIT:            return "nowait";
        case DIAG_PROBECLOSE_NOWAIT_UNRESTORED: return "nowait-unrestored";
        case DIAG_PROBECLOSE_DETACHED:          return "detached";
        case DIAG_PROBECLOSE_BLOCKED:           return "blocked";
    }
    return "unknown";
}

void diag_probeclose_note(char *buf, size_t bufsz, const char *port,
                          diag_probeclose_how_t how) {
    diag_probeclose_note_label(buf, bufsz, port, diag_probeclose_label(how));
}

void diag_probeclose_note_label(char *buf, size_t bufsz, const char *port,
                                const char *label) {
    if (!buf || bufsz == 0)
        return;
    size_t off = strnlen(buf, bufsz);
    if (off >= bufsz) {
        buf[bufsz - 1] = '\0';
        return;
    }
    const char *base = port ? strrchr(port, '/') : NULL;
    base = base ? base + 1 : (port ? port : "?");

    char entry[128];
    int n = snprintf(entry, sizeof(entry), "%s%s(%s)", off ? "," : "", base,
                     label ? label : "?");
    /* Whole entries only: a half-written port name is worse than none. */
    if (n < 0 || (size_t)n >= sizeof(entry) || off + (size_t)n + 1 > bufsz)
        return;
    memcpy(buf + off, entry, (size_t)n + 1);
}

/* -----------------------------------------------------------------------
 * Selftest
 * ----------------------------------------------------------------------- */
#ifdef DIAG_PROBECLOSE_SELFTEST

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>

static int failures = 0;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    } else {
        printf("PASS: %s\n", what);
    }
}

/* A scripted port. Every op appends one token to `log`, so a test can assert
 * the exact call sequence -- including the calls that must NOT happen. */
typedef struct {
    int outq_rc, pending;
    int get_rc;               /* for the probe fd */
    unsigned short cw;        /* closing_wait the probe fd reports */
    int set_rc;               /* for the probe fd */
    int reopen_fd;            /* -1 = the restore open fails */
    int restore_get_rc;
    unsigned short restore_cw;  /* what the reopened port reports */
    int restore_set_rc;
    int detach_rc;
    char log[512];
} fake_port_t;

static fake_port_t F;

static void logf_(const char *fmt, int a, int b) {
    size_t off = strlen(F.log);
    snprintf(F.log + off, sizeof(F.log) - off, fmt, a, b);
}

static int f_outq(int fd, int *pending) {
    logf_("outq(%d) ", fd, 0);
    if (F.outq_rc != 0)
        return -1;
    *pending = F.pending;
    return 0;
}
static int f_get(int fd, unsigned short *cw) {
    logf_("get(%d) ", fd, 0);
    if (fd == F.reopen_fd) {
        if (F.restore_get_rc != 0)
            return -1;
        *cw = F.restore_cw;
        return 0;
    }
    if (F.get_rc != 0)
        return -1;
    *cw = F.cw;
    return 0;
}
static int f_set(int fd, unsigned short cw) {
    logf_("set(%d,%d) ", fd, cw);
    if (fd == F.reopen_fd)
        return F.restore_set_rc == 0 ? 0 : -1;
    return F.set_rc == 0 ? 0 : -1;
}
static int f_reopen(const char *path) {
    logf_("reopen ", 0, 0);
    (void)path;
    return F.reopen_fd;
}
static int f_close(int fd) {
    logf_("close(%d) ", fd, 0);
    return 0;
}
static int f_detach(int fd) {
    logf_("detach(%d) ", fd, 0);
    return F.detach_rc == 0 ? 0 : -1;
}

static const diag_probeclose_ops_t FAKE = {
    f_outq, f_get, f_set, f_reopen, f_close, f_detach,
};

/* A stuck USB tty: 4 bytes of "AT\r\n" the device never took, the kernel's
 * default 30 s closing_wait, and a caller with CAP_SYS_ADMIN. */
static void stuck(void) {
    memset(&F, 0, sizeof(F));
    F.pending = 4;
    F.cw = 3000;
    F.reopen_fd = 99;
    F.restore_cw = PROBECLOSE_WAIT_NONE;
}

static int closed_within_ms(int fd, int ms) {
    for (int waited = 0; waited <= ms; waited += 5) {
        if (fcntl(fd, F_GETFD) < 0 && errno == EBADF)
            return 1;
        poll(NULL, 0, 5);
    }
    return 0;
}

/* The open half's fake open(): records how it was called, and can be held
 * shut -- the stuck tty's open() -- until the test releases it. A released open
 * returns the write end of a fresh pipe, so the test can see (EOF on the read
 * end) whether whoever ended up owning that fd closed it. */
static pthread_mutex_t G_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t G_cv = PTHREAD_COND_INITIALIZER;
static int G_hold;          /* 1 = the next open blocks until released */
static int G_fail_errno;    /* nonzero = the open fails with this errno */
static int G_flags;         /* flags the open was called with */
static int G_calls;
static int G_rd = -1;       /* read end of the pipe the last open returned */
static pthread_t G_thread;  /* the thread the open ran on */

static int fake_open(const char *path, int flags) {
    (void)path;
    pthread_mutex_lock(&G_mu);
    G_calls++;
    G_flags = flags;
    G_thread = pthread_self();
    while (G_hold)
        pthread_cond_wait(&G_cv, &G_mu);
    int fail = G_fail_errno;
    pthread_mutex_unlock(&G_mu);
    if (fail) {
        errno = fail;
        return -1;
    }
    int pp[2];
    if (pipe(pp) != 0)
        return -1;
    pthread_mutex_lock(&G_mu);
    G_rd = pp[0];
    pthread_cond_broadcast(&G_cv);
    pthread_mutex_unlock(&G_mu);
    return pp[1];
}

static void fake_open_reset(void) {
    pthread_mutex_lock(&G_mu);
    G_hold = 0;
    G_fail_errno = 0;
    G_flags = 0;
    G_calls = 0;
    G_rd = -1;
    pthread_mutex_unlock(&G_mu);
}

static long ms_since(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (long)(t1.tv_sec - t0->tv_sec) * 1000L +
           (long)(t1.tv_nsec - t0->tv_nsec) / 1000000L;
}

/* 1 when fd's peer has hung up (read returns EOF) within ms. */
static int eof_within_ms(int fd, int ms) {
    struct pollfd pf = { fd, POLLIN, 0 };
    if (poll(&pf, 1, ms) <= 0)
        return 0;
    char c;
    return read(fd, &c, 1) == 0;
}

/* A pty pair for the termios half. A pty's slave is a real tty with real
 * termios, and -- like any tty -- its settings belong to the tty, not the fd: a
 * change made through one slave fd is what every other slave fd reads. That is
 * the whole termios-clobber mechanism, reproducible with no hardware. */
static int open_pty(char *name, size_t namesz) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0)
        return -1;
    if (grantpt(m) != 0 || unlockpt(m) != 0 || ptsname(m) == NULL) {
        close(m);
        return -1;
    }
    snprintf(name, namesz, "%s", ptsname(m));
    return m;
}

static speed_t speed_of(int fd) {
    struct termios t;
    if (tcgetattr(fd, &t) != 0)
        return (speed_t)-1;
    return cfgetispeed(&t);
}

/* What a probe open does to a port: 115200, raw, VMIN 0 / VTIME 10. */
static void clobber(int fd) {
    struct termios t;
    tcgetattr(fd, &t);
    cfsetispeed(&t, B115200);
    cfsetospeed(&t, B115200);
    t.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 10;
    tcsetattr(fd, TCSANOW, &t);
}

static int readable_now(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLIN };
    return poll(&p, 1, 0) > 0 && (p.revents & POLLIN);
}

static void test_drain_input(void) {
    /* A non-tty AT node (an MHI /dev/mhi_DUN, a /dev/wwan*at* port) holding a
     * reply another prober never read: ATI's answer, left in the pipe. */
    int sv[2];
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "drain: a socketpair");
    const char *stale = "\r\nQuectel\r\nRM520N-GL\r\n\r\nOK\r\n";
    (void)!write(sv[1], stale, strlen(stale));
    check(!isatty(sv[0]) && readable_now(sv[0]), "drain: the stale reply is waiting");
    ssize_t n = diag_probe_drain_input(sv[0]);
    check(n == (ssize_t)strlen(stale), "drain: every stale byte is discarded and counted");
    check(!readable_now(sv[0]), "drain: nothing is left for the next command to read");

    /* Nothing waiting: returns at once, without blocking on the blocking fd. */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    n = diag_probe_drain_input(sv[0]);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long took = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    check(n == 0 && took < 50, "drain: an empty node returns 0 at once");

    /* A node that keeps talking cannot hold the caller: the drain stops at
     * its bound and leaves the rest. */
    char blob[DIAG_PROBE_DRAIN_MAX + 4096];
    memset(blob, 'x', sizeof(blob));
    (void)!write(sv[1], blob, sizeof(blob));
    n = diag_probe_drain_input(sv[0]);
    check(n >= DIAG_PROBE_DRAIN_MAX && n < (ssize_t)sizeof(blob),
          "drain: bounded -- stops at DIAG_PROBE_DRAIN_MAX");
    check(readable_now(sv[0]), "drain: what is past the bound stays unread");
    (void)diag_probe_drain_input(sv[0]);

    /* The peer has gone (POLLHUP, read returns 0): the drain ends, it does
     * not spin. */
    (void)!write(sv[1], "OK\r\n", 4);
    close(sv[1]);
    n = diag_probe_drain_input(sv[0]);
    check(n == 4, "drain: a hung-up node yields its last bytes and the drain ends");
    close(sv[0]);

    check(diag_probe_drain_input(-1) == -1, "drain: an invalid fd is -1");

    /* A tty: tcflush(TCIFLUSH), exactly what the probe did before. */
    char name[256];
    int m = open_pty(name, sizeof(name));
    check(m >= 0, "drain: a pty for the tty case");
    if (m < 0)
        return;
    int s = open(name, O_RDWR | O_NOCTTY);
    clobber(s);   /* raw, as a probe open leaves it */
    (void)!write(m, stale, strlen(stale));
    poll(NULL, 0, 50);   /* let the bytes cross to the slave's input */
    check(readable_now(s), "drain: the stale reply is waiting on the tty");
    check(diag_probe_drain_input(s) == 0, "drain: a tty is flushed, and counts 0");
    check(!readable_now(s), "drain: the tty's input is empty afterwards");
    close(s);
    close(m);
}

static void test_termios_half(void) {
    char name[256];
    int m = open_pty(name, sizeof(name));
    check(m >= 0, "termios: a pty for the termios half");
    if (m < 0)
        return;

    /* The port's owner: a reader at 57600, canonical (not raw). */
    int owner = open(name, O_RDWR | O_NOCTTY);
    check(owner >= 0, "termios: the owner opens the port");
    struct termios want;
    tcgetattr(owner, &want);
    cfsetispeed(&want, B57600);
    cfsetospeed(&want, B57600);
    want.c_lflag |= ICANON;
    tcsetattr(owner, TCSANOW, &want);
    check(speed_of(owner) == B57600, "termios: the owner's port reads 57600");

    /* 19. A probe keeps what it found, clobbers, and diag_probe_close() puts it
     * back. The positive control first: the clobber IS visible to the owner --
     * a gauge that never reads the damage cannot read its repair. */
    {
        int probe = open(name, O_RDWR | O_NOCTTY | O_NONBLOCK);
        struct termios found;
        tcgetattr(probe, &found);
        diag_probe_termios_keep(probe, &found);
        clobber(probe);
        check(speed_of(owner) == B115200,
              "termios: positive control -- the probe's 115200 is the owner's too");
        diag_probeclose_how_t how = diag_probe_close(probe, name);
        check(how == DIAG_PROBECLOSE_PLAIN, "termios: a pty probe closes PLAIN");
        check(speed_of(owner) == B57600,
              "termios: after diag_probe_close() the owner's port is at 57600 again");
        struct termios got;
        tcgetattr(owner, &got);
        check((got.c_lflag & ICANON) != 0,
              "termios: ...and canonical again -- the raw mode is undone too");
    }

    /* 20. Nothing kept, nothing written: a close with no keep() leaves the port
     * as the probe left it (for a caller that opted out). */
    {
        int probe = open(name, O_RDWR | O_NOCTTY | O_NONBLOCK);
        check(diag_probe_termios_restore(probe) == 0,
              "termios: restore with nothing kept returns 0");
        clobber(probe);
        diag_probe_close(probe, name);
        check(speed_of(owner) == B115200,
              "termios: ...and diag_probe_close() writes nothing back");
        tcsetattr(owner, TCSANOW, &want);
    }

    /* 21. forget() really forgets -- a port kept for the source's own use, or a
     * non-tty, must not have a stale entry written over it later. */
    {
        int probe = open(name, O_RDWR | O_NOCTTY | O_NONBLOCK);
        struct termios found;
        tcgetattr(probe, &found);
        diag_probe_termios_keep(probe, &found);
        diag_probe_termios_forget(probe);
        clobber(probe);
        check(diag_probe_termios_restore(probe) == 0,
              "termios: after forget(), restore finds nothing");
        close(probe);
        tcsetattr(owner, TCSANOW, &want);
    }

    /* 22. The restore is one-shot: the entry is gone once written back, so a
     * reused fd number cannot inherit it. */
    {
        int probe = open(name, O_RDWR | O_NOCTTY | O_NONBLOCK);
        struct termios found;
        tcgetattr(probe, &found);
        diag_probe_termios_keep(probe, &found);
        clobber(probe);
        check(diag_probe_termios_restore(probe) == 1,
              "termios: restore writes back what was kept");
        check(diag_probe_termios_restore(probe) == 0,
              "termios: ...once -- a second restore finds nothing");
        close(probe);
    }

    /* 23. Out-of-range fds are ignored, not written past the table. */
    {
        struct termios any;
        memset(&any, 0, sizeof(any));
        diag_probe_termios_keep(-1, &any);
        diag_probe_termios_keep(1 << 20, &any);
        diag_probe_termios_keep(3, NULL);
        check(diag_probe_termios_restore(-1) == 0 &&
              diag_probe_termios_restore(1 << 20) == 0 &&
              diag_probe_termios_restore(3) == 0,
              "termios: a negative, too-large or NULL keep is ignored");
    }

    close(owner);
    close(m);
}

int main(void) {
    diag_probeclose_how_t how;

    /* 1. A healthy AT port: the device took its bytes, so TIOCOUTQ is 0 and
     * the close is exactly the close it always was. Nothing else is touched. */
    memset(&F, 0, sizeof(F));
    how = diag_probe_close_with(&FAKE, 7, "/dev/ttyUSB2");
    check(how == DIAG_PROBECLOSE_PLAIN, "nothing unsent -> PLAIN");
    check(strcmp(F.log, "outq(7) close(7) ") == 0,
          "...and the only calls are TIOCOUTQ and one close()");

    /* 2. Not a tty (MHI mhi_DUN, /dev/wwan*): TIOCOUTQ fails. There is no
     * closing_wait to avoid, so this is a plain close too. */
    memset(&F, 0, sizeof(F));
    F.outq_rc = -1;
    how = diag_probe_close_with(&FAKE, 7, "/dev/mhi_DUN");
    check(how == DIAG_PROBECLOSE_PLAIN, "TIOCOUTQ fails (non-tty) -> PLAIN");
    check(strcmp(F.log, "outq(7) close(7) ") == 0,
          "...without touching closing_wait");

    /* 3. The stuck case: a stuck NMEA tty with a privileged caller. closing_wait goes
     * to NONE for this close, and the port's own value is put back on a fresh
     * open -- in that order, and to exactly the value that was read. */
    stuck();
    how = diag_probe_close_with(&FAKE, 7, "/dev/ttyUSB18");
    check(how == DIAG_PROBECLOSE_NOWAIT, "unsent output + CAP_SYS_ADMIN -> NOWAIT");
    check(strcmp(F.log, "outq(7) get(7) set(7,65535) close(7) reopen get(99) "
                        "set(99,3000) close(99) ") == 0,
          "...NONE before the close, then the original 3000 restored on a new fd");

    /* 4. Unprivileged: TIOCSSERIAL refuses (EPERM). The scan must still not
     * wait, so the close goes to a thread -- and is NOT also done inline. */
    stuck();
    F.set_rc = -1;
    how = diag_probe_close_with(&FAKE, 7, "/dev/ttyUSB18");
    check(how == DIAG_PROBECLOSE_DETACHED, "unsent + EPERM on closing_wait -> DETACHED");
    check(strstr(F.log, "detach(7)") != NULL && strstr(F.log, "close(7)") == NULL,
          "...handed to a thread, never closed inline (that is the 30 s)");
    check(strstr(F.log, "reopen") == NULL, "...and nothing to restore");

    /* 5. No serial_struct at all (TIOCGSERIAL fails, or not Linux). */
    stuck();
    F.get_rc = -1;
    how = diag_probe_close_with(&FAKE, 7, "/dev/ttyUSB18");
    check(how == DIAG_PROBECLOSE_DETACHED, "unsent + no TIOCGSERIAL -> DETACHED");
    check(strstr(F.log, "set(") == NULL, "...closing_wait is never written blind");

    /* 6. The port is ALREADY set not to wait -- possibly by a concurrent scanner
     * between its close and its restore. Close, and write NOTHING: restoring
     * "NONE" here is how a transient change becomes a permanent one. */
    stuck();
    F.cw = PROBECLOSE_WAIT_NONE;
    how = diag_probe_close_with(&FAKE, 7, "/dev/ttyUSB18");
    check(how == DIAG_PROBECLOSE_NOWAIT, "closing_wait already NONE -> NOWAIT");
    check(strcmp(F.log, "outq(7) get(7) close(7) ") == 0,
          "...closed with no set and no restore");

    /* 7. The restore open fails (port unplugged between the two opens). The
     * probe fd is still closed, and the result says the port was left changed. */
    stuck();
    F.reopen_fd = -1;
    how = diag_probe_close_with(&FAKE, 7, "/dev/ttyUSB18");
    check(how == DIAG_PROBECLOSE_NOWAIT_UNRESTORED, "restore open fails -> UNRESTORED");
    check(strstr(F.log, "close(7)") != NULL, "...the probe fd is still closed");

    /* 8. No path to reopen: the change cannot be undone, so say so. */
    stuck();
    how = diag_probe_close_with(&FAKE, 7, NULL);
    check(how == DIAG_PROBECLOSE_NOWAIT_UNRESTORED, "NULL path -> UNRESTORED");
    check(strstr(F.log, "reopen") == NULL, "...and no open is attempted");

    /* 9. The restore write fails: reported, and the restore fd is not leaked. */
    stuck();
    F.restore_set_rc = -1;
    how = diag_probe_close_with(&FAKE, 7, "/dev/ttyUSB18");
    check(how == DIAG_PROBECLOSE_NOWAIT_UNRESTORED, "restore TIOCSSERIAL fails -> UNRESTORED");
    check(strstr(F.log, "close(99)") != NULL, "...and the restore fd is closed");

    /* 10. Someone else changed closing_wait while it was ours (the reopened port
     * no longer reads NONE). Their value wins; ours is not written over it. */
    stuck();
    F.restore_cw = 500;
    how = diag_probe_close_with(&FAKE, 7, "/dev/ttyUSB18");
    check(how == DIAG_PROBECLOSE_NOWAIT, "port changed by another -> NOWAIT, left alone");
    check(strstr(F.log, "set(99,") == NULL, "...no restore written over their value");
    check(strstr(F.log, "close(99)") != NULL, "...and the restore fd is closed");

    /* 11. Unprivileged and no thread could be started: the only way left to
     * release the fd is to block. Say BLOCKED rather than pretend. */
    stuck();
    F.set_rc = -1;
    F.detach_rc = -1;
    how = diag_probe_close_with(&FAKE, 7, "/dev/ttyUSB18");
    check(how == DIAG_PROBECLOSE_BLOCKED, "no thread -> BLOCKED (and closed inline)");
    check(strstr(F.log, "close(7)") != NULL, "...the fd is still released");

    /* 12. Real syscalls, pipe: TIOCOUTQ is ENOTTY -> the plain path, and the
     * fd really is closed when the call returns. */
    {
        int p[2];
        check(pipe(p) == 0, "pipe() for the real-syscall test");
        how = diag_probe_close(p[1], NULL);
        check(how == DIAG_PROBECLOSE_PLAIN, "real pipe fd -> PLAIN");
        check(fcntl(p[1], F_GETFD) < 0 && errno == EBADF, "...and it is closed");
        close(p[0]);
    }

    /* 13. The real detached close releases the fd promptly on its own thread. */
    {
        int p[2];
        check(pipe(p) == 0, "pipe() for the detached-close test");
        check(diag_probeclose_sys.close_detached(p[1]) == 0,
              "real close_detached hands the fd to a thread");
        check(closed_within_ms(p[1], 2000), "...which closes it (within 2 s)");
        close(p[0]);
    }

    /* 14. The one-line summary: basename + label, comma-separated, and an entry
     * that does not fit is dropped whole rather than truncated mid-name. */
    {
        char buf[64] = "";
        diag_probeclose_note(buf, sizeof(buf), "/dev/ttyUSB18", DIAG_PROBECLOSE_NOWAIT);
        diag_probeclose_note(buf, sizeof(buf), "/dev/ttyUSB3", DIAG_PROBECLOSE_DETACHED);
        check(strcmp(buf, "ttyUSB18(nowait),ttyUSB3(detached)") == 0,
              "note: basename(label), comma-separated");
        char small[20] = "";
        diag_probeclose_note(small, sizeof(small), "/dev/ttyUSB18", DIAG_PROBECLOSE_NOWAIT);
        diag_probeclose_note(small, sizeof(small), "/dev/ttyUSB19", DIAG_PROBECLOSE_NOWAIT);
        check(strcmp(small, "ttyUSB18(nowait)") == 0,
              "note: an entry that does not fit is dropped whole");
    }

    /* 15. Labels are distinct and never NULL -- an operator reads them. */
    check(strcmp(diag_probeclose_label(DIAG_PROBECLOSE_NOWAIT), "nowait") == 0 &&
          strcmp(diag_probeclose_label(DIAG_PROBECLOSE_DETACHED), "detached") == 0 &&
          strcmp(diag_probeclose_label(DIAG_PROBECLOSE_BLOCKED), "blocked") == 0 &&
          strcmp(diag_probeclose_label(DIAG_PROBECLOSE_NOWAIT_UNRESTORED),
                 "nowait-unrestored") == 0 &&
          strcmp(diag_probeclose_label(DIAG_PROBECLOSE_PLAIN), "plain") == 0,
          "labels");

    /* ---------------- the open half ---------------- */
    const int SCAN_FLAGS = O_RDWR | O_NOCTTY | O_NONBLOCK;

    /* 16. A healthy port: the open returns at once and its fd comes back, opened
     * with the caller's flags PLUS O_CLOEXEC. */
    {
        fake_open_reset();
        int fd = diag_probe_open_with(fake_open, "/dev/ttyUSB2", SCAN_FLAGS, 1000);
        check(fd >= 0 && G_calls == 1, "open-half: a prompt open returns its fd");
        check((G_flags & SCAN_FLAGS) == SCAN_FLAGS && (G_flags & O_CLOEXEC),
              "...opened with the caller's flags plus O_CLOEXEC");
        if (fd >= 0)
            close(fd);
        if (G_rd >= 0)
            close(G_rd);
    }

    /* 17. An open that FAILS keeps open()'s errno -- a missing port must not read
     * as a timeout, and EWOULDBLOCK-style errors must survive for the callers. */
    {
        fake_open_reset();
        G_fail_errno = ENOENT;
        errno = 0;
        int fd = diag_probe_open_with(fake_open, "/dev/ttyUSB99", SCAN_FLAGS, 1000);
        check(fd == -1 && errno == ENOENT, "open-half: a failed open keeps its errno");
    }

    /* 18. The stuck case: an open() that does not return (a tty in its final close).
     * The call gives up at its deadline with ETIMEDOUT instead of waiting it
     * out -- measured, so a regression to a plain open would read ~forever. */
    {
        fake_open_reset();
        G_hold = 1;
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        errno = 0;
        int fd = diag_probe_open_with(fake_open, "/dev/ttyUSB18", SCAN_FLAGS, 150);
        long took = ms_since(&t0);
        int err = errno;
        check(fd == -1 && err == ETIMEDOUT,
              "open-half: an open that never returns -> -1 ETIMEDOUT");
        check(took >= 140 && took < 1000,
              "...at its 150 ms deadline, not when the open finally returns");

        /* 19. The open completes after the caller left. Its fd is nobody's, so
         * the worker must close it -- or every stuck port would leak an fd, and
         * hold the tty open, for the helper's whole life. */
        pthread_mutex_lock(&G_mu);
        G_hold = 0;
        pthread_cond_broadcast(&G_cv);
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_sec += 2;
        while (G_rd < 0 &&
               pthread_cond_timedwait(&G_cv, &G_mu, &until) != ETIMEDOUT)
            ;
        int rd = G_rd;
        pthread_mutex_unlock(&G_mu);
        check(rd >= 0, "...the abandoned open does complete once released");
        check(rd >= 0 && eof_within_ms(rd, 2000),
              "...and the worker closes the fd nobody is left to own");
        if (rd >= 0)
            close(rd);
    }

    /* 20. deadline <= 0 is a plain inline open on the caller's own thread. */
    {
        fake_open_reset();
        int fd = diag_probe_open_with(fake_open, "/dev/ttyUSB2", SCAN_FLAGS, 0);
        check(fd >= 0 && pthread_equal(G_thread, pthread_self()),
              "open-half: deadline 0 -> inline open, no worker");
        if (fd >= 0)
            close(fd);
        if (G_rd >= 0)
            close(G_rd);
    }

    /* 21. Real syscalls: the fd a real open returns is close-on-exec, so no
     * probe fd -- prompt or late -- is ever inherited by an exec'd child. */
    {
        int fd = diag_probe_open("/dev/null", SCAN_FLAGS, 1000);
        int fdfl = fd >= 0 ? fcntl(fd, F_GETFD) : -1;
        check(fd >= 0 && fdfl >= 0 && (fdfl & FD_CLOEXEC),
              "open-half: a real open's fd is FD_CLOEXEC");
        if (fd >= 0)
            close(fd);
    }

    /* 22. A real open() that blocks IN THE KERNEL is bounded too: a FIFO opened
     * write-only blocks until a reader appears -- the nearest thing a test can
     * build to a tty in its final close. A reader then lets the stranded open
     * finish, so the test leaves no worker behind. (Whether that worker closes
     * its late fd is check 19's job: a FIFO reader sees EOF either way, so it
     * cannot tell.) */
    {
        char dir[] = "/tmp/probeopenXXXXXX";
        char fifo[64];
        int made = mkdtemp(dir) != NULL;
        snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
        made = made && mkfifo(fifo, 0600) == 0;
        check(made, "mkfifo for the real blocking-open test");
        if (made) {
            struct timespec t0;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            errno = 0;
            int fd = diag_probe_open(fifo, O_WRONLY, 150);
            long took = ms_since(&t0);
            int err = errno;
            check(fd == -1 && err == ETIMEDOUT && took < 1000,
                  "open-half: a real kernel-blocked open() -> ETIMEDOUT, bounded");
            int rd = open(fifo, O_RDONLY | O_NONBLOCK);
            if (rd >= 0) {
                poll(NULL, 0, 100);   /* let the stranded open land and close */
                close(rd);
            }
            unlink(fifo);
            rmdir(dir);
        }
    }

    /* ---------------- the termios half ---------------- */
    test_termios_half();

    /* ---------------- the input drain ---------------- */
    test_drain_input();

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nPASS: all diag_probeclose tests\n");
    return 0;
}

#endif /* DIAG_PROBECLOSE_SELFTEST */
