/* test_diag_replayfifo.c - standalone tests for replay FIFO writer-close
 * detection (diag_replayfifo.c).
 *
 * Runs a real FIFO through the read loop's macOS shape: poll(POLLIN) on the
 * blocking read end, with a writer's close never reported (POLLHUP and EOF
 * reads are treated as a timeout, as macOS gives revents 0). The first writer
 * leaves a frame partial; the second writer's whole frame must still decode,
 * not join onto it. Links diag_replayfifo.c, diag_logstream.c and diag_hdlc.c
 * (libc only): `--enable-cell-selftest`.
 */

#ifdef CELL_SELFTEST

#include "diag_replayfifo.h"
#include "diag_logstream.h"
#include "diag_hdlc.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

#define MAX_CODES 16

typedef struct {
    size_t n;
    uint16_t code[MAX_CODES];
} collect_t;

static void collect_cb(const diag_log_record_t *rec, void *user) {
    collect_t *c = (collect_t *)user;
    if (c->n < MAX_CODES)
        c->code[c->n++] = rec->log_code;
}

/* One wire LOG_F frame: cmd, pending, outer_len, inner_len, log_code, ts64,
 * then a 4-byte payload. */
static size_t make_frame(uint16_t code, uint8_t *out, size_t cap) {
    uint8_t body[20];
    memset(body, 0, sizeof(body));
    body[0] = 0x10;
    body[2] = (uint8_t)(sizeof(body) - 4);
    body[4] = body[2];
    body[6] = (uint8_t)(code & 0xFF);
    body[7] = (uint8_t)(code >> 8);
    body[8] = 0x01;
    memset(body + 16, 0x5A, 4);
    return diag_hdlc_build(body[0], body + 1, sizeof(body) - 1, out, cap);
}

typedef struct {
    int fd;
    diag_replayfifo_t watch;
    diag_logstream_t ls;
    collect_t got;
    int flushes;
    int errors;
} loop_t;

/* One pass of the read loop with the writer's close unreported. */
static void tick(loop_t *L) {
    uint8_t buf[4096];
    struct pollfd p = { .fd = L->fd, .events = POLLIN, .revents = 0 };
    int pr = poll(&p, 1, 20);
    if (pr > 0 && (p.revents & POLLIN)) {
        ssize_t r = read(L->fd, buf, sizeof(buf));
        if (r > 0) {
            diag_replayfifo_bytes(&L->watch);
            diag_logstream_feed(&L->ls, buf, (size_t)r, collect_cb, &L->got);
            return;
        }
        if (r < 0) {
            L->errors++;
            return;
        }
    }
    /* Linux reports POLLHUP here; it would spin without the pause. */
    if (pr > 0)
        usleep(20000);
    size_t n = 0;
    switch (diag_replayfifo_idle(&L->watch, L->fd, buf, sizeof(buf), &n)) {
    case DIAG_REPLAYFIFO_DATA:
        diag_logstream_feed(&L->ls, buf, n, collect_cb, &L->got);
        break;
    case DIAG_REPLAYFIFO_CLOSED:
        L->flushes++;
        diag_logstream_flush(&L->ls, collect_cb, &L->got);
        break;
    case DIAG_REPLAYFIFO_ERROR:
        L->errors++;
        break;
    case DIAG_REPLAYFIFO_IDLE:
        break;
    }
}

static int is_blocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return fl >= 0 && !(fl & O_NONBLOCK);
}

static int write_all(int fd, const uint8_t *b, size_t n) {
    return write(fd, b, n) == (ssize_t)n;
}

static void test_split_frame_two_writers(const char *fifo) {
    static loop_t L;
    memset(&L, 0, sizeof(L));
    diag_replayfifo_init(&L.watch);
    diag_logstream_init(&L.ls);

    uint8_t a[64], x[64], y[64], z[64];
    size_t alen = make_frame(0xB0C0, a, sizeof(a));
    size_t xlen = make_frame(0x1111, x, sizeof(x));
    size_t ylen = make_frame(0xB0C1, y, sizeof(y));
    size_t zlen = make_frame(0xB0C2, z, sizeof(z));
    CHECK(alen && xlen && ylen && zlen, "frames built");

    /* Opened as the helper holds it: blocking, without blocking in open(). */
    L.fd = open(fifo, O_RDONLY | O_NONBLOCK);
    CHECK(L.fd >= 0, "open read end: %s", strerror(errno));
    if (L.fd < 0)
        return;
    fcntl(L.fd, F_SETFL, fcntl(L.fd, F_GETFL, 0) & ~O_NONBLOCK);

    int w1 = open(fifo, O_WRONLY);
    CHECK(w1 >= 0, "open writer 1: %s", strerror(errno));
    if (w1 < 0) {
        close(L.fd);
        return;
    }
    CHECK(write_all(w1, a, alen) && write_all(w1, x, xlen / 2), "writer 1 writes");
    tick(&L);
    CHECK(L.got.n == 1 && L.got.code[0] == 0xB0C0, "frame A decoded (n=%zu)", L.got.n);

    tick(&L);
    CHECK(L.flushes == 0, "open quiet writer is not a close (flushes=%d)", L.flushes);
    CHECK(is_blocking(L.fd), "fd blocking again after an EAGAIN probe");

    close(w1);
    tick(&L);
    CHECK(L.flushes == 1, "writer 1 close flushed (flushes=%d)", L.flushes);
    CHECK(L.ls.stats.crc_bad == 1, "partial frame X flushed as a bad frame "
          "(crc_bad=%llu)", (unsigned long long)L.ls.stats.crc_bad);
    tick(&L);
    tick(&L);
    CHECK(L.flushes == 1, "one flush per writer, not per tick (flushes=%d)", L.flushes);
    CHECK(is_blocking(L.fd), "fd blocking again after an EOF probe");

    int w2 = open(fifo, O_WRONLY);
    CHECK(w2 >= 0, "open writer 2: %s", strerror(errno));
    if (w2 < 0) {
        close(L.fd);
        return;
    }
    CHECK(write_all(w2, y, ylen), "writer 2 writes Y");
    tick(&L);
    CHECK(L.got.n == 2 && L.got.code[1] == 0xB0C1,
          "frame Y from writer 2 decoded, not joined onto X (n=%zu)", L.got.n);

    /* Bytes the probe itself reads are fed, not lost. */
    CHECK(write_all(w2, z, zlen), "writer 2 writes Z");
    size_t n = 0;
    uint8_t buf[256];
    diag_replayfifo_rc rc = diag_replayfifo_idle(&L.watch, L.fd, buf, sizeof(buf), &n);
    CHECK(rc == DIAG_REPLAYFIFO_DATA && n == zlen, "probe returns Z (rc=%d n=%zu)",
          (int)rc, n);
    if (rc == DIAG_REPLAYFIFO_DATA)
        diag_logstream_feed(&L.ls, buf, n, collect_cb, &L.got);
    CHECK(L.got.n == 3 && L.got.code[2] == 0xB0C2, "frame Z decoded (n=%zu)", L.got.n);
    CHECK(is_blocking(L.fd), "fd blocking again after a data probe");

    close(w2);
    tick(&L);
    CHECK(L.flushes == 2, "writer 2 close flushed (flushes=%d)", L.flushes);
    CHECK(L.got.n == 3, "no extra records (n=%zu)", L.got.n);
    CHECK(L.errors == 0, "no read errors (%d)", L.errors);
    close(L.fd);
}

static void test_flag(void) {
    diag_replayfifo_t w;
    diag_replayfifo_init(&w);
    CHECK(diag_replayfifo_writer_closed(&w) == 1, "first close flushes");
    CHECK(diag_replayfifo_writer_closed(&w) == 0, "repeat close does not");
    size_t n = 1;
    CHECK(diag_replayfifo_idle(&w, -1, NULL, 0, &n) == DIAG_REPLAYFIFO_IDLE && n == 0,
          "no probe once the writer is gone");
    diag_replayfifo_bytes(&w);
    CHECK(diag_replayfifo_writer_closed(&w) == 1, "bytes re-arm the flush");
    diag_replayfifo_bytes(&w);
    uint8_t b[1];
    CHECK(diag_replayfifo_idle(&w, -1, b, sizeof(b), &n) == DIAG_REPLAYFIFO_ERROR,
          "bad fd is an error");
}

/* Fails the restore (every second call) with EIO, leaving the fd non-blocking. */
static int setfl_calls = 0;
static int setfl_fail_restore(int fd, int flags) {
    if (++setfl_calls % 2 == 0) {
        errno = EIO;
        return -1;
    }
    return fcntl(fd, F_SETFL, flags) < 0 ? -1 : 0;
}

/* Bytes the probe read are returned even when the restore then fails; the
 * error comes on the next call. */
static void test_restore_fails_after_read(const char *fifo) {
    int rfd = open(fifo, O_RDONLY | O_NONBLOCK);
    CHECK(rfd >= 0, "open read end: %s", strerror(errno));
    if (rfd < 0)
        return;
    fcntl(rfd, F_SETFL, fcntl(rfd, F_GETFL, 0) & ~O_NONBLOCK);
    int wfd = open(fifo, O_WRONLY);
    CHECK(wfd >= 0, "open writer: %s", strerror(errno));
    if (wfd < 0) {
        close(rfd);
        return;
    }

    uint8_t f[64], buf[256];
    size_t flen = make_frame(0xB0C3, f, sizeof(f));
    CHECK(flen && write_all(wfd, f, flen), "writer writes F");

    diag_replayfifo_t w;
    diag_replayfifo_init(&w);
    setfl_calls = 0;
    size_t n = 0;
    diag_replayfifo_rc rc = diag_replayfifo_idle_with(&w, setfl_fail_restore, rfd,
                                                      buf, sizeof(buf), &n);
    CHECK(rc == DIAG_REPLAYFIFO_DATA && n == flen && memcmp(buf, f, flen) == 0,
          "read bytes kept when the restore fails (rc=%d n=%zu)", (int)rc, n);

    errno = 0;
    rc = diag_replayfifo_idle_with(&w, setfl_fail_restore, rfd, buf, sizeof(buf), &n);
    CHECK(rc == DIAG_REPLAYFIFO_ERROR && errno == EIO && n == 0,
          "restore error reported on the next call (rc=%d errno=%d n=%zu)",
          (int)rc, errno, n);
    CHECK(setfl_calls == 2, "next call reports without probing (calls=%d)", setfl_calls);

    rc = diag_replayfifo_idle(&w, rfd, buf, sizeof(buf), &n);
    CHECK(rc == DIAG_REPLAYFIFO_IDLE && n == 0, "error reported once (rc=%d)", (int)rc);
    fcntl(rfd, F_SETFL, fcntl(rfd, F_GETFL, 0) & ~O_NONBLOCK);

    /* A restore failure with nothing read is reported at once. */
    setfl_calls = 0;
    rc = diag_replayfifo_idle_with(&w, setfl_fail_restore, rfd, buf, sizeof(buf), &n);
    CHECK(rc == DIAG_REPLAYFIFO_ERROR && errno == EIO && n == 0,
          "empty probe's restore error at once (rc=%d n=%zu)", (int)rc, n);
    rc = diag_replayfifo_idle(&w, rfd, buf, sizeof(buf), &n);
    CHECK(rc == DIAG_REPLAYFIFO_IDLE, "nothing pending after it (rc=%d)", (int)rc);

    close(wfd);
    close(rfd);
}

int main(void) {
    const char *tmp = getenv("TMPDIR");
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/replayfifo.XXXXXX",
             tmp != NULL && *tmp ? tmp : "/tmp");
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    char fifo[600];
    snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
    if (mkfifo(fifo, 0600) != 0) {
        perror("mkfifo");
        rmdir(dir);
        return 1;
    }

    test_flag();
    test_split_frame_two_writers(fifo);
    test_restore_fails_after_read(fifo);

    unlink(fifo);
    rmdir(dir);

    if (failures) {
        fprintf(stderr, "test_diag_replayfifo: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_diag_replayfifo: all passed\n");
    return 0;
}

#endif /* CELL_SELFTEST */
