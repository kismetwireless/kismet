/* SPDX-License-Identifier: Apache-2.0
 *
 * cf_wakeup_probe -- drive capture_framework.c's output-ring signalling
 * directly, with no server and no capture source.
 *
 * Built and run by test_capture_framework_wakeups.py against the tree's
 * libkismetdatasource.a. Each mode prints key=value lines; the test reads them.
 *
 *   commit-latency N
 *       Runs cf_handler_loop() on a pipe pair that the "server" never
 *       writes to, commits N small frames with cf_send_raw_bytes() at a
 *       37 ms spacing (co-prime with the loop's 500 ms select timeout, so the
 *       commits sample every phase of it), and times commit -> readable on the
 *       server end. Prints latency_us= per frame.
 *
 *   wait-after-flush
 *       The end state of the lost wakeup, constructed rather than raced:
 *       the ring is EMPTY (a flush already happened) and nothing will ever be
 *       written again. A caller in cf_handler_wait_ringbuffer() then has no
 *       broadcast coming. After 1000 ms the probe sends one -- standing in for
 *       the unrelated write (a PONG) that eventually rescues it -- and prints how
 *       long the caller was parked and what woke it.
 *
 *   wait-while-pending
 *       The other half: with bytes STILL QUEUED the wait must NOT return on its
 *       own (a fix that simply never waits would pass wait-after-flush). The
 *       probe watches it stay parked for 300 ms, then flushes the way the I/O
 *       loop does and times the wake.
 *
 *   race N
 *       The lost wakeup as it happens in the field. Per iteration: queue bytes, then one
 *       thread fails a send and waits (the caller) while another drains the
 *       ring and broadcasts (the I/O loop) at a jittered moment. Counts the
 *       iterations whose caller was still parked 50 ms after the flush finished.
 *
 *   write-eagain
 *       The I/O loop's write() to the server fails ONCE with EAGAIN (this file
 *       interposes write(); the framework is linked in statically, so its calls
 *       land here). The queued frame must still arrive, whole, not be
 *       consumed as (size_t) -1 bytes -- the entire ring, discarded.
 *
 *   flush-signal-locked
 *       The I/O loop must broadcast a flush WITH the flush mutex held, or the
 *       broadcast can land between a waiter's ring check and its wait (a
 *       sub-microsecond window no timing test hits reliably). So the probe
 *       holds the mutex itself -- a waiter caught mid-check -- and commits two
 *       frames: A is written and the loop then blocks in its broadcast, so B
 *       must NOT arrive until the probe lets go.
 *
 * commit-latency also reports idle_cpu_ms: process CPU over 500 ms with the loop
 * running and nothing to do. A wake pipe that is never drained keeps select()
 * returning at once, a busy loop every latency figure above would miss.
 */

#include "config.h"

#include <poll.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "capture_framework.h"
#include "simple_ringbuf_c.h"

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void sleep_us(long us) {
    struct timespec ts = { us / 1000000, (us % 1000000) * 1000 };
    nanosleep(&ts, NULL);
}

/* write-eagain: the next write() to this fd fails with EAGAIN, once. */
static volatile int eagain_fd = -1;
static volatile int eagain_hits = 0;

ssize_t write(int fd, const void *buf, size_t count) {
    if (fd == eagain_fd) {
        eagain_fd = -1;
        eagain_hits++;
        errno = EAGAIN;
        return -1;
    }
    return syscall(SYS_write, fd, buf, count);
}

static double cpu_ms(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1e3 +
        (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e3;
}

static kis_capture_handler_t *probe_handler(void) {
    kis_capture_handler_t *caph = cf_handler_init("wakeprobe");
    if (caph == NULL) {
        fprintf(stderr, "cf_handler_init failed\n");
        exit(2);
    }
    caph->use_ipc = 1;
    /* No PING will come: 0 disables the loop's 15 s keepalive check. */
    caph->last_ping = 0;
    /* The loop creates these lazily; make them before any thread can send. */
    caph->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);
    caph->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
    if (caph->in_ringbuf == NULL || caph->out_ringbuf == NULL) {
        fprintf(stderr, "ringbuf alloc failed\n");
        exit(2);
    }
    return caph;
}

/* What the I/O loop does after a write: consume, then tell waiters. */
static void flush_like_the_loop(kis_capture_handler_t *caph) {
    pthread_mutex_lock(&caph->out_ringbuf_lock);
    kis_simple_ringbuf_read(caph->out_ringbuf, NULL,
            kis_simple_ringbuf_used(caph->out_ringbuf));
    pthread_mutex_unlock(&caph->out_ringbuf_lock);

    pthread_mutex_lock(&caph->out_ringbuf_flush_cond_mutex);
    pthread_cond_broadcast(&caph->out_ringbuf_flush_cond);
    pthread_mutex_unlock(&caph->out_ringbuf_flush_cond_mutex);
}

/* An unrelated write's broadcast (the PONG that rescues a parked caller). */
static void unrelated_broadcast(kis_capture_handler_t *caph) {
    pthread_mutex_lock(&caph->out_ringbuf_flush_cond_mutex);
    pthread_cond_broadcast(&caph->out_ringbuf_flush_cond);
    pthread_mutex_unlock(&caph->out_ringbuf_flush_cond_mutex);
}

/* ---- commit-latency ---------------------------------------------------- */

static void *loop_thread(void *arg) {
    cf_handler_loop((kis_capture_handler_t *) arg);
    return NULL;
}

static int mode_commit_latency(int n) {
    kis_capture_handler_t *caph = probe_handler();
    int to_helper[2], from_helper[2];
    pthread_t loop;
    uint8_t frame[64], rbuf[4096];
    double total = 0, worst = 0;

    if (pipe(to_helper) < 0 || pipe(from_helper) < 0) {
        perror("pipe");
        return 2;
    }
    caph->in_fd = to_helper[0];
    caph->out_fd = from_helper[1];
    memset(frame, 0xA5, sizeof(frame));

    pthread_create(&loop, NULL, loop_thread, caph);
    sleep_us(20000);

    for (int i = 0; i < n; i++) {
        struct pollfd pfd = { from_helper[0], POLLIN, 0 };
        double t0, dt;

        sleep_us(37000);
        t0 = now_us();
        if (cf_send_raw_bytes(caph, frame, sizeof(frame)) != 1) {
            fprintf(stderr, "cf_send_raw_bytes refused frame %d\n", i);
            return 2;
        }
        if (poll(&pfd, 1, 3000) != 1) {
            printf("latency_us=-1\n");
            fflush(stdout);
            return 3;
        }
        dt = now_us() - t0;
        while (read(from_helper[0], rbuf, sizeof(rbuf)) == (ssize_t) sizeof(rbuf))
            ;
        printf("latency_us=%.0f\n", dt);
        total += dt;
        if (dt > worst)
            worst = dt;
    }
    printf("mean_us=%.0f\nmax_us=%.0f\n", total / n, worst);

    {
        double c0 = cpu_ms();
        sleep_us(500000);
        printf("idle_cpu_ms=%.1f\n", cpu_ms() - c0);
    }
    fflush(stdout);

    /* EOF on the helper's read side ends the loop. */
    close(to_helper[1]);
    pthread_join(loop, NULL);
    return 0;
}

/* ---- write-eagain ------------------------------------------------------ */

static int mode_write_eagain(void) {
    kis_capture_handler_t *caph = probe_handler();
    int to_helper[2], from_helper[2];
    pthread_t loop;
    uint8_t frame[200], got[sizeof(frame) * 2];
    size_t have = 0;
    double until;

    if (pipe(to_helper) < 0 || pipe(from_helper) < 0) {
        perror("pipe");
        return 2;
    }
    caph->in_fd = to_helper[0];
    caph->out_fd = from_helper[1];
    for (size_t i = 0; i < sizeof(frame); i++)
        frame[i] = (uint8_t) (i * 7 + 1);

    pthread_create(&loop, NULL, loop_thread, caph);
    sleep_us(20000);

    eagain_fd = from_helper[1];
    if (cf_send_raw_bytes(caph, frame, sizeof(frame)) != 1) {
        fprintf(stderr, "cf_send_raw_bytes refused the frame\n");
        return 2;
    }

    fcntl(from_helper[0], F_SETFL, fcntl(from_helper[0], F_GETFL, 0) | O_NONBLOCK);
    until = now_us() + 1500000;
    while (now_us() < until && have < sizeof(frame)) {
        ssize_t r = read(from_helper[0], got + have, sizeof(got) - have);
        if (r > 0)
            have += (size_t) r;
        else
            sleep_us(1000);
    }
    printf("eagain_injected=%d\n", eagain_hits);
    printf("delivered_bytes=%zu\n", have);
    printf("intact=%d\n", have == sizeof(frame) && memcmp(got, frame, sizeof(frame)) == 0);
    fflush(stdout);

    close(to_helper[1]);
    pthread_join(loop, NULL);
    return 0;
}

/* ---- flush-signal-locked ----------------------------------------------- */

static int arrives_within(int fd, long budget_us) {
    struct pollfd pfd = { fd, POLLIN, 0 };
    uint8_t rbuf[4096];
    if (poll(&pfd, 1, (int) (budget_us / 1000)) != 1)
        return 0;
    while (read(fd, rbuf, sizeof(rbuf)) == (ssize_t) sizeof(rbuf))
        ;
    return 1;
}

static int mode_flush_signal_locked(void) {
    kis_capture_handler_t *caph = probe_handler();
    int to_helper[2], from_helper[2];
    pthread_t loop;
    uint8_t frame[32];
    int a, b_held, b_after;

    if (pipe(to_helper) < 0 || pipe(from_helper) < 0) {
        perror("pipe");
        return 2;
    }
    caph->in_fd = to_helper[0];
    caph->out_fd = from_helper[1];
    memset(frame, 0x42, sizeof(frame));

    pthread_create(&loop, NULL, loop_thread, caph);
    sleep_us(20000);

    pthread_mutex_lock(&caph->out_ringbuf_flush_cond_mutex);
    cf_send_raw_bytes(caph, frame, sizeof(frame));
    a = arrives_within(from_helper[0], 1000000);
    /* A was written; the loop is now in (or past) its flush broadcast. */
    sleep_us(20000);
    cf_send_raw_bytes(caph, frame, sizeof(frame));
    b_held = arrives_within(from_helper[0], 300000);
    pthread_mutex_unlock(&caph->out_ringbuf_flush_cond_mutex);
    b_after = b_held ? 1 : arrives_within(from_helper[0], 1000000);

    printf("a_arrived=%d\nb_while_held=%d\nb_after_release=%d\n", a, b_held, b_after);
    fflush(stdout);
    close(to_helper[1]);
    pthread_join(loop, NULL);
    return 0;
}

/* ---- the waits --------------------------------------------------------- */

typedef struct {
    kis_capture_handler_t *caph;
    pthread_barrier_t *start;
    volatile int done;
    double returned_at;
} waiter_t;

static void *waiter_thread(void *arg) {
    waiter_t *w = (waiter_t *) arg;
    if (w->start != NULL) {
        uint8_t big[16];
        pthread_barrier_wait(w->start);
        /* The caller's failed send: CAP_FRAMEWORK_RINGBUF_OUT_SZ + 1 never fits. */
        (void) cf_send_raw_bytes(w->caph, big, CAP_FRAMEWORK_RINGBUF_OUT_SZ + 1);
    }
    cf_handler_wait_ringbuffer(w->caph);
    w->returned_at = now_us();
    __atomic_store_n(&w->done, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static int wait_done(waiter_t *w, long budget_us) {
    double until = now_us() + budget_us;
    while (now_us() < until) {
        if (__atomic_load_n(&w->done, __ATOMIC_SEQ_CST))
            return 1;
        sleep_us(500);
    }
    return __atomic_load_n(&w->done, __ATOMIC_SEQ_CST);
}

static int mode_wait_after_flush(void) {
    kis_capture_handler_t *caph = probe_handler();
    waiter_t w = { caph, NULL, 0, 0 };
    pthread_t t;
    double t0 = now_us();

    pthread_create(&t, NULL, waiter_thread, &w);
    if (wait_done(&w, 1000000)) {
        printf("woke_by=self\nparked_ms=%.1f\n", (w.returned_at - t0) / 1e3);
    } else {
        unrelated_broadcast(caph);
        if (!wait_done(&w, 1000000)) {
            printf("woke_by=never\n");
            return 3;
        }
        printf("woke_by=unrelated_broadcast\nparked_ms=%.1f\n", (w.returned_at - t0) / 1e3);
    }
    pthread_join(t, NULL);
    return 0;
}

static int mode_wait_while_pending(void) {
    kis_capture_handler_t *caph = probe_handler();
    waiter_t w = { caph, NULL, 0, 0 };
    uint8_t queued[100];
    pthread_t t;
    double tf;

    memset(queued, 0x5A, sizeof(queued));
    if (cf_send_raw_bytes(caph, queued, sizeof(queued)) != 1) {
        fprintf(stderr, "could not queue\n");
        return 2;
    }
    pthread_create(&t, NULL, waiter_thread, &w);
    if (wait_done(&w, 300000)) {
        printf("returned_while_pending=1\n");
        pthread_join(t, NULL);
        return 0;
    }
    printf("returned_while_pending=0\n");
    tf = now_us();
    flush_like_the_loop(caph);
    if (!wait_done(&w, 1000000)) {
        printf("woke_after_flush_ms=-1\n");
        unrelated_broadcast(caph);
        pthread_join(t, NULL);
        return 3;
    }
    printf("woke_after_flush_ms=%.1f\n", (w.returned_at - tf) / 1e3);
    pthread_join(t, NULL);
    return 0;
}

/* ---- race -------------------------------------------------------------- */

typedef struct {
    kis_capture_handler_t *caph;
    pthread_barrier_t *start;
    long spin_ns;
    double flushed_at;
} flusher_t;

static void *flusher_thread(void *arg) {
    flusher_t *f = (flusher_t *) arg;
    struct timespec a, b;
    pthread_barrier_wait(f->start);
    /* Busy-wait the jitter: nanosleep's floor (~50 us) would put every flush
     * after the caller is already waiting. */
    clock_gettime(CLOCK_MONOTONIC, &a);
    do {
        clock_gettime(CLOCK_MONOTONIC, &b);
    } while ((b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec) < f->spin_ns);
    flush_like_the_loop(f->caph);
    f->flushed_at = now_us();
    return NULL;
}

static int mode_race(int n) {
    kis_capture_handler_t *caph = probe_handler();
    uint8_t queued[100];
    int parked = 0;
    double worst_ms = 0;

    memset(queued, 0x3C, sizeof(queued));
    srand(4659);

    for (int i = 0; i < n; i++) {
        pthread_barrier_t start;
        waiter_t w = { caph, &start, 0, 0 };
        flusher_t f = { caph, &start, (long) (rand() % 20000), 0 };
        pthread_t tw, tf;

        cf_send_raw_bytes(caph, queued, sizeof(queued));
        pthread_barrier_init(&start, NULL, 2);
        pthread_create(&tw, NULL, waiter_thread, &w);
        pthread_create(&tf, NULL, flusher_thread, &f);
        pthread_join(tf, NULL);

        if (!wait_done(&w, 50000)) {
            parked++;
            unrelated_broadcast(caph);
            wait_done(&w, 1000000);
        }
        if (w.done && (w.returned_at - f.flushed_at) / 1e3 > worst_ms)
            worst_ms = (w.returned_at - f.flushed_at) / 1e3;
        pthread_join(tw, NULL);
        pthread_barrier_destroy(&start);
    }
    printf("iterations=%d\nparked_past_flush=%d\nworst_resume_after_flush_ms=%.1f\n",
           n, parked, worst_ms);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc >= 2 && strcmp(argv[1], "commit-latency") == 0)
        return mode_commit_latency(argc >= 3 ? atoi(argv[2]) : 20);
    if (argc >= 2 && strcmp(argv[1], "wait-after-flush") == 0)
        return mode_wait_after_flush();
    if (argc >= 2 && strcmp(argv[1], "wait-while-pending") == 0)
        return mode_wait_while_pending();
    if (argc >= 2 && strcmp(argv[1], "race") == 0)
        return mode_race(argc >= 3 ? atoi(argv[2]) : 200);
    if (argc >= 2 && strcmp(argv[1], "write-eagain") == 0)
        return mode_write_eagain();
    if (argc >= 2 && strcmp(argv[1], "flush-signal-locked") == 0)
        return mode_flush_signal_locked();
    fprintf(stderr, "usage: %s commit-latency [N] | wait-after-flush | "
            "wait-while-pending | race [N] | write-eagain | flush-signal-locked\n",
            argv[0]);
    return 2;
}
