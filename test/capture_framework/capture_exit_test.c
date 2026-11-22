/* Shutdown and free of a handler whose framework threads are still finishing.
 *
 *   tools/unit.sh <tree> test/capture_framework/capture_exit_test.c --set framework \
 *       --libs "-llzma -ldl" --flavor asan [-- ignored | late | stuck | double | openreq | sigfree]
 *
 * The capture callback turns cancels off, as the framework's tail does once the
 * callback returns, and sleeps through cf_handler_shutdown() and cf_handler_free().
 * "ignored" then returns with cancels still off, so the thread runs the framework's
 * tail; "late" turns them back on, so the pending cancel lands then.  Either way
 * cf_handler_free() has to wait for the thread before it returns: the handler is
 * freed right after, and ASan reports a use after free on the thread's next touch
 * of it otherwise.  "stuck" sleeps past the wait: free has to give up in bounded
 * time and leave the thread's locks and pipe alone (the handler is not freed).
 *
 * "double": the main thread and the signal thread shut down together, with an IPC
 * child on the list; the list is walked and freed once.  The child is listed
 * before the threads start: the signal thread can shut down as soon as the capture
 * callback returns.  "lateadd": a child added after shutdown took the list is
 * killed at once and freed by cf_handler_free.  "deepcancel": the capture thread
 * is cancelled asleep below a frame with a stack array; under ASan the unwind
 * must not trip on its redzones.  "openreq": an open while
 * the last capture thread ignores its cancel is refused, no second thread runs.
 * "sigfree": the signal thread is blocked on handler_lock in its shutdown when
 * free starts; free waits for it.  "uwlike": usbwifi/mm8108's capture thread
 * (cancels off, own 1 s wait, leaves on the spindown shutdown sets), then the
 * helper's stop, shutdown, free.  "reconnect": a remote connect after a shutdown
 * resets it and the exit budget.  "hopshut": shutdown stops a hop thread whose
 * channel control reads an IPC record before freeing the records.
 * "freechild": free without shutdown ends the children still listed.
 * "termlock": a child's term callback sends (taking handler_lock) while another
 * thread holds handler_lock and takes out_ringbuf_lock, as shutdown does; neither
 * may wait on the other.  "hopexit": a child exits while shutdown waits for the hop
 * thread; it is marked and freed with the list, no term callback runs.
 * "openfail": an open whose capture thread can't start answers with a failed open.
 * "earlychild": a child that exits during the open, before the signal thread
 * starts, is reaped once it does, with its SIGCHLD already taken, so only the
 * signal thread's start-up sweep can find it; SIGCHLD is then handled (macOS
 * drops it at SIG_DFL even when blocked) and not ignored.  "prethread": a thread
 * started after init and before the first open (cf_ws_ipc_thread, a helper's
 * reader) leaves every child exit to the reaper and sees no EINTR.  "sigign": the
 * same with SIGCHLD inherited as SIG_IGN.  "sigquit": a process-directed SIGQUIT
 * pending since init is taken by the signal thread's sigwait, not delivered with
 * its default action when the signal thread starts.  "reapedchild": a child that
 * exited and was reaped is not signalled by shutdown; its pid may belong to
 * another process by then (kill() is stubbed for that pid only).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "capture_framework.h"
#include "mpack/mpack.h"

int cf_dispatch_rx_content(kis_capture_handler_t *caph, unsigned int cmd,
        uint32_t seqno, const uint8_t *data, size_t packet_sz);

static int failures = 0;

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

/* Overrides libc's kill for the framework linked in here.  Signals to the
 * watched (reaped) pid are counted and never sent: a reused pid is someone
 * else's process.  Everything else goes to the next kill (a sanitizer's or libc's). */
typedef int (*kill_fn)(pid_t, int);
static kill_fn next_kill = NULL;
static pid_t watched_pid = 0;
static int watched_kills = 0;

int kill(pid_t pid, int sig) {
    kill_fn k;
    pid_t w = __atomic_load_n(&watched_pid, __ATOMIC_ACQUIRE);

    if (w > 0 && pid == w) {
        __atomic_add_fetch(&watched_kills, 1, __ATOMIC_ACQ_REL);
        return 0;
    }

    k = __atomic_load_n(&next_kill, __ATOMIC_ACQUIRE);
    if (k == NULL) {
        k = (kill_fn) dlsym(RTLD_NEXT, "kill");
        if (k == NULL) {
            errno = ENOSYS;
            return -1;
        }
        __atomic_store_n(&next_kill, k, __ATOMIC_RELEASE);
    }

    return k(pid, sig);
}

enum { MODE_IGNORED, MODE_LATE, MODE_STUCK, MODE_DOUBLE, MODE_OPENREQ, MODE_SIGFREE,
    MODE_LATEADD, MODE_DEEPCANCEL, MODE_UWLIKE, MODE_RECONNECT, MODE_HOPSHUT,
    MODE_FREECHILD, MODE_TERMLOCK, MODE_HOPEXIT, MODE_OPENFAIL, MODE_EARLYCHILD,
    MODE_PRETHREAD, MODE_SIGIGN, MODE_SIGQUIT, MODE_REAPEDCHILD };

static int mode = MODE_IGNORED;
static int started = 0;
static int cb_runs = 0;
static unsigned int hold_ms = 300;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000ULL + (uint64_t) ts.tv_nsec / 1000000ULL;
}

static void sleep_ms(unsigned int ms) {
    uint64_t until = now_ms() + ms;

    /* A signal cuts a single sleep short */
    while (now_ms() < until)
        usleep(1000);
}

/* Under the lock, as the framework's waits read it: the signal thread drops its
 * count holding it */
static unsigned int live(kis_capture_handler_t *caph, unsigned int *v) {
    unsigned int r;

    pthread_mutex_lock(&caph->thread_exit_lock);
    r = __atomic_load_n(v, __ATOMIC_ACQUIRE);
    pthread_mutex_unlock(&caph->thread_exit_lock);

    return r;
}

/* Cancelled asleep under a frame with a stack array, as pcapfile's capture
 * thread is at EOF: its redzones are left behind by the cancel */
static void __attribute__((noinline)) deep_sleep(void) {
    char buf[256];
    volatile char *p = buf;

    snprintf(buf, sizeof(buf), "deep");
    __atomic_store_n(&started, 1, __ATOMIC_RELEASE);

    while (p[0] != 0)
        sleep(1);
}

/* usbwifi/mm8108's capture thread: cancels off, its own 1 s timed wait, and it
 * leaves on spindown or a stop */
static pthread_mutex_t uw_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t uw_cond = PTHREAD_COND_INITIALIZER;
static int uw_stop = 0, uw_done = 0;

static void uwlike_cb(kis_capture_handler_t *caph) {
    struct timespec deadline;
    int stop = 0, spin = 0;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    __atomic_store_n(&started, 1, __ATOMIC_RELEASE);

    while (!stop && !spin) {
        pthread_mutex_lock(&uw_lock);
        if (!uw_stop) {
            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += 1;
            pthread_cond_timedwait(&uw_cond, &uw_lock, &deadline);
        }
        stop = uw_stop;
        pthread_mutex_unlock(&uw_lock);

        pthread_mutex_lock(&caph->handler_lock);
        spin = caph->spindown;
        pthread_mutex_unlock(&caph->handler_lock);
    }

    cf_handler_spindown(caph);

    pthread_mutex_lock(&uw_lock);
    uw_done = 1;
    pthread_cond_broadcast(&uw_cond);
    pthread_mutex_unlock(&uw_lock);
}

static void uw_stop_capture(void) {
    pthread_mutex_lock(&uw_lock);
    uw_stop = 1;
    pthread_cond_broadcast(&uw_cond);
    while (!uw_done)
        pthread_cond_wait(&uw_cond, &uw_lock);
    pthread_mutex_unlock(&uw_lock);
}

static void capture_cb(kis_capture_handler_t *caph) {
    (void) caph;

    __atomic_add_fetch(&cb_runs, 1, __ATOMIC_ACQ_REL);

    if (mode == MODE_DEEPCANCEL) {
        deep_sleep();
        return;
    }

    /* hopshut too: a callback that returned at once would spin the source down
     * and let the signal thread shut down before the hop thread starts */
    if (mode == MODE_UWLIKE || mode == MODE_HOPSHUT) {
        uwlike_cb(caph);
        return;
    }

    /* Until shutdown spins the source down */
    if (mode == MODE_TERMLOCK || mode == MODE_HOPEXIT || mode == MODE_EARLYCHILD ||
            mode == MODE_PRETHREAD || mode == MODE_SIGIGN || mode == MODE_SIGQUIT ||
            mode == MODE_REAPEDCHILD) {
        int spin = 0;

        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        __atomic_store_n(&started, 1, __ATOMIC_RELEASE);

        while (!spin) {
            sleep_ms(10);
            pthread_mutex_lock(&caph->handler_lock);
            spin = caph->spindown;
            pthread_mutex_unlock(&caph->handler_lock);
        }

        return;
    }

    if (mode == MODE_DOUBLE || mode == MODE_SIGFREE || mode == MODE_LATEADD ||
            mode == MODE_RECONNECT || mode == MODE_FREECHILD || mode == MODE_OPENFAIL) {
        __atomic_store_n(&started, 1, __ATOMIC_RELEASE);
        return;
    }

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    __atomic_store_n(&started, 1, __ATOMIC_RELEASE);

    sleep_ms(hold_ms);

    if (mode == MODE_LATE)
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
}

/* Ends the signal thread's sigwait loop: it then runs cf_handler_shutdown */
static void wake_signal_thread(kis_capture_handler_t *caph) {
    pthread_mutex_lock(&caph->handler_lock);
    caph->spindown = 1;
    pthread_mutex_unlock(&caph->handler_lock);
    kill(getpid(), SIGALRM);
}

static pid_t double_child = -1;

static cf_ipc_t *start_child(kis_capture_handler_t *caph) {
    char *argv[] = { (char *) "sleep", (char *) "30", NULL };
    cf_ipc_t *ipc = cf_ipc_exec(caph, 2, argv);

    CHECK(ipc != NULL);
    if (ipc != NULL)
        double_child = ipc->pid;

    return ipc;
}

static void reap_child(void) {
    pid_t r;
    int st;

    if (double_child <= 0)
        return;

    /* Killed; reaped here, or by the signal thread if a SIGCHLD beat its exit */
    r = waitpid(double_child, &st, 0);
    CHECK(r == double_child || (r < 0 && errno == ECHILD));
    if (r == double_child)
        CHECK(WIFSIGNALED(st));
}

static void run_double(kis_capture_handler_t *caph) {
    wake_signal_thread(caph);
    cf_handler_shutdown(caph);

    CHECK(caph->shutdown_done == 1);
    CHECK(caph->ipc_list == NULL);

    reap_child();
}

static void run_lateadd(kis_capture_handler_t *caph) {
    cf_ipc_t *ipc;

    cf_handler_shutdown(caph);

    ipc = start_child(caph);
    if (ipc == NULL)
        return;

    cf_ipc_add_process(caph, ipc);
    CHECK(caph->ipc_list == ipc);

    reap_child();
}

static void run_openreq(kis_capture_handler_t *caph) {
    /* The capture thread ignores the cancel and keeps running: an open now (with
     * the source reopening, so not spinning down) must not start another */
    pthread_mutex_lock(&caph->handler_lock);
    caph->capture_running = 0;
    pthread_mutex_unlock(&caph->handler_lock);

    CHECK(cf_handler_launch_capture_thread(caph) == -1);
    CHECK(live(caph, &caph->capture_live) == 1);

    /* And after its tail spun the source down */
    while (live(caph, &caph->capture_live))
        usleep(1000);
    CHECK(caph->spindown == 1);
    CHECK(cf_handler_launch_capture_thread(caph) == -1);
    CHECK(live(caph, &caph->capture_live) == 0);
    CHECK(__atomic_load_n(&cb_runs, __ATOMIC_ACQUIRE) == 1);
}

static void run_uwlike(kis_capture_handler_t *caph) {
    /* Land the shutdown 300 ms into the thread's 1 s wait: it sees the spindown
     * when that wait ends, inside shutdown's budget */
    sleep_ms(300);

    cf_handler_spindown(caph);
    cf_handler_shutdown(caph);
    CHECK(live(caph, &caph->capture_live) == 0);

    /* The helper's main: stop its thread, then shut down and free */
    uw_stop_capture();
    cf_handler_shutdown(caph);
}

/* A remote must be able to probe; never called here */
static int probe_cb(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    (void) caph; (void) seqno; (void) definition; (void) msg;
    (void) ret_interface; (void) ret_spectrum;
    *uuid = strdup("00000000-0000-0000-0000-000000000001");
    return 1;
}

static void run_reconnect(kis_capture_handler_t *caph) {
    struct sockaddr_in sin;
    socklen_t sl = sizeof(sin);
    int lfd;

    cf_handler_shutdown(caph);
    CHECK(caph->shutdown_done == 1);
    pthread_mutex_lock(&caph->thread_exit_lock);
    CHECK(caph->exit_deadline_ns != 0);
    pthread_mutex_unlock(&caph->thread_exit_lock);

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(lfd >= 0);
    if (lfd < 0)
        return;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(lfd, (struct sockaddr *) &sin, sizeof(sin)) == 0);
    CHECK(listen(lfd, 1) == 0);
    CHECK(getsockname(lfd, (struct sockaddr *) &sin, &sl) == 0);

    /* As cf_handler_parse_opts requires for a remote: a probe and a --source */
    cf_handler_set_probe_cb(caph, probe_cb);
    caph->cli_sourcedef = strdup("exittest");
    caph->remote_host = strdup("127.0.0.1");
    caph->remote_port = ntohs(sin.sin_port);

    /* The connect makes new rings; the capture thread that used them is gone */
    if (caph->in_ringbuf != NULL)
        kis_simple_ringbuf_free(caph->in_ringbuf);
    caph->in_ringbuf = NULL;
    if (caph->out_ringbuf != NULL)
        kis_simple_ringbuf_free(caph->out_ringbuf);
    caph->out_ringbuf = NULL;

    CHECK(cf_handler_tcp_remote_connect(caph) == 1);

    /* A new connection: a later shutdown runs again with a new budget */
    pthread_mutex_lock(&caph->handler_lock);
    CHECK(caph->shutdown_done == 0 && caph->shutdown == 0 && caph->spindown == 0);
    pthread_mutex_unlock(&caph->handler_lock);
    pthread_mutex_lock(&caph->thread_exit_lock);
    CHECK(caph->exit_deadline_ns == 0);
    CHECK(caph->capture_exit_timed_out == 0 && caph->signal_exit_timed_out == 0 &&
            caph->hop_exit_timed_out == 0);
    pthread_mutex_unlock(&caph->thread_exit_lock);

    cf_handler_shutdown(caph);
    CHECK(caph->shutdown_done == 1);

    close(lfd);
}

static cf_ipc_t *hop_ipc = NULL;
static int hop_calls = 0;

static int hx_armed;
static void hopexit_change(kis_capture_handler_t *caph);

/* zigbee900's channel control talks to its child through the IPC record */
static int hop_cb(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    volatile pid_t pid;

    (void) caph;
    (void) seqno;
    (void) privchan;
    (void) msg;

    pid = hop_ipc->pid;
    (void) pid;

    if (mode == MODE_HOPEXIT && __atomic_exchange_n(&hx_armed, 0, __ATOMIC_ACQ_REL))
        hopexit_change(caph);

    sleep_ms(30);
    __atomic_add_fetch(&hop_calls, 1, __ATOMIC_ACQ_REL);

    return 1;
}

static void run_hopshut(kis_capture_handler_t *caph) {
    char **chans = (char **) malloc(2 * sizeof(char *));
    void **priv = (void **) calloc(2, sizeof(void *));
    int calls;

    hop_ipc = start_child(caph);
    if (hop_ipc == NULL || chans == NULL || priv == NULL)
        return;
    cf_ipc_add_process(caph, hop_ipc);

    chans[0] = strdup("1");
    chans[1] = strdup("6");
    cf_handler_assign_hop_channels(caph, chans, priv, 2, 20.0, 0, 0, 0);

    while (__atomic_load_n(&hop_calls, __ATOMIC_ACQUIRE) < 3)
        usleep(1000);

    cf_handler_shutdown(caph);

    /* The child's SIGCHLD can start the signal thread's shutdown first; this one
     * then waits for it to finish */
    CHECK(live(caph, &caph->hop_live) == 0);
    CHECK(caph->ipc_list == NULL);

    /* A hop list after shutdown starts no thread */
    CHECK(cf_handler_launch_hopping_thread(caph) == -1);
    CHECK(live(caph, &caph->hop_live) == 0);

    while (live(caph, &caph->signal_live))
        usleep(1000);

    /* The hop thread left before the IPC records went */
    CHECK(live(caph, &caph->hop_live) == 0);
    CHECK(caph->ipc_list == NULL);
    calls = __atomic_load_n(&hop_calls, __ATOMIC_ACQUIRE);
    sleep_ms(150);
    CHECK(__atomic_load_n(&hop_calls, __ATOMIC_ACQUIRE) == calls);

    reap_child();
}

static int term_calls = 0;

/* zigbee900's: reports the exit to Kismet; may take handler_lock */
static void term_cb(kis_capture_handler_t *caph, cf_ipc_t *ipc, int rc) {
    (void) ipc;
    (void) rc;

    pthread_mutex_lock(&caph->handler_lock);
    __atomic_add_fetch(&term_calls, 1, __ATOMIC_ACQ_REL);
    pthread_mutex_unlock(&caph->handler_lock);

    cf_send_error(caph, 0, "test child exited");
}

static void run_termlock(kis_capture_handler_t *caph) {
    char *argv[] = { (char *) "sleep", (char *) "0.1", NULL };
    cf_ipc_t *ipc = cf_ipc_exec(caph, 2, argv);
    uint64_t until;
    int r;

    CHECK(ipc != NULL);
    if (ipc == NULL)
        return;
    double_child = ipc->pid;
    cf_ipc_set_term(caph, ipc, term_cb);
    cf_ipc_add_process(caph, ipc);

    /* Holding handler_lock while the child exits and is reaped, then taking
     * out_ringbuf_lock: a reaper holding that one while its callback waits for
     * handler_lock never lets go */
    pthread_mutex_lock(&caph->handler_lock);
    sleep_ms(400);

    /* No pthread_mutex_timedlock on macOS */
    until = now_ms() + 3000;
    while ((r = pthread_mutex_trylock(&caph->out_ringbuf_lock)) == EBUSY && now_ms() < until)
        usleep(1000);
    CHECK(r == 0);
    if (r == 0)
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
    pthread_mutex_unlock(&caph->handler_lock);

    until = now_ms() + 3000;
    while (__atomic_load_n(&term_calls, __ATOMIC_ACQUIRE) == 0 && now_ms() < until)
        usleep(1000);
    CHECK(__atomic_load_n(&term_calls, __ATOMIC_ACQUIRE) == 1);

    /* Reaped and unlinked; the record is the source's to free */
    pthread_mutex_lock(&caph->handler_lock);
    CHECK(caph->ipc_list == NULL);
    pthread_mutex_unlock(&caph->handler_lock);
    if (__atomic_load_n(&term_calls, __ATOMIC_ACQUIRE) == 1)
        cf_ipc_free(caph, ipc);

    cf_handler_shutdown(caph);
    reap_child();
}

static int hx_armed = 0;
static int hx_inside = 0;

static int shutdown_started(kis_capture_handler_t *caph) {
    int r;

    pthread_mutex_lock(&caph->thread_exit_lock);
    r = caph->shutdown_busy;
    pthread_mutex_unlock(&caph->thread_exit_lock);

    return r;
}

/* A channel change that drops handler_lock and runs on into shutdown's wait for
 * the hop thread; its child exits there */
static void hopexit_change(kis_capture_handler_t *caph) {
    pthread_mutex_unlock(&caph->handler_lock);
    __atomic_store_n(&hx_inside, 1, __ATOMIC_RELEASE);

    while (!shutdown_started(caph))
        sleep_ms(1);

    sleep_ms(50);
    kill(hop_ipc->pid, SIGKILL);
    sleep_ms(200);

    pthread_mutex_lock(&caph->handler_lock);
}

static void run_hopexit(kis_capture_handler_t *caph) {
    char **chans = (char **) malloc(2 * sizeof(char *));
    void **priv = (void **) calloc(2, sizeof(void *));
    pid_t r;
    int st;

    hop_ipc = start_child(caph);
    if (hop_ipc == NULL || chans == NULL || priv == NULL)
        return;
    cf_ipc_set_term(caph, hop_ipc, term_cb);
    cf_ipc_add_process(caph, hop_ipc);

    chans[0] = strdup("1");
    chans[1] = strdup("6");
    cf_handler_assign_hop_channels(caph, chans, priv, 2, 20.0, 0, 0, 0);

    while (__atomic_load_n(&hop_calls, __ATOMIC_ACQUIRE) < 1)
        usleep(1000);
    __atomic_store_n(&hx_armed, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&hx_inside, __ATOMIC_ACQUIRE))
        usleep(1000);

    cf_handler_shutdown(caph);

    CHECK(live(caph, &caph->hop_live) == 0);
    CHECK(caph->ipc_list == NULL);
    CHECK(__atomic_load_n(&term_calls, __ATOMIC_ACQUIRE) == 0);

    /* The reaper reaped it during the wait */
    r = waitpid(double_child, &st, WNOHANG);
    CHECK(r < 0 && errno == ECHILD);
}

/* Listed before the capture thread starts, as rtl433 and zigbee900 do in their
 * open callback; it exits before there is a signal thread */
static cf_ipc_t *early_ipc = NULL;

static void start_earlychild(kis_capture_handler_t *caph) {
    char *argv[] = { (char *) "sleep", (char *) "0", NULL };
    sigset_t chld, pend;
    uint64_t until;
    int sig = 0;

    early_ipc = cf_ipc_exec(caph, 2, argv);
    CHECK(early_ipc != NULL);
    if (early_ipc == NULL)
        return;
    double_child = early_ipc->pid;
    cf_ipc_set_term(caph, early_ipc, term_cb);
    cf_ipc_add_process(caph, early_ipc);

    /* Take its SIGCHLD (blocked in every thread, so still pending) and leave the
     * signal thread none to wait for; no sigtimedwait on macOS */
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigemptyset(&pend);
    until = now_ms() + 3000;
    while (now_ms() < until) {
        sigpending(&pend);
        if (sigismember(&pend, SIGCHLD))
            break;
        usleep(1000);
    }
    CHECK(sigismember(&pend, SIGCHLD));
    if (sigismember(&pend, SIGCHLD)) {
        CHECK(sigwait(&chld, &sig) == 0 && sig == SIGCHLD);
    }

    sigpending(&pend);
    CHECK(!sigismember(&pend, SIGCHLD));
}

static void run_earlychild(kis_capture_handler_t *caph) {
    struct sigaction sa;
    uint64_t until;
    pid_t r;
    int st;

    CHECK(sigaction(SIGCHLD, NULL, &sa) == 0);
    CHECK(sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN);
    CHECK((sa.sa_flags & SA_RESTART) != 0);

    if (early_ipc == NULL)
        return;

    until = now_ms() + 3000;
    while (__atomic_load_n(&term_calls, __ATOMIC_ACQUIRE) == 0 && now_ms() < until)
        usleep(1000);
    CHECK(__atomic_load_n(&term_calls, __ATOMIC_ACQUIRE) == 1);

    pthread_mutex_lock(&caph->handler_lock);
    CHECK(caph->ipc_list == NULL);
    pthread_mutex_unlock(&caph->handler_lock);

    r = waitpid(double_child, &st, WNOHANG);
    CHECK(r < 0 && errno == ECHILD);

    if (__atomic_load_n(&term_calls, __ATOMIC_ACQUIRE) == 1)
        cf_ipc_free(caph, early_ipc);

    cf_handler_shutdown(caph);
}

/* A thread started after cf_handler_init and before the first open, as
 * cf_ws_ipc_thread and helpers' own threads are; it takes no signal meant for
 * the signal thread, so its sleeps are never cut short */
static int pre_stop = 0, pre_loops = 0, pre_eintr = 0, pre_terms = 0;
static pthread_t pre_thread;
static int pre_thread_ok = 0;

#define PRE_CHILDREN 20

static void *prethread(void *arg) {
    (void) arg;

    while (!__atomic_load_n(&pre_stop, __ATOMIC_ACQUIRE)) {
        struct timespec ts = { 0, 5 * 1000000L };

        if (nanosleep(&ts, NULL) < 0 && errno == EINTR)
            __atomic_add_fetch(&pre_eintr, 1, __ATOMIC_ACQ_REL);
        __atomic_add_fetch(&pre_loops, 1, __ATOMIC_ACQ_REL);
    }

    return NULL;
}

static void start_prethread(void) {
    pre_thread_ok = pthread_create(&pre_thread, NULL, prethread, NULL) == 0;
    CHECK(pre_thread_ok);
}

/* Unlinked by the reaper before it runs; nothing else holds the record */
static void pre_term_cb(kis_capture_handler_t *caph, cf_ipc_t *ipc, int rc) {
    (void) rc;

    __atomic_add_fetch(&pre_terms, 1, __ATOMIC_ACQ_REL);
    cf_ipc_free(caph, ipc);
}

static void run_prethread(kis_capture_handler_t *caph) {
    char *argv[] = { (char *) "sleep", (char *) "0.02", NULL };
    struct sigaction sa;
    int i, missed = 0;

    /* An inherited SIG_IGN (sigign mode) is replaced too */
    CHECK(sigaction(SIGCHLD, NULL, &sa) == 0);
    CHECK(sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN);

    for (i = 0; i < PRE_CHILDREN; i++) {
        int before = __atomic_load_n(&pre_terms, __ATOMIC_ACQUIRE);
        uint64_t until;
        cf_ipc_t *ipc;

        pthread_mutex_lock(&caph->handler_lock);
        ipc = cf_ipc_exec(caph, 2, argv);
        if (ipc != NULL) {
            cf_ipc_set_term(caph, ipc, pre_term_cb);
            cf_ipc_add_process(caph, ipc);
        }
        pthread_mutex_unlock(&caph->handler_lock);

        CHECK(ipc != NULL);
        if (ipc == NULL)
            break;

        until = now_ms() + 1000;
        while (__atomic_load_n(&pre_terms, __ATOMIC_ACQUIRE) == before && now_ms() < until)
            usleep(1000);

        /* Lost exits stay listed for shutdown to free; a few show the failure */
        if (__atomic_load_n(&pre_terms, __ATOMIC_ACQUIRE) == before && ++missed >= 3)
            break;
    }

    CHECK(missed == 0);
    CHECK(__atomic_load_n(&pre_terms, __ATOMIC_ACQUIRE) == PRE_CHILDREN);

    __atomic_store_n(&pre_stop, 1, __ATOMIC_RELEASE);
    if (pre_thread_ok)
        pthread_join(pre_thread, NULL);

    CHECK(__atomic_load_n(&pre_loops, __ATOMIC_ACQUIRE) > 0);
    CHECK(__atomic_load_n(&pre_eintr, __ATOMIC_ACQUIRE) == 0);

    if (missed || pre_eintr)
        fprintf(stderr, "prethread: %d of %d exits missed, %d EINTR in %d sleeps\n",
                missed, PRE_CHILDREN, pre_eintr, pre_loops);

    cf_handler_shutdown(caph);
}

/* Process-directed, held by the core mask until the signal thread runs */
static void start_sigquit(void) {
    sigset_t pend;

    CHECK(kill(getpid(), SIGQUIT) == 0);
    sigpending(&pend);
    CHECK(sigismember(&pend, SIGQUIT));
}

static void run_sigquit(kis_capture_handler_t *caph) {
    sigset_t pend;
    uint64_t until;

    until = now_ms() + 2000;
    do {
        sigpending(&pend);
        if (!sigismember(&pend, SIGQUIT))
            break;
        usleep(1000);
    } while (now_ms() < until);
    CHECK(!sigismember(&pend, SIGQUIT));

    cf_handler_shutdown(caph);
}

/* rtl433's tool exits on its own and is reaped; a later shutdown and free must
 * leave its pid alone */
static void run_reapedchild(kis_capture_handler_t *caph) {
    char *argv[] = { (char *) "sleep", (char *) "0", NULL };
    cf_ipc_t *ipc = cf_ipc_exec(caph, 2, argv);
    uint64_t until;
    pid_t pid, r;
    int st;

    CHECK(ipc != NULL);
    if (ipc == NULL)
        return;
    pid = ipc->pid;
    cf_ipc_set_term(caph, ipc, pre_term_cb);
    cf_ipc_add_process(caph, ipc);

    until = now_ms() + 3000;
    while (__atomic_load_n(&pre_terms, __ATOMIC_ACQUIRE) == 0 && now_ms() < until)
        usleep(1000);
    CHECK(__atomic_load_n(&pre_terms, __ATOMIC_ACQUIRE) == 1);

    r = waitpid(pid, &st, WNOHANG);
    CHECK(r < 0 && errno == ECHILD);

    pthread_mutex_lock(&caph->handler_lock);
    CHECK(caph->child_pid != pid);
    pthread_mutex_unlock(&caph->handler_lock);

    /* Stays watched through cf_handler_free */
    __atomic_store_n(&watched_pid, pid, __ATOMIC_RELEASE);
    cf_handler_shutdown(caph);
    CHECK(__atomic_load_n(&watched_kills, __ATOMIC_ACQUIRE) == 0);
}

/* An open after the capture thread spun the source down: the open callback
 * succeeds, the capture thread is refused, and the answer is a failed open */
static int open_cb(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    (void) caph; (void) seqno; (void) definition; (void) ret_interface;
    (void) ret_spectrum;
    *dlt = 1;
    *uuid = strdup("00000000-0000-0000-0000-000000000001");
    snprintf(msg, STATUS_MAX, "opened");
    return 1;
}

static void run_openfail(kis_capture_handler_t *caph) {
    char req[64];
    uint8_t out[4096];
    mpack_writer_t w;
    size_t reqlen, used, pos;
    int found = 0;

    while (live(caph, &caph->capture_live))
        usleep(1000);
    CHECK(caph->spindown == 1);

    cf_handler_set_open_cb(caph, open_cb);

    pthread_mutex_lock(&caph->handler_lock);
    pthread_mutex_lock(&caph->out_ringbuf_lock);
    caph->use_ipc = 1;
    /* Made by the first send when there is no loop yet */
    if (caph->out_ringbuf != NULL)
        kis_simple_ringbuf_clear(caph->out_ringbuf);
    pthread_mutex_unlock(&caph->out_ringbuf_lock);
    pthread_mutex_unlock(&caph->handler_lock);

    mpack_writer_init(&w, req, sizeof(req));
    mpack_build_map(&w);
    mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_OPENREQ_FIELD_DEFINITION);
    mpack_write_cstr(&w, "exittest");
    mpack_complete_map(&w);
    reqlen = mpack_writer_buffer_used(&w);
    CHECK(mpack_writer_destroy(&w) == mpack_ok);

    cf_dispatch_rx_content(caph, KIS_EXTERNAL_V3_KDS_OPENREQ, 42,
            (const uint8_t *) req, reqlen);

    pthread_mutex_lock(&caph->out_ringbuf_lock);
    used = 0;
    if (caph->out_ringbuf != NULL) {
        used = kis_simple_ringbuf_used(caph->out_ringbuf);
        if (used > sizeof(out))
            used = sizeof(out);
        used = kis_simple_ringbuf_peek(caph->out_ringbuf, out, used);
    }
    pthread_mutex_unlock(&caph->out_ringbuf_lock);

    for (pos = 0; pos + sizeof(kismet_external_frame_v3_t) <= used; ) {
        kismet_external_frame_v3_t fr;
        uint32_t len;

        memcpy(&fr, out + pos, sizeof(fr));
        len = ntohl(fr.length);

        if (ntohs(fr.pkt_type) == KIS_EXTERNAL_V3_KDS_OPENREPORT && ntohl(fr.seqno) == 42) {
            found++;
            CHECK(ntohs(fr.code) == 0);
        }

        if (len > used - pos - sizeof(fr))
            break;
        pos += sizeof(fr) + len;
    }

    CHECK(found == 1);
    CHECK(live(caph, &caph->capture_live) == 0);
    CHECK(__atomic_load_n(&cb_runs, __ATOMIC_ACQUIRE) == 1);
}

static void *watchdog(void *arg) {
    (void) arg;

    sleep(20);
    fprintf(stderr, "FAIL: hung for 20 s\n");
    _exit(3);
    return NULL;
}

static int run(void) {
    kis_capture_handler_t *caph = cf_handler_init("exittest");
    uint64_t t0, t1;

    CHECK(caph != NULL);
    if (caph == NULL)
        return 1;

    CHECK(caph->monitor_pid == 0 && caph->child_pid == 0);

    cf_handler_set_capture_cb(caph, capture_cb);
    cf_handler_set_chancontrol_cb(caph, hop_cb);

    if (mode == MODE_DOUBLE || mode == MODE_FREECHILD) {
        cf_ipc_t *ipc = start_child(caph);
        if (ipc != NULL)
            cf_ipc_add_process(caph, ipc);
    }

    if (mode == MODE_EARLYCHILD)
        start_earlychild(caph);

    if (mode == MODE_PRETHREAD || mode == MODE_SIGIGN)
        start_prethread();

    if (mode == MODE_SIGQUIT)
        start_sigquit();

    CHECK(cf_handler_launch_capture_thread(caph) == 1);

    while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE))
        usleep(1000);

    t0 = now_ms();

    if (mode == MODE_DOUBLE) {
        run_double(caph);
    } else if (mode == MODE_LATEADD) {
        run_lateadd(caph);
    } else if (mode == MODE_UWLIKE) {
        run_uwlike(caph);
    } else if (mode == MODE_RECONNECT) {
        run_reconnect(caph);
    } else if (mode == MODE_HOPSHUT) {
        run_hopshut(caph);
    } else if (mode == MODE_TERMLOCK) {
        run_termlock(caph);
    } else if (mode == MODE_HOPEXIT) {
        run_hopexit(caph);
    } else if (mode == MODE_EARLYCHILD) {
        run_earlychild(caph);
    } else if (mode == MODE_PRETHREAD || mode == MODE_SIGIGN) {
        run_prethread(caph);
    } else if (mode == MODE_SIGQUIT) {
        run_sigquit(caph);
    } else if (mode == MODE_REAPEDCHILD) {
        run_reapedchild(caph);
    } else if (mode == MODE_OPENFAIL) {
        run_openfail(caph);
        cf_handler_shutdown(caph);
    } else if (mode == MODE_FREECHILD) {
        /* No shutdown: free has to end the child itself */
    } else if (mode == MODE_OPENREQ) {
        run_openreq(caph);
        cf_handler_shutdown(caph);
    } else if (mode == MODE_SIGFREE) {
        /* Hold the lock so the signal thread's shutdown blocks on it */
        pthread_mutex_lock(&caph->handler_lock);
        wake_signal_thread(caph);
        sleep_ms(50);
        pthread_mutex_unlock(&caph->handler_lock);
    } else {
        cf_handler_shutdown(caph);
    }

    cf_handler_free(caph);
    t1 = now_ms();

    if (mode == MODE_STUCK) {
        /* Gave up (one wait in total, in shutdown), before the thread finished */
        CHECK(t1 - t0 < hold_ms - 2000);
        CHECK(live(caph, &caph->capture_live) == 1);

        /* Its locks, pipe and ring were left for it when it does finish */
        while (live(caph, &caph->capture_live) || live(caph, &caph->signal_live))
            usleep(1000);
        CHECK(now_ms() - t0 >= hold_ms - 50);
        CHECK(caph->spindown == 1);
        CHECK(caph->out_ringbuf_wake[0] >= 0 && caph->out_ringbuf_wake[1] >= 0);

        close(caph->out_ringbuf_wake[0]);
        close(caph->out_ringbuf_wake[1]);
        if (caph->out_ringbuf != NULL)
            kis_simple_ringbuf_free(caph->out_ringbuf);
        free(caph->hop_clock);
        free(caph->hop_timing);
        free(caph->switch_windows);
    } else {
        /* Every framework thread is gone: free tore everything down */
        /* Not live(): free destroyed the lock */
        CHECK(__atomic_load_n(&caph->capture_live, __ATOMIC_ACQUIRE) == 0 &&
                __atomic_load_n(&caph->signal_live, __ATOMIC_ACQUIRE) == 0 &&
                __atomic_load_n(&caph->hop_live, __ATOMIC_ACQUIRE) == 0);
        CHECK(caph->ipc_list == NULL);
        CHECK(caph->capture_exit_timed_out == 0 && caph->signal_exit_timed_out == 0 &&
                caph->hop_exit_timed_out == 0);
        CHECK(caph->switch_windows == NULL);
        CHECK(caph->out_ringbuf_wake[0] == -1 && caph->out_ringbuf_wake[1] == -1);

        /* Waited for the thread rather than freeing under it */
        if (mode == MODE_IGNORED || mode == MODE_LATE)
            CHECK(t1 - t0 >= hold_ms - 100);
    }

    if (mode == MODE_FREECHILD)
        reap_child();

    free(caph);

    /* Any stray touch of the handler happens before exit */
    while (now_ms() < t0 + hold_ms + 300)
        usleep(1000);

    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "late") == 0) {
        mode = MODE_LATE;
    } else if (argc > 1 && strcmp(argv[1], "stuck") == 0) {
        mode = MODE_STUCK;
        hold_ms = 4000;
    } else if (argc > 1 && strcmp(argv[1], "double") == 0) {
        mode = MODE_DOUBLE;
    } else if (argc > 1 && strcmp(argv[1], "openreq") == 0) {
        mode = MODE_OPENREQ;
    } else if (argc > 1 && strcmp(argv[1], "sigfree") == 0) {
        mode = MODE_SIGFREE;
    } else if (argc > 1 && strcmp(argv[1], "lateadd") == 0) {
        mode = MODE_LATEADD;
    } else if (argc > 1 && strcmp(argv[1], "deepcancel") == 0) {
        mode = MODE_DEEPCANCEL;
    } else if (argc > 1 && strcmp(argv[1], "uwlike") == 0) {
        mode = MODE_UWLIKE;
        hold_ms = 1500;
    } else if (argc > 1 && strcmp(argv[1], "reconnect") == 0) {
        mode = MODE_RECONNECT;
    } else if (argc > 1 && strcmp(argv[1], "hopshut") == 0) {
        mode = MODE_HOPSHUT;
    } else if (argc > 1 && strcmp(argv[1], "freechild") == 0) {
        mode = MODE_FREECHILD;
    } else if (argc > 1 && strcmp(argv[1], "termlock") == 0) {
        mode = MODE_TERMLOCK;
    } else if (argc > 1 && strcmp(argv[1], "hopexit") == 0) {
        mode = MODE_HOPEXIT;
    } else if (argc > 1 && strcmp(argv[1], "openfail") == 0) {
        mode = MODE_OPENFAIL;
    } else if (argc > 1 && strcmp(argv[1], "earlychild") == 0) {
        mode = MODE_EARLYCHILD;
    } else if (argc > 1 && strcmp(argv[1], "prethread") == 0) {
        mode = MODE_PRETHREAD;
    } else if (argc > 1 && strcmp(argv[1], "sigign") == 0) {
        mode = MODE_SIGIGN;
        signal(SIGCHLD, SIG_IGN);
    } else if (argc > 1 && strcmp(argv[1], "sigquit") == 0) {
        mode = MODE_SIGQUIT;
    } else if (argc > 1 && strcmp(argv[1], "reapedchild") == 0) {
        mode = MODE_REAPEDCHILD;
    }

    /* A deadlock is a failure, not a hang */
    if (mode == MODE_TERMLOCK || mode == MODE_HOPEXIT || mode == MODE_EARLYCHILD ||
            mode == MODE_PRETHREAD || mode == MODE_SIGIGN || mode == MODE_SIGQUIT ||
            mode == MODE_REAPEDCHILD) {
        pthread_t wd;
        sigset_t all, old;

        /* Started with every signal blocked, so none reaches it before it runs;
         * leaves SIGCHLD, SIGALRM and SIGQUIT to the framework's signal thread */
        sigfillset(&all);
        pthread_sigmask(SIG_BLOCK, &all, &old);
        if (pthread_create(&wd, NULL, watchdog, NULL) == 0)
            pthread_detach(wd);
        pthread_sigmask(SIG_SETMASK, &old, NULL);
    }

    run();

    if (failures) {
        fprintf(stderr, "capture_exit_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("capture_exit_test: ok\n");
    return 0;
}
