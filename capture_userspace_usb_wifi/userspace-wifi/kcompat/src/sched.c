/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* Time, timers, wait queues, kthreads, workqueues, tasklets, NAPI and RCU */

#include <time.h>

#include <kcompat/kcompat.h>
#include <kcompat/host.h>

/* Time */
volatile unsigned long jiffies;
static u64 kc_mono_base_ns;

static u64 kc_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64) ts.tv_sec * NSEC_PER_SEC + (u64) ts.tv_nsec;
}

/* jiffies start well above zero so wraparound-safe comparisons against 0 behave */
u64 kc_jiffies_now(void) {
    return (kc_mono_ns() - kc_mono_base_ns) / NSEC_PER_MSEC + 100000;
}

long __kc_jiffies_remaining(u64 deadline) {
    u64 now = kc_jiffies_now();
    return now >= deadline ? 0 : (long) (deadline - now);
}

ktime_t ktime_get(void) {
    return (ktime_t) kc_mono_ns();
}

ktime_t ktime_get_real(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (ktime_t) ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

static void kc_sleep_ns(u64 ns) {
    struct timespec ts = { (time_t) (ns / NSEC_PER_SEC), (long) (ns % NSEC_PER_SEC) };
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
        ;
}

void msleep(unsigned int ms) { kc_sleep_ns((u64) ms * NSEC_PER_MSEC); }
void usleep_range(unsigned long min, unsigned long max) { (void) max; kc_sleep_ns((u64) min * NSEC_PER_USEC); }
void udelay(unsigned long us) { kc_sleep_ns((u64) us * NSEC_PER_USEC); }

static void kc_abs_deadline(struct timespec *ts, long ms) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (ms % 1000) * NSEC_PER_MSEC;
    if (ts->tv_nsec >= NSEC_PER_SEC) {
        ts->tv_sec++;
        ts->tv_nsec -= NSEC_PER_SEC;
    }
}

void __kc_cond_timedwait_ms(pthread_cond_t *c, pthread_mutex_t *m, long ms) {
    struct timespec ts;
    kc_abs_deadline(&ts, ms);
    pthread_cond_timedwait(c, m, &ts);
}

/* Wait queues */
void init_waitqueue_head(wait_queue_head_t *wq) {
    pthread_mutex_init(&wq->lock, NULL);
    pthread_cond_init(&wq->cond, NULL);
}

void __wake_up(wait_queue_head_t *wq) {
    pthread_mutex_lock(&wq->lock);
    pthread_cond_broadcast(&wq->cond);
    pthread_mutex_unlock(&wq->lock);
}

/* RCU: readers don't lock, so a grace period is a pause long enough for any reader in
 * a callback to finish */
void synchronize_rcu(void) {
    msleep(10);
}

void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *)) {
    synchronize_rcu();
    func(head);
}

/* Timers: one thread runs every timer and hrtimer callback, in expiry order */
static pthread_mutex_t kc_timer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t kc_timer_cond = PTHREAD_COND_INITIALIZER;
static struct timer_list *kc_timers;
static struct timer_list *kc_timer_running;
static pthread_cond_t kc_timer_done = PTHREAD_COND_INITIALIZER;
static pthread_t kc_timer_tid;

static void kc_timer_unlink(struct timer_list *t) {
    for (struct timer_list **p = &kc_timers; *p != NULL; p = &(*p)->kc_next) {
        if (*p == t) {
            *p = t->kc_next;
            t->kc_next = NULL;
            break;
        }
    }
    t->pending = false;
}

static void *kc_timer_thread(void *arg) {
    (void) arg;

    pthread_mutex_lock(&kc_timer_lock);
    for (;;) {
        struct timer_list *next = NULL;

        for (struct timer_list *t = kc_timers; t != NULL; t = t->kc_next)
            if (next == NULL || time_before(t->expires, next->expires))
                next = t;

        if (next == NULL) {
            pthread_cond_wait(&kc_timer_cond, &kc_timer_lock);
            continue;
        }

        long wait = (long) (next->expires - jiffies);
        if (wait > 0) {
            __kc_cond_timedwait_ms(&kc_timer_cond, &kc_timer_lock, wait);
            continue;
        }

        kc_timer_unlink(next);
        kc_timer_running = next;
        pthread_mutex_unlock(&kc_timer_lock);

        next->function(next);

        pthread_mutex_lock(&kc_timer_lock);
        kc_timer_running = NULL;
        pthread_cond_broadcast(&kc_timer_done);
    }

    return NULL;
}

void timer_setup(struct timer_list *t, void (*fn)(struct timer_list *), unsigned int flags) {
    t->function = fn;
    t->flags = flags;
    t->expires = 0;
    t->pending = false;
    t->kc_next = NULL;
}

int mod_timer(struct timer_list *t, unsigned long expires) {
    int was;

    pthread_mutex_lock(&kc_timer_lock);
    was = t->pending;
    if (was)
        kc_timer_unlink(t);
    t->expires = expires;
    t->pending = true;
    t->kc_next = kc_timers;
    kc_timers = t;
    pthread_cond_broadcast(&kc_timer_cond);
    pthread_mutex_unlock(&kc_timer_lock);

    return was;
}

void add_timer(struct timer_list *t) {
    mod_timer(t, t->expires);
}

int timer_delete(struct timer_list *t) {
    int was;

    pthread_mutex_lock(&kc_timer_lock);
    was = t->pending;
    if (was)
        kc_timer_unlink(t);
    pthread_mutex_unlock(&kc_timer_lock);

    return was;
}

/* Also waits for a running callback, unless called from that callback */
int timer_delete_sync(struct timer_list *t) {
    int was;

    pthread_mutex_lock(&kc_timer_lock);
    was = t->pending;
    if (was)
        kc_timer_unlink(t);
    while (kc_timer_running == t && !pthread_equal(pthread_self(), kc_timer_tid))
        pthread_cond_wait(&kc_timer_done, &kc_timer_lock);
    pthread_mutex_unlock(&kc_timer_lock);

    return was;
}

static void kc_hrtimer_fn(struct timer_list *tl) {
    struct hrtimer *t = container_of(tl, struct hrtimer, kc_timer);
    t->function(t);
}

void hrtimer_setup(struct hrtimer *t, enum hrtimer_restart (*fn)(struct hrtimer *), int clock,
        enum hrtimer_mode mode) {
    (void) clock;
    (void) mode;
    t->function = fn;
    timer_setup(&t->kc_timer, kc_hrtimer_fn, 0);
}

void hrtimer_start(struct hrtimer *t, ktime_t tim, enum hrtimer_mode mode) {
    unsigned long expires;

    if (mode & HRTIMER_MODE_REL)
        expires = jiffies + (unsigned long) DIV_ROUND_UP(tim, NSEC_PER_MSEC);
    else
        expires = (unsigned long) (tim / NSEC_PER_MSEC);

    mod_timer(&t->kc_timer, expires);
}

int hrtimer_cancel(struct hrtimer *t) {
    return timer_delete_sync(&t->kc_timer);
}

int hrtimer_try_to_cancel(struct hrtimer *t) {
    return timer_delete(&t->kc_timer);
}

/* kthreads */
static __thread struct task_struct *kc_current_task;

struct task_struct *kc_current(void) {
    /* Threads kcompat didn't create get a task on first use */
    if (kc_current_task == NULL) {
        struct task_struct *t = calloc(1, sizeof(*t));
        if (t == NULL)
            abort();
        t->thread = pthread_self();
        snprintf(t->comm, sizeof(t->comm), "host");
        pthread_mutex_init(&t->lock, NULL);
        pthread_cond_init(&t->cond, NULL);
        init_completion(&t->exit_done);
        kc_current_task = t;
    }
    return kc_current_task;
}

static void *kc_kthread_main(void *arg) {
    struct task_struct *t = arg;

    kc_current_task = t;

    /* Created threads wait for wake_up_process() before running */
    pthread_mutex_lock(&t->lock);
    while (!t->woken && !t->should_stop)
        pthread_cond_wait(&t->cond, &t->lock);
    t->woken = false;
    bool stop = t->should_stop;
    pthread_mutex_unlock(&t->lock);

    t->result = stop ? -EINTR : t->threadfn(t->data);

    pthread_mutex_lock(&t->lock);
    t->exited = true;
    pthread_mutex_unlock(&t->lock);
    complete_all(&t->exit_done);

    return NULL;
}

struct task_struct *kthread_create(int (*fn)(void *), void *data, const char *fmt, ...) {
    struct task_struct *t;
    va_list ap;

    if ((t = calloc(1, sizeof(*t))) == NULL)
        return ERR_PTR(-ENOMEM);

    va_start(ap, fmt);
    vsnprintf(t->comm, sizeof(t->comm), fmt, ap);
    va_end(ap);

    t->threadfn = fn;
    t->data = data;
    t->state = TASK_RUNNING;
    pthread_mutex_init(&t->lock, NULL);
    pthread_cond_init(&t->cond, NULL);
    init_completion(&t->exit_done);

    if (pthread_create(&t->thread, NULL, kc_kthread_main, t) != 0) {
        free(t);
        return ERR_PTR(-EAGAIN);
    }

    return t;
}

int wake_up_process(struct task_struct *t) {
    pthread_mutex_lock(&t->lock);
    t->woken = true;
    pthread_cond_broadcast(&t->cond);
    pthread_mutex_unlock(&t->lock);
    return 1;
}

/* Sleeps until woken; a wakeup since set_current_state() returns immediately */
void schedule(void) {
    struct task_struct *t = current;

    pthread_mutex_lock(&t->lock);
    if (t->state != TASK_RUNNING)
        while (!t->woken && !t->should_stop && !t->should_park)
            pthread_cond_wait(&t->cond, &t->lock);
    t->woken = false;
    t->state = TASK_RUNNING;
    pthread_mutex_unlock(&t->lock);
}

long schedule_timeout(long timeout) {
    struct task_struct *t = current;
    u64 deadline = kc_jiffies_now() + (u64) timeout;
    long rem;

    pthread_mutex_lock(&t->lock);
    while (!t->woken && !t->should_stop && (rem = __kc_jiffies_remaining(deadline)) > 0)
        __kc_cond_timedwait_ms(&t->cond, &t->lock, rem);
    t->woken = false;
    t->state = TASK_RUNNING;
    pthread_mutex_unlock(&t->lock);

    return __kc_jiffies_remaining(deadline);
}

bool kthread_should_stop(void) {
    return READ_ONCE(current->should_stop);
}

bool kthread_should_park(void) {
    return READ_ONCE(current->should_park);
}

void kthread_parkme(void) {
    struct task_struct *t = current;

    pthread_mutex_lock(&t->lock);
    t->parked = true;
    pthread_cond_broadcast(&t->cond);
    while (t->should_park && !t->should_stop)
        pthread_cond_wait(&t->cond, &t->lock);
    t->parked = false;
    t->state = TASK_RUNNING;
    pthread_mutex_unlock(&t->lock);
}

int kthread_park(struct task_struct *t) {
    pthread_mutex_lock(&t->lock);
    t->should_park = true;
    pthread_cond_broadcast(&t->cond);
    if (t != current)
        while (!t->parked && !t->exited)
            pthread_cond_wait(&t->cond, &t->lock);
    pthread_mutex_unlock(&t->lock);
    return 0;
}

void kthread_unpark(struct task_struct *t) {
    pthread_mutex_lock(&t->lock);
    t->should_park = false;
    pthread_cond_broadcast(&t->cond);
    pthread_mutex_unlock(&t->lock);
}

int kthread_stop(struct task_struct *t) {
    int r;

    pthread_mutex_lock(&t->lock);
    t->should_stop = true;
    t->should_park = false;
    t->woken = true;
    pthread_cond_broadcast(&t->cond);
    pthread_mutex_unlock(&t->lock);

    wait_for_completion(&t->exit_done);
    pthread_join(t->thread, NULL);
    r = t->result;
    free(t);

    return r;
}

/* Workqueues: each runs its work in order on one thread */
struct workqueue_struct {
    char name[32];
    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct work_struct *head;
    struct work_struct *tail;
    struct work_struct *running;
    pthread_t thread;
    bool stop;
};

struct workqueue_struct *system_wq;

static void *kc_wq_thread(void *arg) {
    struct workqueue_struct *wq = arg;

    kc_current();
    snprintf(current->comm, sizeof(current->comm), "%s", wq->name);

    pthread_mutex_lock(&wq->lock);
    for (;;) {
        struct work_struct *w = wq->head;

        if (w == NULL) {
            if (wq->stop)
                break;
            pthread_cond_wait(&wq->cond, &wq->lock);
            continue;
        }

        wq->head = w->kc_next;
        if (wq->head == NULL)
            wq->tail = NULL;
        w->kc_next = NULL;
        wq->running = w;
        /* Cleared before running so the work can requeue itself */
        clear_bit(0, &w->pending);
        pthread_mutex_unlock(&wq->lock);

        w->func(w);

        pthread_mutex_lock(&wq->lock);
        wq->running = NULL;
        pthread_cond_broadcast(&wq->cond);
    }
    pthread_mutex_unlock(&wq->lock);

    return NULL;
}

struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags, int max, ...) {
    struct workqueue_struct *wq;
    va_list ap;

    (void) flags;
    (void) max;

    if ((wq = calloc(1, sizeof(*wq))) == NULL)
        return NULL;

    va_start(ap, max);
    vsnprintf(wq->name, sizeof(wq->name), fmt, ap);
    va_end(ap);

    pthread_mutex_init(&wq->lock, NULL);
    pthread_cond_init(&wq->cond, NULL);

    if (pthread_create(&wq->thread, NULL, kc_wq_thread, wq) != 0) {
        free(wq);
        return NULL;
    }

    return wq;
}

void flush_workqueue(struct workqueue_struct *wq) {
    pthread_mutex_lock(&wq->lock);
    while (wq->head != NULL || wq->running != NULL)
        pthread_cond_wait(&wq->cond, &wq->lock);
    pthread_mutex_unlock(&wq->lock);
}

void destroy_workqueue(struct workqueue_struct *wq) {
    if (wq == NULL)
        return;
    pthread_mutex_lock(&wq->lock);
    wq->stop = true;
    pthread_cond_broadcast(&wq->cond);
    pthread_mutex_unlock(&wq->lock);
    pthread_join(wq->thread, NULL);
    free(wq);
}

void __kc_init_work(struct work_struct *w, work_func_t fn) {
    w->func = fn;
    w->pending = 0;
    w->wq = NULL;
    w->kc_next = NULL;
}

bool queue_work(struct workqueue_struct *wq, struct work_struct *w) {
    if (test_and_set_bit(0, &w->pending))
        return false;

    pthread_mutex_lock(&wq->lock);
    w->wq = wq;
    w->kc_next = NULL;
    if (wq->tail)
        wq->tail->kc_next = w;
    else
        wq->head = w;
    wq->tail = w;
    pthread_cond_broadcast(&wq->cond);
    pthread_mutex_unlock(&wq->lock);

    return true;
}

/* Removes queued work; returns true if it was queued */
static bool kc_work_dequeue(struct work_struct *w) {
    struct workqueue_struct *wq = w->wq;
    bool found = false;

    if (wq == NULL)
        return false;

    pthread_mutex_lock(&wq->lock);
    struct work_struct *prev = NULL;
    for (struct work_struct *i = wq->head; i != NULL; prev = i, i = i->kc_next) {
        if (i == w) {
            if (prev)
                prev->kc_next = i->kc_next;
            else
                wq->head = i->kc_next;
            if (wq->tail == i)
                wq->tail = prev;
            i->kc_next = NULL;
            clear_bit(0, &w->pending);
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&wq->lock);

    return found;
}

bool flush_work(struct work_struct *w) {
    struct workqueue_struct *wq = w->wq;
    bool waited = false;

    if (wq == NULL || pthread_equal(pthread_self(), wq->thread))
        return false;

    pthread_mutex_lock(&wq->lock);
    while (test_bit(0, &w->pending) || wq->running == w) {
        waited = true;
        pthread_cond_wait(&wq->cond, &wq->lock);
    }
    pthread_mutex_unlock(&wq->lock);

    return waited;
}

bool cancel_work(struct work_struct *w) {
    return kc_work_dequeue(w);
}

bool cancel_work_sync(struct work_struct *w) {
    bool r = kc_work_dequeue(w);
    flush_work(w);
    return r;
}

static void kc_delayed_work_timer(struct timer_list *t) {
    struct delayed_work *dw = container_of(t, struct delayed_work, timer);
    queue_work(dw->wq, &dw->work);
}

void __kc_init_delayed_work(struct delayed_work *dw, work_func_t fn) {
    __kc_init_work(&dw->work, fn);
    timer_setup(&dw->timer, kc_delayed_work_timer, 0);
    dw->wq = NULL;
}

bool queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *dw, unsigned long delay) {
    if (work_pending(&dw->work) || timer_pending(&dw->timer))
        return false;

    dw->wq = wq;
    if (delay == 0)
        return queue_work(wq, &dw->work);

    mod_timer(&dw->timer, jiffies + delay);
    return true;
}

bool mod_delayed_work(struct workqueue_struct *wq, struct delayed_work *dw, unsigned long delay) {
    bool pending = timer_delete(&dw->timer) | kc_work_dequeue(&dw->work);

    dw->wq = wq;
    if (delay == 0)
        queue_work(wq, &dw->work);
    else
        mod_timer(&dw->timer, jiffies + delay);

    return pending;
}

bool cancel_delayed_work(struct delayed_work *dw) {
    return timer_delete(&dw->timer) | kc_work_dequeue(&dw->work);
}

bool cancel_delayed_work_sync(struct delayed_work *dw) {
    bool r = timer_delete_sync(&dw->timer) | kc_work_dequeue(&dw->work);
    flush_work(&dw->work);
    return r;
}

bool flush_delayed_work(struct delayed_work *dw) {
    if (timer_delete_sync(&dw->timer))
        queue_work(dw->wq ? dw->wq : system_wq, &dw->work);
    return flush_work(&dw->work);
}

/* Tasklets run on the system workqueue */
static void kc_tasklet_work(struct work_struct *w) {
    struct tasklet_struct *t = container_of(w, struct tasklet_struct, work);
    t->callback(t);
}

void tasklet_setup(struct tasklet_struct *t, void (*cb)(struct tasklet_struct *)) {
    t->callback = cb;
    __kc_init_work(&t->work, kc_tasklet_work);
}

void tasklet_schedule(struct tasklet_struct *t) {
    queue_work(system_wq, &t->work);
}

void tasklet_kill(struct tasklet_struct *t) {
    cancel_work_sync(&t->work);
}

/* Threaded NAPI: each napi gets a poll thread; a schedule during a poll reruns it */
struct kc_napi_thread {
    struct napi_struct *napi;
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool scheduled;
    struct kc_napi_thread *next;
};

static pthread_mutex_t kc_napi_lock = PTHREAD_MUTEX_INITIALIZER;
static struct kc_napi_thread *kc_napi_threads;

static void *kc_napi_main(void *arg) {
    struct kc_napi_thread *nt = arg;

    kc_current();

    pthread_mutex_lock(&nt->lock);
    for (;;) {
        while (!nt->scheduled)
            pthread_cond_wait(&nt->cond, &nt->lock);
        nt->scheduled = false;
        pthread_mutex_unlock(&nt->lock);

        nt->napi->poll(nt->napi, nt->napi->weight);

        pthread_mutex_lock(&nt->lock);
    }

    return NULL;
}

void napi_schedule(struct napi_struct *n) {
    struct kc_napi_thread *nt;

    pthread_mutex_lock(&kc_napi_lock);
    for (nt = kc_napi_threads; nt != NULL; nt = nt->next)
        if (nt->napi == n)
            break;

    if (nt == NULL) {
        if ((nt = calloc(1, sizeof(*nt))) == NULL) {
            pthread_mutex_unlock(&kc_napi_lock);
            return;
        }
        nt->napi = n;
        pthread_mutex_init(&nt->lock, NULL);
        pthread_cond_init(&nt->cond, NULL);
        if (pthread_create(&nt->thread, NULL, kc_napi_main, nt) != 0) {
            free(nt);
            pthread_mutex_unlock(&kc_napi_lock);
            return;
        }
        nt->next = kc_napi_threads;
        kc_napi_threads = nt;
    }
    pthread_mutex_unlock(&kc_napi_lock);

    pthread_mutex_lock(&nt->lock);
    nt->scheduled = true;
    pthread_cond_signal(&nt->cond);
    pthread_mutex_unlock(&nt->lock);
}

/* Runtime start */
static void *kc_ticker_thread(void *arg) {
    (void) arg;
    for (;;) {
        jiffies = (unsigned long) kc_jiffies_now();
        kc_sleep_ns(NSEC_PER_MSEC);
    }
    return NULL;
}

int kc_runtime_init(void) {
    static bool started;
    pthread_t t;

    if (started)
        return 0;

    kc_mono_base_ns = kc_mono_ns();
    jiffies = (unsigned long) kc_jiffies_now();

    if (pthread_create(&t, NULL, kc_ticker_thread, NULL) != 0 ||
            pthread_create(&kc_timer_tid, NULL, kc_timer_thread, NULL) != 0)
        return -EAGAIN;

    if ((system_wq = alloc_workqueue("events", 0, 0)) == NULL)
        return -ENOMEM;

    started = true;
    return 0;
}
