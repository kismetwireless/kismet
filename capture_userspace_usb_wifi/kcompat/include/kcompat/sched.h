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

#ifndef __KCOMPAT_SCHED_H__
#define __KCOMPAT_SCHED_H__

/* Time, timers, kthreads and workqueues.
 *
 * jiffies run at HZ=1000 from the monotonic clock.  Each timer and each workqueue
 * is serviced by a thread; kthreads are pthreads with kernel-style sleep/wakeup:
 * set_current_state() followed by schedule() blocks until wake_up_process(), and a
 * wakeup between the two is not lost. */

#include "sync.h"

#include <time.h>

#define HZ 1000
#define USEC_PER_SEC 1000000L
#define NSEC_PER_SEC 1000000000L
#define NSEC_PER_MSEC 1000000L
#define NSEC_PER_USEC 1000L
#define USEC_PER_MSEC 1000L
#define MSEC_PER_SEC 1000L
#define MAX_JIFFY_OFFSET ((LONG_MAX >> 1) - 1)

/* Advanced every millisecond by the kcompat ticker thread */
extern volatile unsigned long jiffies;
#define jiffies_64 ((u64) jiffies)
static inline u64 get_jiffies_64(void) { return kc_jiffies_now(); }
static inline unsigned long msecs_to_jiffies(unsigned int m) { return m; }
#define round_jiffies_relative(j) (j)
static inline unsigned long usecs_to_jiffies(unsigned int u) { return DIV_ROUND_UP(u, 1000); }
static inline unsigned int jiffies_to_msecs(unsigned long j) { return (unsigned int) j; }
static inline unsigned int jiffies_to_usecs(unsigned long j) { return (unsigned int) (j * 1000); }
static inline unsigned long nsecs_to_jiffies(u64 n) { return (unsigned long) (n / NSEC_PER_MSEC); }
#define time_after(a, b) ((long) ((b) - (a)) < 0)
#define time_before(a, b) time_after(b, a)
#define time_after_eq(a, b) ((long) ((a) - (b)) >= 0)
#define time_before_eq(a, b) time_after_eq(b, a)
#define time_after32(a, b) ((s32) ((u32) (b) - (u32) (a)) < 0)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_is_before_jiffies(a) time_after(jiffies, a)
#define time_in_range(a, b, c) (time_after_eq(a, b) && time_before_eq(a, c))

void msleep(unsigned int ms);
void usleep_range(unsigned long min, unsigned long max);
void udelay(unsigned long us);
#define ndelay(ns) udelay(DIV_ROUND_UP(ns, 1000))
#define mdelay(ms) msleep(ms)
#define ssleep(s) msleep((s) * 1000)
#define fsleep(us) usleep_range(us, us)
#define msleep_interruptible(ms) ({ msleep(ms); 0UL; })
#define usleep_idle_range usleep_range

/* ktime is nanoseconds */
ktime_t ktime_get(void);
ktime_t ktime_get_real(void);
#define ktime_get_boottime() ktime_get()
#define ktime_get_ns() ((u64) ktime_get())
#define ktime_get_boottime_ns() ((u64) ktime_get())
#define ktime_get_real_ns() ((u64) ktime_get_real())
#define ktime_get_boottime_seconds() ((s64) (ktime_get() / NSEC_PER_SEC))
#define ktime_get_real_seconds() ((s64) (ktime_get_real() / NSEC_PER_SEC))
#define ktime_get_seconds() ((s64) (ktime_get() / NSEC_PER_SEC))
#define ktime_sub(a, b) ((a) - (b))
#define ktime_add(a, b) ((a) + (b))
#define ktime_add_ms(k, ms) ((k) + (s64) (ms) * NSEC_PER_MSEC)
#define ktime_add_us(k, us) ((k) + (s64) (us) * NSEC_PER_USEC)
#define ktime_to_ns(k) ((s64) (k))
#define ktime_to_us(k) ((s64) (k) / NSEC_PER_USEC)
#define ktime_to_ms(k) ((s64) (k) / NSEC_PER_MSEC)
#define ns_to_ktime(ns) ((ktime_t) (ns))
#define ms_to_ktime(ms) ((ktime_t) (ms) * NSEC_PER_MSEC)
#define ktime_ms_delta(a, b) ktime_to_ms(ktime_sub(a, b))
#define ktime_us_delta(a, b) ktime_to_us(ktime_sub(a, b))
#define ktime_compare(a, b) ((a) < (b) ? -1 : (a) > (b) ? 1 : 0)
#define ktime_after(a, b) ((a) > (b))
#define ktime_before(a, b) ((a) < (b))

struct timespec64 {
    s64 tv_sec;
    long tv_nsec;
};

/* Timers */
struct timer_list {
    void (*function)(struct timer_list *);
    unsigned long expires;
    unsigned int flags;
    /* Owned by the timer thread */
    bool pending;
    struct timer_list *kc_next;
};
void timer_setup(struct timer_list *t, void (*fn)(struct timer_list *), unsigned int flags);
int mod_timer(struct timer_list *t, unsigned long expires);
void add_timer(struct timer_list *t);
/* Not the POSIX timer_delete() from time.h */
#define timer_delete kc_timer_delete
int timer_delete(struct timer_list *t);
int timer_delete_sync(struct timer_list *t);
#define del_timer timer_delete
#define del_timer_sync timer_delete_sync
#define timer_shutdown_sync timer_delete_sync
static inline bool timer_pending(const struct timer_list *t) { return READ_ONCE(t->pending); }
#define timer_container_of(var, t, field) container_of(t, typeof(*var), field)
#define from_timer(var, t, field) timer_container_of(var, t, field)

/* hrtimers, on the timer thread with millisecond resolution */
enum hrtimer_restart {
    HRTIMER_NORESTART,
    HRTIMER_RESTART,
};
enum hrtimer_mode {
    HRTIMER_MODE_ABS = 0,
    HRTIMER_MODE_REL = 1,
    HRTIMER_MODE_REL_SOFT = 1,
    HRTIMER_MODE_ABS_SOFT = 0,
};
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif
struct hrtimer {
    enum hrtimer_restart (*function)(struct hrtimer *);
    struct timer_list kc_timer;
};
void hrtimer_setup(struct hrtimer *t, enum hrtimer_restart (*fn)(struct hrtimer *), int clock,
        enum hrtimer_mode mode);
void hrtimer_start(struct hrtimer *t, ktime_t tim, enum hrtimer_mode mode);
int hrtimer_cancel(struct hrtimer *t);
int hrtimer_try_to_cancel(struct hrtimer *t);
static inline bool hrtimer_active(const struct hrtimer *t) { return timer_pending(&t->kc_timer); }
static inline bool hrtimer_is_queued(const struct hrtimer *t) { return timer_pending(&t->kc_timer); }
static inline ktime_t hrtimer_get_remaining(const struct hrtimer *t) {
    return timer_pending(&t->kc_timer) ?
        (ktime_t) ((long) (t->kc_timer.expires - jiffies)) * NSEC_PER_MSEC : 0;
}
#define hrtimer_get_expires(t) ((ktime_t) (t)->kc_timer.expires * NSEC_PER_MSEC)

/* kthreads */
#define TASK_RUNNING 0
#define TASK_INTERRUPTIBLE 1
#define TASK_UNINTERRUPTIBLE 2
#define MAX_SCHEDULE_TIMEOUT LONG_MAX
#define TASK_COMM_LEN 16

struct task_struct {
    pthread_t thread;
    char comm[TASK_COMM_LEN];
    int (*threadfn)(void *);
    void *data;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool woken;
    bool should_stop;
    bool should_park;
    bool parked;
    int state;
    int result;
    bool exited;
    struct completion exit_done;
};

struct task_struct *kc_current(void);
#define current kc_current()
struct task_struct *kthread_create(int (*fn)(void *), void *data, const char *fmt, ...) __printf(3, 4);
#define kthread_run(fn, data, fmt, ...) ({ \
    struct task_struct *__k = kthread_create(fn, data, fmt, ##__VA_ARGS__); \
    if (!IS_ERR(__k)) wake_up_process(__k); \
    __k; })
int wake_up_process(struct task_struct *t);
int kthread_stop(struct task_struct *t);
bool kthread_should_stop(void);
bool kthread_should_park(void);
void kthread_parkme(void);
int kthread_park(struct task_struct *t);
void kthread_unpark(struct task_struct *t);
void schedule(void);
long schedule_timeout(long timeout);
#define schedule_timeout_interruptible(t) schedule_timeout(t)
#define schedule_timeout_uninterruptible(t) schedule_timeout(t)
#define set_current_state(s) (current->state = (s))
#define __set_current_state(s) set_current_state(s)
#define set_user_nice(t, n) do { (void) (t); (void) (n); } while (0)
#define sched_set_fifo_low(t) do { (void) (t); } while (0)
#define sched_set_fifo(t) do { (void) (t); } while (0)
#define signal_pending(t) 0

/* Workqueues */
struct work_struct;
typedef void (*work_func_t)(struct work_struct *);
struct workqueue_struct;

struct work_struct {
    work_func_t func;
    unsigned long pending;
    struct workqueue_struct *wq;
    struct work_struct *kc_next;
};
struct delayed_work {
    struct work_struct work;
    struct timer_list timer;
    struct workqueue_struct *wq;
};

#define WQ_UNBOUND 0x2
#define WQ_FREEZABLE 0x4
#define WQ_MEM_RECLAIM 0x8
#define WQ_HIGHPRI 0x10
#define WQ_PERCPU 0x0
/* Bottom-half workqueues run as ordinary ones */
#define WQ_BH 0x0
void __kc_init_work(struct work_struct *w, work_func_t fn);
void __kc_init_delayed_work(struct delayed_work *w, work_func_t fn);
#define INIT_WORK(w, fn) __kc_init_work(w, fn)
#define INIT_DELAYED_WORK(w, fn) __kc_init_delayed_work(w, fn)
#define INIT_DELAYED_WORK_DEFERRABLE INIT_DELAYED_WORK
#define to_delayed_work(w) container_of(w, struct delayed_work, work)
struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags, int max, ...);
#define alloc_ordered_workqueue(fmt, flags, ...) alloc_workqueue(fmt, flags, 1, ##__VA_ARGS__)
#define create_singlethread_workqueue(name) alloc_workqueue("%s", 0, 1, name)
void destroy_workqueue(struct workqueue_struct *wq);
void flush_workqueue(struct workqueue_struct *wq);
bool queue_work(struct workqueue_struct *wq, struct work_struct *w);
bool queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *w, unsigned long delay);
bool mod_delayed_work(struct workqueue_struct *wq, struct delayed_work *w, unsigned long delay);
bool cancel_work(struct work_struct *w);
bool cancel_work_sync(struct work_struct *w);
bool cancel_delayed_work(struct delayed_work *w);
bool cancel_delayed_work_sync(struct delayed_work *w);
bool flush_work(struct work_struct *w);
bool flush_delayed_work(struct delayed_work *w);
static inline bool work_pending(struct work_struct *w) { return test_bit(0, &w->pending); }
static inline bool delayed_work_pending(struct delayed_work *w) {
    return work_pending(&w->work) || timer_pending(&w->timer);
}
extern struct workqueue_struct *system_wq;
#define system_percpu_wq system_wq
#define system_unbound_wq system_wq
#define system_highpri_wq system_wq
#define schedule_work(w) queue_work(system_wq, w)
#define schedule_delayed_work(w, d) queue_delayed_work(system_wq, w, d)

/* Tasklets run as work */
struct tasklet_struct {
    struct work_struct work;
    void (*callback)(struct tasklet_struct *);
};

#endif
