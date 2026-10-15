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

#ifndef __KCOMPAT_SYNC_H__
#define __KCOMPAT_SYNC_H__

/* Locks, atomics, RCU, wait queues and completions on pthreads.
 *
 * Spinlocks are mutexes; there is no interrupt context in userspace, so the _bh and
 * _irqsave variants are the same lock.  RCU readers take no lock; writers are expected
 * to wait in synchronize_rcu() before freeing, which sleeps long enough for readers in
 * this single-device model to finish. */

#include <pthread.h>

#include "base.h"

/* Spinlocks */
typedef struct {
    pthread_mutex_t m;
} spinlock_t;

#define DEFINE_SPINLOCK(x) spinlock_t x = { PTHREAD_MUTEX_INITIALIZER }
static inline void spin_lock_init(spinlock_t *l) { pthread_mutex_init(&l->m, NULL); }
static inline void spin_lock(spinlock_t *l) { pthread_mutex_lock(&l->m); }
static inline void spin_unlock(spinlock_t *l) { pthread_mutex_unlock(&l->m); }
static inline int spin_trylock(spinlock_t *l) { return pthread_mutex_trylock(&l->m) == 0; }
#define spin_lock_bh spin_lock
#define spin_unlock_bh spin_unlock
#define spin_lock_irq spin_lock
#define spin_unlock_irq spin_unlock
#define spin_lock_irqsave(l, flags) do { (flags) = 0; spin_lock(l); } while (0)
#define spin_unlock_irqrestore(l, flags) do { (void) (flags); spin_unlock(l); } while (0)
#define spin_lock_nested(l, sub) spin_lock(l)
#define assert_spin_locked(l) do { (void) (l); } while (0)
#define local_bh_disable() do { } while (0)
#define local_bh_enable() do { } while (0)
#define local_irq_save(f) do { (f) = 0; } while (0)
#define local_irq_restore(f) do { (void) (f); } while (0)
#define rcu_read_lock_bh() do { } while (0)
#define rcu_read_unlock_bh() do { } while (0)

/* rcu guard is a no-op, matching rcu_read_lock() */
typedef void *class_rcu_t;
static inline void class_rcu_destructor(void **p) { (void) p; }
static inline void *class_rcu_constructor(void) { return (void *) 1; }

typedef struct {
    pthread_rwlock_t l;
} rwlock_t;
static inline void rwlock_init(rwlock_t *l) { pthread_rwlock_init(&l->l, NULL); }
#define read_lock(x) pthread_rwlock_rdlock(&(x)->l)
#define read_unlock(x) pthread_rwlock_unlock(&(x)->l)
#define write_lock(x) pthread_rwlock_wrlock(&(x)->l)
#define write_unlock(x) pthread_rwlock_unlock(&(x)->l)
#define read_lock_bh read_lock
#define read_unlock_bh read_unlock
#define write_lock_bh write_lock
#define write_unlock_bh write_unlock

/* Mutexes */
struct mutex {
    pthread_mutex_t m;
    int locked;
};
#define DEFINE_MUTEX(x) struct mutex x = { PTHREAD_MUTEX_INITIALIZER, 0 }
static inline void mutex_init(struct mutex *l) { pthread_mutex_init(&l->m, NULL); l->locked = 0; }
static inline void mutex_destroy(struct mutex *l) { pthread_mutex_destroy(&l->m); }
static inline void mutex_lock(struct mutex *l) {
    pthread_mutex_lock(&l->m);
    __atomic_store_n(&l->locked, 1, __ATOMIC_SEQ_CST);
}
static inline int mutex_trylock(struct mutex *l) {
    if (pthread_mutex_trylock(&l->m) != 0)
        return 0;
    __atomic_store_n(&l->locked, 1, __ATOMIC_SEQ_CST);
    return 1;
}
static inline void mutex_unlock(struct mutex *l) {
    __atomic_store_n(&l->locked, 0, __ATOMIC_SEQ_CST);
    pthread_mutex_unlock(&l->m);
}
static inline bool mutex_is_locked(struct mutex *l) { return __atomic_load_n(&l->locked, __ATOMIC_SEQ_CST); }
#define mutex_lock_nested(l, sub) mutex_lock(l)
static inline int mutex_lock_interruptible(struct mutex *l) { mutex_lock(l); return 0; }
DEFINE_GUARD(mutex, struct mutex *, mutex_lock(_T), mutex_unlock(_T))
DEFINE_GUARD(spinlock, spinlock_t *, spin_lock(_T), spin_unlock(_T))
DEFINE_GUARD(spinlock_bh, spinlock_t *, spin_lock(_T), spin_unlock(_T))
DEFINE_GUARD(spinlock_irqsave, spinlock_t *, spin_lock(_T), spin_unlock(_T))

/* Atomics */
typedef struct {
    int counter;
} atomic_t;
typedef struct {
    s64 counter;
} atomic64_t;
typedef struct {
    long counter;
} atomic_long_t;
#define ATOMIC_INIT(i) { (i) }
#define ATOMIC64_INIT(i) { (i) }

#define __KC_ATOMIC_OPS(pfx, type, vtype) \
static inline vtype pfx##_read(const type *v) { return __atomic_load_n(&v->counter, __ATOMIC_SEQ_CST); } \
static inline void pfx##_set(type *v, vtype i) { __atomic_store_n(&v->counter, i, __ATOMIC_SEQ_CST); } \
static inline void pfx##_add(vtype i, type *v) { __atomic_fetch_add(&v->counter, i, __ATOMIC_SEQ_CST); } \
static inline void pfx##_sub(vtype i, type *v) { __atomic_fetch_sub(&v->counter, i, __ATOMIC_SEQ_CST); } \
static inline void pfx##_inc(type *v) { pfx##_add(1, v); } \
static inline void pfx##_dec(type *v) { pfx##_sub(1, v); } \
static inline vtype pfx##_add_return(vtype i, type *v) { return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST); } \
static inline vtype pfx##_sub_return(vtype i, type *v) { return __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST); } \
static inline vtype pfx##_inc_return(type *v) { return pfx##_add_return(1, v); } \
static inline vtype pfx##_dec_return(type *v) { return pfx##_sub_return(1, v); } \
static inline vtype pfx##_fetch_add(vtype i, type *v) { return __atomic_fetch_add(&v->counter, i, __ATOMIC_SEQ_CST); } \
static inline vtype pfx##_fetch_sub(vtype i, type *v) { return __atomic_fetch_sub(&v->counter, i, __ATOMIC_SEQ_CST); } \
static inline bool pfx##_dec_and_test(type *v) { return pfx##_dec_return(v) == 0; } \
static inline bool pfx##_inc_and_test(type *v) { return pfx##_inc_return(v) == 0; } \
static inline vtype pfx##_xchg(type *v, vtype n) { return __atomic_exchange_n(&v->counter, n, __ATOMIC_SEQ_CST); } \
static inline vtype pfx##_cmpxchg(type *v, vtype o, vtype n) { \
    __atomic_compare_exchange_n(&v->counter, &o, n, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return o; } \
static inline bool pfx##_try_cmpxchg(type *v, vtype *o, vtype n) { \
    return __atomic_compare_exchange_n(&v->counter, o, n, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); }
__KC_ATOMIC_OPS(atomic, atomic_t, int)
__KC_ATOMIC_OPS(atomic64, atomic64_t, s64)
__KC_ATOMIC_OPS(atomic_long, atomic_long_t, long)
static inline bool atomic_add_unless(atomic_t *v, int a, int u) {
    int c = atomic_read(v);
    do {
        if (c == u)
            return false;
    } while (!atomic_try_cmpxchg(v, &c, c + a));
    return true;
}
#define atomic_inc_not_zero(v) atomic_add_unless((v), 1, 0)

#define xchg(p, n) __atomic_exchange_n(p, n, __ATOMIC_SEQ_CST)
#define cmpxchg(p, o, n) ({ typeof(*(p)) __o = (o); \
    __atomic_compare_exchange_n(p, &__o, n, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); __o; })

typedef struct {
    atomic_t refs;
} refcount_t;
static inline void refcount_set(refcount_t *r, int n) { atomic_set(&r->refs, n); }
static inline unsigned int refcount_read(const refcount_t *r) { return atomic_read(&r->refs); }
static inline void refcount_inc(refcount_t *r) { atomic_inc(&r->refs); }
static inline bool refcount_dec_and_test(refcount_t *r) { return atomic_dec_and_test(&r->refs); }

/* RCU */
struct rcu_head {
    struct rcu_head *next;
    void (*func)(struct rcu_head *);
};
#define rcu_read_lock() do { } while (0)
#define rcu_read_unlock() do { } while (0)
#define rcu_read_lock_held() 1
#define rcu_dereference(p) __atomic_load_n(&(p), __ATOMIC_ACQUIRE)
#define rcu_dereference_bh(p) rcu_dereference(p)
#define rcu_dereference_raw(p) rcu_dereference(p)
#define rcu_dereference_check(p, c) rcu_dereference(p)
#define rcu_dereference_protected(p, c) (p)
#define rcu_access_pointer(p) rcu_dereference(p)
#define rcu_assign_pointer(p, v) __atomic_store_n(&(p), (v), __ATOMIC_RELEASE)
#define RCU_INIT_POINTER(p, v) do { (p) = (v); } while (0)
#define rcu_replace_pointer(p, v, c) ({ typeof(p) __old = (p); rcu_assign_pointer(p, v); __old; })
#define rcu_pointer_handoff(p) (p)
void synchronize_rcu(void);
#define synchronize_net() synchronize_rcu()
void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *));
#define kfree_rcu(ptr, field) do { synchronize_rcu(); kfree(ptr); } while (0)
#define kfree_rcu_mightsleep(ptr) do { synchronize_rcu(); kfree(ptr); } while (0)
#define rcu_barrier() do { } while (0)

/* Wait queues; conditions are checked under the queue lock so a wakeup between the check
 * and the wait is never lost */
struct wait_queue_head {
    pthread_mutex_t lock;
    pthread_cond_t cond;
};
typedef struct wait_queue_head wait_queue_head_t;
void init_waitqueue_head(wait_queue_head_t *wq);
void __wake_up(wait_queue_head_t *wq);
/* Waits until woken or timeout_ms passes; returns false on timeout */
bool __kc_wait_wq(wait_queue_head_t *wq, long timeout_ms);
long __kc_jiffies_remaining(u64 deadline);
#define wake_up(wq) __wake_up(wq)
#define wake_up_all(wq) __wake_up(wq)
#define wake_up_interruptible(wq) __wake_up(wq)
#define wake_up_interruptible_all(wq) __wake_up(wq)
#define wake_up_locked(wq) __wake_up(wq)

#define wait_event(wq, condition) do { \
    pthread_mutex_lock(&(wq).lock); \
    while (!(condition)) \
        pthread_cond_wait(&(wq).cond, &(wq).lock); \
    pthread_mutex_unlock(&(wq).lock); \
} while (0)
/* Returns 0 on timeout, otherwise the remaining jiffies (at least 1) */
#define wait_event_timeout(wq, condition, timeout) ({ \
    u64 __dl = kc_jiffies_now() + (u64) (timeout); \
    long __ret = 1; \
    pthread_mutex_lock(&(wq).lock); \
    while (!(condition)) { \
        long __rem = __kc_jiffies_remaining(__dl); \
        if (__rem <= 0) { __ret = (condition) ? 1 : 0; break; } \
        __kc_cond_timedwait_ms(&(wq).cond, &(wq).lock, __rem); \
    } \
    if (__ret) { long __r = __kc_jiffies_remaining(__dl); __ret = __r > 0 ? __r : 1; } \
    pthread_mutex_unlock(&(wq).lock); \
    __ret; })
#define wait_event_interruptible_timeout(wq, condition, timeout) \
    wait_event_timeout(wq, condition, timeout)
#define wait_event_interruptible(wq, condition) ({ wait_event(wq, condition); 0; })
#define wait_event_killable(wq, condition) wait_event_interruptible(wq, condition)
void __kc_cond_timedwait_ms(pthread_cond_t *c, pthread_mutex_t *m, long ms);
u64 kc_jiffies_now(void);

/* Completions */
struct completion {
    unsigned int done;
    wait_queue_head_t wait;
};
#define DECLARE_COMPLETION_ONSTACK(x) struct completion x; init_completion(&x)
static inline void init_completion(struct completion *c) { c->done = 0; init_waitqueue_head(&c->wait); }
static inline void reinit_completion(struct completion *c) { c->done = 0; }
static inline void complete(struct completion *c) {
    pthread_mutex_lock(&c->wait.lock);
    c->done++;
    pthread_cond_broadcast(&c->wait.cond);
    pthread_mutex_unlock(&c->wait.lock);
}
static inline void complete_all(struct completion *c) {
    pthread_mutex_lock(&c->wait.lock);
    c->done = UINT_MAX / 2;
    pthread_cond_broadcast(&c->wait.cond);
    pthread_mutex_unlock(&c->wait.lock);
}
static inline unsigned long wait_for_completion_timeout(struct completion *c, unsigned long timeout) {
    unsigned long r = wait_event_timeout(c->wait, c->done > 0, timeout);
    if (r) {
        pthread_mutex_lock(&c->wait.lock);
        if (c->done > 0 && c->done < UINT_MAX / 2)
            c->done--;
        pthread_mutex_unlock(&c->wait.lock);
    }
    return r;
}
static inline void wait_for_completion(struct completion *c) {
    wait_event(c->wait, c->done > 0);
    pthread_mutex_lock(&c->wait.lock);
    if (c->done < UINT_MAX / 2)
        c->done--;
    pthread_mutex_unlock(&c->wait.lock);
}
static inline bool completion_done(struct completion *c) { return READ_ONCE(c->done) > 0; }

#endif
