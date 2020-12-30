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

/* 
 * So it turns out GCC < 4.9.0 has a broken std::timex_mutex implementation
 * which makes it unusable (well, unusable in a timed fashion).
 *
 * Since Kismet needs to support older implementations, we need to work around
 * this by detecting it and implementing our own mutex on those systems.
 */

#ifndef __KISMET_MUTEX_H__
#define __KISMET_MUTEX_H__

#include "config.h"

#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#ifdef HAVE_CXX14
#include <shared_mutex>
#endif


#include <pthread.h>

#include "fmt.h"

// Seconds a lock is allowed to be held before throwing a timeout error
// Tuning this is a balance between slower systems or systems swapping heavily, 
// and faulting more quickly.
#define KIS_THREAD_DEADLOCK_TIMEOUT     30

#define DISABLE_MUTEX_TIMEOUT 1

class kis_tristate_mutex {
public:
    kis_tristate_mutex() : 
        state{0},
        excl_tid{std::thread::id()},
        excl_ct{0},
        excl_pend{0},
        shared1_ct{0},
        shared2_ct{0} { }

    ~kis_tristate_mutex() {
        std::lock_guard<std::mutex> lk(state_m);
    }

    kis_tristate_mutex(const kis_tristate_mutex&) = delete;
    kis_tristate_mutex& operator=(const kis_tristate_mutex&) = delete;

    void lock_shared_1() {
        std::unique_lock<std::mutex> lk(state_m);

        auto tid = std::this_thread::get_id();

        // Allow recursive promotion to exclusive
        if (excl_ct && tid == excl_tid) {
            return lock_exclusive_nr(lk);
        }

        // Prevent cross-group deadlock
        if (shared2_tid_map.find(tid) != shared2_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock shared 1 while holding shared 2", tid));

        auto sh1_tid = shared1_tid_map.find(tid);

        // Allow recursion to happen at all times
        if (sh1_tid != shared1_tid_map.end()) {
            sh1_tid->second++;
            shared1_ct++;
            return;
        }

        // No contenders
        if (state == 0 || state == state_shared_1) {
            state |= state_shared_1;
            shared1_tid_map[tid] = 1;
            shared1_ct++;
            return;
        }

        // State 1 defers to state 2 first
        while ((state & state_shared_2)) {
            state_2_cond.wait(lk);
        }

        while ((state & state_excl)) {
            state_e_cond.wait(lk);
        }

        // We're trying to get state
        state |= state_shared_1;

        // Assign to this thread and increment
        shared1_tid_map[tid] = 1;
        shared1_ct++;
    }

    bool try_lock_shared_1() {
        std::unique_lock<std::mutex> lk(state_m);

        auto tid = std::this_thread::get_id();

        if (excl_ct && tid == excl_tid)
            return try_lock_exclusive_nr(lk);

        if (shared2_tid_map.find(tid) != shared2_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock shared 1 while holding shared 2", tid));

        auto sh1_tid = shared1_tid_map.find(tid);

        if (sh1_tid != shared1_tid_map.end()) {
            sh1_tid->second++;
            shared1_ct++;
            return true;
        }

        if (state == 0 || state == state_shared_1) {
            state |= state_shared_1;
            shared1_tid_map[tid] = 1;
            shared1_ct++;
            return true;
        }

        return false;
    }

    void unlock_shared_1() {
        std::unique_lock<std::mutex> lk(state_m);

        auto tid = std::this_thread::get_id();

        // Handle promoted recursion
        if (excl_ct && tid == excl_tid)
            return unlock_exclusive_nr(lk);

        // Safety
        if (shared1_ct == 0)
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock shared_1 when shared_1 not locked", tid));

        auto sh1_tid = shared1_tid_map.find(tid);

        if (sh1_tid == shared1_tid_map.end())
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock shared_1 but has no shared_1 lock", tid));

        // Purge thread record
        if (sh1_tid->second == 1)
            shared1_tid_map.erase(sh1_tid);
        else
            sh1_tid->second--;

        if (shared1_ct == 1) {
            // We're done with this state, nobody holding it
            state &= (~state_shared_1);
            shared1_ct = 0;
            state_1_cond.notify_one();
        } else {
            shared1_ct--;
        }
    }

    void lock_shared_2() {
        std::unique_lock<std::mutex> lk(state_m);

        auto tid = std::this_thread::get_id();

        // Allow recursive promotion to exclusive
        if (excl_ct && tid == excl_tid)
            return lock_exclusive_nr(lk);

        // Prevent cross-group deadlock
        if (shared1_tid_map.find(tid) != shared1_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock shared 2 while holding shared 1", tid));

        auto sh2_tid = shared2_tid_map.find(tid);

        // Allow recursion to happen at all times
        if (sh2_tid != shared2_tid_map.end()) {
            sh2_tid->second++;
            shared2_ct++;
            return;
        }

        // No contenders
        if (state == 0 || state == state_shared_2) {
            state |= state_shared_2;
            shared2_tid_map[tid] = 1;
            shared2_ct++;
            return;
        }

        // State 2 defers to state E first
        while ((state & state_excl)) {
            state_e_cond.wait(lk);
        }

        while ((state & state_shared_1)) {
            state_1_cond.wait(lk);
        }

        // We're trying to get state
        state |= state_shared_2;

        // Assign to this thread and increment
        shared2_tid_map[tid] = 1;
        shared2_ct++;
    }

    bool try_lock_shared_2() {
        std::unique_lock<std::mutex> lk(state_m);

        auto tid = std::this_thread::get_id();

        if (excl_ct && tid == excl_tid)
            return try_lock_exclusive_nr(lk);

        if (shared1_tid_map.find(tid) != shared1_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock shared 2 while holding shared 1", tid));

        auto sh2_tid = shared2_tid_map.find(tid);

        if (sh2_tid != shared2_tid_map.end()) {
            sh2_tid->second++;
            shared2_ct++;
            return true;
        }

        if (state == 0 || state == state_shared_2) {
            state |= state_shared_2;
            shared2_tid_map[tid] = 1;
            shared2_ct++;
            return true;
        }

        return false;
    }

    void unlock_shared_2() {
        std::unique_lock<std::mutex> lk(state_m);

        auto tid = std::this_thread::get_id();

        // Handle promoted recursion
        if (excl_ct && tid == excl_tid)
            return unlock_exclusive_nr(lk);

        // Safety
        if (shared2_ct == 0)
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock shared_2 when shared_2 not locked", tid));

        auto sh2_tid = shared2_tid_map.find(tid);

        if (sh2_tid == shared2_tid_map.end())
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock shared_2 but has no shared_2 lock", tid));

        // Purge thread record
        if (sh2_tid->second == 1)
            shared2_tid_map.erase(sh2_tid);
        else
            sh2_tid->second--;

        if (shared2_ct == 1) {
            // We're done with this state, nobody holding it
            state &= (~state_shared_2);
            shared2_ct = 0;
            state_2_cond.notify_one();
        } else {
            shared2_ct--;
        }
    }

    void lock_exclusive() {
        std::unique_lock<std::mutex> lk(state_m);
        return lock_exclusive_nr(lk);
    }

    void lock_exclusive_nr(std::unique_lock<std::mutex>& lk) {
        auto tid = std::this_thread::get_id();

        // Recursive lock
        if (tid == excl_tid) {
            excl_ct++;
            return;
        }

        // Prevent cross-group deadlock; can lock as exclusive when already exclusive, but cannot lock as exclusive
        // when we recursively own another state.
        if (shared1_tid_map.find(tid) != shared1_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock exclusive while holding shared 1", tid));
        if (shared2_tid_map.find(tid) != shared2_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock exclusive while holding shared 2", tid));

        // No contenders
        if (state == 0) {
            excl_ct = 1;
            excl_tid = tid;
            state |= state_excl;
            return;
        }

        // Exclusive defers to 1, 2, then allows a new exclusive lock
        while ((state & state_shared_1)) {
            state_1_cond.wait(lk);
        }

        while ((state & state_shared_2)) {
            state_2_cond.wait(lk);
        }

        // While another exclusive lock is held
        if (excl_ct) {
            excl_pend++;
            // Increment the pending count, wait for a wakeup from pending exclusive mode
            while (excl_ct)
                state_e2_cond.wait(lk);
            excl_pend--;
        }

        state |= state_excl;
        excl_ct++;
        excl_tid = tid;
    }

    bool try_lock_exclusive() {
        std::unique_lock<std::mutex> lk(state_m);
        return try_lock_exclusive_nr(lk);
    }

    bool try_lock_exclusive_nr(std::unique_lock<std::mutex>& lk) {
        auto tid = std::this_thread::get_id();

        if (tid == excl_tid) {
            excl_ct++;
            return true;
        }

        if (shared1_tid_map.find(tid) != shared1_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock exclusive while holding shared 1", tid));
        if (shared2_tid_map.find(tid) != shared2_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock exclusive while holding shared 2", tid));

        if (state == 0) {
            excl_ct = 1;
            excl_tid = tid;
            state |= state_excl;
            return true;
        }

        return false;
    }

    void unlock_exclusive() {
        std::unique_lock<std::mutex> lk(state_m);
        return unlock_exclusive_nr(lk);
    }

    void unlock_exclusive_nr(std::unique_lock<std::mutex>& lk) {
        auto tid = std::this_thread::get_id();

        // Safety
        if (!(state & state_excl))
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock exclusive when exclusive not locked", tid));

        if (tid != excl_tid)
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock exclusive but owned by {}", tid, excl_tid));

        if (excl_ct == 0)
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock exclusive but exclusive count 0", tid));

        if (excl_ct == 1) {
            excl_ct = 0;
            excl_tid = std::thread::id();

            // Are we done or do we have more exclusive locks queued up
            if (excl_pend == 0) {
                // We're done, clear exclusive state, reset, wake up next waiter
                state &= (~state_excl);
                state_e_cond.notify_one();
            } else {
                // We've got another exclusive lock trying to get in, wake it up and let it absorb the
                // exclusive lock state.  This may favor exclusive locks over the others; test.
                state_e2_cond.notify_one();
            }
        } else {
            excl_ct--;
        }
    }

protected:
    std::mutex state_m;

    std::condition_variable state_1_cond;
    std::condition_variable state_2_cond;
    std::condition_variable state_e_cond;
    std::condition_variable state_e2_cond;

    unsigned int state;
    static constexpr unsigned int state_shared_1 = (1U << 1);
    static constexpr unsigned int state_shared_2 = (1U << 2);
    static constexpr unsigned int state_excl = (1U << 3);

    std::thread::id excl_tid;
    unsigned int excl_ct;
    unsigned int excl_pend;

    using tid_map_t = std::unordered_map<std::thread::id, unsigned int>;
    
    tid_map_t shared1_tid_map;
    unsigned int shared1_ct;

    tid_map_t shared2_tid_map;
    unsigned int shared2_ct;

};


class kis_default_shared_mutex {
public:
    kis_default_shared_mutex() :
        base() {}  
    ~kis_default_shared_mutex() = default;

    kis_default_shared_mutex(const kis_default_shared_mutex&) = delete;
    kis_default_shared_mutex& operator=(const kis_default_shared_mutex&) = delete;

    void lock() { return base.lock_shared_1(); }
    bool try_lock() { return base.try_lock_shared_1(); }
    void unlock() { return base.unlock_shared_1(); }

    void lock_exclusive() { return base.lock_exclusive(); }
    bool try_lock_exclusive() { return base.try_lock_exclusive(); }
    void unlock_exclusive() { return base.unlock_exclusive(); }

private:
    kis_tristate_mutex base;
};

class kis_shared_mutex {
    kis_shared_mutex() :
        base() {}  
    ~kis_shared_mutex() = default;

    kis_shared_mutex(const kis_default_shared_mutex&) = delete;
    kis_shared_mutex& operator=(const kis_default_shared_mutex&) = delete;

    void lock() { return base.lock_exclusive(); }
    bool try_lock() { return base.try_lock_exclusive(); }
    void unlock() { return base.unlock_exclusive(); }

    void lock_shared() { return base.lock_shared_1(); }
    bool try_lock_shared() { return base.try_lock_shared_1(); }
    void unlock_shared() { return base.unlock_shared_1(); }

private:
    kis_tristate_mutex base;
};

// View of a tristate mutex to make each state act as a traditional lockable mutex 
class kis_tristate_mutex_view {
public:
    enum class view_mode {
        group1,
        group2,
        exclusive
    };

    kis_tristate_mutex_view(kis_tristate_mutex& mutex, kis_tristate_mutex_view::view_mode mode) :
        mutex{mutex},
        mode{mode} { }

    ~kis_tristate_mutex_view() = default;

    kis_tristate_mutex_view(const kis_tristate_mutex_view&) = delete;
    kis_tristate_mutex_view& operator=(const kis_tristate_mutex_view&) = delete;

    void lock() { 
        switch (mode) {
            case view_mode::group1:
                mutex.lock_shared_1();
                break;
            case view_mode::group2:
                mutex.lock_shared_2();
                break;
            case view_mode::exclusive:
                mutex.lock_exclusive();
                break;
        }
    }

    bool try_lock() { 
        switch (mode) {
            case view_mode::group1:
                return mutex.try_lock_shared_1();
                break;
            case view_mode::group2:
                return mutex.try_lock_shared_2();
                break;
            case view_mode::exclusive:
                return mutex.try_lock_exclusive();
                break;
        }
    }

    void unlock() { 
        switch (mode) {
            case view_mode::group1:
                return mutex.unlock_shared_1();
                break;
            case view_mode::group2:
                return mutex.unlock_shared_2();
                break;
            case view_mode::exclusive:
                return mutex.unlock_exclusive();
                break;
        }
    }

private:
    kis_tristate_mutex& mutex;
    view_mode mode;
};



// Optionally force the custom c++ workaround mutex
#define ALWAYS_USE_KISMET_MUTEX         0

// Some compilers (older openwrt CC images, Ubuntu 14.04) are still in use and have a broken
// std::recursive_timed_mutex implementation which uses the wrong precision for the timer leading
// to an instant timer failure;  Optionally re-implement a std::mutex using C pthread 
// primitives and locking
class kis_recursive_pthread_timed_mutex {
public:
    kis_recursive_pthread_timed_mutex() {
        // Make a recursive mutex that the owning thread can lock multiple times;
        // Required to allow a timer event to reschedule itself on completion
        pthread_mutexattr_t mutexattr;
        pthread_mutexattr_init(&mutexattr);
        pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&mutex, &mutexattr);
    }
        
    ~kis_recursive_pthread_timed_mutex() {
        pthread_mutex_destroy(&mutex);
    }

    bool try_lock_for(const std::chrono::seconds& d) {
#if defined(HAVE_PTHREAD_TIMELOCK) && !defined(DISABLE_MUTEX_TIMEOUT)
        // Only use timeouts if a) they're supported and b) not disabled in configure
        struct timespec t;

        clock_gettime(CLOCK_REALTIME, &t); 
        t.tv_sec += d.count();

        if (pthread_mutex_timedlock(&mutex, &t) != 0) {
            return false;
        }
#else
        pthread_mutex_lock(&mutex);
#endif

        return true;
    }

    void lock() {
        pthread_mutex_lock(&mutex);
    }

    void unlock() {
        pthread_mutex_unlock(&mutex);
    }

private:
    pthread_mutex_t mutex;
};

class kis_recursive_timed_mutex {
public:
    kis_recursive_timed_mutex() :
        base() {}  
    ~kis_recursive_timed_mutex() = default;

    kis_recursive_timed_mutex(const kis_default_shared_mutex&) = delete;
    kis_recursive_timed_mutex& operator=(const kis_default_shared_mutex&) = delete;

    void lock(const std::string name = "") { return base.lock_exclusive(); }
    bool try_lock(const std::string name = "") { return base.try_lock_exclusive(); }

    bool try_lock_for(const std::chrono::seconds& d, const std::string& agent_name = "UNKNOWN") {
        return try_lock();
    }

    void unlock() { return base.unlock_exclusive(); }

    void lock_shared(const std::string name = "") { return base.lock_shared_1(); }
    bool try_lock_shared(const std::string name = "") { return base.try_lock_shared_1(); }
    bool try_lock_shared_for(const std::chrono::seconds& d, const std::string& agent_name = "UNKNOWN") {
        return try_lock_shared();
    }

    void unlock_shared() { return base.unlock_shared_1(); }

    void set_name(std::string n) {
        mutex_name = n;
    }

    std::string mutex_name;

private:
    kis_tristate_mutex base;
};

#if 0
// C++14 defines a shared_mutex, and a timed shared mutex, but not a recursive, timed,
// shared mutex; implement our own thread ID 
class kis_recursive_timed_mutex {
public:
    kis_recursive_timed_mutex() :
#ifdef DEBUG_MUTEX_NAME
        mutex_name {"unnamed"},
#endif
        owner {std::thread::id()},
        owner_count {0},
        shared_owner_count {0} { }

#ifdef DEBUG_MUTEX_NAME
    std::string mutex_name;
    void set_name(const std::string& name) {
        mutex_name = name;
    }
#else
    void set_name(const std::string& name) { }
#endif

    // Write operation; allow recursion through the owner TID, but do not
    // allow a write lock if ANY thread holds a RO lock
    bool try_lock(const std::string& agent_name = "UNKNOWN") {
        state_mutex.lock();
        // Must wait for shared locks to release before we can acquire a write lock
        if (shared_owner_count) 
            return false;

        // If we're already the owner, increment the recursion counter
        if (owner_count > 0 && std::this_thread::get_id() == owner) {
            // Increment the write lock count and we're done
            owner_count++;
            state_mutex.unlock();
            return true;
        }

        // Attempt to acquire and continue
        state_mutex.unlock();
        if (mutex.try_lock() == false) {
            return false;
        }
        state_mutex.lock();

        lock_name = agent_name;

        // Acquire the owner write lock
        owner = std::this_thread::get_id();
        owner_count = 1;

        state_mutex.unlock();
        return true;
    }

    // Write operation; allow recursion through the owner TID, but do not
    // allow a write lock if ANY thread holds a RO lock
    bool try_lock_for(const std::chrono::seconds& d, const std::string& agent_name = "UNKNOWN") {
        state_mutex.lock();
        // Must wait for shared locks to release before we can acquire a write lock
        if (shared_owner_count) {
            state_mutex.unlock();

            // This will be unlocked when the shared count hits 0 so sit trying to lock it again
            if (mutex.try_lock_for(d) == false) {
#ifdef DEBUG_MUTEX_NAME
                throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within {} (shared held by {} @ {}, wanted by {})", mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT, lock_name, owner, agent_name)));
#else
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within {} (shared held)", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
            }

            state_mutex.lock();

            lock_name = agent_name;

            // Set the owner & count
            owner = std::this_thread::get_id();
            owner_count = 1;

            state_mutex.unlock();

            return true;
        }

        // If we're already the owner, increment the recursion counter
        if (owner_count > 0 && std::this_thread::get_id() == owner) {
            // Increment the write lock count and we're done
            owner_count++;
            state_mutex.unlock();
            return true;
        }

        // Attempt to acquire and continue
        state_mutex.unlock();
        if (mutex.try_lock_for(d) == false) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: shared mutex {} lock not available within {} (claiming write, held by {} @ {}, wanted by {})", mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT, lock_name, owner, agent_name)));
#else
            throw(std::runtime_error(fmt::format("deadlock: shared mutex lock not available within {} (claiming write)", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
        }
        state_mutex.lock();

        lock_name = agent_name;

        // Acquire the owner write lock
        owner = std::this_thread::get_id();
        owner_count = 1;

        state_mutex.unlock();
        return true;
    }

    bool try_lock_shared_for(const std::chrono::seconds& d, const std::string& agent_name="UNKNOWN") {
        state_mutex.lock();
        if (owner_count > 0) {
            // Allow a RO lock as if it were a RW lock if the thread is the owner
            if (std::this_thread::get_id() == owner) {
                owner_count++;
                state_mutex.unlock();
                return true;
            }

            // If we have any other writer lock, we must block until it's gone; the RW 
            // count hitting 0 will unlock us
            state_mutex.unlock();
            if (mutex.try_lock_for(d) == false) {
#ifdef DEBUG_MUTEX_NAME
                throw(std::runtime_error(fmt::format("deadlock: shared mutex {} lock not available within {} (write held by {} @ {}, wanted by {})", mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT, lock_name, owner, agent_name)));
#else
                throw(std::runtime_error(fmt::format("deadlock: shared mutex lock not available within {} (write held)", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
            }

            // We now own the lock, increment RO
            state_mutex.lock();
            lock_name = agent_name;
            shared_owner_count++;
            state_mutex.unlock();
            return true;
        }

        // If nobody owns it...
        if (shared_owner_count == 0) {
            // Grab the lock
            state_mutex.unlock();
            if (mutex.try_lock_for(d) == false) {
#ifdef DEBUG_MUTEX_NAME
                throw(std::runtime_error(fmt::format("deadlock: shared mutex {} lock not available within {} (claiming shared held by {} @ {}, wanted by {})", mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT, lock_name, owner, agent_name)));
#else
                throw(std::runtime_error(fmt::format("deadlock: shared mutex lock not available within {} (claiming shared)", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
            }
            state_mutex.lock();
        }

        // Increment the RO usage count
        shared_owner_count++;

        state_mutex.unlock();
        return true;
    }

    void lock(const std::string& agent_name = "UNKNOWN") {
        try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT), agent_name);
    }

    void lock_shared(const std::string& agent_name = "UNKNOWN") {
        try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT), agent_name);
    }

    void unlock() {
        state_mutex.lock();
        if (owner_count > 0) {
            // Write lock has expired, unlock mutex
            if (--owner_count == 0) {
                owner = std::thread::id();
                mutex.unlock();
            }

            state_mutex.unlock();
            return;
        } else {
            state_mutex.unlock();
            // throw std::runtime_error("Mutex got a write-unlock when no write lock held");
        }
    }

    void unlock_shared() {
        state_mutex.lock();
        // If it's a RW thread
        if (owner_count > 0) {
            // If the shared unlock is coming from the rw owner, treat it like a rw lock
            if (std::this_thread::get_id() == owner) {
                if (owner_count > 0) {
                    // Write lock has expired, unlock mutex
                    if (--owner_count == 0) {
                        owner = std::thread::id();
                        mutex.unlock();
                    }

                    state_mutex.unlock();
                    return;
                } else {
                    state_mutex.unlock();
                    // throw std::runtime_error("Mutex got a shared unlock by a write-unlock owner when no write lock held");
                }
            }

            // Otherwise we can't do a shared unlock while a write lock is held
            state_mutex.unlock();
            // throw std::runtime_error("Mutex got a shared-unlock when a write lock held");
        }

        if (shared_owner_count > 0) {
            // Decrement RO lock count
            if (--shared_owner_count == 0) {
                // Release the lock if we've hit 0
                mutex.unlock();
                state_mutex.unlock();
                return;
            }
        }

        // Otherwise nothing else to do here
        state_mutex.unlock();
    }

private:
    // Recursive write lock
    std::thread::id owner;
    unsigned int owner_count;

    std::string lock_name;

    // RO shared locks
    unsigned int shared_owner_count;

    std::mutex state_mutex;

// Use std::recursive_timed_mutex components when we can, unless we're forcing pthread mode; base it
// on the GCC versions to detect broken compilers
#if ALWAYS_USE_KISMET_MUTEX != 0 || \
    (!defined(__clang__) && defined (GCC_VERSION_MAJOR) && (GCC_VERSION_MAJOR < 4 || \
        (GCC_VERSION_MAJOR == 4 && GCC_VERSION_MINOR < 9)))
    kis_recursive_pthread_timed_mutex mutex;
#else
    std::timed_mutex mutex;
#endif
};

#endif



// A scoped locker like std::lock_guard that provides RAII scoped locking of a kismet mutex;
// unless disabled in ./configure use a timed lock mutex and throw an exception if unable
// to acquire the lock within KIS_THREAD_DEADLOCK_TIMEOUT seconds, it's better to crash
// than to hang; we allow a short-cut unlock to unlock before the end of scope, in which case
// we no longer unlock AGAIN at descope
class local_locker {
public:
    local_locker(kis_recursive_timed_mutex *in, const std::string& ln = "UNKNOWN") : 
        lock_name {ln},
        cpplock {in},
        s_cpplock {nullptr},
        hold_lock {true} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));

#ifdef DISABLE_MUTEX_TIMEOUT
        cpplock->lock();
#else
        if (!cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT), ln)) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
        }
#endif
    }

    local_locker(kis_recursive_timed_mutex *in, const std::string& ln, int lock_seconds) : 
        lock_name {ln},
        cpplock {in},
        s_cpplock {nullptr},
        hold_lock {true} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));

#ifdef DISABLE_MUTEX_TIMEOUT
        cpplock->lock();
#else
        if (!cpplock->try_lock_for(std::chrono::seconds(lock_seconds), ln)) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", cpplock->mutex_name, lock_seconds)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", lock_seconds)));
#endif
        }
#endif
    }

    local_locker(std::shared_ptr<kis_recursive_timed_mutex> in, const std::string& ln = "UNKNOWN") :
        lock_name {ln},
        cpplock {nullptr},
        s_cpplock {in},
        hold_lock {true} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));

#ifdef DISABLE_MUTEX_TIMEOUT
        s_cpplock->lock();
#else
        if (!s_cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT), ln)) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", s_cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
        }
#endif

    }

    local_locker() = delete;

    void unlock() {
        hold_lock = false;

        if (cpplock)
            cpplock->unlock();
        if (s_cpplock)
            s_cpplock->unlock();
    }

    ~local_locker() {
        if (hold_lock) {
            if (cpplock)
                cpplock->unlock();
            if (s_cpplock)
                s_cpplock->unlock();
        }
    }

protected:
    std::string lock_name;
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
    std::atomic<bool> hold_lock;
};

// A local RAII locker for READ ONLY access, allows us to optimize the read-only mutexes
// if we're on C++14 and above, acts like a normal mutex locker if we're on older compilers.
class local_shared_locker {
public:
    local_shared_locker(kis_recursive_timed_mutex *in, const std::string& ln = "UNKNOWN") : 
        lock_name {ln},
        hold_lock {true},
        cpplock {in},
        s_cpplock {nullptr} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));

#ifdef DISABLE_MUTEX_TIMEOUT
        cpplock->lock_shared();
#else
        if (!cpplock->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
        }
#endif
    }

    local_shared_locker(std::shared_ptr<kis_recursive_timed_mutex> in, const std::string& ln = "UNKNOWN") :
        lock_name {ln},
        hold_lock {true},
        cpplock {nullptr},
        s_cpplock {in} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));

#ifdef DISABLE_MUTEX_TIMEOUT
        s_cpplock->lock_shared();
#else
        if (!s_cpplock->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", s_cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
        }
#endif
    }

    local_shared_locker() = delete;

    void unlock() {
        hold_lock = false;
        if (cpplock)
            cpplock->unlock_shared();
        if (s_cpplock)
            s_cpplock->unlock_shared();
    }

    ~local_shared_locker() {
        if (hold_lock) {
            if (cpplock)
                cpplock->unlock_shared();
            if (s_cpplock)
                s_cpplock->unlock_shared();
        }
    }

protected:
    std::string lock_name;
    std::atomic<bool> hold_lock;
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
};


// RAII-style scoped locker, but only locks on demand, not creation
class local_demand_locker {
public:
    local_demand_locker(kis_recursive_timed_mutex *in, const std::string& ln = "UNKNOWN") : 
        lock_name {ln},
        hold_lock {false},
        cpplock {in},
        s_cpplock {nullptr} { }

    local_demand_locker(std::shared_ptr<kis_recursive_timed_mutex> in, const std::string& ln = "UNKNOWN") :
        lock_name {ln},
        hold_lock {false},
        cpplock {nullptr},
        s_cpplock {in} { }

    void unlock() {
        if (!hold_lock)
            return;

        hold_lock = false;

        if (cpplock)
            cpplock->unlock();
        if (s_cpplock)
            s_cpplock->unlock();
    }

    void lock() {
        if (hold_lock)
            throw(std::runtime_error("possible deadlock - demand_locker locking while "
                        "already holding a lock"));

        hold_lock = true;

#ifdef DISABLE_MUTEX_TIMEOUT
        if (cpplock)
            cpplock->lock();
        else if (s_cpplock)
            s_cpplock->lock();
#else
        if (cpplock) {
            if (!cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT), lock_name)) {
#ifdef DEBUG_MUTEX_NAME
                throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                                "{}", cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                                "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
            }
        } else if (s_cpplock) {
            if (!s_cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT), lock_name)) {
#ifdef DEBUG_MUTEX_NAME
                throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                                "{}", s_cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                                "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
            }
        }

#endif
    }

    ~local_demand_locker() {
        unlock();
    }

protected:
    std::string lock_name;
    std::atomic<bool> hold_lock;
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
};

// RAII-style scoped locker, but only locks on demand, not creation, with shared mutex
class local_shared_demand_locker {
public:
    local_shared_demand_locker(kis_recursive_timed_mutex *in, const std::string& ln) : 
        lock_name {ln},
        hold_lock {false},
        cpplock {in},
        s_cpplock {nullptr} { }

    local_shared_demand_locker(std::shared_ptr<kis_recursive_timed_mutex> in, const std::string& ln) :
        lock_name {ln},
        hold_lock {false},
        cpplock {nullptr},
        s_cpplock {in} { }

    void unlock() {
        if (!hold_lock)
            return;

        hold_lock = false;

        if (cpplock)
            cpplock->unlock_shared();
        if (s_cpplock)
            s_cpplock->unlock_shared();
    }

    void lock() {
        if (hold_lock)
            throw(std::runtime_error("possible deadlock - shared_demand_locker locking while "
                        "already holding a lock"));

        hold_lock = true;

#ifdef DISABLE_MUTEX_TIMEOUT
        if (cpplock)
            cpplock->lock_shared();
        else if (s_cpplock)
            s_cpplock->lock_shared();
#else
        if (cpplock) {
            if (!cpplock->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
#ifdef DEBUG_MUTEX_NAME
                throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                                "{}", cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                                "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
            }
        } else if (s_cpplock) {
            if (!s_cpplock->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
#ifdef DEBUG_MUTEX_NAME
                throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                                "{}", s_cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                                "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
            }
        }
#endif
    }

    ~local_shared_demand_locker() {
        unlock();
    }

protected:
    std::string lock_name;
    std::atomic<bool> hold_lock;
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
};

// Act as a scoped locker on a mutex that never expires; used for performing
// end-of-life mutex maintenance
class local_eol_locker {
public:
    local_eol_locker(kis_recursive_timed_mutex *in, const std::string& ln = "UNKNOWN") :
        lock_name {ln},
        cpplock {in},
        s_cpplock {nullptr} {
#ifdef DISABLE_MUTEX_TIMEOUT
        cpplock->lock();
#else
        if (!cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT), lock_name)) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
        }
#endif
    }

    local_eol_locker(kis_recursive_timed_mutex *in, const std::string& ln, int timeout_seconds) :
        lock_name {ln},
        cpplock {in},
        s_cpplock {nullptr} {
#ifdef DISABLE_MUTEX_TIMEOUT
        cpplock->lock();
#else
        if (!cpplock->try_lock_for(std::chrono::seconds(timeout_seconds), lock_name)) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", cpplock->mutex_name, timeout_seconds)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", timeout_seconds)));
#endif
        }
#endif
    }

    local_eol_locker(std::shared_ptr<kis_recursive_timed_mutex> in, const std::string& ln = "UNKNOWN") :
        lock_name {ln},
        cpplock {nullptr},
        s_cpplock {in} {
#ifdef DISABLE_MUTEX_TIMEOUT
        s_cpplock->lock();
#else
        if (!s_cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT), lock_name)) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", s_cpplock->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
        }
#endif
    }

    void unlock() {
        if (cpplock)
            cpplock->unlock();
        if (s_cpplock)
            s_cpplock->unlock();
    }

    ~local_eol_locker() { }

protected:
    std::string lock_name;
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
};

class local_eol_shared_locker {
public:
    local_eol_shared_locker(kis_recursive_timed_mutex *in, const std::string& ln = "UNKNOWN") {
#ifdef DISABLE_MUTEX_TIMEOUT
        in->lock_shared();
#else
        if (!in->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", in->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
        }
#endif
    }

    local_eol_shared_locker(std::shared_ptr<kis_recursive_timed_mutex> in, const std::string& ln = "UNKNOWN") {
#ifdef DISABLE_MUTEX_TIMEOUT
        in->lock_shared();
#else
        if (!in->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
#ifdef DEBUG_MUTEX_NAME
            throw(std::runtime_error(fmt::format("deadlock: mutex {} not available within "
                            "{}", in->mutex_name, KIS_THREAD_DEADLOCK_TIMEOUT)));
#else
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
#endif
        }
#endif
    }
};

// Act as a scope-based unlocker; assuming a mutex is already locked, unlock
// when it leaves scope
class local_unlocker {
public:
    local_unlocker(kis_recursive_timed_mutex *in) : 
        cpplock {in},
        s_cpplock {nullptr} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));
    }

    local_unlocker(std::shared_ptr<kis_recursive_timed_mutex> in) :
        cpplock {nullptr},
        s_cpplock {in} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));
    }

    ~local_unlocker() {
        if (cpplock)
            cpplock->unlock();
        if (s_cpplock)
            s_cpplock->unlock();
    }

protected:
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
};

class local_shared_unlocker {
public:
    local_shared_unlocker(kis_recursive_timed_mutex *in) : 
        cpplock {in},
        s_cpplock {nullptr} { }

    local_shared_unlocker(std::shared_ptr<kis_recursive_timed_mutex> in) :
        cpplock {nullptr},
        s_cpplock {in} { }

    ~local_shared_unlocker() {
        if (cpplock)
            cpplock->unlock_shared();
        if (s_cpplock)
            s_cpplock->unlock_shared();
    }

protected:
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
};

#endif

