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
        state_mask{0},
        group_1_ct{0},
        group_2_ct{0},
        owned_ct{0},
        owned_pending_ct{0} { }

    ~kis_tristate_mutex() {
        std::lock_guard<std::mutex> lk(state_mutex);
    }

    kis_tristate_mutex(const kis_tristate_mutex&) = delete;
    kis_tristate_mutex& operator=(const kis_tristate_mutex&) = delete;

    void lock_group1() {
        std::unique_lock<std::mutex> lk(state_mutex);

        // Treat a recursive lock under exclusive ownership as an exclusive lock
        if ((state_mask & owned_entered) && owned_id == std::this_thread::get_id()) {
            owned_ct++;
            return;
        }

        // Flag that we're trying to enter group1
        state_mask |= group1_entered;

        while (!group_1_ct && ((state_mask & group2_entered) || (state_mask & owned_entered))) {
            cond_1.wait(lk);
        }

        group_1_ct++;
    }

    bool try_lock_group1() {
        std::unique_lock<std::mutex> lk(state_mutex);

        // Recursive
        if ((state_mask & owned_entered) && owned_id == std::this_thread::get_id()) {
            owned_ct++;
            return true;
        }

        if (group_1_ct == 0 && ((state_mask & group2_entered) || (state_mask & owned_entered)))
            return false;

        state_mask |= group1_entered;
        group_1_ct++;

        return true;
    }

    void unlock_group1() {
        std::lock_guard<std::mutex> lk(state_mutex);

        if ((state_mask & owned_entered) && owned_id == std::this_thread::get_id())
            return unlock_exclusive_impl();

        if (group_1_ct == 0)
            throw std::runtime_error("illegal unlock_group1 when no group1 lock held");

        group_1_ct--;

        if (group_1_ct == 0) {
            state_mask &= ~group1_entered;
            cond_1.notify_one();
        }
    }

    // Explicit write ops
    void lock_group2() {
        std::unique_lock<std::mutex> lk(state_mutex);

        // Treat a recursive lock under exclusive ownership as an exclusive lock
        if ((state_mask & owned_entered) && owned_id == std::this_thread::get_id()) {
            owned_ct++;
            return;
        }

        // Flag that we're trying to enter group2
        state_mask |= group2_entered;

        while (!group_2_ct && ((state_mask & group1_entered) || (state_mask & owned_entered))) {
            cond_1.wait(lk);
        }

        group_2_ct++;
    }

    bool try_lock_group2() {
        std::unique_lock<std::mutex> lk(state_mutex);

        // Handle recursive
        if ((state_mask & owned_entered) && owned_id == std::this_thread::get_id()) {
            owned_ct++;
            return true;
        }

        if (group_2_ct == 0 && ((state_mask & group1_entered) || (state_mask & owned_entered)))
            return false;

        state_mask |= group2_entered;
        group_2_ct++;

        return true;
    }

    void unlock_group2() {
        std::unique_lock<std::mutex> lk(state_mutex);

        if ((state_mask & owned_entered) && owned_id == std::this_thread::get_id())
            return unlock_exclusive_impl();

        if (group_2_ct == 0)
            throw std::runtime_error("illegal unlock_group2 when no group2 lock held");

        group_2_ct--;

        if (group_2_ct == 0) {
            state_mask &= ~group2_entered;
            cond_1.notify_one();
        }
    }

    // Explicit write ops
    void lock_exclusive() {
        std::unique_lock<std::mutex> lk(state_mutex);

        // If this is a recursive lock in the same ownership thread, allow it immediately
        // otherwise the caller will block
        if ((state_mask & owned_entered) && owned_ct && owned_id == std::this_thread::get_id()) {
            owned_ct++;
            return;
        }

        // Flag we're trying to enter exclusive mode
        state_mask |= owned_entered;

        // Wait for the ownership count of the exclusive owner to discharge
        owned_pending_ct++;

        // Wait for shared locks to complete
        while (group_1_ct || group_2_ct) {
            cond_1.wait(lk);
        }

        // Wait for competing owned locks to complete
        while (owned_ct) {
            cond_2.wait(lk);
        }

        owned_pending_ct--;

        // Increment and set owner
        owned_id = std::this_thread::get_id();
        owned_ct = 1;
    }

    bool try_lock_exclusive() {
        if ((state_mask & owned_entered) && owned_id == std::this_thread::get_id()) {
            owned_ct++;
            return true;
        }

        if (owned_ct && owned_id != std::this_thread::get_id())
            return false;

        if ((state_mask & group1_entered) || (state_mask & group2_entered))
            return false;

        state_mask |= owned_entered;
        owned_id = std::this_thread::get_id();
        owned_ct = 1;

        return true;
    }

    void unlock_exclusive() {
        std::lock_guard<std::mutex> lk(state_mutex);
        unlock_exclusive_impl();
    }

protected:
    void unlock_exclusive_impl() {
        if (owned_ct == 0)
            throw std::runtime_error("illegal unlock_exclusive when no exclusive lock held");

        if (owned_id != std::this_thread::get_id())
            throw std::runtime_error(fmt::format("illegal unlock_exclusive from {} when not "
                        "the exclusive lock owner {}", std::this_thread::get_id(), owned_id));

        owned_ct--;

        if (owned_ct == 0) {
            owned_id = std::thread::id();

            // If we have another exclusive ownership, we need to discharge it first because it's
            // blocking g1 and g2
            if (owned_pending_ct) {
                cond_2.notify_one();
            } else {
                // Clear ownership
                state_mask &= ~owned_entered;
                cond_1.notify_one();
            }
        }
    }

    std::mutex state_mutex;
    std::condition_variable cond_1;
    std::condition_variable cond_2;
    std::condition_variable cond_3;

    unsigned char state_mask;

    unsigned int group_1_ct;
    unsigned int group_2_ct;
    unsigned int owned_ct;
    unsigned int owned_pending_ct;

    std::thread::id owned_id;

    static constexpr unsigned char group1_entered = 1U << 1;
    static constexpr unsigned char group2_entered = 1U << 2;
    static constexpr unsigned char owned_entered = 1U << 3;
};

class kis_default_shared_mutex {
public:
    kis_default_shared_mutex() :
        base() {}  
    ~kis_default_shared_mutex() = default;

    kis_default_shared_mutex(const kis_default_shared_mutex&) = delete;
    kis_default_shared_mutex& operator=(const kis_default_shared_mutex&) = delete;

    void lock() { return base.lock_group1(); }
    bool try_lock() { return base.try_lock_group1(); }
    void unlock() { return base.unlock_group1(); }

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

    void lock_shared() { return base.lock_group1(); }
    bool try_lock_shared() { return base.try_lock_group1(); }
    void unlock_shared() { return base.unlock_group1(); }

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
                mutex.lock_group1();
                break;
            case view_mode::group2:
                mutex.lock_group2();
                break;
            case view_mode::exclusive:
                mutex.lock_exclusive();
                break;
        }
    }

    bool try_lock() { 
        switch (mode) {
            case view_mode::group1:
                return mutex.try_lock_group1();
                break;
            case view_mode::group2:
                return mutex.try_lock_group2();
                break;
            case view_mode::exclusive:
                return mutex.try_lock_exclusive();
                break;
        }
    }

    void unlock() { 
        switch (mode) {
            case view_mode::group1:
                return mutex.unlock_group1();
                break;
            case view_mode::group2:
                return mutex.unlock_group2();
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

    void lock_shared(const std::string name = "") { return base.lock_group1(); }
    bool try_lock_shared(const std::string name = "") { return base.try_lock_group1(); }
    bool try_lock_shared_for(const std::chrono::seconds& d, const std::string& agent_name = "UNKNOWN") {
        return try_lock_shared();
    }

    void unlock_shared() { return base.unlock_group1(); }

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

