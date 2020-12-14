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

// Simple proxy mutex which implements a std::recursive_mutex with a mandatory timer;
// attempts to lock are translated into timed lock attempts and will throw at the 
// expiration of the timeout
class kis_mandatory_mutex {
public:
    kis_mandatory_mutex() :
        lock_nm{"UNKNOWN"},
        lock_tm{KIS_THREAD_DEADLOCK_TIMEOUT} { }

    kis_mandatory_mutex(const std::string& lock_nm) :
        lock_nm{lock_nm},
        lock_tm{KIS_THREAD_DEADLOCK_TIMEOUT} { }

    void set_timeout(unsigned int tm) {
        lock_tm = tm;
    }

    const unsigned int& get_timeout() const {
        return lock_tm;
    }

    void lock() {
        if (lock_tm != 0) {
            if (!mutex.try_lock_for(std::chrono::seconds(lock_tm)))
                throw std::runtime_error("mandatory timed mutex \"" + lock_nm + "\" timed out");
        } else {
            mutex.lock();
        }
    }

    void unlock() {
        mutex.unlock();
    }

    bool try_lock() {
        if (lock_tm != 0)
            return mutex.try_lock_for(std::chrono::seconds(lock_tm));

        return mutex.try_lock();
    }

protected:
    std::string lock_nm;
    unsigned int lock_tm;

    std::recursive_timed_mutex mutex;
};

// Tristate mutex capable of locking "self" multiple times from multiple threads, so long as 
// 'other' and 'exclusive' are not set
class kis_tristate_mutex {
public:
    kis_tristate_mutex(const std::string& lock_nm,
            unsigned int& lock_tm,
            kis_mandatory_mutex& self_mutex,
            std::atomic<unsigned int>& self_count,
            std::promise<void>& self_promise,
            std::shared_future<void>& self_ft,
            kis_mandatory_mutex& other_mutex,
            std::atomic<unsigned int>& other_count,
            std::promise<void>& other_promise,
            std::shared_future<void>& other_ft,
            kis_mandatory_mutex& ex_mutex,
            std::atomic<bool>& ex_locked,
            std::promise<void>& ex_promise,
            std::shared_future<void>& ex_ft) :
    lock_nm{lock_nm},
    lock_tm{lock_tm},
    self_mutex{self_mutex},
    self_count{self_count},
    self_promise{self_promise},
    self_ft{self_ft},
    other_mutex{other_mutex},
    other_count{other_count},
    other_promise{other_promise},
    other_ft{other_ft},
    ex_mutex{ex_mutex},
    ex_locked{ex_locked},
    ex_promise{ex_promise},
    ex_ft{ex_ft} { }

    void lock() {
        // Get all 3 state controls at the same time
        std::unique_lock<kis_mandatory_mutex> self_ul(self_mutex, std::defer_lock);
        std::unique_lock<kis_mandatory_mutex> other_ul(other_mutex, std::defer_lock);
        std::unique_lock<kis_mandatory_mutex> ex_ul(ex_mutex, std::defer_lock);
        std::lock(self_ul, other_ul, ex_ul);

        if (ex_locked) {
            std::shared_future<void> ex_ft_cp = ex_ft;

            // Wait for the exclusive lock to release, holding the other locks
            ex_ul.unlock();

            if (lock_tm != 0) {
                try {
                    auto status = ex_ft_cp.wait_for(std::chrono::seconds(lock_tm));
                    if (status != std::future_status::ready) {
                        throw std::runtime_error("timeout waiting for exclusive lock future");
                    }
                } catch (const std::exception& e) {
                    throw std::runtime_error("tristate_mutex \"" + lock_nm + "\" lock failed: " + e.what());
                }
            } else {
                ex_ft_cp.wait();
            }
        }

        if (other_count > 0) {
            std::shared_future<void> other_ft_cp = other_ft;

            // Wait for the other pair of the lock
            other_ul.unlock();

            if (lock_tm != 0) {
                try {
                    auto status = other_ft_cp.wait_for(std::chrono::seconds(lock_tm));
                    if (status != std::future_status::ready) {
                        throw std::runtime_error("timeout waiting for other future");
                    }
                } catch (const std::exception& e) {
                    throw std::runtime_error("tristate_mutex \"" + lock_nm + "\" lock failed: " + e.what());
                }
            } else {
                other_ft_cp.wait();
            }
        }

        // We've got all 3 state locks, and we've discharged exclusive and other restrictions
        self_count.fetch_add(1, std::memory_order_acquire);
    }

    void unlock() {
        if (self_count == 0)
            throw std::runtime_error("tristate_mutex \"" + lock_nm + "\" unlock() called when no lock held");

        // Decrement and wake up if we hit 0
        if (self_count.fetch_sub(1, std::memory_order_release) == 1) {
            try {
                self_promise.set_value();
            } catch (const std::future_error& fe) {
                // Ignore error if no futures are listening
            }

            // Reset the future and base shared promise
            self_promise = std::promise<void>();
            self_ft = std::shared_future<void>(self_promise.get_future());
        }
    }

    bool try_lock() {
        // try_lock is currently time-unbounded which means we can't try to lock
        // multiple locks with a proper time block; unsure if this will cause
        // problems yet or not

        if (ex_locked) {
            return false;
        }

        if (other_count) {
            return false;
        }

        // Get all 3 state controls at the same time
        std::unique_lock<kis_mandatory_mutex> self_ul(self_mutex, std::defer_lock);
        std::unique_lock<kis_mandatory_mutex> other_ul(other_mutex, std::defer_lock);
        std::unique_lock<kis_mandatory_mutex> ex_ul(ex_mutex, std::defer_lock);
        std::lock(self_ul, other_ul, ex_ul);

        // We've got all 3 state locks, and we've discharged exclusive and other restrictions
        self_count.fetch_add(1, std::memory_order_acquire);

        return true;
    }

protected:
    std::string lock_nm;
    unsigned int& lock_tm;

    kis_mandatory_mutex& self_mutex;
    std::atomic<unsigned int>& self_count;
    std::promise<void>& self_promise;
    std::shared_future<void>& self_ft;

    kis_mandatory_mutex& other_mutex;
    std::atomic<unsigned int>& other_count;
    std::promise<void>& other_promise;
    std::shared_future<void>& other_ft;

    kis_mandatory_mutex& ex_mutex;
    std::atomic<bool>& ex_locked;
    std::promise<void>& ex_promise;
    std::shared_future<void>& ex_ft;
};

class kis_tristate_ex_mutex {
public:
    kis_tristate_ex_mutex(const std::string& lock_nm,
            unsigned int& lock_tm,
            kis_mandatory_mutex& m1_mutex,
            std::atomic<unsigned int>& m1_count,
            std::promise<void>& m1_promise,
            std::shared_future<void>& m1_ft,
            kis_mandatory_mutex& m2_mutex,
            std::atomic<unsigned int>& m2_count,
            std::promise<void>& m2_promise,
            std::shared_future<void>& m2_ft,
            kis_mandatory_mutex& ex_mutex,
            std::atomic<bool>& ex_locked,
            std::promise<void>& ex_promise,
            std::shared_future<void>& ex_ft) :
    lock_nm{lock_nm},
    lock_tm{lock_tm},
    m1_mutex{m1_mutex},
    m1_count{m1_count},
    m1_promise{m1_promise},
    m1_ft{m1_ft},
    m2_mutex{m2_mutex},
    m2_count{m2_count},
    m2_promise{m2_promise},
    m2_ft{m2_ft},
    ex_mutex{ex_mutex},
    ex_locked{ex_locked},
    ex_promise{ex_promise},
    ex_ft{ex_ft} { }

    void lock() {
        // Get all 3 state controls at the same time
        std::unique_lock<kis_mandatory_mutex> m1_ul(m1_mutex, std::defer_lock);
        std::unique_lock<kis_mandatory_mutex> m2_ul(m2_mutex, std::defer_lock);
        std::unique_lock<kis_mandatory_mutex> ex_ul(ex_mutex, std::defer_lock);
        std::lock(m1_ul, m2_ul, ex_ul);

        if (ex_locked)
            throw std::runtime_error("tristate_mutex \"" + lock_nm + "\" exclusive lock failed, already "
                    "exclusively locked");

        if (m1_count > 0) {
            std::shared_future<void> m1_ft_cp = m1_ft;

            // Wait for the m1 pair of the lock
            m1_ul.unlock();

            if (lock_tm != 0) {
                try {
                    auto status = m1_ft_cp.wait_for(std::chrono::seconds(lock_tm));
                    if (status != std::future_status::ready) {
                        throw std::runtime_error("timeout waiting for m1 future");
                    }
                } catch (const std::exception& e) {
                    throw std::runtime_error("tristate_mutex \"" + lock_nm + "\" lock failed: " + e.what());
                }
            } else {
                m1_ft_cp.wait();
            }
        }

        if (m2_count > 0) {
            std::shared_future<void> m2_ft_cp = m2_ft;

            // Wait for the m2 pair of the lock
            m2_ul.unlock();

            if (lock_tm != 0) {
                try {
                    auto status = m2_ft_cp.wait_for(std::chrono::seconds(lock_tm));
                    if (status != std::future_status::ready) {
                        throw std::runtime_error("timeout waiting for m2 future");
                    }
                } catch (const std::exception& e) {
                    throw std::runtime_error("tristate_mutex \"" + lock_nm + "\" lock failed: " + e.what());
                }
            } else {
                m2_ft_cp.wait();
            }
        }

        ex_locked = true;
    }

    void unlock() {
        if (!ex_locked)
            throw std::runtime_error("tristate_mutex \"" + lock_nm + "\" unlock() called when no exclusive lock held");

        ex_locked = false;

        try {
            ex_promise.set_value();
        } catch (const std::future_error& fe) {
            // Ignore error if no futures are listening
        }

        // Reset the future and base shared promise
        ex_promise = std::promise<void>();
        ex_ft = std::shared_future<void>(ex_promise.get_future());
    }

    bool try_lock() {
        // try_lock is currently time-unbounded which means we can't try to lock
        // multiple locks with a proper time block; unsure if this will cause
        // problems yet or not
        
        if (ex_locked)
            throw std::runtime_error("tristate_mutex \"" + lock_nm + "\" exclusive lock failed, already "
                    "exclusively locked");

        if (m1_count != 0) {
            return false;
        }

        if (m2_count != 0) {
            return false;
        }

        std::unique_lock<kis_mandatory_mutex> m1_ul(m1_mutex, std::defer_lock);
        std::unique_lock<kis_mandatory_mutex> m2_ul(m2_mutex, std::defer_lock);
        std::unique_lock<kis_mandatory_mutex> ex_ul(ex_mutex, std::defer_lock);
        std::lock(m1_ul, m2_ul, ex_ul);

        ex_locked.store(true, std::memory_order_acquire);

        return true;
    }

protected:
    std::string lock_nm;
    unsigned int& lock_tm;

    kis_mandatory_mutex& m1_mutex;
    std::atomic<unsigned int>& m1_count;
    std::promise<void>& m1_promise;
    std::shared_future<void>& m1_ft;

    kis_mandatory_mutex& m2_mutex;
    std::atomic<unsigned int>& m2_count;
    std::promise<void>& m2_promise;
    std::shared_future<void>& m2_ft;

    kis_mandatory_mutex& ex_mutex;
    std::atomic<bool>& ex_locked;
    std::promise<void>& ex_promise;
    std::shared_future<void>& ex_ft;
};

class kis_tristate_mutex_group {
public:
    kis_tristate_mutex_group() :
        lock_nm{"UNKNOWN"},
        lock_tm{KIS_THREAD_DEADLOCK_TIMEOUT},
        m1_mutex{"UNKNOWN_M1"},
        m1_count{0},
        m1_promise{},
        m1_ft{m1_promise.get_future()},
        m2_mutex{"UNKNOWN_M2"},
        m2_count{0},
        m2_promise{},
        m2_ft{m2_promise.get_future()},
        ex_mutex{"UNKNOWN_EX"},
        ex_locked{false},
        ex_promise{},
        ex_ft{ex_promise.get_future()},
        m1_tristate(lock_nm + "_WR",
                lock_tm,
                m1_mutex, m1_count, m1_promise, m1_ft,
                m2_mutex, m2_count, m2_promise, m2_ft,
                ex_mutex, ex_locked, ex_promise, ex_ft),
        m2_tristate(lock_nm + "_WR",
                lock_tm,
                m2_mutex, m2_count, m2_promise, m2_ft,
                m1_mutex, m1_count, m1_promise, m1_ft,
                ex_mutex, ex_locked, ex_promise, ex_ft),
        ex_tristate(lock_nm + "_EX",
                lock_tm,
                m1_mutex, m1_count, m1_promise, m1_ft,
                m2_mutex, m2_count, m2_promise, m2_ft,
                ex_mutex, ex_locked, ex_promise, ex_ft) { }

    kis_tristate_mutex_group(const std::string& lock_nm) :
        lock_nm{lock_nm},
        lock_tm{KIS_THREAD_DEADLOCK_TIMEOUT},
        m1_mutex{lock_nm + "_M1"},
        m1_count{0},
        m1_promise{},
        m1_ft{m1_promise.get_future()},
        m2_mutex{lock_nm + "_M2"},
        m2_count{0},
        m2_promise{},
        m2_ft{m2_promise.get_future()},
        ex_mutex{lock_nm + "_EX"},
        ex_locked{false},
        ex_promise{},
        ex_ft{ex_promise.get_future()},
        m1_tristate(lock_nm + "_WR",
                lock_tm,
                m1_mutex, m1_count, m1_promise, m1_ft,
                m2_mutex, m2_count, m2_promise, m2_ft,
                ex_mutex, ex_locked, ex_promise, ex_ft),
        m2_tristate(lock_nm + "_WR",
                lock_tm,
                m2_mutex, m2_count, m2_promise, m2_ft,
                m1_mutex, m1_count, m1_promise, m1_ft,
                ex_mutex, ex_locked, ex_promise, ex_ft),
        ex_tristate(lock_nm + "_EX",
                lock_tm,
                m1_mutex, m1_count, m1_promise, m1_ft,
                m2_mutex, m2_count, m2_promise, m2_ft,
                ex_mutex, ex_locked, ex_promise, ex_ft) { }

    void set_name(const std::string& name) {
        lock_nm = name;
    }

    const std::string& get_name() const {
        return lock_nm;
    }

    void set_timeout(unsigned int timeout) {
        lock_tm = timeout;
    }

    unsigned int get_timeout() const {
        return lock_tm;
    }

    kis_tristate_mutex& get_wr_tristate() {
        return m1_tristate;
    }

    kis_tristate_mutex& get_sh_tristate() {
        return m2_tristate;
    }


    kis_tristate_ex_mutex& get_ex_tristate() {
        return ex_tristate;
    }

protected:
    std::string lock_nm;

    unsigned int lock_tm;

    kis_mandatory_mutex m1_mutex;
    std::atomic<unsigned int> m1_count;
    std::promise<void> m1_promise;
    std::shared_future<void> m1_ft;

    kis_mandatory_mutex m2_mutex;
    std::atomic<unsigned int> m2_count;
    std::promise<void> m2_promise;
    std::shared_future<void> m2_ft;

    kis_mandatory_mutex ex_mutex;
    std::atomic<bool> ex_locked;
    std::promise<void> ex_promise;
    std::shared_future<void> ex_ft;

    kis_tristate_mutex m1_tristate;
    kis_tristate_mutex m2_tristate;
    kis_tristate_ex_mutex ex_tristate;
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

