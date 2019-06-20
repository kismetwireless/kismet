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
#define KIS_THREAD_DEADLOCK_TIMEOUT     15

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
        owner {std::thread::id()},
        owner_count {0},
        shared_owner_count {0} { }

    // Write operation; allow recursion through the owner TID, but do not
    // allow a write lock if ANY thread holds a RO lock
    bool try_lock_for(const std::chrono::seconds& d) {
        state_mutex.lock();
        // Must wait for shared locks to release before we can acquire a write lock
        if (shared_owner_count) {
            state_mutex.unlock();

            // This will be unlocked when the shared count hits 0 so sit trying to lock it again
            if (mutex.try_lock_for(d) == false) {
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within {} (shared held)", KIS_THREAD_DEADLOCK_TIMEOUT)));
            }

            state_mutex.lock();

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
            throw(std::runtime_error(fmt::format("deadlock: shared mutex lock not available within {} (claiming write)", KIS_THREAD_DEADLOCK_TIMEOUT)));
        }
        state_mutex.lock();

        // Acquire the owner write lock
        owner = std::this_thread::get_id();
        owner_count = 1;

        state_mutex.unlock();
        return true;
    }

    bool try_lock_shared_for(const std::chrono::seconds& d) {
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
                throw(std::runtime_error(fmt::format("deadlock: shared mutex lock not available within {} (write held)", KIS_THREAD_DEADLOCK_TIMEOUT)));
            }

            // We now own the lock, increment RO
            state_mutex.lock();
            shared_owner_count++;
            state_mutex.unlock();
            return true;
        }

        // If nobody owns it...
        if (shared_owner_count == 0) {
            // Grab the lock
            state_mutex.unlock();
            if (mutex.try_lock_for(d) == false) {
                throw(std::runtime_error(fmt::format("deadlock: shared mutex lock not available within {} (claiming shared)", KIS_THREAD_DEADLOCK_TIMEOUT)));
            }
            state_mutex.lock();
        }

        // Increment the RO usage count
        shared_owner_count++;

        state_mutex.unlock();
        return true;
    }

    void lock() {
        state_mutex.lock();
        // Must wait for shared locks to release before we can acquire a write lock
        if (shared_owner_count) {
            state_mutex.unlock();
            // This will be unlocked when the shared count hits 0
            mutex.lock();

            state_mutex.lock();
            // Set the owner & count
            owner = std::this_thread::get_id();
            owner_count = 1;
            state_mutex.unlock();

            return;
        }

        // If we're already the owner, increment the recursion counter
        if (owner_count > 0 && std::this_thread::get_id() == owner) {
            // Increment the write lock count and we're done
            owner_count++;
            state_mutex.unlock();
            return;
        }

        // Attempt to acquire and continue; this blocks
        state_mutex.unlock();

        mutex.lock();
        state_mutex.lock();
        owner = std::this_thread::get_id();
        owner_count = 1;

        state_mutex.unlock();

        return;
    }

    void lock_shared() {
        state_mutex.lock();

        // If the lock has a rw hold
        if (owner_count > 0) {
            // If it's held by the same thread as trying to lock it, treat it as a rw recursive lock
            if (std::this_thread::get_id() == owner) {
                owner_count++;
                state_mutex.unlock();
                return;
            }

            // If we have any other writer lock, we must block until it's gone; the RW 
            // count hitting 0 will unlock us
            state_mutex.unlock();

            mutex.lock();

            state_mutex.lock();
            // We now own the lock, increment RO
            shared_owner_count++;
            state_mutex.unlock();
            return;
        }

        if (shared_owner_count == 0) {
            state_mutex.unlock();
            // Grab the lock
            mutex.lock();

            state_mutex.lock();
        }

        // Increment the RO usage count
        shared_owner_count++;

        state_mutex.unlock();
        return;
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
            throw std::runtime_error("Mutex got a write-unlock when no write lock held");
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
                    throw std::runtime_error("Mutex got a shared unlock by a write-unlock owner when no write lock held");
                }
            }

            // Otherwise we can't do a shared unlock while a write lock is held
            state_mutex.unlock();
            throw std::runtime_error("Mutex got a shared-unlock when a write lock held");
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
    local_locker(kis_recursive_timed_mutex *in) : 
        cpplock {in},
        s_cpplock {nullptr},
        hold_lock {true} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));

#ifdef DISABLE_MUTEX_TIMEOUT
        cpplock->lock();
#else
        if (!cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
        }
#endif
    }

    local_locker(std::shared_ptr<kis_recursive_timed_mutex> in) :
        cpplock {nullptr},
        s_cpplock {in},
        hold_lock {true} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));

#ifdef DISABLE_MUTEX_TIMEOUT
        s_cpplock->lock();
#else
        if (!s_cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
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
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
    std::atomic<bool> hold_lock;
};

// A local RAII locker for READ ONLY access, allows us to optimize the read-only mutexes
// if we're on C++14 and above, acts like a normal mutex locker if we're on older compilers.
class local_shared_locker {
public:
    local_shared_locker(kis_recursive_timed_mutex *in) : 
        hold_lock {true},
        cpplock {in},
        s_cpplock {nullptr} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));

#ifdef DISABLE_MUTEX_TIMEOUT
        cpplock->shared_lock();
#else
        if (!cpplock->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
        }
#endif
    }

    local_shared_locker(std::shared_ptr<kis_recursive_timed_mutex> in) :
        hold_lock {true},
        cpplock {nullptr},
        s_cpplock {in} {

        if (in == nullptr)
            throw(std::runtime_error("threading failure: mutex is null"));

#ifdef DISABLE_MUTEX_TIMEOUT
        s_cpplock->shared_lock();
#else
        if (!s_cpplock->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
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
    std::atomic<bool> hold_lock;
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
};


// RAII-style scoped locker, but only locks on demand, not creation
class local_demand_locker {
public:
    local_demand_locker(kis_recursive_timed_mutex *in) : 
        hold_lock {false},
        cpplock {in},
        s_cpplock {nullptr} { }

    local_demand_locker(std::shared_ptr<kis_recursive_timed_mutex> in) :
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
            if (!cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                                "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
            }
        } else if (s_cpplock) {
            if (!s_cpplock->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                                "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
            }
        }

#endif
    }

    ~local_demand_locker() {
        unlock();
    }

protected:
    std::atomic<bool> hold_lock;
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
};

// RAII-style scoped locker, but only locks on demand, not creation, with shared mutex
class local_shared_demand_locker {
public:
    local_shared_demand_locker(kis_recursive_timed_mutex *in) : 
        hold_lock {false},
        cpplock {in},
        s_cpplock {nullptr} { }

    local_shared_demand_locker(std::shared_ptr<kis_recursive_timed_mutex> in) :
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
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                                "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
            }
        } else if (s_cpplock) {
            if (!s_cpplock->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
                throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                                "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
            }
        }
#endif
    }

    ~local_shared_demand_locker() {
        unlock();
    }

protected:
    std::atomic<bool> hold_lock;
    kis_recursive_timed_mutex *cpplock;
    std::shared_ptr<kis_recursive_timed_mutex> s_cpplock;
};

// Act as a scoped locker on a mutex that never expires; used for performing
// end-of-life mutex maintenance
class local_eol_locker {
public:
    local_eol_locker(kis_recursive_timed_mutex *in) {
#ifdef DISABLE_MUTEX_TIMEOUT
        in->lock();
#else
        if (!in->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
        }
#endif
    }

    local_eol_locker(std::shared_ptr<kis_recursive_timed_mutex> in) {
#ifdef DISABLE_MUTEX_TIMEOUT
        in->lock();
#else
        if (!in->try_lock_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
        }
#endif
    }

    ~local_eol_locker() { }
};

class local_eol_shared_locker {
public:
    local_eol_shared_locker(kis_recursive_timed_mutex *in) {
#ifdef DISABLE_MUTEX_TIMEOUT
        in->lock_shared();
#else
        if (!in->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
        }
#endif
    }

    local_eol_shared_locker(std::shared_ptr<kis_recursive_timed_mutex> in) {
#ifdef DISABLE_MUTEX_TIMEOUT
        in->lock_shared();
#else
        if (!in->try_lock_shared_for(std::chrono::seconds(KIS_THREAD_DEADLOCK_TIMEOUT))) {
            throw(std::runtime_error(fmt::format("deadlock: mutex not available within "
                            "{}", KIS_THREAD_DEADLOCK_TIMEOUT)));
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

