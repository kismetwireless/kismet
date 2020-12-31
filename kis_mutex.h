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


// A tristate primitive which provides 2 mutually exclusive shared lock groups (shared 1 and shared 2),
// and a single exclusive lock.  Permits recursion, promoted locking when holding the exclusive lock,
// and attempts at fair distribution of locking modes.
//
// Transformed into a standard mutex-like object via kis_tristate_mutex_view
class kis_tristate_mutex {
public:
    kis_tristate_mutex() : 
        mutex_nm{"UNKNOWN"},
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

    void set_name(const std::string& nm) {
        mutex_nm = nm;
    }

    const std::string& get_name() const {
        return mutex_nm;
    }

    void lock_shared_1() {
        std::unique_lock<std::mutex> lk(state_m);

        auto tid = std::this_thread::get_id();

        // Allow recursive promotion to exclusive
        if (excl_ct && tid == excl_tid) {
            return lock_exclusive_nr(lk);
        }

        // Prevent cross-group deadlock
        if (shared2_tid_map.find(tid) != shared2_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock "
                        "shared 1 while holding shared 2", tid));

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
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock "
                        "shared 1 while holding shared 2", tid));

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
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock "
                        "shared_1 when shared_1 not locked", tid));

        auto sh1_tid = shared1_tid_map.find(tid);

        if (sh1_tid == shared1_tid_map.end())
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock "
                        "shared_1 but has no shared_1 lock", tid));

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
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock "
                        "shared 2 while holding shared 1", tid));

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
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock "
                        "shared 2 while holding shared 1", tid));

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
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock "
                        "shared_2 when shared_2 not locked", tid));

        auto sh2_tid = shared2_tid_map.find(tid);

        if (sh2_tid == shared2_tid_map.end())
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock "
                        "shared_2 but has no shared_2 lock", tid));

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
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock "
                        "exclusive while holding shared 1", tid));
        if (shared2_tid_map.find(tid) != shared2_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock "
                        "exclusive while holding shared 2", tid));

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
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock "
                        "exclusive while holding shared 1", tid));
        if (shared2_tid_map.find(tid) != shared2_tid_map.end())
            throw std::runtime_error(fmt::format("deadlock prevented, thread {} attempted to lock "
                        "exclusive while holding shared 2", tid));

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
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock "
                        "exclusive when exclusive not locked", tid));

        if (tid != excl_tid)
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock "
                        "exclusive but owned by {}", tid, excl_tid));

        if (excl_ct == 0)
            throw std::runtime_error(fmt::format("invalid usage, thread {} attempted to unlock "
                        "exclusive but exclusive count 0", tid));

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

    std::string mutex_nm;

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

// A shared, recursive mutex implemented on top of the tristate primitive
class kis_shared_mutex {
public:
    kis_shared_mutex() :
        base() {}  
    ~kis_shared_mutex() = default;

    kis_shared_mutex(const kis_shared_mutex&) = delete;
    kis_shared_mutex& operator=(const kis_shared_mutex&) = delete;

    void set_name(const std::string& nm) {
        base.set_name(nm);
    }

    const std::string& get_name() const {
        return base.get_name();
    }

    void lock(const std::string& op = "UNKNOWN") { return base.lock_exclusive(); }
    bool try_lock(const std::string& op = "UNKNOWN") { return base.try_lock_exclusive(); }
    void unlock() { return base.unlock_exclusive(); }

    void lock_shared(const std::string& op = "UNKNOWN") { return base.lock_shared_1(); }
    bool try_lock_shared(const std::string& op = "UNKNOWN") { return base.try_lock_shared_1(); }
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

template<class M>
class kis_lock_guard {
public:
    kis_lock_guard(M& m, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op} {
            mutex.lock(op);
        }

    kis_lock_guard(M& m, std::adopt_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op} {
            // don't lock, adopt existing
            // mutex.lock();
        }

    kis_lock_guard(const kis_lock_guard&) = delete;
    kis_lock_guard& operator=(const kis_lock_guard&) = delete;

    ~kis_lock_guard() {
        mutex.unlock();
    }

protected:
    M& mutex;
    std::string op;
};

template<class M>
class kis_shared_lock_guard {
public:
    kis_shared_lock_guard(M& m, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op} {
            mutex.lock_shared(op);
        }

    kis_shared_lock_guard(M& m, std::adopt_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op} {
            // don't lock, adopt existing
            // mutex.lock_shared();
        }

    kis_shared_lock_guard(const kis_shared_lock_guard&) = delete;
    kis_shared_lock_guard& operator=(const kis_shared_lock_guard&) = delete;

    ~kis_shared_lock_guard() {
        mutex.unlock_shared();
    }

protected:
    M& mutex;
    std::string op;
};

template<class M>
class kis_unique_lock {
public:
    kis_unique_lock(M& m, const std::string& op) :
        mutex{m},
        op{op} {
            mutex.lock(op);
        }

    kis_unique_lock(M& m, std::defer_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op} { }

    kis_unique_lock(M& m, std::adopt_lock_t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        locked{true} { }

    kis_unique_lock(const kis_unique_lock&) = delete;
    kis_unique_lock& operator=(const kis_unique_lock&) = delete;

    ~kis_unique_lock() {
        if (locked)
            mutex.unlock();
    }

    void lock(const std::string& op = "UNKNOWN") {
        if (locked)
            throw std::runtime_error(fmt::format("invalid use: thread {} attempted to lock "
                        "unique lock {} when already locked fo {}", 
                        std::this_thread::get_id(), mutex.get_name(), op));

        locked = true;
        mutex.lock(op);
    }

    bool try_lock(const std::string& op = "UNKNOWN") {
        if (locked)
            throw std::runtime_error(fmt::format("invalid use: thread {} attempted to try_lock "
                        "unique lock {} when already locked for {}", 
                        std::this_thread::get_id(), mutex.get_name(), op));

        auto r = mutex.try_lock(op);
        locked = r;
        return r;
    }

    void unlock() {
        if (!locked)
            throw std::runtime_error(fmt::format("unvalid use:  thread{} attempted to unlock "
                        "unique lock {} when not locked", std::this_thread::get_id(), 
                        mutex.get_name()));

        mutex.unlock();
        locked = false;
    }

protected:
    M& mutex;
    std::string op;
    bool locked{false};
};

#endif

