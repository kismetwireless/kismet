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

#ifndef __KISMET_MUTEX_H__
#define __KISMET_MUTEX_H__

#include "config.h"

#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include <limits.h>

#include "fmt.h"

#define KIS_THREAD_TIMEOUT      30

class kis_mutex : public std::recursive_timed_mutex {
private:
    std::string name;

public:
    kis_mutex() :
        name{"UNNAMED"} { }
    kis_mutex(const std::string& name) :
        name{name} { }

    kis_mutex(const kis_mutex&) = delete;
    kis_mutex& operator=(const kis_mutex&) = delete;

    ~kis_mutex() = default;

    void set_name(const std::string& name) {
        this->name = name;
    }

    const std::string& get_name() const {
        return name;
    }

    // Previous workaround for gcc try_lock_for bugs here, but now we require c++14 so we don't
    // need them

    void lock_shared() {
        throw std::runtime_error("lock_shared called on non-shared mutex");
    }

    bool try_lock_shared() {
        throw std::runtime_error("try_lock_shared called on non-shared mutex");
    }

    template<class Rep, class Period>
    bool try_lock_shared_for(const std::chrono::duration<Rep, Period>& timeout_duration) {
        throw std::runtime_error("try_lock_shared_for called on non-shared mutex");
    }

    template<class Clock, class Duration>
    bool try_lock_shared_until(const std::chrono::time_point<Clock, Duration>& timeout_time) {
        throw std::runtime_error("try_lock_shared_until called on non-shared mutex");
    }

    void unlock_shared() {
        throw std::runtime_error("unlock_shared called on non-shared mutex");
    }
};


class kis_shared_mutex : public std::shared_mutex {
private:
    std::string name;

public:
    kis_shared_mutex() :
        name{"UNNAMED"} { }
    kis_shared_mutex(const std::string& name) :
        name{name} { }

    kis_shared_mutex(const kis_shared_mutex&) = delete;
    kis_shared_mutex& operator=(const kis_shared_mutex&) = delete;

    ~kis_shared_mutex() = default;

    void set_name(const std::string& name) {
        this->name = name;
    }

    const std::string& get_name() const {
        return name;
    }

    void lock(void) {
        std::thread::id this_id = std::this_thread::get_id();
        if (owner == this_id) {
            count++;
        } else {
            shared_mutex::lock();
            owner = this_id;
            count = 1;
        }
    }

    void unlock(void) {
        if (count > 1) {
            count--;
        } else {
            owner = std::thread::id();
            count = 0;
            shared_mutex::unlock();
        }
    }

private:
    std::atomic<std::thread::id> owner;
    int count;
};


namespace kismet {
    typedef struct { } retain_lock_t;
    constexpr retain_lock_t retain_lock;

    typedef struct { } shared_lock_t;
    constexpr shared_lock_t shared_lock;
}

template<class M>
class kis_lock_guard {
public:
    kis_lock_guard(M& m, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        retain{false} {
            mutex.lock();
        }

    kis_lock_guard(M& m, std::adopt_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        retain{false} { }

    kis_lock_guard(M& m, kismet::retain_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        retain{true} {
            mutex.lock();
        }

    kis_lock_guard(const kis_lock_guard&) = delete;
    kis_lock_guard& operator=(const kis_lock_guard&) = delete;

    ~kis_lock_guard() {
        if (!retain) {
            mutex.unlock();
        }
    }

protected:
    M& mutex;
    std::string op;
    bool retain;
};

template<class M>
class kis_unique_lock {
public:
    kis_unique_lock(M& m, const std::string& op) :
        mutex{m},
        op{op} {
            mutex.lock();
            locked = true;
        }

    kis_unique_lock(M& m, std::defer_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        locked{false} { }

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
                        "unique lock {} when already locked for {}", 
                        std::this_thread::get_id(), mutex.get_name(), op));
        mutex.lock();
        locked = true;

    }

    bool try_lock(const std::string& op = "UNKNOWN") {
        if (locked)
            throw std::runtime_error(fmt::format("invalid use: thread {} attempted to try_lock "
                        "unique lock {} when already locked for {}", 
                        std::this_thread::get_id(), mutex.get_name(), op));

        // auto r = mutex.try_lock_for(std::chrono::seconds(KIS_THREAD_TIMEOUT));
        auto r = mutex.try_lock();
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

template<class M>
class kis_shared_lock {
public:
    kis_shared_lock(M& m, const std::string& op) :
        mutex{m},
        op{op} {
            mutex.lock_shared();
            locked = true;
        }

    kis_shared_lock(M& m, std::defer_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        locked{false} { }

    kis_shared_lock(M& m, std::adopt_lock_t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        locked{true} { }

    kis_shared_lock(const kis_shared_lock&) = delete;
    kis_shared_lock& operator=(const kis_shared_lock&) = delete;

    ~kis_shared_lock() {
        if (locked)
            mutex.unlock_shared();
    }

    void lock(const std::string& op = "UNKNOWN") {
        if (locked)
            throw std::runtime_error(fmt::format("invalid use: thread {} attempted to lock "
                        "unique lock {} when already locked for {}", 
                        std::this_thread::get_id(), mutex.get_name(), op));
        mutex.lock_shared();
        locked = true;

    }

    void unlock() {
        if (!locked)
            throw std::runtime_error(fmt::format("invalid use:  thread{} attempted to unlock "
                        "unique lock {} when not locked", std::this_thread::get_id(), 
                        mutex.get_name()));

        mutex.unlock_shared();
        locked = false;
    }

protected:
    M& mutex;
    std::string op;
    bool locked{false};
};

#endif

