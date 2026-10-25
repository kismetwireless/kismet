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

#ifndef __OBJECTPOOL_H__
#define __OBJECTPOOL_H__ 

#include <functional>
#include <memory>
#include <stack>
#include <thread>
#include <mutex>

#include "kis_mutex.h"

template <class T>
class shared_object_pool {
private:
    // Only the pool reference is kept per object; the deleter is copied into every
    // shared_ptr control block, so the reset function lives in the pool
    struct pool_deleter {
    public:
        explicit pool_deleter(std::weak_ptr<shared_object_pool<T>* > pool) :
            pool_(pool) { }

        void operator()(T* ptr) {
            if (auto pool_ptr = pool_.lock()) {
                (*pool_ptr.get())->recycle(ptr);
                return;
            }

            std::default_delete<T>{}(ptr);
        }

    private:
        std::weak_ptr<shared_object_pool<T>* > pool_;
    };

    // Owns ptr from the start, so a failed reset or add deletes it exactly once
    void recycle(T* ptr) noexcept {
        auto obj = std::unique_ptr<T>{ptr};

        try {
            std::function<void (T*)> reset;

            {
                kis_lock_guard<kis_mutex> lg(pool_mutex);
                reset = reset_;
            }

            reset(obj.get());
            add(std::move(obj));
        } catch (...) {

        }
    }

public:
    using ptr_type = std::unique_ptr<T, pool_deleter>;

    shared_object_pool() : 
        this_(new shared_object_pool<T>*(this)),
        max_sz{0},
        reset_{[](T*) {}} { }

    shared_object_pool(size_t maxsz) :
        this_(new shared_object_pool<T>*(this)),
        max_sz{maxsz},
        reset_([](T*) {}) { }

    virtual ~shared_object_pool() { }

    void set_max(size_t sz) {
        kis_lock_guard<kis_mutex> lg(pool_mutex);
        max_sz = sz;
    }

    void set_reset(std::function<void (T*)> reset) {
        kis_lock_guard<kis_mutex> lg(pool_mutex);
        reset_ = reset;
    }

    void add(std::unique_ptr<T> t) {
        kis_lock_guard<kis_mutex> lg(pool_mutex);

        if (max_sz == 0 || (max_sz != 0 && size() < max_sz)) {
            pool_.push(std::move(t));
        } 
    }

    void reduce(size_t sz) {
        kis_lock_guard<kis_mutex> lg(pool_mutex);

        while (pool_.size() > sz) {
            pool_.pop();
        }
    }

    ptr_type acquire() {
        kis_lock_guard<kis_mutex> lg(pool_mutex);
        if (pool_.empty()) {
            return ptr_type(new T(),
                    pool_deleter{std::weak_ptr<shared_object_pool<T>*>{this_}});
        } else {
            ptr_type tmp(pool_.top().release(),
                    pool_deleter{std::weak_ptr<shared_object_pool<T>*>{this_}});
            pool_.pop();
            return tmp;
        }
    }

    bool empty() {
        kis_lock_guard<kis_mutex> lg(pool_mutex);
        return pool_.empty();
    }

    size_t size() {
        kis_lock_guard<kis_mutex> lg(pool_mutex);
        return pool_.size();
    }

private:
    std::shared_ptr<shared_object_pool<T>* > this_;
    std::stack<std::unique_ptr<T> > pool_;
    kis_mutex pool_mutex;
    size_t max_sz;
    std::function<void (T*)> reset_;
};

#endif /* ifndef OBJECTPOOL_H */

