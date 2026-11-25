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

#ifndef __CONCURRENCY_LIMIT_H__
#define __CONCURRENCY_LIMIT_H__

#include "config.h"

#include <atomic>
#include <utility>

// Counts jobs of one kind running at once and turns away those over the limit.  A
// slot is held for as long as its job runs and is given back when it goes out of
// scope; the limit must outlive every slot it hands out.
class concurrency_limit {
public:
    class slot {
    public:
        slot() = default;

        slot(slot&& o) noexcept :
            owner_{std::exchange(o.owner_, nullptr)} { }

        slot& operator=(slot&& o) noexcept {
            if (this != &o) {
                release();
                owner_ = std::exchange(o.owner_, nullptr);
            }

            return *this;
        }

        slot(const slot&) = delete;
        slot& operator=(const slot&) = delete;

        ~slot() {
            release();
        }

        bool held() const {
            return owner_ != nullptr;
        }

        void release() {
            if (owner_ != nullptr) {
                owner_->active_.fetch_sub(1);
                owner_ = nullptr;
            }
        }

    private:
        friend class concurrency_limit;

        explicit slot(concurrency_limit *owner) :
            owner_{owner} { }

        concurrency_limit *owner_ = nullptr;
    };

    // 0 is no limit
    explicit concurrency_limit(unsigned int limit) :
        max_{limit} { }

    concurrency_limit(const concurrency_limit&) = delete;
    concurrency_limit& operator=(const concurrency_limit&) = delete;

    void set_max(unsigned int limit) {
        max_ = limit;
    }

    unsigned int max() const {
        return max_;
    }

    unsigned int active() const {
        return active_;
    }

    // A held slot, or an empty one when the limit is reached
    [[nodiscard]] slot try_acquire() {
        const unsigned int limit = max_;
        unsigned int cur = active_.load();

        do {
            if (limit != 0 && cur >= limit)
                return slot{};
        } while (!active_.compare_exchange_weak(cur, cur + 1));

        return slot{this};
    }

private:
    std::atomic<unsigned int> max_;
    std::atomic<unsigned int> active_{0};
};

#endif
