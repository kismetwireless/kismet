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

#include "wired_flow_history.h"

#include <algorithm>
#include <limits>

namespace {

constexpr time_t min_s = 60;
constexpr time_t hour_s = 3600;
constexpr size_t n_hours = 24;

constexpr size_t sec_slot(time_t t) { return static_cast<size_t>(t % min_s); }
constexpr size_t min_slot_of(time_t t) { return static_cast<size_t>((t / min_s) % 60); }
constexpr size_t hr_slot(time_t t) { return static_cast<size_t>((t / hour_s) % n_hours); }

// Zeroes the n slots after first, wrapping; n is at most the array's size
template <typename A>
void zero_after(A& a, size_t first, time_t n) {
    const auto count = static_cast<size_t>(std::min<time_t>(n, static_cast<time_t>(a.size())));
    for (size_t i = 1; i <= count; i++)
        a[(first + i) % a.size()] = {};
}

}

void flow_history::min_slot::set(size_t i, uint64_t v) {
    if (i < 2)
        bytes[i] = v;
    else
        packets[i - 2] = static_cast<uint32_t>(std::min<uint64_t>(v, std::numeric_limits<uint32_t>::max()));
}

void flow_history::reset(time_t now) {
    const auto p = pool;
    *this = flow_history{now};
    pool = p;
}

void flow_history::advance_to(time_t now) {
    now = clamp_time(now);
    if (now <= last)
        return;

    const auto& cur = sec[sec_slot(last)];
    for (size_t i = 0; i < n_series; i++)
        acc_min[i] += cur[i];

    if (now / min_s != last / min_s) {
        auto& m = min[min_slot_of(last)];
        for (size_t i = 0; i < n_series; i++) {
            m.set(i, acc_min[i]);
            acc_hr[i] += acc_min[i];
            acc_min[i] = 0;
        }

        // The skipped minutes, and the new one, whose slot still holds an hour-old minute
        zero_after(min, min_slot_of(last), now / min_s - last / min_s);
    }

    if (now / hour_s != last / hour_s) {
        hr[hr_slot(last)] = acc_hr;
        acc_hr = {};
        zero_after(hr, hr_slot(last), now / hour_s - last / hour_s);
    }

    zero_after(sec, sec_slot(last), now - last);

    last = now;
}

void flow_history::move_to(time_t now) {
    now = clamp_time(now);
    if (now > last)
        advance_to(now);
    else if (last - now > max_backstep_s)
        reset(now);
}

flow_history::rrd_vectors flow_history::vectors(series s) const {
    const auto i = static_cast<size_t>(s);
    rrd_vectors v;
    v.last_time = last;

    for (size_t k = 0; k < sec.size(); k++)
        v.minute[k] = static_cast<double>(sec[k][i]);

    for (size_t k = 0; k < min.size(); k++)
        v.hour[k] = static_cast<double>(min[k].get(i)) / min_s;

    for (size_t k = 0; k < hr.size(); k++)
        v.day[k] = static_cast<double>(hr[k][i]) / hour_s;

    // The current minute and hour so far, over their full length, as kis_tracked_rrd does
    const uint64_t minute_so_far = acc_min[i] + sec[sec_slot(last)][i];
    v.hour[min_slot_of(last)] = static_cast<double>(minute_so_far) / min_s;
    v.day[hr_slot(last)] = static_cast<double>(acc_hr[i] + minute_so_far) / hour_s;

    return v;
}

uint64_t flow_history::day_total(series s) const {
    const auto i = static_cast<size_t>(s);
    uint64_t t = acc_hr[i] + acc_min[i] + sec[sec_slot(last)][i];
    for (size_t k = 0; k < hr.size(); k++) {
        if (k != hr_slot(last))
            t += hr[k][i];
    }
    return t;
}
