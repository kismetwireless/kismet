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

#include "config.h"

#include <algorithm>
#include <cstdlib>

#include "btle_corotation.h"

namespace {

constexpr int64_t prune_interval_ms = 1000;
constexpr int64_t check_interval_ms = 250;

int64_t abs_diff(int64_t a, int64_t b) {
    return a > b ? a - b : b - a;
}

}

const btle_corotation::sighting *btle_corotation::on(const addr& a, uint64_t source) {
    for (size_t i = 0; i < a.n_seen; i++)
        if (a.seen[i].source == source)
            return &a.seen[i];
    return nullptr;
}

btle_corotation::sighting *btle_corotation::on(addr& a, uint64_t source) {
    for (size_t i = 0; i < a.n_seen; i++)
        if (a.seen[i].source == source)
            return &a.seen[i];
    return nullptr;
}

void btle_corotation::prune(int64_t now_ms) {
    for (auto i = addrs_.begin(); i != addrs_.end(); ) {
        if (now_ms - i->second.last_ms > p_.keep_ms)
            i = addrs_.erase(i);
        else
            ++i;
    }

    waiting_.erase(std::remove_if(waiting_.begin(), waiting_.end(),
                [this](const device_key& k) { return addrs_.find(k) == addrs_.end(); }),
            waiting_.end());

    chains_.erase(std::remove_if(chains_.begin(), chains_.end(),
                [this, now_ms](const chain& c) { return now_ms - c.last_ms > p_.chain_keep_ms; }),
            chains_.end());
}

void btle_corotation::observe(const device_key& key, int64_t now_ms, uint64_t structure,
        int signal, uint64_t source, std::vector<rotation>& out) {
    // Timing and signal only compare on one receiver
    if (source == 0)
        return;

    // Whatever a receiver reports, so the average can't overflow
    signal = std::clamp(signal, -200, 50);

    kis_lock_guard<kis_mutex> lk(mutex, "btle_corotation observe");

    if (now_ms - last_prune_ms > prune_interval_ms) {
        last_prune_ms = now_ms;
        prune(now_ms);
    }

    auto i = addrs_.find(key);

    if (i == addrs_.end()) {
        // Full: ignore new addresses rather than drop ones a rotation may need
        if (addrs_.size() >= max_addrs)
            return;

        addr a{now_ms, now_ms, structure, {}, 1, false};
        a.seen[0] = sighting{source, now_ms, now_ms, signal * 16, 1};
        addrs_.emplace(key, a);
        waiting_.push_back(key);
    } else {
        auto& a = i->second;

        a.first_ms = std::min(a.first_ms, now_ms);
        a.last_ms = std::max(a.last_ms, now_ms);

        // A scan response carries none; the advertising that follows does
        if (a.structure == 0)
            a.structure = structure;

        auto s = on(a, source);

        if (s == nullptr && a.n_seen < max_sources) {
            s = &a.seen[a.n_seen++];
            *s = sighting{source, now_ms, now_ms, signal * 16, 1};
        } else if (s != nullptr) {
            s->first_ms = std::min(s->first_ms, now_ms);
            s->last_ms = std::max(s->last_ms, now_ms);
            // The mean of the first frames, then a running average
            if (s->n_signal < 16)
                s->n_signal++;
            s->avg16 += (signal * 16 - s->avg16) / s->n_signal;
        }
    }

    if (now_ms - last_check_ms >= check_interval_ms) {
        last_check_ms = now_ms;
        check(now_ms, out);
    }
}

void btle_corotation::check(int64_t now_ms, std::vector<rotation>& out) {
    std::vector<device_key> due;

    waiting_.erase(std::remove_if(waiting_.begin(), waiting_.end(),
                [this, now_ms, &due](const device_key& k) {
                    auto ai = addrs_.find(k);

                    if (ai == addrs_.end() || ai->second.checked)
                        return true;

                    const int64_t age = now_ms - ai->second.first_ms;

                    if (age >= p_.settle_ms && due.size() < max_checks) {
                        due.push_back(k);
                        return true;
                    }

                    // A flood waits its turn; one left this long can't be checked fairly
                    return age > p_.settle_ms + p_.window_ms;
                }), waiting_.end());

    std::vector<device_key> quiet, fresh;

    for (const auto& k : due) {
        auto ai = addrs_.find(k);

        if (ai == addrs_.end() || ai->second.checked || ai->second.structure == 0)
            continue;

        ai->second.checked = true;

        for (size_t i = 0; i < ai->second.n_seen; i++) {
            if (!find_rotation(ai->second, ai->second.seen[i], quiet, fresh))
                continue;

            // Its fellow new addresses rotated with it: no need to look again
            for (const auto& f : fresh) {
                auto fi = addrs_.find(f);
                if (fi != addrs_.end())
                    fi->second.checked = true;
            }

            record(quiet, fresh, now_ms, out);
            break;
        }
    }
}

bool btle_corotation::find_rotation(const addr& a, const sighting& s,
        std::vector<device_key>& quiet, std::vector<device_key>& fresh) const {
    const int64_t t = s.first_ms;

    quiet.clear();
    fresh.clear();

    // Heard earlier on another receiver: it didn't start here
    if (a.first_ms < t - p_.window_ms)
        return false;

    for (const auto& [k, x] : addrs_) {
        const auto xs = on(x, s.source);

        if (xs == nullptr)
            continue;

        // Averages: a new address's over its first seconds, a quiet one's at its end
        const bool near = std::abs(xs->avg16 - s.avg16) <= p_.signal_window * 16;
        const bool started = near && x.first_ms >= t - p_.window_ms &&
            abs_diff(xs->first_ms, t) <= p_.window_ms;
        // Not heard on any receiver since the moment
        const bool stopped = near && x.first_ms < t - p_.window_ms && x.last_ms <= t + p_.window_ms &&
            abs_diff(xs->last_ms, t) <= p_.window_ms;

        if (started)
            fresh.push_back(k);
        else if (stopped)
            quiet.push_back(k);
        else
            continue;

        if (fresh.size() > max_sets || quiet.size() > max_sets)
            return false;
    }

    if (quiet.size() < 2 || quiet.size() != fresh.size())
        return false;

    // The same structures on both sides: every new address has a set to continue
    auto structures = [this](const std::vector<device_key>& v) {
        std::vector<uint64_t> r;
        r.reserve(v.size());
        for (const auto& k : v) {
            auto i = addrs_.find(k);
            r.push_back(i == addrs_.end() ? 0 : i->second.structure);
        }
        std::sort(r.begin(), r.end());
        return r;
    };

    const auto qs = structures(quiet);

    if (qs.front() == 0)
        return false;

    return qs == structures(fresh);
}

void btle_corotation::record(std::vector<device_key>& quiet, std::vector<device_key>& fresh,
        int64_t now_ms, std::vector<rotation>& out) {
    std::sort(quiet.begin(), quiet.end());
    std::sort(fresh.begin(), fresh.end());

    for (const auto& c : chains_)
        if (c.fresh == fresh)
            return;

    // The addresses that started together last time went quiet together this time
    auto ci = std::find_if(chains_.begin(), chains_.end(),
            [&quiet](const chain& c) { return c.fresh == quiet; });

    if (ci != chains_.end()) {
        out.push_back(rotation{quiet, fresh});
        chains_.erase(ci);
    }

    if (chains_.size() >= max_chains)
        chains_.erase(std::min_element(chains_.begin(), chains_.end(),
                    [](const chain& x, const chain& y) { return x.last_ms < y.last_ms; }));

    chains_.push_back(chain{fresh, now_ms});
}
