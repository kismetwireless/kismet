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

int64_t abs_diff(int64_t a, int64_t b) {
    return a > b ? a - b : b - a;
}

}

void btle_corotation::prune(int64_t now_ms) {
    for (auto i = addrs_.begin(); i != addrs_.end(); ) {
        if (now_ms - i->second.last_ms > p_.keep_ms)
            i = addrs_.erase(i);
        else
            ++i;
    }

    for (auto i = chains_.begin(); i != chains_.end(); ) {
        if (now_ms - i->second.last_ms > p_.chain_keep_ms)
            i = chains_.erase(i);
        else
            ++i;
    }
}

void btle_corotation::observe(const device_key& key, int64_t now_ms, uint64_t structure,
        int signal, uint64_t source) {
    // Timing and signal only compare on one receiver
    if (source == 0)
        return;

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

        addrs_.emplace(key, addr{now_ms, now_ms, signal, signal, source, structure});
        return;
    }

    auto& a = i->second;

    if (now_ms > a.last_ms) {
        a.last_ms = now_ms;
        a.last_signal = signal;
    }

    // One address, one receiver; heard on another, it's no use for timing
    if (a.source != source)
        a.source = 0;
}

void btle_corotation::rotated(const device_key& key, const device_key& pred, std::vector<join>& out) {
    kis_lock_guard<kis_mutex> lk(mutex, "btle_corotation rotated");

    auto ai = addrs_.find(pred);
    auto ni = addrs_.find(key);

    if (ai == addrs_.end() || ni == addrs_.end())
        return;

    const auto& a = ai->second;
    const auto& an = ni->second;

    if (a.source == 0 || a.source != an.source)
        return;

    // The other addresses that went quiet with the anchor, and that started with its next
    std::vector<std::pair<device_key, const addr *>> quiet, fresh;

    for (const auto& [k, x] : addrs_) {
        if (k == key || k == pred || x.source != a.source)
            continue;

        const bool q = abs_diff(x.last_ms, a.last_ms) <= p_.window_ms &&
            std::abs(x.last_signal - a.last_signal) <= p_.signal_window;
        const bool n = abs_diff(x.first_ms, an.first_ms) <= p_.window_ms &&
            std::abs(x.first_signal - an.first_signal) <= p_.signal_window;

        // Came and went within the moment: can't say which side it's on
        if (q && n)
            return;

        if (q)
            quiet.emplace_back(k, &x);
        else if (n)
            fresh.emplace_back(k, &x);
    }

    auto ci = chains_.find(pred);

    if (quiet.empty() || quiet.size() != fresh.size()) {
        if (ci != chains_.end())
            chains_.erase(ci);
        return;
    }

    // Every structure exactly once on each side, so each pairs one way only
    auto unique = [](const std::vector<std::pair<device_key, const addr *>>& v) {
        for (size_t i = 0; i < v.size(); i++) {
            if (v[i].second->structure == 0)
                return false;
            for (size_t j = i + 1; j < v.size(); j++)
                if (v[i].second->structure == v[j].second->structure)
                    return false;
        }
        return true;
    };

    if (!unique(quiet) || !unique(fresh)) {
        if (ci != chains_.end())
            chains_.erase(ci);
        return;
    }

    std::vector<member> members;

    for (const auto& q : quiet) {
        const uint64_t s = q.second->structure;
        auto fi = std::find_if(fresh.begin(), fresh.end(),
                [s](const auto& f) { return f.second->structure == s; });

        if (fi == fresh.end()) {
            if (ci != chains_.end())
                chains_.erase(ci);
            return;
        }

        members.push_back(member{s, q.first, fi->first, false});
    }

    // A set that rotated with the anchor last time too, from where it went then
    if (ci != chains_.end()) {
        for (auto& m : members) {
            for (const auto& pm : ci->second.members) {
                if (pm.structure != m.structure || !(pm.next == m.quiet))
                    continue;

                m.confirmed = true;

                if (!pm.confirmed)
                    out.push_back(join{m.quiet, key});
                out.push_back(join{m.next, key});
                break;
            }
        }

        chains_.erase(ci);
    }

    if (chains_.size() >= max_chains)
        chains_.erase(std::min_element(chains_.begin(), chains_.end(),
                    [](const auto& x, const auto& y) { return x.second.last_ms < y.second.last_ms; }));

    chains_.emplace(key, chain{std::move(members), an.first_ms});
}
