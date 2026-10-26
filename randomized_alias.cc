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

#include "randomized_alias.h"

namespace {

constexpr size_t alias_max_per_fingerprint = 32;

}

void randomized_alias_linker::prune(time_t now) {
    for (auto mi = recs_.begin(); mi != recs_.end(); ) {
        auto& v = mi->second;
        v.erase(std::remove_if(v.begin(), v.end(),
                    [this, now](const rec& r) { return now - r.last > p_.keep; }), v.end());

        if (v.empty())
            mi = recs_.erase(mi);
        else
            ++mi;
    }

    pending_.erase(std::remove_if(pending_.begin(), pending_.end(),
                [this, now](const pending& pl) { return now - pl.first > p_.keep; }), pending_.end());

    for (auto si = seen_.begin(); si != seen_.end(); ) {
        if (now - si->second.last > p_.keep)
            si = seen_.erase(si);
        else
            ++si;
    }
}

void randomized_alias_linker::observe(uint64_t fingerprint, const device_key& key, time_t now,
        int seq, std::vector<link>& out) {
    kis_lock_guard<kis_mutex> lk(mutex, "randomized_alias_linker observe");

    if (now - last_prune > p_.window) {
        last_prune = now;
        prune(now);
    }

    auto si = seen_.find(key);
    if (si == seen_.end())
        si = seen_.emplace(key, seen{now, key}).first;
    else if (now > si->second.last)
        si->second.last = now;

    auto group_of = [this](const device_key& k) {
        auto i = seen_.find(k);
        return i == seen_.end() ? k : i->second.group;
    };

    auto& recs = recs_[fingerprint];

    auto find_rec = [&recs](const device_key& k) -> rec * {
        for (auto& r : recs)
            if (r.key == k)
                return &r;
        return nullptr;
    };

    auto self = find_rec(key);

    if (self != nullptr) {
        if (now > self->last)
            self->last = now;
        self->last_seq = seq;
    } else {
        // Earlier addresses with this fingerprint which went quiet recently, and how
        // many separate devices with it were heard in that time
        std::vector<rec *> cands;
        std::vector<rec *> seq_cands;
        std::vector<device_key> active_groups;

        for (auto& r : recs) {
            // An address with a later one linked to it is that same device
            if (now - r.last > p_.window || r.succeeded)
                continue;

            const auto g = group_of(r.key);
            if (std::find(active_groups.begin(), active_groups.end(), g) == active_groups.end())
                active_groups.push_back(g);

            // Still heard, under any fingerprint, after the new address appeared
            auto rs = seen_.find(r.key);
            if (r.last > now || (rs != seen_.end() && rs->second.last > now))
                continue;

            cands.push_back(&r);

            if (seq >= 0 && r.last_seq >= 0) {
                const int diff = (seq - r.last_seq + 4096) % 4096;
                if (diff >= 1 && diff <= p_.seq_window)
                    seq_cands.push_back(&r);
            }
        }

        rec nr{key, now, now, seq, false};

        if (seq_cands.size() == 1) {
            seq_cands[0]->succeeded = true;
            pending_.push_back(pending{fingerprint, key, seq_cands[0]->key, now, "sequence"});
        } else if (cands.size() == 1 && active_groups.size() == 1) {
            cands[0]->succeeded = true;
            pending_.push_back(pending{fingerprint, key, cands[0]->key, now, p_.unique_method});
        } else {
            // Another device with this fingerprint is around, so a link made without
            // a sequence number could belong to either
            for (auto& pl : pending_) {
                if (pl.fingerprint == fingerprint && pl.method == p_.unique_method) {
                    if (auto pred = find_rec(pl.pred))
                        pred->succeeded = false;
                    pl.method = nullptr;
                }
            }
        }

        if (recs.size() >= alias_max_per_fingerprint)
            recs.erase(std::min_element(recs.begin(), recs.end(),
                        [](const rec& a, const rec& b) { return a.last < b.last; }));

        recs.push_back(nr);
    }

    // Settle pending links: the earlier address was heard again, so it's another
    // device, or it has stayed quiet long enough
    for (auto& pl : pending_) {
        if (pl.method == nullptr)
            continue;

        auto ps = seen_.find(pl.pred);

        if (ps == seen_.end() || ps->second.last > pl.first) {
            auto ri = recs_.find(pl.fingerprint);
            if (ri != recs_.end())
                for (auto& r : ri->second)
                    if (r.key == pl.pred)
                        r.succeeded = false;
            pl.method = nullptr;
            continue;
        }

        if (now - pl.first < p_.confirm)
            continue;

        const auto old_group = group_of(pl.key);
        const auto new_group = ps->second.group;

        out.push_back(link{pl.key, pl.pred, new_group, pl.method});
        pl.method = nullptr;

        // This address, and later ones already linked to it, join the earlier group
        for (auto& s : seen_) {
            if (s.second.group != old_group)
                continue;

            s.second.group = new_group;

            if (s.first != pl.key)
                out.push_back(link{s.first, device_key{}, new_group, nullptr});
        }
    }

    pending_.erase(std::remove_if(pending_.begin(), pending_.end(),
                [](const pending& pl) { return pl.method == nullptr; }), pending_.end());
}
