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

#include "randomized_alias.h"

namespace {

constexpr size_t alias_max_per_fingerprint = 32;

}

void randomized_alias_linker::prune(time_t now) {
    for (auto mi = recs_.begin(); mi != recs_.end(); ) {
        auto& v = mi->second;
        const auto before = v.size();
        // Kept while the address is heard, for a number it sends now and then
        v.erase(std::remove_if(v.begin(), v.end(),
                    [this, now](const rec& r) {
                        auto si = seen_.find(r.key);
                        const time_t last = si == seen_.end() ? r.last : std::max(r.last, si->second.last);
                        return now - last > p_.keep;
                    }), v.end());
        rec_count_ -= before - v.size();

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

device_key randomized_alias_linker::group(const device_key& key) {
    kis_lock_guard<kis_mutex> lk(mutex, "randomized_alias_linker group");
    return group_of(key);
}

device_key randomized_alias_linker::group_of(const device_key& k) const {
    auto i = seen_.find(k);
    return i == seen_.end() ? k : i->second.group;
}

randomized_alias_linker::rec *randomized_alias_linker::find_rec(uint64_t fingerprint,
        const device_key& k) {
    auto bi = recs_.find(fingerprint);
    if (bi == recs_.end())
        return nullptr;

    for (auto& r : bi->second)
        if (r.key == k)
            return &r;

    return nullptr;
}

void randomized_alias_linker::release(pending& pl) {
    if (pl.kind == pending_kind::carry)
        if (auto pred = find_rec(pl.fingerprint, pl.pred))
            pred->succeeded = false;
    pl.method = nullptr;
}

bool randomized_alias_linker::has_strong(const device_key& k) const {
    for (const auto& pl : pending_)
        if (pl.method != nullptr && pl.strong && pl.key == k)
            return true;
    return false;
}

bool randomized_alias_linker::push_pending(const pending& np) {
    if (pending_.size() >= max_pending)
        return false;

    // A sequence match outranks the key's links made without one
    if (np.strong)
        for (auto& pl : pending_)
            if (pl.method != nullptr && pl.key == np.key && pl.kind != pending_kind::same && !pl.strong)
                release(pl);

    pending_.push_back(np);
    return true;
}

randomized_alias_linker::rec *randomized_alias_linker::signal_pick(const pending& pl) {
    const auto self = find_rec(pl.fingerprint, pl.key);

    if (self == nullptr || self->last_source == 0)
        return nullptr;

    rec *best = nullptr;
    int best_d = 0, next_d = std::numeric_limits<int>::max();

    for (size_t i = 0; i < pl.n_cands; i++) {
        auto r = find_rec(pl.fingerprint, pl.cands[i]);
        auto rs = seen_.find(pl.cands[i]);

        // Taken by another address since, forgotten, or heard again: not this one's
        if (r == nullptr || r->succeeded || rs == seen_.end() || rs->second.last > pl.first)
            continue;

        // One heard elsewhere can't be ruled out
        if (r->last_source != self->last_source)
            return nullptr;

        const int d = std::abs(self->avg16 - r->avg16);

        if (best == nullptr || d < best_d) {
            next_d = best == nullptr ? next_d : best_d;
            best = r;
            best_d = d;
        } else if (d < next_d) {
            next_d = d;
        }
    }

    if (best == nullptr || best_d > p_.signal_window * 16)
        return nullptr;

    if (next_d != std::numeric_limits<int>::max() && next_d - best_d < p_.signal_margin * 16)
        return nullptr;

    return best;
}

void randomized_alias_linker::observe(uint64_t fingerprint, const device_key& key, time_t now,
        int seq, std::vector<link>& out, int signal, uint64_t source) {
    observe(fingerprint, key, now, seq, out, signal, source,
            seq_rules{4096, p_.seq_window, "sequence", false, 0, nullptr, alias_max_per_fingerprint});
}

void randomized_alias_linker::observe(uint64_t fingerprint, const device_key& key, time_t now,
        int seq, std::vector<link>& out, int signal, uint64_t source, const seq_rules& rules) {
    kis_lock_guard<kis_mutex> lk(mutex, "randomized_alias_linker observe");

    if (now - last_prune > p_.window) {
        last_prune = now;
        prune(now);
    }

    const int modulus = std::max(rules.modulus, 1);
    if (seq < 0 || seq >= modulus)
        seq = -1;

    // Whatever a receiver reports, so the average can't overflow
    if (signal == no_signal || source == 0)
        signal = no_signal;
    else
        signal = std::clamp(signal, -200, 50);

    // Under a flood, prune early, at most once a second, then ignore what doesn't fit
    auto make_room = [this, now](auto full) {
        if (full() && now > last_prune) {
            last_prune = now;
            prune(now);
        }
        return !full();
    };

    auto si = seen_.find(key);
    if (si == seen_.end()) {
        if (!make_room([this]() { return seen_.size() >= max_seen; }))
            return;
        si = seen_.emplace(key, seen{now, now, key}).first;
    } else {
        si->second.first = std::min(si->second.first, now);
        si->second.last = std::max(si->second.last, now);
    }

    // A number sent now and then may first come well after the address started, and
    // well after the earlier address last sent one, so it's timed by frames of any kind
    const time_t start = rules.only ? si->second.first : now;

    auto self = find_rec(fingerprint, key);

    if (self != nullptr) {
        if (now > self->last)
            self->last = now;

        if (!rules.only) {
            self->last_seq = seq;
        } else if (seq >= 0) {
            // A late or repeated frame doesn't move it back
            if (self->last_seq < 0 || self->last_seq >= modulus ||
                    (seq - self->last_seq + modulus) % modulus < modulus / 2)
                self->last_seq = seq;
        }

        if (signal != no_signal) {
            if (self->last_source != source) {
                self->avg16 = signal * 16;
                self->n_signal = 1;
                self->last_source = source;
            } else {
                // The mean of the first frames, then a running average
                if (self->n_signal < 16)
                    self->n_signal++;
                self->avg16 += (signal * 16 - self->avg16) / self->n_signal;
            }
        }

        settle(now, out);
        return;
    }

    const size_t cap = std::max<size_t>(rules.max_recs, 1);
    auto bucket_full = [this, fingerprint, cap]() {
        auto bi = recs_.find(fingerprint);
        return bi != recs_.end() && bi->second.size() >= cap;
    };

    // A full bucket replaces its oldest, so it needs no room
    if (!bucket_full() && !make_room([this, &bucket_full]() {
                return !bucket_full() && rec_count_ >= max_recs_total; })) {
        settle(now, out);
        return;
    }

    auto& recs = recs_[fingerprint];

    // Earlier addresses with this fingerprint which went quiet recently, and how
    // many separate devices with it were heard in that time
    std::vector<rec *> cands;
    std::vector<rec *> seq_cands;
    std::vector<device_key> active_groups;

    for (auto& r : recs) {
        auto rs = seen_.find(r.key);
        const time_t r_last = rules.only && rs != seen_.end() ? std::max(r.last, rs->second.last) : r.last;

        // An address with a later one linked to it is that same device
        if (start - r_last > p_.window || r.succeeded)
            continue;

        const auto g = group_of(r.key);
        if (std::find(active_groups.begin(), active_groups.end(), g) == active_groups.end())
            active_groups.push_back(g);

        // Still heard, under any fingerprint, after the new address appeared
        if (r.last > start || (rs != seen_.end() && rs->second.last > start))
            continue;

        cands.push_back(&r);

        if (seq >= 0 && r.last_seq >= 0 && r.last_seq < modulus) {
            const int diff = (seq - r.last_seq + modulus) % modulus;
            if (diff >= 1 && diff <= rules.window)
                seq_cands.push_back(&r);
        }
    }

    rec *seq_pick = nullptr;

    if (seq_cands.size() == 1) {
        seq_pick = seq_cands[0];
    } else if (rules.only && seq_cands.size() > 1) {
        // A device's sets that share a number are one group: carry on from its latest
        const auto g = group_of(seq_cands[0]->key);
        if (std::all_of(seq_cands.begin(), seq_cands.end(),
                    [this, &g](const rec *r) { return group_of(r->key) == g; }))
            seq_pick = *std::max_element(seq_cands.begin(), seq_cands.end(),
                    [](const rec *a, const rec *b) { return a->last < b->last; });
    }

    if (seq_pick != nullptr) {
        if (push_pending(pending{fingerprint, key, seq_pick->key, now, rules.method,
                    pending_kind::carry, rules.only, rules.only}))
            seq_pick->succeeded = true;
    } else if (rules.only && seq >= 0) {
        // A number that matches nothing links nothing
    } else if (cands.size() == 1 && active_groups.size() == 1) {
        if (!has_strong(key) && push_pending(pending{fingerprint, key, cands[0]->key, now,
                    p_.unique_method, pending_kind::carry, false, rules.only}))
            cands[0]->succeeded = true;
    } else {
        // Another device with this fingerprint is around, so a link made without
        // a sequence number could belong to either
        for (auto& pl : pending_)
            if (pl.fingerprint == fingerprint && pl.method == p_.unique_method)
                release(pl);

        // Picked once settled, by average signals: one frame's is too rough
        if (p_.signal_window > 0 && signal != no_signal && !cands.empty() &&
                cands.size() <= max_signal_cands && !has_strong(key)) {
            pending pl{fingerprint, key, device_key{}, now, "signal", pending_kind::signal,
                false, rules.only};

            for (auto c : cands)
                pl.cands[pl.n_cands++] = c->key;

            push_pending(pl);
        }
    }

    // The same number on another address heard just now, on this receiver at a similar
    // signal: the same device sending two sets
    if (rules.same_window > 0 && seq >= 0 && p_.signal_window > 0 && signal != no_signal &&
            source != 0) {
        const auto my_group = group_of(key);
        rec *mate = nullptr;
        bool ambiguous = false;

        for (auto& r : recs) {
            if (r.last_seq != seq || now - r.last > rules.same_window)
                continue;
            if (r.last_source != source || std::abs(signal * 16 - r.avg16) > p_.signal_window * 16)
                continue;

            const auto g = group_of(r.key);
            if (g == my_group)
                continue;

            if (mate != nullptr && group_of(mate->key) != g) {
                ambiguous = true;
                break;
            }

            if (mate == nullptr || r.last > mate->last)
                mate = &r;
        }

        if (mate != nullptr && !ambiguous)
            push_pending(pending{fingerprint, key, mate->key, now,
                    rules.same_method != nullptr ? rules.same_method : rules.method,
                    pending_kind::same, false, rules.only});
    }

    while (recs.size() >= cap) {
        recs.erase(std::min_element(recs.begin(), recs.end(),
                    [](const rec& a, const rec& b) { return a.last < b.last; }));
        rec_count_--;
    }

    recs.push_back(rec{key, now, now, seq, signal == no_signal ? 0 : signal * 16,
            (uint8_t) (signal == no_signal ? 0 : 1), signal == no_signal ? 0 : source, false});
    rec_count_++;

    settle(now, out);
}

void randomized_alias_linker::join(const device_key& key, const device_key& pred,
        const char *method, std::vector<link>& out) {
    kis_lock_guard<kis_mutex> lk(mutex, "randomized_alias_linker join");

    if (seen_.find(key) == seen_.end() || seen_.find(pred) == seen_.end())
        return;

    merge(key, pred, method, link_kind::join, out);
}

void randomized_alias_linker::merge(const device_key& key, const device_key& pred,
        const char *method, link_kind kind, std::vector<link>& out) {
    const auto old_group = group_of(key);
    const auto new_group = group_of(pred);

    if (old_group == new_group)
        return;

    out.push_back(link{key, pred, new_group, method, kind});

    // This address, and later ones already linked to it, join the earlier group
    for (auto& s : seen_) {
        if (s.second.group != old_group)
            continue;

        s.second.group = new_group;

        if (s.first != key)
            out.push_back(link{s.first, device_key{}, new_group, nullptr, kind});
    }
}

void randomized_alias_linker::settle(time_t now, std::vector<link>& out) {
    for (auto& pl : pending_) {
        if (pl.method == nullptr)
            continue;

        if (pl.kind == pending_kind::signal) {
            if (now - pl.first < p_.confirm)
                continue;

            // An address one of these linked already has its earlier address
            if (auto pred = pl.only && group_of(pl.key) != pl.key ? nullptr : signal_pick(pl)) {
                merge(pl.key, pred->key, pl.method, link_kind::carry, out);
                pred->succeeded = true;
            }

            pl.method = nullptr;
            continue;
        }

        auto ps = seen_.find(pl.pred);

        if (ps == seen_.end()) {
            release(pl);
            continue;
        }

        // Both still heard, still with the same number
        if (pl.kind == pending_kind::same) {
            const auto a = find_rec(pl.fingerprint, pl.key);
            const auto b = find_rec(pl.fingerprint, pl.pred);

            if (a == nullptr || b == nullptr) {
                release(pl);
                continue;
            }

            if (now - pl.first < same_confirm)
                continue;

            if (a->last > pl.first && b->last > pl.first && a->last_seq == b->last_seq) {
                merge(pl.key, pl.pred, pl.method, link_kind::same, out);
                pl.method = nullptr;
            }

            continue;
        }

        // The earlier address was heard again, so it's another device, or it has
        // stayed quiet long enough
        if (ps->second.last > pl.first) {
            release(pl);
            continue;
        }

        if (now - pl.first < p_.confirm)
            continue;

        // An address one of these linked already has its earlier address
        if (pl.only && group_of(pl.key) != pl.key) {
            release(pl);
            continue;
        }

        merge(pl.key, pl.pred, pl.method, link_kind::carry, out);
        pl.method = nullptr;
    }

    pending_.erase(std::remove_if(pending_.begin(), pending_.end(),
                [](const pending& pl) { return pl.method == nullptr; }), pending_.end());
}
