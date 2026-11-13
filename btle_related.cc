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

#include "btle_related.h"

#include <algorithm>

btle_related_tracker::btle_related_tracker(const params& p) :
    p_{p} {
    mutex.set_name("btle_related_tracker");
}

void btle_related_tracker::settle(group& c, time_t now, std::vector<state>& out, const device_key *always) {
    const auto size = static_cast<uint32_t>(c.members.size());

    // Members are never empty here; ties go to the one heard last
    const auto newest = std::max_element(c.members.begin(), c.members.end(),
            [](const member& a, const member& b) {
                return a.first < b.first || (a.first == b.first && a.last < b.last);
            });
    const auto newest_first = newest->first;
    const auto newest_key = newest->key;

    const auto active = static_cast<uint32_t>(std::count_if(c.members.begin(), c.members.end(),
                [this, now](const member& m) { return now - m.last < p_.quiet; }));

    for (auto& m : c.members) {
        const bool old = now - m.last >= p_.quiet && newest_first > m.last;

        const bool report = (always != nullptr && m.key == *always) ||
            m.rep_size != size || m.rep_old != old || !(m.rep_newest == newest_key) ||
            m.rep_truncated != c.truncated || m.rep_active != active;

        m.rep_size = size;
        m.rep_old = old;
        m.rep_newest = newest_key;
        m.rep_truncated = c.truncated;
        m.rep_active = active;

        if (report)
            out.push_back(state{m.key, c.id, size, old, newest_key, c.truncated, active});
    }
}

void btle_related_tracker::forget(std::unordered_map<uint64_t, group>::iterator ci) {
    for (const auto& m : ci->second.members)
        where_.erase(m.key);
    lru_.erase(ci->second.lru);
    groups_.erase(ci);
}

void btle_related_tracker::leave(uint64_t fp, const device_key& key, time_t now, std::vector<state>& out) {
    auto ci = groups_.find(fp);
    if (ci == groups_.end())
        return;

    auto& members = ci->second.members;
    members.erase(std::remove_if(members.begin(), members.end(),
                [&key](const member& m) { return m.key == key; }), members.end());

    if (members.empty())
        forget(ci);
    else
        settle(ci->second, now, out, nullptr);
}

bool btle_related_tracker::steady(uint64_t fingerprint, const device_key& key, time_t now) {
    if (p_.steady <= 0)
        return true;

    // An address quiet for the steady time starts over
    if (now != last_prune) {
        last_prune = now;
        for (auto ai = addrs_.begin(); ai != addrs_.end(); ) {
            if (now - ai->second.last > p_.steady)
                ai = addrs_.erase(ai);
            else
                ++ai;
        }
    }

    auto ai = addrs_.find(key);
    if (ai == addrs_.end()) {
        if (addrs_.size() < max_addrs)
            addrs_.emplace(key, addr{fingerprint, now, now, false});
        return true;
    }

    auto& a = ai->second;
    if (now > a.last)
        a.last = now;

    if (a.fingerprint != fingerprint) {
        a.fingerprint = fingerprint;
        a.since = now;
        a.unsteady = true;
    } else if (a.unsteady && now - a.since >= p_.steady) {
        a.unsteady = false;
    }

    return !a.unsteady;
}

void btle_related_tracker::observe(uint64_t fingerprint, const device_key& key, time_t now,
        std::vector<state>& out) {
    kis_lock_guard<kis_mutex> lk(mutex, "btle_related_tracker observe");

    auto wi = where_.find(key);

    // Too little payload to say anything: still heard in whatever group it's in
    if (fingerprint == 0) {
        if (wi != where_.end())
            join(wi->second, key, now, out);
        else
            out.push_back(state{key, 0, 0, false, device_key{}, false, 0});
        return;
    }

    const bool keep = steady(fingerprint, key, now);

    if (wi != where_.end() && (!keep || wi->second != fingerprint)) {
        leave(wi->second, key, now, out);
        where_.erase(wi);
    }

    if (!keep) {
        out.push_back(state{key, 0, 0, false, device_key{}, false, 0});
        return;
    }

    join(fingerprint, key, now, out);
}

void btle_related_tracker::join(uint64_t fingerprint, const device_key& key, time_t now,
        std::vector<state>& out) {
    auto ci = groups_.find(fingerprint);
    if (ci == groups_.end()) {
        // Make room by forgetting the least recently heard group
        while (!groups_.empty() && groups_.size() >= p_.max_groups)
            forget(groups_.find(lru_.front()));

        ci = groups_.emplace(fingerprint, group{next_id++, {}, false, lru_.end()}).first;
        ci->second.lru = lru_.insert(lru_.end(), fingerprint);
    } else {
        lru_.splice(lru_.end(), lru_, ci->second.lru);
    }

    auto& c = ci->second;
    auto mi = std::find_if(c.members.begin(), c.members.end(),
            [&key](const member& m) { return m.key == key; });

    if (mi != c.members.end()) {
        mi->last = now;
    } else {
        // A full group makes room by dropping its longest quiet member, which keeps
        // its last state
        while (!c.members.empty() && c.members.size() >= p_.max_members) {
            auto oldest = std::min_element(c.members.begin(), c.members.end(),
                    [](const member& a, const member& b) { return a.last < b.last; });
            where_.erase(oldest->key);
            c.members.erase(oldest);
            c.truncated = true;
        }

        c.members.push_back(member{key, now, now, 0, false, device_key{}, false, 0});
        where_[key] = fingerprint;
    }

    settle(c, now, out, &key);
}

void btle_related_tracker::age(time_t now, std::vector<state>& out) {
    kis_lock_guard<kis_mutex> lk(mutex, "btle_related_tracker age");

    for (auto& ci : groups_)
        settle(ci.second, now, out, nullptr);
}

std::vector<device_key> btle_related_tracker::members_of(const device_key& key) {
    kis_lock_guard<kis_mutex> lk(mutex, "btle_related_tracker members_of");

    std::vector<device_key> ret;

    auto wi = where_.find(key);
    if (wi == where_.end())
        return ret;

    auto ci = groups_.find(wi->second);
    if (ci == groups_.end())
        return ret;

    ret.reserve(ci->second.members.size());
    for (const auto& m : ci->second.members)
        ret.push_back(m.key);

    return ret;
}
