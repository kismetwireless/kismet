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

#ifndef __BTLE_RELATED_H__
#define __BTLE_RELATED_H__

#include "config.h"

#include <time.h>
#include <list>
#include <unordered_map>
#include <vector>

#include "kis_mutex.h"
#include "trackedelement.h"

// Groups related rotating random BTLE addresses by their advertising payload: every
// address heard with the same payload fingerprint is in one group, whether they
// advertise at once or one after another.  An address is old once it has been quiet
// for the quiet time and a newer address in its group appeared after it was last
// heard, as when a device moves to its next address.
//
// Groups aren't forgotten by time, only to stay within the limits: past max_groups
// the least recently heard group is forgotten, and a group past max_members drops its
// longest quiet address and is marked truncated.  Forgotten addresses keep the state
// they had.
//
// An address whose payload changes while it keeps the address says nothing lasting with
// any one payload, and would flap from group to group, so it's left out of groups until
// it keeps one payload for the steady time.
class btle_related_tracker {
public:
    struct params {
        // A member must be quiet this long to be old
        time_t quiet;
        size_t max_groups;
        size_t max_members;
        // How long an address whose payload changed must keep its new one to be grouped
        // again; 0 groups it at once
        time_t steady;
    };

    // At most this many addresses are followed for payload changes; past that, new ones
    // are grouped as if steady
    static constexpr size_t max_addrs = 16384;

    // What an address's group fields should be now; group 0 is none
    struct state {
        device_key key;
        uint64_t group;
        uint32_t size;
        bool old;
        // The group's most recently appeared address
        device_key newest;
        // Older addresses were dropped from the group to stay within max_members
        bool truncated;
        // Addresses heard within the quiet time: about how many devices are there now
        uint32_t active;
    };

    btle_related_tracker(const params& p);

    // An address advertised this fingerprint, 0 when its payload is too short to say
    // anything, which keeps it in its group.  Appends the address itself, and every
    // other address whose state changed.
    void observe(uint64_t fingerprint, const device_key& key, time_t now, std::vector<state>& out);

    // Settles which addresses are old as time passes; appends changes
    void age(time_t now, std::vector<state>& out);

    // Every address in key's group, itself included; empty when it's in none
    std::vector<device_key> members_of(const device_key& key);

protected:
    struct member {
        device_key key;
        time_t first;
        time_t last;
        // Last state handed out for this member
        uint32_t rep_size;
        bool rep_old;
        device_key rep_newest;
        bool rep_truncated;
        uint32_t rep_active;
    };

    struct group {
        uint64_t id;
        std::vector<member> members;
        bool truncated;
        // Place in lru_
        std::list<uint64_t>::iterator lru;
    };

    // An address's payload, while it's followed for changes
    struct addr {
        uint64_t fingerprint;
        // When it started sending this payload
        time_t since;
        time_t last;
        bool unsteady;
    };

    // Whether key's payload has held long enough to group it
    bool steady(uint64_t fingerprint, const device_key& key, time_t now);
    // Joins (or stays in) fp's group
    void join(uint64_t fp, const device_key& key, time_t now, std::vector<state>& out);
    // Leaves fp's group, reporting the members left behind
    void leave(uint64_t fp, const device_key& key, time_t now, std::vector<state>& out);
    // Reports the members whose state changed, and always, when it's set
    void settle(group& c, time_t now, std::vector<state>& out, const device_key *always);
    // Forgets a group; its members keep their last state
    void forget(std::unordered_map<uint64_t, group>::iterator ci);

    params p_;

    kis_mutex mutex;
    std::unordered_map<uint64_t, group> groups_;
    std::unordered_map<device_key, uint64_t> where_;
    // Group fingerprints, least recently heard first
    std::list<uint64_t> lru_;
    uint64_t next_id = 1;
    std::unordered_map<device_key, addr> addrs_;
    time_t last_prune = 0;
};

#endif
