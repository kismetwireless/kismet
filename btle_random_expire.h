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

#ifndef __BTLE_RANDOM_EXPIRE_H__
#define __BTLE_RANDOM_EXPIRE_H__

#include "config.h"

#include <cstdint>
#include <ctime>

// btle_random_expire: whether a BTLE device on a rotating random address can be
// forgotten.  Pure, so the rules can be tested without a device tracker.
namespace btle_random_expire {

// What the device record says, read under its lock
struct facts {
    bool rotating;              // resolvable / non-resolvable private, or Find My
    uint64_t packets;
    time_t idle;                // seconds since it was last heard
    bool linked;                // alias_group: payload, signal, Handoff or co-rotation link
    uint32_t related_count;     // addresses sharing its exact payload, itself included
    bool tracker;
    bool remoteid;
    uint32_t alerts;
    bool named;                 // a user-set name
    bool saved_tag;             // a tag that's written to the database
};

struct params {
    time_t idle;                // 0 disables expiry
    uint64_t max_packets;
};

enum class verdict : uint8_t {
    expire,
    keep_disabled, keep_static, keep_packets, keep_recent, keep_linked, keep_related,
    keep_tracker, keep_remoteid, keep_alerts, keep_named, keep_tagged,
};

// The linker can still join a quiet address to a new one for its 120 s keep, pruned
// up to 15 s late (randomized_alias.cc); expiring sooner would cut the chain
inline constexpr time_t min_idle_linking = 150;

constexpr time_t effective_idle(time_t configured, bool linking) {
    if (configured <= 0)
        return 0;
    return (linking && configured < min_idle_linking) ? min_idle_linking : configured;
}

constexpr verdict judge(const facts& f, const params& p) {
    if (p.idle <= 0)
        return verdict::keep_disabled;
    if (!f.rotating)
        return verdict::keep_static;
    if (f.packets > p.max_packets)
        return verdict::keep_packets;
    if (f.idle < p.idle)
        return verdict::keep_recent;
    if (f.linked)
        return verdict::keep_linked;
    if (f.related_count >= 2)
        return verdict::keep_related;
    if (f.tracker)
        return verdict::keep_tracker;
    if (f.remoteid)
        return verdict::keep_remoteid;
    if (f.alerts != 0)
        return verdict::keep_alerts;
    if (f.named)
        return verdict::keep_named;
    if (f.saved_tag)
        return verdict::keep_tagged;
    return verdict::expire;
}

}

#endif
