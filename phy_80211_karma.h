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

#ifndef __PHY_80211_KARMA_H__
#define __PHY_80211_KARMA_H__

#include "config.h"

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <string_view>
#include <vector>

// Karma / mana access point detection: a BSSID answering probes for networks it never
// broadcast-beacons.  The state of one BSSID is the SSIDs it answered for (or sent only
// unicast beacons for) and doesn't beacon; times are packet times, so replays and several
// sources agree.  Nothing here depends on the tracker, so it can be tested on its own.
namespace dot11_karma {

struct params {
    // SSIDs a client probed for near the response, beyond the hidden SSID allowance
    unsigned int min_matched = 3;
    // Any SSIDs, beyond the allowance, for a preloaded pool nobody nearby asked for
    unsigned int min_unbeaconed = 10;
    // Only SSIDs answered within this long of the newest one count
    time_t window = 600;
    // A probe for the SSID within this long of the response matches it
    time_t probe_window = 60;
    // SSIDs kept per BSSID, at least the larger threshold
    size_t max_ssids = 64;
};

enum class flag : uint8_t {
    none = 0,
    // A client probed for it within the probe window
    matched = 1 << 0,
    // Seen in a unicast beacon
    directed_beacon = 1 << 1,
    // A related BSSID (multiple BSSID set, BSS timestamp) beacons it
    excluded = 1 << 2,
};

constexpr flag operator|(flag a, flag b) {
    return static_cast<flag>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}

constexpr bool has(flag set, flag f) {
    return (static_cast<uint8_t>(set) & static_cast<uint8_t>(f)) != 0;
}

struct entry {
    uint32_t hash = 0;
    flag flags = flag::none;
    time_t first = 0;
    time_t last = 0;
};

struct counts {
    unsigned int unbeaconed = 0;
    unsigned int matched = 0;
    unsigned int directed = 0;
};

// SSIDs that never count: empty or all NUL (hidden networks and the mesh ID, which has no
// SSID), and Wi-Fi Direct names, which P2P devices answer for in the listen state
constexpr bool ignored_ssid(std::string_view ssid, unsigned int ssid_len, bool blank) {
    if (ssid_len == 0 || blank || ssid.empty())
        return true;

    return ssid.substr(0, 7) == "DIRECT-";
}

// A probe at probe_ts falls within the window of the responses from first to last
constexpr bool probe_matches(time_t first, time_t last, time_t probe_ts, time_t probe_window) {
    if (probe_ts <= 0)
        return false;

    return probe_ts + probe_window >= first && probe_ts <= last + probe_window;
}

// Subtracts the hidden SSID allowance without wrapping
constexpr unsigned int less_allowance(unsigned int n, unsigned int allowance) {
    return n > allowance ? n - allowance : 0;
}

// At most one hidden SSID is allowed for: more cloaked SSIDs on one BSSID are rare, and NUL
// padded beacons of different lengths would otherwise each add one
inline constexpr unsigned int max_hidden_allowance = 1;

constexpr bool should_fire(const counts& c, unsigned int hidden_allowance, const params& p) {
    hidden_allowance = std::min(hidden_allowance, max_hidden_allowance);

    return less_allowance(c.matched, hidden_allowance) >= p.min_matched ||
        less_allowance(c.unbeaconed, hidden_allowance) >= p.min_unbeaconed;
}

// Per-BSSID state; the caller holds the device lock
class state {
public:
    // Records an SSID answered (or unicast-beaconed) at ts; full lists drop an excluded entry
    // first, then the one answered longest ago.  Returns the entry.
    entry& seen(uint32_t hash, time_t ts, flag f, size_t max_ssids) {
        newest = std::max(newest, ts);

        for (auto& e : entries) {
            if (e.hash == hash) {
                e.first = std::min(e.first, ts);
                e.last = std::max(e.last, ts);
                e.flags = e.flags | f;
                return e;
            }
        }

        if (max_ssids > 0 && entries.size() >= max_ssids) {
            auto victim = entries.begin();

            for (auto i = entries.begin(); i != entries.end(); ++i) {
                if (has(i->flags, flag::excluded) != has(victim->flags, flag::excluded)) {
                    if (has(i->flags, flag::excluded))
                        victim = i;
                } else if (i->last < victim->last) {
                    victim = i;
                }
            }

            *victim = entry{hash, f, ts, ts};
            return *victim;
        }

        entries.push_back(entry{hash, f, ts, ts});
        return entries.back();
    }

    entry *find(uint32_t hash) {
        for (auto& e : entries)
            if (e.hash == hash)
                return &e;
        return nullptr;
    }

    // The BSSID broadcast-beacons the SSID, so it no longer counts; true if it was listed
    bool beaconed(uint32_t hash) {
        for (auto i = entries.begin(); i != entries.end(); ++i) {
            if (i->hash == hash) {
                entries.erase(i);
                return true;
            }
        }

        return false;
    }

    bool any_unmatched() const {
        for (const auto& e : entries)
            if (!has(e.flags, flag::matched) && !has(e.flags, flag::excluded))
                return true;
        return false;
    }

    // Entries answered within the window of the newest one, leaving out excluded ones
    counts count(time_t window) const {
        counts c;

        for (const auto& e : entries) {
            if (has(e.flags, flag::excluded) || newest - e.last > window)
                continue;

            c.unbeaconed++;

            if (has(e.flags, flag::matched))
                c.matched++;
            if (has(e.flags, flag::directed_beacon))
                c.directed++;
        }

        return c;
    }

    std::vector<entry> entries;
    time_t newest = 0;
    // Alerts once per BSSID
    bool alerted = false;
};

}

#endif
