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
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Karma / mana access point detection: a BSSID answering probes for networks it never
// broadcast-beacons, or broadcast-beaconing a pool of many networks (PineAP).  The state of
// one BSSID is the SSIDs it answered for (or sent only unicast beacons for), and the SSIDs it
// beacons once it beacons more than one; times are packet times, so replays and several
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
    // Different SSIDs broadcast-beaconed by the BSSID within the window, for a beaconed pool
    unsigned int min_pool = 10;
    // SSIDs kept per BSSID, in each list, at least the largest threshold
    size_t max_ssids = 64;
    // Picks which SSIDs of a pool too big for the list are sampled; random at startup, so the
    // SSIDs a pool beacons can't be chosen to stay out of the sample
    uint32_t sample_seed = 0;
};

enum class flag : uint8_t {
    none = 0,
    // A client probed for it within the probe window
    matched = 1 << 0,
    // Seen in a unicast beacon
    directed_beacon = 1 << 1,
    // A related BSSID (multiple BSSID set, BSS timestamp) beacons it
    excluded = 1 << 2,
    // The BSSID broadcast-beacons it too; counted apart, while the BSSID beacons a pool
    beaconed = 1 << 3,
    // Pool: the BSSID answered probes for it too, a second sighting besides its beacon
    answered = 1 << 4,
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
    // Pool: broadcast beacons in different seconds, up to min_pool_beacons
    uint8_t beacons = 0;
    // Pool: the sample level when it started to count; it stands for 2^level SSIDs
    uint8_t level = 0;
    time_t first = 0;
    time_t last = 0;
};

// A pool SSID counts once beaconed in two different seconds, or beaconed and answered: a
// corrupted SSID is a one-off, while a pool repeats each SSID
inline constexpr uint8_t min_pool_beacons = 2;

// A pool bigger than the list keeps a sample of its SSIDs, 1 in 2^level, so each one stays
// long enough to be beaconed again (a round robin of 1000 SSIDs repeats each one only every
// 1000 beacons).  The count is then an estimate, each SSID weighted by the level it started to
// count at, once at least min_pool_sampled SSIDs counted while sampling; fewer could be a few
// repeated SSIDs among one-offs.
inline constexpr uint8_t max_sample_level = 12;
inline constexpr unsigned int min_pool_sampled = 8;

// The counts of a BSSID which beacons nothing new are recomputed this often, so SSIDs leaving
// the window leave the counts
inline constexpr time_t refresh_s = 5;

// Spreads attacker-chosen SSID hashes (murmur3 finalizer)
constexpr uint32_t mix_hash(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;
    return h;
}

constexpr bool in_sample(uint32_t hash, uint32_t seed, uint8_t level) {
    return (mix_hash(hash ^ seed) & ((1U << level) - 1)) == 0;
}

// Why a BSSID is suspect (dot11.karma.reason)
enum class reason : uint8_t {
    none = 0,
    answers = 1,
    pool = 2,
    both = 3,
};

enum class pool_result : uint8_t {
    same,
    // The SSID counts in the pool now, and didn't before
    grew,
};

struct counts {
    unsigned int unbeaconed = 0;
    unsigned int matched = 0;
    unsigned int directed = 0;
    // Different SSIDs broadcast-beaconed
    unsigned int pool = 0;
    // Answered SSIDs the BSSID also beacons, while it beacons a pool
    unsigned int answered_pool = 0;
    // New broadcast SSIDs within flood_span_s, when it was a beacon flood within the window
    unsigned int flood = 0;
    // pool is an estimate from a sample
    bool estimated = false;
};

// A BSSID beaconing this many SSIDs beacons a pool, and its answers for them are kept; one
// beaconed SSID is any AP, whose answers for it are dropped
inline constexpr unsigned int min_pool_beaconer = 2;

// A BSSID without a state beacons a pool once this many other SSIDs were beaconed twice: an AP
// renamed twice has two
inline constexpr unsigned int pool_evident_twice = 3;

// A beacon flood: at least 4 x min_pool new broadcast SSIDs a second, over flood_span_s
inline constexpr time_t flood_span_s = 5;

constexpr unsigned int flood_min(const params& p) {
    return 4 * p.min_pool * static_cast<unsigned int>(flood_span_s);
}

// Sampled new SSIDs a flood needs within flood_span_s, besides the weighted flood_min: at a
// high sample level, a few one-offs (corrupted SSIDs) would otherwise weigh as a flood
inline constexpr unsigned int min_flood_sampled = 16;

// Frame times count within 1970 to 2100 (2038 with a 32-bit time_t); a time outside it counts
// at the nearest end.  Clocks
// of different sources aren't compensated: one far ahead holds the window of the BSSIDs it
// hears until the others catch up.
inline constexpr time_t max_frame_time =
    static_cast<time_t>(std::min<int64_t>(4'102'444'800, std::numeric_limits<time_t>::max()));

constexpr time_t sane_time(time_t ts) {
    return std::clamp<time_t>(ts, 1, max_frame_time);
}

// last is within window of newest, without overflowing on hostile times
constexpr bool in_window(time_t newest, time_t last, time_t window) {
    return last >= newest ||
        static_cast<uint64_t>(newest) - static_cast<uint64_t>(last) <=
            static_cast<uint64_t>(window);
}

// a and b are at most window apart, either way
constexpr bool within(time_t a, time_t b, time_t window) {
    return in_window(a, b, window) && in_window(b, a, window);
}

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

// At most this many pool SSIDs are left out because a related BSSID beacons them too: two
// BSSIDs beaconing the same pool would otherwise cancel each other out
inline constexpr unsigned int max_related_pool_allowance = 2;

// Answers for SSIDs the BSSID beacons too never fire: an AP beacons and answers for each of
// its own networks.  A pool fires on its own.
constexpr reason fire_reason(const counts& c, unsigned int hidden_allowance, const params& p) {
    hidden_allowance = std::min(hidden_allowance, max_hidden_allowance);

    const bool answers = less_allowance(c.matched, hidden_allowance) >= p.min_matched ||
        less_allowance(c.unbeaconed, hidden_allowance) >= p.min_unbeaconed;
    const bool pool = c.pool >= p.min_pool || c.flood > 0;

    return static_cast<reason>((answers ? static_cast<uint8_t>(reason::answers) : 0) |
            (pool ? static_cast<uint8_t>(reason::pool) : 0));
}

constexpr bool should_fire(const counts& c, unsigned int hidden_allowance, const params& p) {
    return fire_reason(c, hidden_allowance, p) != reason::none;
}

// The alert text after the BSSID, leaving out the counts which are zero; pool for a BSSID
// beaconing a pool (c.pool >= min_pool) or a flood
inline std::string alert_text(const counts& c, bool pool) {
    std::string paren;

    auto add_paren = [&paren](unsigned int n, const char *what) {
        if (n == 0)
            return;
        paren += paren.empty() ? " (" : ", ";
        paren += std::to_string(n);
        paren += what;
    };

    add_paren(c.matched, " probed for by clients");
    add_paren(c.directed, " sent in unicast beacons");

    if (!paren.empty())
        paren += ")";

    if (!pool)
        return "answered probes for " + std::to_string(c.unbeaconed) + " networks it does not advertise" +
            paren + ", which may indicate a karma or mana access point impersonating networks clients look for";

    std::string t = "beaconed " + std::string(c.estimated ? "about " : "") + std::to_string(c.pool) +
        " different networks" + (c.estimated ? " (estimated)" : "");

    if (c.flood > 0)
        t += ", " + std::to_string(c.flood) + " new ones within " + std::to_string(flood_span_s) +
            " seconds (a beacon flood)";

    if (c.answered_pool > 0)
        t += ", answered probes for " + std::to_string(c.answered_pool) + " of them";

    if (c.unbeaconed > 0)
        t += (c.answered_pool > 0 ? " and for " : ", answered probes for ") + std::to_string(c.unbeaconed) +
            " networks it does not beacon" + paren;

    return t + ", which may indicate a karma access point beaconing a pool of impersonated networks";
}

// The SSIDs of a pool which count (state::pool_count)
struct pool_size {
    unsigned int ssids = 0;
    // ssids was scaled up from a sample
    bool estimated = false;
};

// What a broadcast beacon did to a state
struct beacon_result {
    // An SSID joined the pool count, or a flood began
    bool grew = false;
    // An answer for the SSID was marked beaconed or dropped
    bool changed = false;
    // pool_count() after the frame, when grew or changed
    pool_size pool;
};

// Per-BSSID state; the caller holds the device lock
class state {
public:
    // The time a frame at ts counts at (sane_time), which moves the newest time counted
    time_t frame_time(time_t ts) {
        ts = sane_time(ts);
        newest = std::max(newest, ts);
        return ts;
    }

    // Records an SSID answered (or unicast-beaconed) at ts (see frame_time).  Full lists drop
    // an excluded entry first, then one the BSSID beacons, then the one answered longest ago.
    entry *seen(uint32_t hash, time_t ts, flag f, const params& p) {
        return seen_at(hash, frame_time(ts), f, p);
    }

    // seen() at a time frame_time() returned
    entry *seen_at(uint32_t hash, time_t ts, flag f, const params& p) {
        for (auto& e : entries) {
            if (e.hash == hash) {
                e.first = std::min(e.first, ts);
                e.last = std::max(e.last, ts);
                e.flags = e.flags | f;
                return &e;
            }
        }

        if (p.max_ssids > 0 && entries.size() >= p.max_ssids) {
            auto victim = victim_of(entries, rank_answer);
            *victim = entry{hash, f, 0, 0, ts, ts};
            return &*victim;
        }

        entries.push_back(entry{hash, f, 0, 0, ts, ts});
        return &entries.back();
    }

    entry *find(uint32_t hash) {
        for (auto& e : entries)
            if (e.hash == hash)
                return &e;
        return nullptr;
    }

    // Unmatched entries which count as unbeaconed
    bool any_unmatched() const {
        for (const auto& e : entries)
            if (!has(e.flags, flag::matched) && !has(e.flags, flag::excluded) &&
                    !has(e.flags, flag::beaconed))
                return true;
        return false;
    }

    // A pool SSID which counts: beaconed in the window, twice or with an answer for it
    bool pool_live(const entry& e, time_t window) const {
        return in_window(newest, e.last, window) &&
            (e.beacons >= min_pool_beacons || has(e.flags, flag::answered));
    }

    // Records a broadcast beacon for an SSID at ts (see frame_time), adding it to the pool if
    // add (an SSID which may join a pool; otherwise only one already there is updated);
    // answered if the BSSID answered probes for it.  A full pool drops the SSIDs out of the
    // window, then samples (pool_make_room); full of SSIDs which count, it drops an excluded
    // one first, then the one beaconed longest ago.  A new sampled SSID counts towards a flood,
    // for the 2^sample_level SSIDs it stands for.
    pool_result pool_seen(uint32_t hash, time_t ts, const params& p, bool add, bool answered) {
        return pool_seen_at(hash, frame_time(ts), p, add, answered);
    }

    // pool_seen() at a time frame_time() returned
    pool_result pool_seen_at(uint32_t hash, time_t ts, const params& p, bool add, bool answered) {
        const flag af = answered ? flag::answered : flag::none;

        for (auto& e : pool) {
            if (e.hash != hash)
                continue;

            const bool was = pool_live(e, p.window);

            if (!in_window(newest, e.last, p.window)) {
                // Back after leaving the window: counted afresh
                e = entry{hash, has(e.flags, flag::excluded) ? flag::excluded : flag::none, 1, 0, ts, ts};
            } else {
                if (ts != e.first && e.beacons < min_pool_beacons)
                    e.beacons++;
                e.first = std::min(e.first, ts);
                e.last = std::max(e.last, ts);
            }

            e.flags = e.flags | af;
            return started(e, was, p.window) ? pool_result::grew : pool_result::same;
        }

        // An SSID left out of the sample isn't kept, so its repeats would look new
        if (!add || !in_sample(hash, p.sample_seed, sample_level))
            return pool_result::same;

        if (p.max_ssids > 0 && pool.size() >= p.max_ssids) {
            pool_make_room(p);

            if (!in_sample(hash, p.sample_seed, sample_level))
                return pool_result::same;
        }

        const auto res = flood_seen(ts, p, 1U << sample_level) ? pool_result::grew : pool_result::same;
        entry *e;

        if (p.max_ssids > 0 && pool.size() >= p.max_ssids) {
            e = &*victim_of(pool, rank_pool);
            *e = entry{hash, af, 1, 0, ts, ts};
        } else {
            e = &pool.emplace_back(entry{hash, af, 1, 0, ts, ts});
        }

        return started(*e, false, p.window) ? pool_result::grew : res;
    }

    // An answer for an SSID in the pool, the second sighting of one beaconed once
    pool_result pool_answered(uint32_t hash, time_t window) {
        for (auto& e : pool) {
            if (e.hash != hash)
                continue;

            const bool was = pool_live(e, window);
            e.flags = e.flags | flag::answered;
            return started(e, was, window) ? pool_result::grew : pool_result::same;
        }

        return pool_result::same;
    }

    // Seeds the pool of a new state with an SSID the BSSID beaconed before, from first to
    // last, if last is within the window of ts (from frame_time); beaconed in two different
    // seconds, or answered for too, it counts
    void pool_seed(uint32_t hash, time_t first, time_t last, time_t ts, const params& p,
            bool answered = false) {
        first = sane_time(first);
        last = sane_time(last);

        if ((p.max_ssids > 0 && pool.size() >= p.max_ssids) || !within(ts, last, p.window))
            return;

        for (const auto& e : pool)
            if (e.hash == hash)
                return;

        pool.push_back(entry{hash, answered ? flag::answered : flag::none,
                static_cast<uint8_t>(last > first ? min_pool_beacons : 1), sample_level, first, last});
        newest = std::max(newest, std::min(last, ts));
    }

    // A broadcast beacon for an SSID (see pool_seen): the BSSID beacons it, so an answer for it
    // is kept as an answered pool SSID while it beacons a pool and dropped otherwise
    beacon_result broadcast_beacon(uint32_t hash, time_t ts, const params& p, bool add) {
        return broadcast_beacon_at(hash, frame_time(ts), p, add);
    }

    // broadcast_beacon() at a time frame_time() returned
    beacon_result broadcast_beacon_at(uint32_t hash, time_t ts, const params& p, bool add) {
        beacon_result r;
        auto e = std::find_if(entries.begin(), entries.end(),
                [hash](const entry& x) { return x.hash == hash; });
        const bool answered = e != entries.end();

        r.grew = pool_seen_at(hash, ts, p, add, answered) == pool_result::grew;

        if (answered && !has(e->flags, flag::beaconed)) {
            r.pool = pool_count(p);
            r.changed = true;

            if (r.pool.ssids >= min_pool_beaconer)
                e->flags = e->flags | flag::beaconed;
            else
                entries.erase(e);
        } else if (r.grew) {
            r.pool = pool_count(p);
        }

        return r;
    }

    // Different SSIDs beaconed within the window of the newest one which count (pool_live); up
    // to max_related_pool_allowance a related BSSID beacons too are left out.  Sampling, each
    // stands for 2^level SSIDs, the level when it started to count.
    pool_size pool_count(const params& p) const {
        unsigned int n = 0;
        unsigned int related = 0;
        unsigned int weighted = 0;
        unsigned int estimate = 0;

        for (const auto& e : pool) {
            if (!pool_live(e, p.window))
                continue;

            if (has(e.flags, flag::excluded)) {
                related++;
            } else {
                n++;
                estimate += 1U << std::min(e.level, max_sample_level);
                if (e.level > 0)
                    weighted++;
            }
        }

        const unsigned int extra = less_allowance(related, max_related_pool_allowance);

        // SSIDs which counted before the level rose stand for themselves, so n is a lower bound
        if (weighted >= min_pool_sampled && estimate > n)
            return pool_size{estimate + extra, true};

        return pool_size{n + extra, false};
    }

    // Makes room in a full pool: drops the SSIDs out of the window, then while it's still full
    // and holds SSIDs which don't count, samples half as many SSIDs, dropping those which don't
    // count and aren't sampled.  SSIDs which count stay, so one-offs can't push out a pool.
    void pool_make_room(const params& p) {
        pool_drop_expired(p);

        auto uncounted = [this, &p](const entry& e) { return !pool_live(e, p.window); };

        while (pool.size() >= p.max_ssids && sample_level < max_sample_level &&
                std::any_of(pool.begin(), pool.end(), uncounted)) {
            sample_level++;
            std::erase_if(pool, [&](const entry& e) {
                    return uncounted(e) && !in_sample(e.hash, p.sample_seed, sample_level);
                });
        }
    }

    // On a refresh: drops the SSIDs out of the window, and samples twice as many once few are
    // left, one level a refresh
    void pool_expire(const params& p) {
        pool_drop_expired(p);

        if (sample_level > 0 && pool.size() < p.max_ssids / 4)
            sample_level--;
    }

    // The counts haven't been recomputed for refresh_s
    bool refresh_due() const {
        return !in_window(newest, last_eval, refresh_s);
    }

    // A beacon flood within the window
    bool flooding(const params& p) const {
        return flood_last != 0 && in_window(newest, flood_last, p.window);
    }

    // Entries answered within the window of the newest one, leaving out excluded ones;
    // pool_ssids is pool_count(), counted once by the caller.  Answers for beaconed SSIDs are
    // kept from the second beaconed SSID on, and count once the pool reaches min_pool.
    counts count(const params& p, pool_size pool_ssids) const {
        counts c;

        c.pool = pool_ssids.ssids;
        c.estimated = pool_ssids.estimated;
        c.flood = flooding(p) ? flood_peak : 0;

        const bool pooled = c.pool >= p.min_pool;

        // The pool SSIDs, sorted, and whether each counts: one lookup per answer
        std::vector<std::pair<uint32_t, bool>> beaconed;

        if (pooled && std::any_of(entries.begin(), entries.end(),
                    [](const entry& e) { return has(e.flags, flag::beaconed); })) {
            beaconed.reserve(pool.size());
            for (const auto& e : pool)
                beaconed.emplace_back(e.hash, pool_live(e, p.window));
            std::sort(beaconed.begin(), beaconed.end());
        }

        for (const auto& e : entries) {
            if (has(e.flags, flag::excluded) || !in_window(newest, e.last, p.window))
                continue;

            if (has(e.flags, flag::beaconed)) {
                if (pooled && pool_ssid_live(beaconed, e.hash))
                    c.answered_pool++;
                continue;
            }

            c.unbeaconed++;

            if (has(e.flags, flag::matched))
                c.matched++;
            if (has(e.flags, flag::directed_beacon))
                c.directed++;
        }

        c.answered_pool = std::min(c.answered_pool, c.pool);

        return c;
    }

    counts count(const params& p) const {
        return count(p, pool_count(p));
    }

    std::vector<entry> entries;
    // The newest frame time counted
    time_t newest = 0;
    // SSIDs the BSSID broadcast-beacons, once it beacons more than one; a sample of them, 1 in
    // 2^sample_level, once they don't fit
    std::vector<entry> pool;
    uint8_t sample_level = 0;
    // Alerts once per BSSID
    bool alerted = false;
    // Newest frame time the counts were recomputed at
    time_t last_eval = 0;
    // New broadcast SSIDs since flood_start, weighted, and the most of them in flood_span_s
    unsigned int flood_new = 0;
    // Sampled SSIDs since flood_start, up to min_flood_sampled
    unsigned int flood_sampled = 0;
    unsigned int flood_peak = 0;
    time_t flood_start = 0;
    // When new SSIDs last came at flood_min a span
    time_t flood_last = 0;

private:
    // Sets the level of a pool SSID which started to count, and returns whether it did
    bool started(entry& e, bool was, time_t window) const {
        if (was || !pool_live(e, window))
            return false;

        e.level = sample_level;
        return true;
    }

    // Counts a new broadcast SSID standing for weight SSIDs; true when a beacon flood begins
    bool flood_seen(time_t ts, const params& p, unsigned int weight) {
        if (flood_start == 0 || !within(flood_start, ts, flood_span_s - 1)) {
            flood_start = ts;
            flood_new = 0;
            flood_sampled = 0;
        }

        flood_new = weight > std::numeric_limits<unsigned int>::max() - flood_new ?
            std::numeric_limits<unsigned int>::max() : flood_new + weight;

        if (flood_sampled < min_flood_sampled)
            flood_sampled++;

        if (flood_new < flood_min(p) || flood_sampled < min_flood_sampled)
            return false;

        const bool began = !flooding(p);
        flood_last = ts;
        flood_peak = std::max(flood_peak, flood_new);
        return began;
    }

    void pool_drop_expired(const params& p) {
        std::erase_if(pool, [this, &p](const entry& e) {
                return !in_window(newest, e.last, p.window);
            });
    }

    // A beaconed SSID is in the pool and counts there; one a sampled pool left out may
    bool pool_ssid_live(const std::vector<std::pair<uint32_t, bool>>& sorted, uint32_t hash) const {
        auto i = std::lower_bound(sorted.begin(), sorted.end(), std::make_pair(hash, false));

        // Pool hashes are unique
        if (i != sorted.end() && i->first == hash)
            return i->second;

        return sample_level > 0;
    }

    // Answers a full list drops first: excluded, then beaconed
    static int rank_answer(const entry& e) {
        return has(e.flags, flag::excluded) ? 0 : has(e.flags, flag::beaconed) ? 1 : 2;
    }

    // Pool SSIDs a full pool drops first: excluded, then those which don't count yet, so
    // one-off corrupted SSIDs never push out the pool
    static int rank_pool(const entry& e) {
        return has(e.flags, flag::excluded) ? 0 :
            (e.beacons < min_pool_beacons && !has(e.flags, flag::answered)) ? 1 : 2;
    }

    // The entry of the lowest rank a full list drops, the oldest of them
    template<typename R>
    static std::vector<entry>::iterator victim_of(std::vector<entry>& list, R rank) {
        auto victim = list.begin();

        for (auto i = list.begin(); i != list.end(); ++i) {
            if (rank(*i) < rank(*victim) || (rank(*i) == rank(*victim) && i->last < victim->last))
                victim = i;
        }

        return victim;
    }
};

}

#endif
