/* Tests for the karma / mana access point detection state (phy_80211_karma.h).
 *
 *   make test/dot11_karma/karma_test && test/dot11_karma/karma_test
 */

#include "config.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <string>

#include "phy_80211_karma.h"

using namespace dot11_karma;

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static constexpr params p{};
static constexpr time_t T0 = 1'790'000'000;

static_assert(ignored_ssid("", 0, false));
static_assert(ignored_ssid("", 8, true));
static_assert(ignored_ssid("DIRECT-xy-Printer", 17, false));
static_assert(!ignored_ssid("DIRECT", 6, false));
static_assert(!ignored_ssid("homenet", 7, false));

static_assert(probe_matches(100, 100, 100, 60));
static_assert(probe_matches(100, 100, 40, 60));
static_assert(probe_matches(100, 100, 160, 60));
static_assert(!probe_matches(100, 100, 39, 60));
static_assert(!probe_matches(100, 100, 161, 60));
static_assert(!probe_matches(100, 100, 0, 60));
// Answered from 100 to 500: a probe at 520 is near the last answer
static_assert(probe_matches(100, 500, 520, 60));

static_assert(less_allowance(1, 1) == 0);
static_assert(less_allowance(0, 1) == 0);
static_assert(less_allowance(4, 1) == 3);

static_assert(!should_fire(counts{2, 2, 0}, 0, p));
static_assert(should_fire(counts{3, 3, 0}, 0, p));
static_assert(!should_fire(counts{3, 3, 0}, 1, p));
static_assert(should_fire(counts{4, 3, 0}, 0, p));
static_assert(!should_fire(counts{9, 0, 0}, 0, p));
static_assert(should_fire(counts{10, 0, 0}, 0, p));
static_assert(!should_fire(counts{10, 0, 0}, 1, p));
// The hidden allowance is capped at one, however many cloaked SSIDs a BSSID beacons
static_assert(max_hidden_allowance == 1);
static_assert(should_fire(counts{4, 4, 0}, 2, p));
static_assert(should_fire(counts{11, 0, 0}, 33, p));
static_assert(should_fire(counts{8, 8, 0}, ~0U, p));

// A probe response for each hash at ts, matched when a client probed at probe_ts
static void respond(state& st, uint32_t hash, time_t ts, time_t probe_ts) {
    auto e = st.seen(hash, ts, flag::none, p);
    if (e != nullptr && probe_matches(e->first, e->last, probe_ts, p.probe_window))
        e->flags = e->flags | flag::matched;
}

static bool fires(const state& st, unsigned int hidden = 0) {
    return should_fire(st.count(p), hidden, p);
}

// A broadcast beacon, as the phy records it
static beacon_result bcn(state& st, uint32_t hash, time_t ts, bool add = true, const params& pp = p) {
    return st.broadcast_beacon(hash, ts, pp, add);
}

// A hidden AP answers directed probes for its real name, which its beacons leave out
static void test_hidden_ap() {
    state st;
    for (int i = 0; i < 20; i++)
        respond(st, 1, T0 + i, T0 + i);
    CHECK(st.entries.size() == 1);
    CHECK(st.count(p).matched == 1);
    CHECK(!fires(st, 1));
}

// Responses heard before the first beacon, from three APs; the late beacon clears each
static void test_late_beacon() {
    state st;
    respond(st, 1, T0, T0);
    CHECK(st.entries.size() == 1);
    // Not a pool beaconer: the answer is dropped, as for any AP
    auto r = bcn(st, 1, T0 + 1);
    CHECK(r.changed && r.pool.ssids== 1);
    CHECK(st.entries.empty());
    CHECK(st.count(p).unbeaconed == 0);
    CHECK(!bcn(st, 1, T0 + 2).changed);
    CHECK(!bcn(st, 2, T0 + 2).changed);
    CHECK(!st.any_unmatched());
    CHECK(!fires(st));
}

// A renamed AP answers for its old and its new name
static void test_rename() {
    state st;
    respond(st, 1, T0, T0);
    respond(st, 2, T0 + 300, T0 + 300);
    CHECK(st.count(p).matched == 2);
    CHECK(!fires(st));
}

static void test_karma_fires() {
    state st;
    respond(st, 1, T0, T0 - 1);
    respond(st, 2, T0 + 5, T0 + 4);
    CHECK(!fires(st));
    respond(st, 3, T0 + 9, T0 + 8);
    CHECK(fires(st));
    // One beaconed hidden SSID is allowed for
    CHECK(!fires(st, 1));
    respond(st, 4, T0 + 12, T0 + 12);
    CHECK(fires(st, 1));
}

// Probes outside the probe window don't match; ten unmatched SSIDs still fire
static void test_window_and_pool() {
    state st;
    for (uint32_t h = 1; h <= 9; h++)
        respond(st, h, T0 + h, T0 - 1000);
    CHECK(st.count(p).matched == 0);
    CHECK(!fires(st));
    respond(st, 10, T0 + 10, 0);
    CHECK(st.count(p).unbeaconed == 10);
    CHECK(fires(st));
}

// Answers older than the window before the newest don't count
static void test_window_ages_out() {
    state st;
    respond(st, 1, T0, T0);
    respond(st, 2, T0 + 1, T0 + 1);
    respond(st, 3, T0 + p.window + 10, T0 + p.window + 10);
    CHECK(st.count(p).unbeaconed == 1);
    CHECK(!fires(st));
}

// A probe seen after the response (another source, out of order) matches on the re-check
static void test_late_probe() {
    state st;
    respond(st, 1, T0, 0);
    CHECK(st.any_unmatched());
    auto e = st.find(1);
    CHECK(e != nullptr);
    if (e != nullptr && probe_matches(e->first, e->last, T0 + 2, p.probe_window))
        e->flags = e->flags | flag::matched;
    CHECK(!st.any_unmatched());
    CHECK(st.count(p).matched == 1);
}

// Unicast beacons count, and keep counting until a broadcast beacon for the SSID
static void test_directed_beacons() {
    state st;
    for (uint32_t h = 1; h <= 3; h++)
        st.seen(h, T0 + h, flag::directed_beacon, p);
    auto c = st.count(p);
    CHECK(c.directed == 3);
    CHECK(c.unbeaconed == 3);
    // Unicast beacons again for the same SSIDs change nothing
    st.seen(2, T0 + 20, flag::directed_beacon, p);
    CHECK(st.entries.size() == 3);
    CHECK(bcn(st, 2, T0 + 21).changed);
    CHECK(st.count(p).directed == 2);
}

// Order doesn't matter: first and last are the earliest and latest times
static void test_order() {
    state st;
    st.seen(1, T0 + 50, flag::none, p);
    st.seen(1, T0 + 10, flag::none, p);
    st.seen(1, T0 + 30, flag::none, p);
    auto e = st.find(1);
    CHECK(e != nullptr && e->first == T0 + 10 && e->last == T0 + 50);
    CHECK(st.newest == T0 + 50);
}

// Full lists drop excluded entries first, then beaconed ones, then the oldest answer
static void test_cap() {
    state st;
    params small = p;
    small.max_ssids = 4;
    for (uint32_t h = 1; h <= 4; h++)
        st.seen(h, T0 + h, flag::none, small);
    st.find(3)->flags = flag::excluded;
    st.seen(5, T0 + 5, flag::none, small);
    CHECK(st.entries.size() == 4);
    CHECK(st.find(3) == nullptr);
    CHECK(st.find(1) != nullptr);
    st.seen(6, T0 + 6, flag::none, small);
    CHECK(st.entries.size() == 4);
    CHECK(st.find(1) == nullptr);
    CHECK(st.find(6) != nullptr);
    for (uint32_t h = 7; h < 1000; h++)
        st.seen(h, T0 + h, flag::none, small);
    CHECK(st.entries.size() == 4);
    CHECK(st.find(999) != nullptr);
}

// A full list keeps real unbeaconed answers over newer answers the BSSID also beacons
static void test_cap_beaconed_first() {
    state st;
    params small = p;
    small.max_ssids = 4;
    st.seen(1, T0 + 1, flag::none, small);
    st.seen(2, T0 + 2, flag::none, small);
    st.seen(3, T0 + 3, flag::beaconed, small);
    st.seen(4, T0 + 4, flag::beaconed, small);
    st.seen(5, T0 + 5, flag::none, small);
    CHECK(st.find(1) != nullptr && st.find(2) != nullptr);
    CHECK(st.find(3) == nullptr && st.find(4) != nullptr);
    st.seen(6, T0 + 6, flag::none, small);
    CHECK(st.find(4) == nullptr);
    CHECK(st.find(1) != nullptr);
    st.seen(7, T0 + 7, flag::none, small);
    CHECK(st.find(1) == nullptr);
    CHECK(st.count(small, pool_size{}).unbeaconed == 4);
}

static_assert(sane_time(0) == 1);
static_assert(sane_time(std::numeric_limits<time_t>::min()) == 1);
static_assert(sane_time(std::numeric_limits<time_t>::max()) == max_frame_time);
static_assert(sane_time(T0) == T0);

// Frame times count as they come, newest the latest, within 1970 to 2100; clock skew between
// sources isn't compensated (a known limit)
static void test_times() {
    // A frame after a long gap, or a replayed one a day old, counts at its time
    state gap;
    gap.pool_seen(1, T0, p, true, false);
    CHECK(gap.pool_seen(2, T0 + 1000, p, true, false) == pool_result::same);
    CHECK(gap.newest == T0 + 1000);
    state past;
    for (uint32_t h = 1; h <= 3; h++)
        respond(past, h, T0 + h - 86400, 0);
    CHECK(past.count(p).unbeaconed == 3);

    // Hostile times don't overflow the window test, and count clamped
    CHECK(!in_window(std::numeric_limits<time_t>::max(), std::numeric_limits<time_t>::min(), 600));
    CHECK(in_window(std::numeric_limits<time_t>::min(), std::numeric_limits<time_t>::max(), 600));
    CHECK(within(T0, T0 + 600, 600) && within(T0 + 600, T0, 600) && !within(T0, T0 + 601, 600));
    state hostile;
    auto lo = hostile.seen(1, std::numeric_limits<time_t>::min(), flag::none, p);
    CHECK(lo != nullptr && lo->first == 1 && lo->last == 1);
    CHECK(hostile.seen(2, T0, flag::none, p) != nullptr);
    CHECK(hostile.count(p).unbeaconed == 1);
    auto hi = hostile.seen(3, std::numeric_limits<time_t>::max(), flag::none, p);
    CHECK(hi != nullptr && hi->last == max_frame_time);
    CHECK(hostile.newest == max_frame_time);
    CHECK(hostile.count(p).unbeaconed == 1);
    hostile.seed({seed_ssid{9, std::numeric_limits<time_t>::min(), std::numeric_limits<time_t>::max(), 0}},
            max_frame_time, p);
    CHECK(hostile.pool.size() == 1 && hostile.pool[0].first == 1 &&
            hostile.pool[0].last == max_frame_time);
}

// A beacon flood of one-offs is a pool by itself
static void test_pool_flood() {
    state st;
    bool grew = false;
    for (uint32_t i = 0; i < flood_min(p); i++)
        grew = st.broadcast_beacon(10'000 + i, T0 + i * flood_span_s / flood_min(p), p, true).grew || grew;
    CHECK(grew);
    auto c = st.count(p);
    CHECK(c.flood >= flood_min(p));
    CHECK(fire_reason(c, 0, p) == reason::pool);
    CHECK(alert_text(c, true).find("beacon flood") != std::string::npos);
    // It counts within the window, no longer
    st.broadcast_beacon(1, T0 + p.window + flood_span_s + 1, p, true);
    CHECK(st.count(p).flood == 0);
    // Under the rate, never
    state slow;
    for (uint32_t i = 0; i < 4 * flood_min(p); i++)
        slow.broadcast_beacon(10'000 + i, T0 + i / (flood_min(p) / flood_span_s / 2), p, true);
    CHECK(slow.count(p).flood == 0);

    // A pool a little bigger than the list, each SSID beaconed 10 times a second: the SSIDs
    // sampled out aren't new each time, so it's no flood
    for (uint32_t seed : {0U, 1U, 0xdeadbeefU, 0x12345678U, 77U}) {
        params pp = p;
        pp.sample_seed = seed;
        state rr;
        unsigned int most = 0;
        for (uint32_t i = 0; i < 700 * 60; i++) {
            bcn(rr, 1 + i % 70, T0 + i / 700, true, pp);
            most = std::max(most, rr.flood_new);
        }
        CHECK(rr.count(pp).flood == 0);
        CHECK(most <= 2 * 70);
        CHECK(should_fire(rr.count(pp), 0, pp));
    }
    // A flood sampled from the start still counts, each sampled SSID for 2^level
    state big;
    big.sample_level = 3;
    for (uint32_t i = 0; i < 8 * flood_min(p); i++)
        big.broadcast_beacon(10'000 + i, T0 + i * flood_span_s / (8 * flood_min(p)), p, true);
    CHECK(big.count(p).flood >= flood_min(p));
    CHECK(big.count(p).flood <= 2 * 8 * flood_min(p));
}

// SSIDs which counted before sampling stand for themselves: one-offs raising the level don't
// inflate a few real SSIDs into a pool
static void test_pool_weight() {
    params small = p;
    small.max_ssids = 16;
    for (uint32_t seed = 1; seed <= 64; seed++) {
        small.sample_seed = seed * 2654435761U;
        state st;
        for (uint32_t i = 0; i < 4000; i++) {
            if (i % 5 == 0)
                for (uint32_t h = 1; h <= 9; h++)
                    st.broadcast_beacon(h, T0 + i / 5, small, true);
            st.broadcast_beacon(5000 + i, T0 + i / 5, small, true);
        }
        CHECK(st.sample_level > 0);
        CHECK(st.count(small).pool == 9);
        // Sampling, but the count wasn't scaled up: not an estimate
        CHECK(!st.count(small).estimated);
    }
    // A sampled pool steps its level down one refresh at a time
    state st;
    st.sample_level = 5;
    st.pool_expire(p);
    CHECK(st.sample_level == 4);
    st.pool_expire(p);
    CHECK(st.sample_level == 3);
}

// NUL padded hidden beacons of 33 lengths don't buy 33 allowances
static void test_hidden_evasion() {
    state st;
    for (uint32_t h = 1; h <= 8; h++)
        respond(st, h, T0 + h, T0 + h);
    CHECK(st.count(p).matched == 8);
    CHECK(fires(st, 33));
    CHECK(fires(st, 1));
}

// Entries a related BSSID beacons don't count
static void test_excluded() {
    state st;
    for (uint32_t h = 1; h <= 3; h++)
        respond(st, h, T0 + h, T0 + h);
    CHECK(fires(st));
    st.find(2)->flags = st.find(2)->flags | flag::excluded;
    CHECK(st.count(p).matched == 2);
    CHECK(!fires(st));
    CHECK(!st.any_unmatched());
}

static_assert(!should_fire(counts{0, 0, 0, 9}, 0, p));
static_assert(should_fire(counts{0, 0, 0, 10}, 0, p));
// The hidden allowance doesn't apply to a pool
static_assert(should_fire(counts{0, 0, 0, 10}, 1, p));

// A BSSID broadcast-beaconing a rotating pool, one SSID per beacon, each SSID at ts and ts + 1
static unsigned int beacon_pool(state& st, uint32_t first, uint32_t n, time_t ts,
        const params& pp = p) {
    unsigned int grew = 0;
    for (time_t k = 0; k < 2; k++)
        for (uint32_t h = first; h < first + n; h++)
            if (bcn(st, h, ts + k, true, pp).grew)
                grew++;
    return grew;
}

static void test_pool_threshold() {
    state st;
    CHECK(beacon_pool(st, 100, 9, T0) == 9);
    // The same SSIDs again, with changed tags (an AP changing its configuration), add nothing
    CHECK(beacon_pool(st, 100, 9, T0 + 30) == 0);
    CHECK(st.count(p).pool == 9);
    CHECK(!fires(st));
    beacon_pool(st, 109, 1, T0 + 31);
    CHECK(st.count(p).pool == 10);
    CHECK(fires(st));
}

static void test_pool_window() {
    state st;
    beacon_pool(st, 100, 9, T0);
    beacon_pool(st, 200, 1, T0 + p.window + 1);
    CHECK(st.count(p).pool == 1);
    CHECK(!fires(st));
    // Beaconing the old ones again brings them back, counted afresh: twice more
    for (uint32_t h = 100; h < 109; h++)
        CHECK(!bcn(st, h, T0 + p.window + 2, false).grew);
    CHECK(st.count(p).pool == 1);
    for (uint32_t h = 100; h < 109; h++)
        CHECK(bcn(st, h, T0 + p.window + 3, false).grew);
    // Refreshing an SSID already in the window changes no count
    CHECK(!bcn(st, 100, T0 + p.window + 4, false).grew);
    CHECK(!bcn(st, 999, T0 + p.window + 4, false).grew);
    CHECK(st.count(p).pool == 10);
}

static void test_pool_cap() {
    state st;
    params small = p;
    small.max_ssids = 16;
    beacon_pool(st, 1, 1000, T0, small);
    CHECK(st.pool.size() <= 16);
    // A sample of a pool too big for the list, scaled up
    CHECK(st.sample_level > 0);
    CHECK(st.count(small).pool >= 256);
    CHECK(st.count(small).estimated);
    for (uint32_t i = 0; i < 1000; i++)
        st.pool_seen(5000 + i, T0 + i, small, true, false);
    CHECK(st.pool.size() <= 16);
    CHECK(st.newest == T0 + 999);
    // One-off SSIDs (corrupted ones) take the free slots, never the SSIDs which count
    state pool;
    beacon_pool(pool, 1, 10, T0, small);
    for (uint32_t i = 0; i < 1000; i++)
        bcn(pool, 5000 + i, T0 + 2 + i % 100, true, small);
    CHECK(pool.pool.size() <= 16);
    CHECK(pool.pool_count(p).ssids == 10);
}

// A round robin of n SSIDs, one per beacon at 10 beacons a second: seconds until the pool
// reaches min_pool, or -1 if it doesn't within the window
static time_t round_robin(state& st, uint32_t n, const params& pp) {
    for (uint32_t i = 0; i < 10 * pp.window; i++) {
        auto r = bcn(st, 1 + i % n, T0 + i / 10, true, pp);
        if (r.grew && r.pool.ssids>= pp.min_pool)
            return i / 10;
    }
    return -1;
}

// A pool bigger than the list, each SSID repeated only every n beacons, still counts
static void test_pool_round_robin() {
    for (uint32_t seed : {0U, 1U, 0xdeadbeefU, 0x12345678U, 0x9e3779b9U, 77U, 4242U, 0xffffffffU}) {
        params pp = p;
        pp.sample_seed = seed;
        for (uint32_t n : {100U, 1000U}) {
            state st;
            const time_t t = round_robin(st, n, pp);
            // Within a little more than the time the round robin takes to repeat
            CHECK(t >= 0 && t <= static_cast<time_t>(n / 10 + 30));
            CHECK(st.pool.size() <= pp.max_ssids);
            CHECK(should_fire(st.count(pp), 0, pp));
        }
    }
}

// A normal AP's two SSIDs among a flood of one-off (corrupted) SSIDs: the sample never scales
// up the few which repeat
static void test_pool_flood_quiet() {
    for (uint32_t seed : {0U, 1U, 0xdeadbeefU, 0x12345678U}) {
        params pp = p;
        pp.sample_seed = seed;
        state st;
        unsigned int most = 0;
        for (uint32_t i = 0; i < 6000; i++) {
            const time_t ts = T0 + i / 10;
            bcn(st, 1 + i % 2, ts, true, pp);
            bcn(st, 100'000 + i, ts, true, pp);
            most = std::max(most, st.pool_count(pp).ssids);
        }
        CHECK(most == 2);
        CHECK(st.pool.size() <= pp.max_ssids);
        CHECK(!fires(st));
    }
}

// The pool counts go down once the SSIDs leave the window, and the sample grows back
static void test_pool_expire() {
    state st;
    CHECK(round_robin(st, 1000, p) >= 0);
    CHECK(st.sample_level > 0);
    const time_t end = T0 + 600;
    unsigned int refreshes = 0;
    for (time_t t = end; t < end + 2 * p.window; t += 1) {
        bcn(st, 1, t, false);
        if (st.refresh_due()) {
            st.pool_expire(p);
            st.last_eval = t;
            refreshes++;
        }
        CHECK(!st.refresh_due());
    }
    CHECK(refreshes >= (2 * p.window) / (refresh_s + 1));
    CHECK(st.pool_count(p).ssids <= 1);
    CHECK(st.sample_level == 0);
}

// Answered pool SSIDs count only while their pool SSID does, and never above the pool
static void test_answered_pool_clamp() {
    state st;
    beacon_pool(st, 1, 12, T0);
    for (uint32_t h = 1; h <= 12; h++)
        CHECK(st.seen(h, T0 + 1, flag::beaconed, p) != nullptr);
    // Beaconed once only: in the pool, not counting there
    bcn(st, 50, T0 + 1);
    CHECK(st.seen(50, T0 + 1, flag::beaconed, p) != nullptr);
    CHECK(st.count(p).pool == 12);
    CHECK(st.count(p).answered_pool == 12);
    CHECK(st.count(p, pool_size{10}).answered_pool == 10);
}

// One-off SSIDs, as bit errors in a beacon's SSID give, never count in a pool
static void test_pool_corrupt() {
    state st;
    for (time_t t = 0; t < 30; t++)
        bcn(st, 1, T0 + t);
    for (uint32_t i = 0; i < 20; i++)
        CHECK(!bcn(st, 1000 + i, T0 + i).grew);
    CHECK(st.pool_count(p).ssids == 1);
    CHECK(!fires(st));
    // The same beacon heard twice in one second, or by two sources, is one sighting
    CHECK(!bcn(st, 2000, T0 + 5).grew);
    CHECK(!bcn(st, 2000, T0 + 5).grew);
    CHECK(st.pool_count(p).ssids == 1);
    CHECK(bcn(st, 2000, T0 + 6).grew);
}

// A new state's pool starts with the SSIDs beaconed before it
static void test_pool_seed() {
    state st;
    // Outside the window either way: from long ago, or from a source with a wrong clock
    st.seed({seed_ssid{1, T0, T0 + 3, 0}, seed_ssid{2, T0 + 5, T0 + 5, 0},
            seed_ssid{3, T0 - 5000, T0 - 4000, 0}, seed_ssid{4, T0 + 100'000, T0 + 100'000, 0}}, T0 + 10, p);
    CHECK(st.pool.size() == 2);
    CHECK(st.pool_count(p).ssids == 1);
    CHECK(st.newest == T0 + 5);
    params small = p;
    small.max_ssids = 4;
    std::vector<seed_ssid> seeds;
    for (uint32_t h = 0; h < 100; h++)
        seeds.push_back(seed_ssid{h, T0, T0 + 1, 0});
    state cap;
    cap.seed(seeds, T0 + 1, small);
    CHECK(cap.pool.size() == 4);
}

// Answering each probe and broadcast-beaconing that SSID once, after the answer or before it,
// as the phy sees it: the beaconed SSIDs make a pool
static void evade(bool beacon_first, uint32_t n, bool expect) {
    state st;
    // Its own SSID, beaconed before the state existed
    st.seed({seed_ssid{1, T0, T0 + 3, 0}}, T0 + 3, p);
    for (uint32_t i = 0; i < n; i++) {
        const uint32_t h = 100 + i;
        const time_t ts = T0 + 4 + i;
        if (beacon_first) {
            bcn(st, h, ts);
            // The answer for an SSID it beacons: kept once it beacons a pool
            st.pool_answered(h, p.window);
            CHECK(st.pool_count(p).ssids >= min_pool_beaconer);
            CHECK(st.seen(h, ts, flag::beaconed, p) != nullptr);
        } else {
            respond(st, h, ts, ts);
            auto r = bcn(st, h, ts);
            CHECK(r.grew && r.changed && r.pool.ssids== i + 2);
        }
    }
    CHECK(st.pool_count(p).ssids == n + 1);
    CHECK(st.entries.size() == n);
    CHECK(st.count(p).unbeaconed == 0);
    CHECK(st.count(p).answered_pool == (n + 1 >= p.min_pool ? n : 0));
    CHECK(fires(st) == expect);
}

static void test_evade_single_beacons() {
    evade(false, 40, true);
    evade(false, 8, false);
    evade(true, 40, true);
    evade(true, 8, false);
}

static_assert(fire_reason(counts{3, 3, 0, 0}, 0, p) == reason::answers);
static_assert(fire_reason(counts{0, 0, 0, 10}, 0, p) == reason::pool);
static_assert(fire_reason(counts{10, 0, 0, 10}, 0, p) == reason::both);
static_assert(fire_reason(counts{2, 2, 0, 9}, 0, p) == reason::none);

// The alert text leaves out the counts which are zero
static void test_alert_text() {
    CHECK(alert_text(counts{4, 3, 0, 0, 0}, false) ==
            "answered probes for 4 networks it does not advertise (3 probed for by clients), "
            "which may indicate a karma or mana access point impersonating networks clients look for");
    CHECK(alert_text(counts{12, 0, 2, 0, 0}, false).find("(2 sent in unicast beacons)") != std::string::npos);
    CHECK(alert_text(counts{0, 0, 0, 40, 0}, true) ==
            "beaconed 40 different networks, which may indicate a karma access point beaconing a pool "
            "of impersonated networks");
    CHECK(alert_text(counts{2, 1, 1, 12, 5}, true) ==
            "beaconed 12 different networks, answered probes for 5 of them and for 2 networks it does "
            "not beacon (1 probed for by clients, 1 sent in unicast beacons), which may indicate a karma "
            "access point beaconing a pool of impersonated networks");
    CHECK(alert_text(counts{3, 0, 0, 10, 0}, true).find(", answered probes for 3 networks it does not beacon,") !=
            std::string::npos);
    // A flood of one-offs leads with the flood, never a pool of 0
    CHECK(alert_text(counts{0, 0, 0, 0, 0, 250}, true) ==
            "flooded beacons for 250 new networks within 5 seconds (a beacon flood), which may indicate a "
            "karma access point beaconing a pool of impersonated networks");
    CHECK(alert_text(counts{0, 0, 0, 12, 0, 250, true}, true) ==
            "beaconed about 12 different networks (estimated), 250 new ones within 5 seconds (a beacon "
            "flood), which may indicate a karma access point beaconing a pool of impersonated networks");
    // Raised later, rate limited, after the counts decayed: worded for the reason, without zeros
    CHECK(alert_text(counts{}, true) ==
            "beaconed a pool of different networks, which may indicate a karma access point beaconing a "
            "pool of impersonated networks");
    CHECK(alert_text(counts{}, false) ==
            "answered probes for networks it does not advertise, which may indicate a karma or mana "
            "access point impersonating networks clients look for");
    CHECK(alert_text(counts{0, 0, 0, 3, 0}, false).find("0 ") == std::string::npos);

    // Worded for the stored reason or for what the counts show now, whichever has a pool
    constexpr auto answers = static_cast<uint8_t>(reason::answers);
    constexpr auto pooled = static_cast<uint8_t>(reason::pool);
    static_assert(!alert_pool(counts{12, 3, 0, 0, 0}, answers, p));
    static_assert(!alert_pool(counts{12, 3, 0, 9, 0}, answers, p));
    static_assert(alert_pool(counts{}, pooled, p));
    static_assert(alert_pool(counts{12, 3, 0, 10, 0}, answers, p));
    static_assert(alert_pool(counts{12, 3, 0, 0, 0, 250}, answers, p));
    // Flagged for answers, raised later with a pool: both, and no zero clause
    const auto both = alert_text(counts{12, 3, 0, 14, 0}, alert_pool(counts{12, 3, 0, 14, 0}, answers, p));
    CHECK(both.find("beaconed 14 different networks") != std::string::npos);
    CHECK(both.find("answered probes for 12 networks it does not beacon (3 probed for by clients)") != std::string::npos);
    // Flagged for a pool, raised later with answers only: the answers are kept
    const auto later = alert_text(counts{12, 3, 0, 0, 0}, alert_pool(counts{12, 3, 0, 0, 0}, pooled, p));
    CHECK(later == "beaconed a pool of different networks, answered probes for 12 networks it does not beacon "
            "(3 probed for by clients), which may indicate a karma access point beaconing a pool of "
            "impersonated networks");
    CHECK(both.find(" 0 ") == std::string::npos && later.find(" 0 ") == std::string::npos);
}

// A new state is seeded with the SSIDs beaconed before it: those which count first, and the
// answers for them only once it beacons a pool
static void test_seed() {
    state one;
    one.seed({seed_ssid{1, T0, T0, T0 + 1}}, T0 + 2, p);
    CHECK(one.pool_count(p).ssids == 1);
    CHECK(one.entries.empty());

    state two;
    two.seed({seed_ssid{1, T0, T0 + 3, 0}, seed_ssid{2, T0, T0, T0 + 1}, seed_ssid{3, T0 + 1, T0 + 1, 0}}, T0 + 4, p);
    CHECK(two.pool.size() == 3);
    CHECK(two.pool_count(p).ssids == 2);
    CHECK(two.entries.size() == 1);
    CHECK(two.find(2) != nullptr && has(two.find(2)->flags, flag::beaconed));
    CHECK(two.count(p).unbeaconed == 0);

    // One-offs listed first don't push the SSIDs which count out of a small pool
    params small = p;
    small.max_ssids = 4;
    std::vector<seed_ssid> seeds;
    for (uint32_t h = 100; h < 110; h++)
        seeds.push_back(seed_ssid{h, T0, T0, 0});
    for (uint32_t h = 1; h <= 4; h++)
        seeds.push_back(seed_ssid{h, T0, T0 + 2, 0});
    state cap;
    cap.seed(seeds, T0 + 3, small);
    CHECK(cap.pool.size() == 4);
    CHECK(cap.pool_count(small).ssids == 4);
}

// A counting SSID a full pool dropped comes back with a beacon which may add it (a cached
// beacon the BSSID broadcast-beacons), and not with one which only refreshes
static void test_cached_readd() {
    params small = p;
    small.max_ssids = 4;
    state st;
    for (uint32_t h = 1; h <= 5; h++) {
        bcn(st, h, T0 + h, true, small);
        bcn(st, h, T0 + h + 10, true, small);
    }
    CHECK(st.pool.size() == 4);
    auto in_pool = [&st](uint32_t h) {
        return std::any_of(st.pool.begin(), st.pool.end(), [h](const entry& e) { return e.hash == h; });
    };
    CHECK(!in_pool(1));
    bcn(st, 1, T0 + 20, false, small);
    CHECK(!in_pool(1));
    bcn(st, 1, T0 + 20, true, small);
    CHECK(in_pool(1));
    CHECK(st.pool.size() == 4);
}

// A repeated answer for an SSID already counted only moves its times, between refreshes
static void test_repeat_answer() {
    state st;
    for (uint32_t h = 1; h <= 3; h++)
        respond(st, h, T0, T0);
    st.last_eval = st.newest;
    CHECK(st.repeat_answer(1, T0 + 2, p) == T0 + 2);
    CHECK(st.find(1)->last == T0 + 2);
    CHECK(st.find(1)->first == T0);
    // Not listed, not matched to a probe yet, or beaconed: the full path
    CHECK(st.repeat_answer(9, T0 + 2, p) == 0);
    respond(st, 5, T0 + 2, 0);
    CHECK(st.repeat_answer(5, T0 + 2, p) == 0);
    CHECK(st.find(5)->last == T0 + 2);
    CHECK(st.seen(4, T0 + 2, flag::beaconed, p) != nullptr);
    CHECK(st.repeat_answer(4, T0 + 2, p) == 0);
    // A refresh is due
    CHECK(st.repeat_answer(2, T0 + refresh_s + 1, p) == 0);
    st.last_eval = st.newest;
    CHECK(st.repeat_answer(2, T0 + refresh_s + 1, p) == T0 + refresh_s + 1);
    // Out of the window
    st.last_eval = T0 + p.window + 100;
    CHECK(st.repeat_answer(3, T0 + p.window + 100, p) == 0);
}

// A renamed AP, twice: three names
static void test_pool_rename() {
    state st;
    beacon_pool(st, 1, 1, T0);
    beacon_pool(st, 2, 1, T0 + 100);
    beacon_pool(st, 3, 1, T0 + 200);
    CHECK(st.count(p).pool == 3);
    CHECK(!fires(st));
}

// Answers for SSIDs it also beacons are answered pool SSIDs, never unbeaconed ones, and are
// kept only once it beacons more than one SSID
static void test_answered_pool() {
    state st;
    for (uint32_t h = 1; h <= 5; h++)
        respond(st, h, T0 + h, T0 + h);
    CHECK(st.count(p).matched == 5);
    CHECK(fires(st));
    // The first beaconed SSID is any AP's own: its answer is dropped
    beacon_pool(st, 1, 1, T0 + 10);
    CHECK(st.find(1) == nullptr);
    // From the second on it beacons a pool, and the answers are kept apart
    beacon_pool(st, 2, 4, T0 + 10);
    auto c = st.count(p);
    CHECK(c.pool == 5);
    CHECK(c.unbeaconed == 0);
    CHECK(c.matched == 0);
    // Kept, but counted only once the pool reaches min_pool
    CHECK(c.answered_pool == 0);
    CHECK(st.entries.size() == 4);
    CHECK(!fires(st));
    CHECK(!st.any_unmatched());
    // Answered after being beaconed, and an unbeaconed answer alongside
    auto e = st.seen(6, T0 + 11, flag::beaconed, p);
    CHECK(e != nullptr && has(e->flags, flag::beaconed));
    respond(st, 50, T0 + 11, 0);
    CHECK(st.any_unmatched());
    // Reaching min_pool: the unmatched unbeaconed answer is what the phy matches probes for
    CHECK(beacon_pool(st, 6, 5, T0 + 12) == 5);
    c = st.count(p);
    CHECK(c.pool == 10);
    CHECK(c.answered_pool == 5);
    CHECK(c.unbeaconed == 1);
    CHECK(fires(st));
    // Answered pool SSIDs don't count once it beacons one SSID only
    CHECK(st.count(p, pool_size{1}).answered_pool == 0);
    CHECK(st.count(p, pool_size{1}).unbeaconed == 1);
}

static_assert(!should_fire(counts{0, 0, 0, 9, 64}, 0, p));

// A normal AP whose answer came before its first beacon: the beacon drops the answer
static void test_normal_ap_late_beacon() {
    state st;
    respond(st, 1, T0, 0);
    CHECK(beacon_pool(st, 1, 1, T0 + 1) == 1);
    CHECK(st.entries.empty());
    CHECK(st.pool_count(p).ssids == 1);
    // Its later beacons change nothing
    auto r = bcn(st, 1, T0 + 3, false);
    CHECK(!r.grew && !r.changed);
    CHECK(st.count(p).unbeaconed == 0);
}

// Up to two pool SSIDs a related BSSID beacons are left out, no more
static void test_pool_related() {
    state st;
    beacon_pool(st, 1, 10, T0);
    for (uint32_t i = 0; i < 2; i++)
        st.pool[i].flags = flag::excluded;
    CHECK(st.count(p).pool == 8);
    CHECK(!fires(st));
    for (auto& e : st.pool)
        e.flags = flag::excluded;
    CHECK(st.count(p).pool == 8);
    CHECK(max_related_pool_allowance == 2);
}

int main() {
    test_hidden_ap();
    test_late_beacon();
    test_rename();
    test_karma_fires();
    test_window_and_pool();
    test_window_ages_out();
    test_late_probe();
    test_directed_beacons();
    test_order();
    test_cap();
    test_cap_beaconed_first();
    test_times();
    test_pool_flood();
    test_pool_weight();
    test_excluded();
    test_hidden_evasion();
    test_pool_threshold();
    test_pool_window();
    test_pool_cap();
    test_pool_round_robin();
    test_pool_flood_quiet();
    test_pool_expire();
    test_answered_pool_clamp();
    test_pool_rename();
    test_answered_pool();
    test_normal_ap_late_beacon();
    test_pool_related();
    test_pool_corrupt();
    test_pool_seed();
    test_evade_single_beacons();
    test_alert_text();
    test_seed();
    test_cached_readd();
    test_repeat_answer();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("dot11_karma: all tests passed\n");
    return 0;
}
