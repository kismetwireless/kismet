/* Tests for the karma / mana access point detection state (phy_80211_karma.h).
 *
 *   make test/dot11_karma/karma_test && test/dot11_karma/karma_test
 */

#include "config.h"

#include <cstdio>

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
    auto& e = st.seen(hash, ts, flag::none, p.max_ssids);
    if (probe_matches(e.first, e.last, probe_ts, p.probe_window))
        e.flags = e.flags | flag::matched;
}

static bool fires(const state& st, unsigned int hidden = 0) {
    return should_fire(st.count(p.window), hidden, p);
}

// A hidden AP answers directed probes for its real name, which its beacons leave out
static void test_hidden_ap() {
    state st;
    for (int i = 0; i < 20; i++)
        respond(st, 1, T0 + i, T0 + i);
    CHECK(st.entries.size() == 1);
    CHECK(st.count(p.window).matched == 1);
    CHECK(!fires(st, 1));
}

// Responses heard before the first beacon, from three APs; the late beacon clears each
static void test_late_beacon() {
    state st;
    respond(st, 1, T0, T0);
    CHECK(st.entries.size() == 1);
    CHECK(st.beaconed(1));
    CHECK(st.entries.empty());
    CHECK(!st.beaconed(1));
    CHECK(!fires(st));
}

// A renamed AP answers for its old and its new name
static void test_rename() {
    state st;
    respond(st, 1, T0, T0);
    respond(st, 2, T0 + 300, T0 + 300);
    CHECK(st.count(p.window).matched == 2);
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
    CHECK(st.count(p.window).matched == 0);
    CHECK(!fires(st));
    respond(st, 10, T0 + 10, 0);
    CHECK(st.count(p.window).unbeaconed == 10);
    CHECK(fires(st));
}

// Answers older than the window before the newest don't count
static void test_window_ages_out() {
    state st;
    respond(st, 1, T0, T0);
    respond(st, 2, T0 + 1, T0 + 1);
    respond(st, 3, T0 + p.window + 10, T0 + p.window + 10);
    CHECK(st.count(p.window).unbeaconed == 1);
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
    CHECK(st.count(p.window).matched == 1);
}

// Unicast beacons count, and keep counting until a broadcast beacon for the SSID
static void test_directed_beacons() {
    state st;
    for (uint32_t h = 1; h <= 3; h++)
        st.seen(h, T0 + h, flag::directed_beacon, p.max_ssids);
    auto c = st.count(p.window);
    CHECK(c.directed == 3);
    CHECK(c.unbeaconed == 3);
    // Unicast beacons again for the same SSIDs change nothing
    st.seen(2, T0 + 20, flag::directed_beacon, p.max_ssids);
    CHECK(st.entries.size() == 3);
    CHECK(st.beaconed(2));
    CHECK(st.count(p.window).directed == 2);
}

// Order doesn't matter: first and last are the earliest and latest times
static void test_order() {
    state st;
    st.seen(1, T0 + 50, flag::none, p.max_ssids);
    st.seen(1, T0 + 10, flag::none, p.max_ssids);
    st.seen(1, T0 + 30, flag::none, p.max_ssids);
    auto e = st.find(1);
    CHECK(e != nullptr && e->first == T0 + 10 && e->last == T0 + 50);
    CHECK(st.newest == T0 + 50);
}

// Full lists drop excluded entries first, then the oldest answer
static void test_cap() {
    state st;
    params small = p;
    small.max_ssids = 4;
    for (uint32_t h = 1; h <= 4; h++)
        st.seen(h, T0 + h, flag::none, small.max_ssids);
    st.find(3)->flags = flag::excluded;
    st.seen(5, T0 + 5, flag::none, small.max_ssids);
    CHECK(st.entries.size() == 4);
    CHECK(st.find(3) == nullptr);
    CHECK(st.find(1) != nullptr);
    st.seen(6, T0 + 6, flag::none, small.max_ssids);
    CHECK(st.entries.size() == 4);
    CHECK(st.find(1) == nullptr);
    CHECK(st.find(6) != nullptr);
    for (uint32_t h = 7; h < 1000; h++)
        st.seen(h, T0 + h, flag::none, small.max_ssids);
    CHECK(st.entries.size() == 4);
    CHECK(st.find(999) != nullptr);
}

// NUL padded hidden beacons of 33 lengths don't buy 33 allowances
static void test_hidden_evasion() {
    state st;
    for (uint32_t h = 1; h <= 8; h++)
        respond(st, h, T0 + h, T0 + h);
    CHECK(st.count(p.window).matched == 8);
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
    CHECK(st.count(p.window).matched == 2);
    CHECK(!fires(st));
    CHECK(!st.any_unmatched());
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
    test_excluded();
    test_hidden_evasion();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("dot11_karma: all tests passed\n");
    return 0;
}
