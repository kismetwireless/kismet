/* Tests for the wired flow table's running totals and wired_flow_rates, which turns them into
 * per-second samples for the phy's aggregate RRDs.
 *
 *   make test/ethernet/flow_rates_test && test/ethernet/flow_rates_test
 */

#include "config.h"

#include <algorithm>
#include <cstdio>
#include <random>
#include <vector>

#include "wired_flow_tracker.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

using rates = wired_flow_rates;
using totals = wired_flow_tracker::totals;

constexpr time_t base_time = 1700000000 + 1234;

static totals make_totals(uint64_t bytes, uint64_t packets, uint64_t created, uint64_t refused, size_t flows) {
    totals t;
    t.bytes = bytes;
    t.packets = packets;
    t.created = created;
    t.refused = refused;
    t.flows = flows;
    return t;
}

static uint64_t feed_sum(const rates::feed& f, rates::series s) {
    uint64_t sum = 0;
    for (size_t i = 0; i < f.n_samples; i++)
        sum += f.samples[i].v[static_cast<size_t>(s)];
    return sum;
}

static uint64_t v(const rates::sample& s, rates::series k) {
    return s.v[static_cast<size_t>(k)];
}

// The first read counts everything since the table was made, in its own second
static void test_first() {
    rates r;
    const auto f = r.next(base_time, make_totals(1000, 10, 3, 1, 2));
    CHECK(!f.restart);
    CHECK(f.n_samples == 1);
    CHECK(f.samples[0].t == base_time);
    CHECK(v(f.samples[0], rates::series::bytes) == 1000);
    CHECK(v(f.samples[0], rates::series::packets) == 10);
    CHECK(v(f.samples[0], rates::series::created) == 3);
    CHECK(v(f.samples[0], rates::series::refused) == 1);
    CHECK(f.gauge_time == base_time);
    CHECK(f.flows == 2);
}

// One read a second: each second gets its own difference
static void test_steady() {
    rates r;
    r.next(base_time, make_totals(0, 0, 0, 0, 0));

    for (time_t i = 1; i <= 120; i++) {
        const auto u = static_cast<uint64_t>(i);
        const auto f = r.next(base_time + i, make_totals(u * u * 100, u * u, u, 2 * u, static_cast<size_t>(u)));
        CHECK(!f.restart);
        CHECK(f.n_samples == 1);
        CHECK(f.samples[0].t == base_time + i);
        CHECK(v(f.samples[0], rates::series::bytes) == (2 * u - 1) * 100);
        CHECK(v(f.samples[0], rates::series::packets) == 2 * u - 1);
        CHECK(v(f.samples[0], rates::series::created) == 1);
        CHECK(v(f.samples[0], rates::series::refused) == 2);
        CHECK(f.gauge_time == base_time + i);
        CHECK(f.flows == u);
    }
}

// A second read in the same second adds to that second and sets the gauge for it again, at
// the same time, so a gauge RRD replaces the value instead of adding to it
static void test_same_second() {
    rates r;
    r.next(base_time, make_totals(100, 1, 1, 0, 1));
    auto f = r.next(base_time + 1, make_totals(300, 3, 2, 0, 2));
    CHECK(f.n_samples == 1 && f.samples[0].t == base_time + 1 && v(f.samples[0], rates::series::bytes) == 200);

    f = r.next(base_time + 1, make_totals(350, 4, 2, 0, 2));
    CHECK(!f.restart);
    CHECK(f.n_samples == 1);
    CHECK(f.samples[0].t == base_time + 1);
    CHECK(v(f.samples[0], rates::series::bytes) == 50);
    CHECK(v(f.samples[0], rates::series::packets) == 1);
    CHECK(f.gauge_time == base_time + 1);
    CHECK(f.flows == 2);

    // Nothing new: a zero sample, still the same second
    f = r.next(base_time + 1, make_totals(350, 4, 2, 0, 2));
    CHECK(f.n_samples == 1 && f.samples[0].t == base_time + 1 && v(f.samples[0], rates::series::bytes) == 0);

    f = r.next(base_time + 2, make_totals(400, 5, 2, 0, 1));
    CHECK(f.n_samples == 1 && f.samples[0].t == base_time + 2 && v(f.samples[0], rates::series::bytes) == 50);
    CHECK(f.flows == 1);
}

// A late read spreads its counts over the seconds it skipped, oldest first, the remainder in
// the newest; the sum is exact
static void test_spread() {
    for (time_t gap = 2; gap <= rates::max_spread_s; gap++) {
        rates r;
        r.next(base_time, make_totals(0, 0, 0, 0, 0));
        const auto f = r.next(base_time + gap, make_totals(1003, 7, 1, 13, 5));
        const auto n = static_cast<uint64_t>(gap);

        CHECK(!f.restart);
        CHECK(f.n_samples == static_cast<size_t>(gap));
        for (size_t i = 0; i < f.n_samples; i++) {
            CHECK(f.samples[i].t == base_time + 1 + static_cast<time_t>(i));
            const bool newest = i + 1 == f.n_samples;
            CHECK(v(f.samples[i], rates::series::bytes) == 1003 / n + (newest ? 1003 % n : 0));
            CHECK(v(f.samples[i], rates::series::packets) == 7 / n + (newest ? 7 % n : 0));
        }
        CHECK(feed_sum(f, rates::series::bytes) == 1003);
        CHECK(feed_sum(f, rates::series::packets) == 7);
        CHECK(feed_sum(f, rates::series::created) == 1);
        CHECK(feed_sum(f, rates::series::refused) == 13);
        CHECK(f.gauge_time == base_time + gap);
        CHECK(f.flows == 5);

        // And the next second follows on
        const auto g = r.next(base_time + gap + 1, make_totals(1010, 8, 1, 13, 5));
        CHECK(g.n_samples == 1 && g.samples[0].t == base_time + gap + 1);
        CHECK(v(g.samples[0], rates::series::bytes) == 7);
    }
}

// A stall or a clock step forward: all of it in the newest second
static void test_long_gap() {
    for (time_t gap : { rates::max_spread_s + 1, time_t{60}, time_t{3600}, time_t{86400 * 400} }) {
        rates r;
        r.next(base_time, make_totals(0, 0, 0, 0, 0));
        const auto f = r.next(base_time + gap, make_totals(500, 5, 1, 0, 1));
        CHECK(!f.restart);
        CHECK(f.n_samples == 1);
        CHECK(f.samples[0].t == base_time + gap);
        CHECK(v(f.samples[0], rates::series::bytes) == 500);
        CHECK(f.gauge_time == base_time + gap);
    }
}

// The clock stepping back up to max_backstep_s counts in the last second fed until the clock
// passes it again; further back starts over
static void test_backstep() {
    for (time_t back : { time_t{1}, time_t{3}, time_t{30}, rates::max_backstep_s }) {
        rates r;
        r.next(base_time, make_totals(0, 0, 0, 0, 0));
        r.next(base_time + 100, make_totals(10, 1, 0, 0, 1));

        uint64_t bytes = 10;
        for (time_t t = base_time + 100 - back; t <= base_time + 100; t++) {
            bytes += 5;
            const auto f = r.next(t, make_totals(bytes, 1, 0, 0, 1));
            CHECK(!f.restart);
            CHECK(f.n_samples == 1);
            CHECK(f.samples[0].t == base_time + 100);
            CHECK(v(f.samples[0], rates::series::bytes) == 5);
            CHECK(f.gauge_time == base_time + 100);
        }

        const auto f = r.next(base_time + 101, make_totals(bytes + 5, 1, 0, 0, 1));
        CHECK(!f.restart && f.n_samples == 1 && f.samples[0].t == base_time + 101);
    }

    for (time_t back : { rates::max_backstep_s + 1, time_t{3600}, time_t{86400 * 400} }) {
        rates r;
        r.next(base_time, make_totals(0, 0, 0, 0, 0));
        r.next(base_time + 100, make_totals(10, 1, 0, 0, 1));

        auto f = r.next(base_time + 100 - back, make_totals(25, 2, 1, 0, 2));
        CHECK(f.restart);
        CHECK(f.n_samples == 1);
        CHECK(f.samples[0].t == base_time + 100 - back);
        CHECK(v(f.samples[0], rates::series::bytes) == 15);
        CHECK(f.gauge_time == base_time + 100 - back);
        CHECK(f.flows == 2);

        // Carries on from the new time, without starting over again
        f = r.next(base_time + 101 - back, make_totals(30, 3, 1, 0, 2));
        CHECK(!f.restart && f.n_samples == 1 && f.samples[0].t == base_time + 101 - back);
        CHECK(v(f.samples[0], rates::series::bytes) == 5);
    }
}

// Counters wrapping past 2^64 still give the right difference; anything over max_count is capped
static void test_wrap_and_cap() {
    rates r;
    const uint64_t near = UINT64_MAX - 10;
    r.next(base_time, make_totals(near, near, near, near, 0));
    auto f = r.next(base_time + 1, make_totals(5, 5, 5, 5, 0));
    for (size_t k = 0; k < rates::n_series; k++)
        CHECK(f.samples[0].v[k] == 16);

    f = r.next(base_time + 2, make_totals(5 + (UINT64_C(1) << 60), 5, 5, 5, 0));
    CHECK(v(f.samples[0], rates::series::bytes) == rates::max_count);
    CHECK(v(f.samples[0], rates::series::packets) == 0);

    // A spread of capped counts stays within the cap
    f = r.next(base_time + 5, make_totals(UINT64_MAX, 5, 5, 5, 0));
    CHECK(f.n_samples == 3);
    CHECK(feed_sum(f, rates::series::bytes) == rates::max_count);
}

// Random reads, late, repeated and stepped back up to the limit: every count is fed exactly
// once, sample times never go backwards and never pass the read time, and spreads stay small
static void test_conservation() {
    std::mt19937_64 rng(0x5eed);

    for (int run = 0; run < 200; run++) {
        rates r;
        totals t;
        time_t now = base_time + static_cast<time_t>(rng() % 86400);
        time_t newest = 0;
        uint64_t fed[rates::n_series] = {};

        for (int i = 0; i < 2000; i++) {
            switch (rng() % 10) {
                case 0: break;                                              // same second
                case 1: now += 2 + static_cast<time_t>(rng() % 6); break;   // late
                case 2:                                                     // stepped back
                    now = std::max(now - static_cast<time_t>(rng() % 61), newest - rates::max_backstep_s);
                    break;
                case 3: now += static_cast<time_t>(rng() % 100000); break;  // stall
                default: now += 1; break;
            }
            const time_t before = newest;

            t.bytes += rng() % 1000000;
            t.packets += rng() % 1000;
            t.created += rng() % 10;
            t.refused += rng() % 10;
            t.flows = static_cast<size_t>(rng() % 5000);

            const auto f = r.next(now, t);
            CHECK(!f.restart);
            CHECK(f.n_samples >= 1 && f.n_samples <= static_cast<size_t>(rates::max_spread_s));
            CHECK(f.flows == t.flows);
            for (size_t s = 0; s < f.n_samples; s++) {
                CHECK(f.samples[s].t >= newest);
                newest = f.samples[s].t;
                for (size_t k = 0; k < rates::n_series; k++)
                    fed[k] += f.samples[s].v[k];
            }
            CHECK(f.gauge_time == newest);
            // The read's own second, or the last one fed when the clock is behind it
            CHECK(newest == (i == 0 || now > before ? now : before));
        }

        CHECK(fed[0] == t.bytes);
        CHECK(fed[1] == t.packets);
        CHECK(fed[2] == t.created);
        CHECK(fed[3] == t.refused);
    }
}

static wired_flow_tracker::observation obs(uint8_t host, uint16_t sport, uint64_t bytes, time_t seen) {
    wired_flow_tracker::observation o;
    o.src.family = o.dst.family = 4;
    o.src.a[0] = 10; o.src.a[3] = host;
    o.dst.a[0] = 198; o.dst.a[1] = 51; o.dst.a[2] = 100; o.dst.a[3] = 1;
    o.proto = 17;
    o.sport = sport;
    o.dport = 53;
    o.bytes = bytes;
    o.ts = o.seen = seen;
    return o;
}

// The table's totals count what add() counts: bytes and packets of packets in a flow, flows
// created, and new flows deferred or dropped
static void test_tracker_totals() {
    for (auto policy : { wired_flow_tracker::full_policy::evict, wired_flow_tracker::full_policy::drop }) {
        wired_flow_tracker::params p;
        p.max_flows = 20;
        p.admit_pct = 50;
        p.on_full = policy;
        wired_flow_tracker t(p, 0x5eed);

        uint64_t bytes = 0, packets = 0;
        time_t now = base_time;

        for (int i = 0; i < 400; i++) {
            if (i % 50 == 49)
                now += 20;
            const auto res = t.add(obs(static_cast<uint8_t>(i % 37), static_cast<uint16_t>(1000 + i % 3),
                        static_cast<uint64_t>(60 + i), now));
            if (res == wired_flow_tracker::result::created || res == wired_flow_tracker::result::updated) {
                bytes += static_cast<uint64_t>(60 + i);
                packets++;
            }

            const auto tot = t.get_totals();
            const auto st = t.get_stats();
            CHECK(tot.bytes == bytes);
            CHECK(tot.packets == packets);
            CHECK(tot.created == st.created);
            CHECK(tot.refused == st.deferred + st.dropped_full);
            CHECK(tot.flows == st.flows);
        }

        const auto st = t.get_stats();
        CHECK(st.deferred > 0);
        CHECK(policy == wired_flow_tracker::full_policy::evict || st.dropped_full > 0);

        // Expiry lowers the flow count, never a total
        const auto before = t.get_totals();
        t.expire(now + 100000);
        const auto after = t.get_totals();
        CHECK(after.flows == 0);
        CHECK(after.bytes == before.bytes && after.packets == before.packets);
        CHECK(after.created == before.created && after.refused == before.refused);
    }

    // Ignored packets and a table with no room for flows count nothing
    wired_flow_tracker::params p;
    p.max_flows = 0;
    wired_flow_tracker off(p, 0x5eed);
    off.add(obs(1, 1000, 100, base_time));
    const auto tot = off.get_totals();
    CHECK(tot.bytes == 0 && tot.packets == 0 && tot.created == 0 && tot.refused == 0 && tot.flows == 0);
}

int main() {
    test_first();
    test_steady();
    test_same_second();
    test_spread();
    test_long_gap();
    test_backstep();
    test_wrap_and_cap();
    test_conservation();
    test_tracker_totals();

    if (failures != 0) {
        fprintf(stderr, "flow_rates_test: %d failures\n", failures);
        return 1;
    }

    printf("flow_rates_test: ok\n");
    return 0;
}
