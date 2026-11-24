/* Tests for wired_flow_history, the history pool of wired_flow_tracker and flow keys.
 *
 *   make test/ethernet/flow_history_test && test/ethernet/flow_history_test
 *
 * The history is checked against a plain list of samples binned by hand, over random
 * sequences with gaps from a second to years and clock steps back.
 */

#include "config.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <limits>
#include <random>
#include <thread>
#include <vector>

#include "wired_flow_history.h"
#include "wired_flow_tracker.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

using series = flow_history::series;
constexpr series all_series[] = { series::bytes_ab, series::bytes_ba, series::packets_ab, series::packets_ba };

// A Tuesday in 2023, mid-hour, so the first steps cross minute and hour boundaries at odd places
constexpr time_t base_time = 1700000000 + 1234;

// The reference: every sample at the second it was counted in, binned when asked
struct ref_history {
    struct sample { time_t t; bool ab; uint64_t bytes; };

    time_t last;
    std::vector<sample> samples;

    explicit ref_history(time_t now) : last{now} { }

    void record(time_t now, bool ab, uint64_t bytes) {
        if (now > last) {
            last = now;
        } else if (last - now > flow_history::max_backstep_s) {
            samples.clear();
            last = now;
        }
        samples.push_back({last, ab, bytes});

        // Older than any vector shows
        if (samples.size() > 512)
            std::erase_if(samples, [this](const sample& s) { return s.t <= last - 2 * 86400; });
    }

    static uint64_t value(const sample& s, series which) {
        switch (which) {
            case series::bytes_ab: return s.ab ? s.bytes : 0;
            case series::bytes_ba: return s.ab ? 0 : s.bytes;
            case series::packets_ab: return s.ab ? 1 : 0;
            case series::packets_ba: return s.ab ? 0 : 1;
        }
        return 0;
    }

    // Sum of samples whose time / div is in (cur - n, cur], into slot (time / div) % n
    template <size_t N>
    void bin(series which, time_t now, time_t div, std::array<uint64_t, N>& out) const {
        out.fill(0);
        const time_t cur = now / div;
        for (const auto& s : samples) {
            const time_t b = s.t / div;
            if (b > cur - static_cast<time_t>(N) && b <= cur)
                out[static_cast<size_t>(b % static_cast<time_t>(N))] += value(s, which);
        }
    }

    flow_history::rrd_vectors vectors(series which, time_t now) const {
        flow_history::rrd_vectors v;
        v.last_time = now;
        std::array<uint64_t, 60> secs, mins;
        std::array<uint64_t, 24> hrs;
        bin(which, now, 1, secs);
        bin(which, now, 60, mins);
        bin(which, now, 3600, hrs);
        for (size_t i = 0; i < 60; i++) {
            v.minute[i] = static_cast<double>(secs[i]);
            v.hour[i] = static_cast<double>(mins[i]) / 60;
        }
        for (size_t i = 0; i < 24; i++)
            v.day[i] = static_cast<double>(hrs[i]) / 3600;
        return v;
    }

    uint64_t day_total(series which) const {
        std::array<uint64_t, 24> hrs;
        bin(which, last, 3600, hrs);
        uint64_t t = 0;
        for (auto h : hrs)
            t += h;
        return t;
    }
};

static bool same(const flow_history::rrd_vectors& a, const flow_history::rrd_vectors& b) {
    return a.last_time == b.last_time && a.minute == b.minute && a.hour == b.hour && a.day == b.day;
}

static bool matches(const flow_history& h, const ref_history& r) {
    if (h.last_time() != r.last)
        return false;
    for (auto s : all_series) {
        if (!same(h.vectors(s), r.vectors(s, r.last)) || h.day_total(s) != r.day_total(s))
            return false;
    }
    return true;
}

static void test_reference_model() {
    constexpr time_t gaps[] = { 0, 1, 2, 59, 60, 61, 119, 3599, 3600, 3601, 7199, 86399, 86400, 86401, 1000000000 };
    constexpr time_t backs[] = { 1, 2, 3, 30, 60, 61, 3600 };

    std::mt19937_64 rng(0x5eed);
    int mismatches = 0;

    for (int run = 0; run < 120 && mismatches == 0; run++) {
        time_t t = base_time + static_cast<time_t>(rng() % 86400);
        flow_history h(t);
        ref_history r(t);

        for (int step = 0; step < 400; step++) {
            const auto pick = rng() % 100;
            time_t when;
            if (pick < 50)
                when = r.last + static_cast<time_t>(rng() % 3);
            else if (pick < 85)
                when = r.last + gaps[rng() % std::size(gaps)];
            else
                when = r.last - backs[rng() % std::size(backs)];

            const bool ab = rng() & 1;
            const uint64_t bytes = 60 + rng() % 1455;

            h.record(when, ab, bytes);
            r.record(when, ab, bytes);

            if (!matches(h, r) && mismatches++ == 0)
                fprintf(stderr, "reference mismatch: run %d step %d at %lld\n", run, step,
                        static_cast<long long>(when));

            // A reader moves a copy forward without traffic
            if (step % 50 == 49) {
                flow_history c = h;
                const time_t ahead = r.last + gaps[rng() % std::size(gaps)];
                c.advance_to(ahead);
                for (auto s : all_series)
                    if (!same(c.vectors(s), r.vectors(s, std::max(ahead, r.last))) && mismatches++ == 0)
                        fprintf(stderr, "advance mismatch: run %d step %d\n", run, step);
            }
        }
    }

    CHECK(mismatches == 0);
}

static void test_known_values() {
    // 10 s into a minute, 34 minutes into an hour
    const time_t t0 = 3600 * 500000 + 34 * 60 + 10;
    flow_history h(t0);
    h.record(t0, true, 600);
    h.record(t0 + 1, true, 300);
    h.record(t0 + 1, false, 60);

    auto v = h.vectors(series::bytes_ab);
    CHECK(v.last_time == t0 + 1);
    CHECK(v.minute[10] == 600 && v.minute[11] == 300 && v.minute[12] == 0);
    // The current minute and hour are their totals so far over the full length
    CHECK(v.hour[34] == 15.0 && v.hour[33] == 0);
    CHECK(v.day[(t0 / 3600) % 24] == 0.25);
    CHECK(h.vectors(series::packets_ab).minute[11] == 1 && h.vectors(series::packets_ba).minute[11] == 1);
    CHECK(h.vectors(series::bytes_ba).hour[34] == 1.0);

    // A minute later the old minute is finished and the new one is empty
    h.advance_to(t0 + 60);
    v = h.vectors(series::bytes_ab);
    CHECK(v.hour[34] == 15.0 && v.hour[35] == 0);
    // t0 + 1 is still 59 s back; t0 has dropped out
    CHECK(v.minute[10] == 0 && v.minute[11] == 300);
    CHECK(v.day[(t0 / 3600) % 24] == 0.25);

    // advance_to never goes back
    h.advance_to(t0);
    CHECK(h.last_time() == t0 + 60);

    // An hour and more later only the day vector remembers it
    h.advance_to(t0 + 3600 + 60);
    v = h.vectors(series::bytes_ab);
    CHECK(v.hour[34] == 0 && v.hour[35] == 0);
    CHECK(v.day[(t0 / 3600) % 24] == 0.25);
    CHECK(h.day_total(series::bytes_ab) == 900);

    // A day later nothing is left
    h.advance_to(t0 + 86400 + 1);
    CHECK(h.day_total(series::bytes_ab) == 0 && h.day_total(series::packets_ba) == 0);
    v = h.vectors(series::bytes_ab);
    CHECK(std::all_of(v.day.begin(), v.day.end(), [](double d) { return d == 0; }));
    CHECK(h.start_time() == t0);
}

static void test_backsteps() {
    for (time_t back : { 3, 30, 60 }) {
        flow_history h(base_time);
        h.record(base_time, true, 100);
        h.record(base_time - back, true, 50);
        // Counted in the newest second, nothing lost
        CHECK(h.last_time() == base_time && h.start_time() == base_time);
        CHECK(h.vectors(series::bytes_ab).minute[base_time % 60] == 150);
        CHECK(h.day_total(series::packets_ab) == 2);
    }

    // Past 60 s the clock stepped back: start again there
    flow_history h(base_time);
    h.record(base_time, true, 100);
    h.record(base_time - 61, false, 50);
    CHECK(h.last_time() == base_time - 61 && h.start_time() == base_time - 61);
    CHECK(h.day_total(series::bytes_ab) == 0 && h.day_total(series::bytes_ba) == 50);

    // Before the epoch counts as 0, in range
    flow_history n(-5);
    n.record(-100, true, 1);
    n.record(std::numeric_limits<time_t>::min(), true, 1);
    CHECK(n.last_time() == 0 && n.day_total(series::packets_ab) == 2);
    n.record(std::numeric_limits<time_t>::max(), true, 1);
    CHECK(n.day_total(series::packets_ab) == 1);
}

static void test_saturation() {
    flow_history h(base_time);
    h.record(base_time, true, 3000000000ULL);
    h.record(base_time, true, 3000000000ULL);
    h.record(base_time, false, std::numeric_limits<uint64_t>::max());
    CHECK(h.vectors(series::bytes_ab).minute[base_time % 60] == 4294967295.0);
    CHECK(h.vectors(series::bytes_ba).minute[base_time % 60] == 4294967295.0);

    // Wider tiers keep full counts of saturated seconds
    for (time_t i = 1; i <= 120; i++)
        h.record(base_time + i, true, 3000000000ULL);
    CHECK(h.day_total(series::bytes_ab) == 4294967295ULL + 120 * 3000000000ULL);

    flow_history::min_slot m;
    m.set(2, 5000000000ULL);
    m.set(0, 5000000000ULL);
    CHECK(m.get(2) == 4294967295ULL && m.get(0) == 5000000000ULL);
    CHECK(sizeof(flow_history) <= 3264);
}

/* Tracker */

constexpr uint64_t test_seed = 0x5eed;

static wired_flow_tracker::observation obs(uint8_t a, uint16_t sport, time_t seen, uint64_t bytes = 100,
        bool reply = false, uint8_t flags = 0) {
    wired_flow_tracker::observation o;
    o.src.family = o.dst.family = 4;
    o.src.a[0] = 192; o.src.a[1] = 0; o.src.a[2] = 2; o.src.a[3] = a;
    o.dst.a[0] = 198; o.dst.a[1] = 51; o.dst.a[2] = 100; o.dst.a[3] = 1;
    o.proto = flags != 0 ? 6 : 17;
    o.sport = sport;
    o.dport = 53;
    o.tcp_flags = flags;
    o.bytes = bytes;
    o.ts = seen;
    o.seen = seen;
    if (reply) {
        std::swap(o.src, o.dst);
        std::swap(o.sport, o.dport);
    }
    return o;
}

static std::vector<wired_flow_tracker::flow> all_flows(const wired_flow_tracker& t) {
    std::vector<wired_flow_tracker::flow> out;
    size_t total = 0;
    t.snapshot({}, 0, 0, out, total);
    return out;
}

static const wired_flow_tracker::flow* find_port(const std::vector<wired_flow_tracker::flow>& v, uint16_t port) {
    for (const auto& f : v)
        if (f.k.port_a == port || f.k.port_b == port)
            return &f;
    return nullptr;
}

static size_t with_history(const std::vector<wired_flow_tracker::flow>& v) {
    return static_cast<size_t>(std::count_if(v.begin(), v.end(),
                [](const wired_flow_tracker::flow& f) { return f.history_time != 0; }));
}

struct flow_peek : public wired_flow_tracker {
    using wired_flow_tracker::wired_flow_tracker;

    // Shards are picked with the tracker's own seeded hasher
    size_t shard_of(const observation& o) const {
        key k;
        k.family = o.src.family;
        k.proto = o.proto;
        k.vlan = o.vlan;
        const bool src_is_a = o.src.a < o.dst.a || (o.src.a == o.dst.a && o.sport <= o.dport);
        k.addr_a = src_is_a ? o.src.a : o.dst.a;
        k.addr_b = src_is_a ? o.dst.a : o.src.a;
        k.port_a = src_is_a ? o.sport : o.dport;
        k.port_b = src_is_a ? o.dport : o.sport;
        return hasher(k) % n_shards;
    }

    std::atomic<size_t>& pool() { return n_histories; }
};

static void test_admission() {
    wired_flow_tracker::params p;
    p.history_min_packets = 8;
    wired_flow_tracker t(p, test_seed);

    uint64_t bytes_ab = 0, pre = 0;
    for (int i = 1; i <= 7; i++) {
        t.add(obs(1, 1000, base_time + i, 100 + i));
        bytes_ab += 100 + i;
    }
    pre = bytes_ab;
    auto v = all_flows(t);
    CHECK(v.size() == 1 && v[0].history_time == 0 && v[0].serial == 1 && t.get_stats().histories == 0);

    // The packet that reaches the threshold is the first in the history
    t.add(obs(1, 1000, base_time + 8, 500));
    bytes_ab += 500;
    v = all_flows(t);
    CHECK(v[0].history_time == base_time + 8 && t.get_stats().histories == 1);

    // Replies and later packets; history = counters - the first 7 packets
    uint64_t bytes_ba = 0;
    for (int i = 9; i < 400; i++) {
        const bool reply = i % 3 == 0;
        const uint64_t b = 60 + static_cast<uint64_t>(i);
        t.add(obs(1, 1000, base_time + i * 7, b, reply));
        (reply ? bytes_ba : bytes_ab) += b;
    }

    wired_flow_tracker::flow f;
    flow_history h(0);
    CHECK(t.lookup(v[0].k, v[0].serial, base_time + 400 * 7, f, &h));
    CHECK(f.bytes_ab == bytes_ab && f.bytes_ba == bytes_ba);
    CHECK(h.day_total(series::bytes_ab) == bytes_ab - pre && h.day_total(series::bytes_ba) == bytes_ba);
    CHECK(h.day_total(series::packets_ab) + h.day_total(series::packets_ba) == f.packets_ab + f.packets_ba - 7);
    CHECK(h.pool == nullptr && h.last_time() == base_time + 400 * 7);

    // Off: nobody gets one
    p.max_histories = 0;
    wired_flow_tracker off(p, test_seed);
    for (int i = 0; i < 20; i++)
        off.add(obs(1, 1000, base_time + i));
    CHECK(with_history(all_flows(off)) == 0 && off.get_stats().histories == 0);
    CHECK(off.lookup(all_flows(off)[0].k, 1, base_time, f, &h) && f.history_time == 0);

    // A minimum of 0 means 1; the cap is never above max_flows
    p.max_histories = 100;
    p.history_min_packets = 0;
    p.max_flows = 10;
    wired_flow_tracker one(p, test_seed);
    one.add(obs(1, 1000, base_time));
    CHECK(one.get_stats().histories == 1);
    CHECK(one.get_params().max_histories == 10 && one.get_params().history_min_packets == 1);
}

static void test_pool_cap_and_release() {
    wired_flow_tracker::params p;
    p.max_histories = 2;
    p.history_min_packets = 2;
    p.history_idle = 10;
    p.udp_idle = 300;
    wired_flow_tracker t(p, test_seed);

    for (uint16_t port : { 1, 2, 3 })
        for (int i = 0; i < 2; i++)
            t.add(obs(1, port, base_time));

    auto st = t.get_stats();
    CHECK(st.histories == 2 && st.histories_denied == 1);

    // Later packets retry but aren't counted again
    for (int i = 0; i < 5; i++)
        t.add(obs(1, 3, base_time + 1));
    st = t.get_stats();
    CHECK(st.histories == 2 && st.histories_denied == 1);
    CHECK(find_port(all_flows(t), 3)->history_time == 0);

    // Flow 2 stays busy; flow 1 is idle past history_idle and gives its history back
    t.add(obs(1, 2, base_time + 15));
    CHECK(t.expire(base_time + 15) == 0);
    st = t.get_stats();
    CHECK(st.histories == 1 && st.histories_released == 1 && st.flows == 3);
    auto v = all_flows(t);
    CHECK(find_port(v, 1)->history_time == 0 && find_port(v, 2)->history_time != 0);

    // Room again: flow 3's next packet takes it
    t.add(obs(1, 3, base_time + 16));
    v = all_flows(t);
    CHECK(find_port(v, 3)->history_time == base_time + 16 && t.get_stats().histories == 2);
    CHECK(with_history(v) == t.get_stats().histories);

    // Below 90% full nothing is taken back, however idle
    p.max_histories = 10;
    wired_flow_tracker u(p, test_seed);
    for (uint16_t port = 1; port <= 8; port++)
        for (int i = 0; i < 2; i++)
            u.add(obs(1, port, base_time));
    CHECK(u.get_stats().histories == 8);
    u.expire(base_time + 200);
    CHECK(u.get_stats().histories == 8 && u.get_stats().histories_released == 0);

    // At 9 of 10 idle ones are released until the pool is below 9
    for (int i = 0; i < 2; i++)
        u.add(obs(1, 9, base_time + 200));
    CHECK(u.get_stats().histories == 9);
    u.expire(base_time + 205);
    CHECK(u.get_stats().histories == 8 && u.get_stats().histories_released == 1);
    CHECK(find_port(all_flows(u), 9)->history_time != 0);

    // Expiry frees histories with their flows
    u.expire(base_time + 1000);
    CHECK(u.get_stats().histories == 0 && u.get_stats().flows == 0);
    CHECK(u.get_stats().histories_released == 1);
}

// A flow of shard s, distinct by port
static wired_flow_tracker::observation in_shard(const flow_peek& t, size_t s, uint16_t& port, time_t seen,
        uint8_t flags = 0) {
    for (;;) {
        auto o = obs(1, port++, seen, 100, false, flags);
        if (t.shard_of(o) == s)
            return o;
    }
}

static void test_evict_prefers_no_history() {
    using r = wired_flow_tracker::result;
    wired_flow_tracker::params p;
    p.max_flows = 4;
    p.admit_pct = 100;
    p.max_histories = 4;
    p.history_min_packets = 3;
    flow_peek t(p, test_seed);

    uint16_t port = 1;
    std::vector<wired_flow_tracker::observation> hist, plain;
    for (int i = 0; i < 2; i++) {
        hist.push_back(in_shard(t, 0, port, base_time));
        for (int k = 0; k < 3; k++)
            CHECK(t.add(hist.back()) != r::dropped);
    }
    // Newer, but without history
    for (int i = 0; i < 2; i++) {
        plain.push_back(in_shard(t, 0, port, base_time + 100));
        CHECK(t.add(plain.back()) == r::created);
    }
    CHECK(t.get_stats().flows == 4 && t.get_stats().histories == 2);

    auto nf = in_shard(t, 0, port, base_time + 1000);
    CHECK(t.add(nf) == r::deferred);
    CHECK(t.add(nf) == r::created);
    auto v = all_flows(t);
    CHECK(t.get_stats().evicted == 1 && t.get_stats().histories == 2);
    CHECK(find_port(v, hist[0].sport) != nullptr && find_port(v, hist[1].sport) != nullptr);
    CHECK((find_port(v, plain[0].sport) == nullptr) != (find_port(v, plain[1].sport) == nullptr));

    // Closed TCP still goes first, history or not; its history goes back to the pool
    flow_peek c(p, test_seed);
    port = 1;
    auto closed = in_shard(c, 0, port, base_time, 0x10);
    for (int k = 0; k < 3; k++)
        c.add(closed);
    closed.tcp_flags = 0x11;
    c.add(closed);
    for (int i = 0; i < 3; i++)
        c.add(in_shard(c, 0, port, base_time + 100));
    CHECK(c.get_stats().histories == 1 && c.get_stats().flows == 4);
    nf = in_shard(c, 0, port, base_time + 1000);
    c.add(nf);
    CHECK(c.add(nf) == r::created);
    CHECK(find_port(all_flows(c), closed.sport) == nullptr);
    CHECK(c.get_stats().histories == 0 && c.pool().load() == 0);
}

static void test_lookup() {
    wired_flow_tracker::params p;
    p.history_min_packets = 1;
    p.udp_idle = 10;
    wired_flow_tracker t(p, test_seed);

    t.add(obs(1, 1000, base_time, 100));
    t.add(obs(2, 1000, base_time, 100));
    auto v = all_flows(t);
    CHECK(v.size() == 2 && v[0].serial != v[1].serial && v[0].serial != 0 && v[1].serial != 0);
    const auto k = find_port(v, 1000)->k;
    const auto* f1 = v[0].k == k ? &v[0] : &v[1];
    const auto serial = f1->serial;

    wired_flow_tracker::flow f;
    flow_history h(0);
    CHECK(t.lookup(k, serial, base_time + 5, f, &h));
    CHECK(f.k == k && f.serial == serial && f.history_time == base_time && f.bytes_ab + f.bytes_ba == 100);
    CHECK(h.last_time() == base_time + 5 && h.vectors(series::bytes_ab).minute[(base_time + 5) % 60] == 0);
    CHECK(t.lookup(k, serial, base_time + 5, f, nullptr));
    CHECK(!t.lookup(k, serial + 100, base_time, f, &h));
    CHECK(!t.lookup(k, 0, base_time, f, &h));

    wired_flow_tracker::key missing = k;
    missing.port_b ^= 1;
    CHECK(!t.lookup(missing, serial, base_time, f, &h));

    // The same tuple later is another flow: the old serial no longer finds it
    t.expire(base_time + 100);
    t.add(obs(1, 1000, base_time + 100, 100));
    CHECK(!t.lookup(k, serial, base_time + 100, f, &h));
    v = all_flows(t);
    CHECK(v.size() == 1 && v[0].serial > serial && t.lookup(k, v[0].serial, base_time + 100, f, &h));
}

static void test_destruction() {
    // Histories outstanding when the tracker goes; ASan checks the frees
    for (int round = 0; round < 3; round++) {
        wired_flow_tracker::params p;
        p.history_min_packets = 1;
        wired_flow_tracker t(p, test_seed + static_cast<uint64_t>(round));
        for (uint16_t i = 0; i < 500; i++)
            t.add(obs(static_cast<uint8_t>(i), i, base_time));
        CHECK(t.get_stats().histories == 500);
    }
}

static void test_threads() {
    wired_flow_tracker::params p;
    p.max_flows = 256;
    p.max_histories = 64;
    p.history_min_packets = 2;
    p.history_idle = 1;
    p.udp_idle = 4;
    p.evict_idle = 1;
    wired_flow_tracker t(p, test_seed);

    std::atomic<time_t> now{base_time};
    std::atomic<bool> done{false};
    std::atomic<int> bad{0};

    std::vector<std::thread> threads;
    for (int w = 0; w < 4; w++) {
        threads.emplace_back([&, w]() {
            std::mt19937 rng(static_cast<unsigned int>(w));
            for (int i = 0; i < 40000; i++) {
                const time_t n = now.load();
                // Packet threads read the clock a little apart
                t.add(obs(static_cast<uint8_t>(rng() % 64), static_cast<uint16_t>(rng() % 8),
                            n - static_cast<time_t>(rng() % 3), 64 + rng() % 1400, rng() & 1));
            }
        });
    }

    threads.emplace_back([&]() {
        while (!done.load()) {
            now.fetch_add(1);
            t.expire(now.load());
            const auto st = t.get_stats();
            if (st.histories > p.max_histories || st.histories > st.flows + 4)
                bad.fetch_add(1);
            std::this_thread::yield();
        }
    });

    threads.emplace_back([&]() {
        wired_flow_tracker::flow f;
        flow_history h(0);
        while (!done.load()) {
            for (const auto& fl : all_flows(t)) {
                if (t.lookup(fl.k, fl.serial, now.load(), f, &h) && f.history_time != 0) {
                    if (h.day_total(series::packets_ab) > f.packets_ab ||
                            h.day_total(series::bytes_ba) > f.bytes_ba)
                        bad.fetch_add(1);
                }
            }
        }
    });

    for (int w = 0; w < 4; w++)
        threads[static_cast<size_t>(w)].join();
    done = true;
    for (size_t i = 4; i < threads.size(); i++)
        threads[i].join();

    const auto st = t.get_stats();
    CHECK(bad.load() == 0);
    CHECK(st.histories <= p.max_histories && st.histories == with_history(all_flows(t)));
    CHECK(st.created - st.evicted - st.expired == st.flows);
    t.expire(now.load() + 1000);
    CHECK(t.get_stats().histories == 0 && t.get_stats().flows == 0);
}

static bool parses(std::string_view s) {
    wired_flow_tracker::key k;
    uint64_t serial = 0;
    return wired_flow_tracker::parse_key(s, k, serial);
}

// Parsed keys print back as the same text
static bool round_trips(std::string_view s) {
    wired_flow_tracker::key k;
    uint64_t serial = 0;
    return wired_flow_tracker::parse_key(s, k, serial) && wired_flow_tracker::format_key(k, serial) == s;
}

static wired_flow_tracker::key v4_key() {
    wired_flow_tracker::key k;
    k.family = 4;
    k.proto = 17;
    k.port_a = 1000;
    k.port_b = 53;
    k.addr_a = {192, 0, 2, 5};
    k.addr_b = {198, 51, 100, 1};
    return k;
}

static void test_key_known_values() {
    const std::string v4 = wired_flow_tracker::format_key(v4_key(), 1);
    CHECK(v4 == "041103e800350000000000c0000205c6336401-0000000000000001");
    CHECK(v4.size() == wired_flow_tracker::key_text_len_v4);

    auto kv = v4_key();
    kv.vlan = wired_flow_tracker::vlan_key(2, 100, 200);
    CHECK(wired_flow_tracker::format_key(kv, 0x10) == "041103e8003502000640c8c0000205c6336401-0000000000000010");

    wired_flow_tracker::key k6;
    k6.family = 6;
    k6.proto = 6;
    k6.port_a = 443;
    k6.port_b = 50000;
    k6.addr_a = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    k6.addr_b = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const std::string v6 = wired_flow_tracker::format_key(k6, 0xfedcba9876543210ULL);
    CHECK(v6 == "060601bbc3500000000000" "20010db8000000000000000000000001" "20010db8000000000000000000000002"
            "-fedcba9876543210");
    CHECK(v6.size() == wired_flow_tracker::key_text_len_v6);

    wired_flow_tracker::key k;
    uint64_t serial = 0;
    CHECK(wired_flow_tracker::parse_key(v6, k, serial) && k == k6 && serial == 0xfedcba9876543210ULL);
    CHECK(wired_flow_tracker::parse_key(v4, k, serial) && k == v4_key() && serial == 1);
}

static void test_key_round_trip() {
    std::mt19937_64 rng(test_seed);
    size_t bad = 0;

    for (int i = 0; i < 20000; i++) {
        wired_flow_tracker::key k;
        k.family = (rng() & 1) ? 4 : 6;
        k.proto = static_cast<uint8_t>(rng());
        k.port_a = static_cast<uint16_t>(rng());
        k.port_b = static_cast<uint16_t>(rng());
        k.vlan = wired_flow_tracker::vlan_key(static_cast<uint8_t>(rng() % 5), static_cast<uint16_t>(rng()),
                static_cast<uint16_t>(rng()));
        const size_t len = k.family == 4 ? 4 : 16;
        for (size_t j = 0; j < len; j++) {
            // Few distinct bytes, so equal addresses and the port tie-break come up
            k.addr_a[j] = static_cast<uint8_t>(rng() % 3);
            k.addr_b[j] = static_cast<uint8_t>(rng() % 3);
        }
        if (k.addr_a > k.addr_b)
            std::swap(k.addr_a, k.addr_b);
        if (k.addr_a == k.addr_b && k.port_a > k.port_b)
            std::swap(k.port_a, k.port_b);
        uint64_t serial = rng();
        if (serial == 0)
            serial = 1;

        const auto s = wired_flow_tracker::format_key(k, serial);
        wired_flow_tracker::key pk;
        uint64_t ps = 0;
        if (!wired_flow_tracker::parse_key(s, pk, ps) || !(pk == k) || ps != serial ||
                wired_flow_tracker::format_key(pk, ps) != s)
            bad++;
    }

    CHECK(bad == 0);
}

static void test_key_hostile() {
    const std::string v4 = wired_flow_tracker::format_key(v4_key(), 1);
    const size_t sep = v4.find('-');
    CHECK(sep == 38);

    CHECK(!parses(""));
    CHECK(!parses(std::string(8192, '0')));
    CHECK(!parses(std::string(8192, 'a')));
    CHECK(!parses(v4.substr(0, 54)));
    CHECK(!parses(v4 + "0"));
    CHECK(!parses(v4 + "-"));
    CHECK(!parses(v4.substr(0, 40) + "0" + v4.substr(40)));      // 17-digit serial

    // Exactly one bad character anywhere
    std::string up = v4;
    up[14] = 'C';
    CHECK(!parses(up));
    std::string all_up = v4;
    for (auto& c : all_up)
        c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    CHECK(!parses(all_up));
    CHECK(!parses(v4.substr(0, 20) + "%00" + v4.substr(23)));
    CHECK(!parses(v4.substr(0, 20) + "%2f" + v4.substr(23)));
    CHECK(!parses(v4.substr(0, 20) + "%2F" + v4.substr(23)));
    std::string nul = v4;
    nul[30] = '\0';
    CHECK(!parses(nul));

    // The separator missing, moved or doubled
    std::string nosep = v4;
    nosep[sep] = '0';
    CHECK(!parses(nosep));
    std::string moved = v4;
    std::swap(moved[sep], moved[sep + 1]);
    CHECK(!parses(moved));
    CHECK(!parses(v4.substr(0, sep) + "--" + v4.substr(sep + 2)));

    // Family against length
    std::string fam5 = v4;
    fam5[1] = '5';
    CHECK(!parses(fam5));
    std::string fam6 = v4;
    fam6[1] = '6';
    CHECK(!parses(fam6));
    std::string fam0 = v4;
    fam0[1] = '0';
    CHECK(!parses(fam0));
    auto k6 = v4_key();
    k6.family = 6;
    std::string v6 = wired_flow_tracker::format_key(k6, 1);
    CHECK(v6.size() == wired_flow_tracker::key_text_len_v6 && round_trips(v6));
    v6[1] = '4';
    CHECK(!parses(v6));

    // Serial 0
    CHECK(!parses(v4.substr(0, sep + 1) + std::string(16, '0')));

    // VLAN bits vlan_key never sets
    std::string vl = v4;
    vl[14] = 'f';                       // bits 28-31 of the VLAN field
    CHECK(!parses(vl));
    vl = v4;
    vl[15] = '1';                       // bit 24
    CHECK(!parses(vl));
    vl = v4;
    vl[13] = 'f';                       // 15 tags: a value vlan_key can make
    CHECK(round_trips(vl));

    // Sides out of order: add() puts the lower address (then port) on side a
    auto swapped = v4_key();
    std::swap(swapped.addr_a, swapped.addr_b);
    CHECK(!parses(wired_flow_tracker::format_key(swapped, 1)));
    auto same_addr = v4_key();
    same_addr.addr_b = same_addr.addr_a;
    CHECK(!parses(wired_flow_tracker::format_key(same_addr, 1)));        // port 1000 > 53
    std::swap(same_addr.port_a, same_addr.port_b);
    CHECK(round_trips(wired_flow_tracker::format_key(same_addr, 1)));

    // Every one-byte change: accepted only as text that round-trips, and never for a byte
    // outside [0-9a-f-]
    size_t bad = 0;
    for (const auto& base : { v4, wired_flow_tracker::format_key(k6, 0x1234) }) {
        for (size_t pos = 0; pos < base.size(); pos++) {
            for (int b = 0; b < 256; b++) {
                std::string m = base;
                m[pos] = static_cast<char>(b);
                const bool allowed = (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || b == '-';
                if (parses(m) && (!allowed || !round_trips(m)))
                    bad++;
            }
        }
    }
    CHECK(bad == 0);
}

// A key from a list row finds that flow, and only while it's the same flow
static void test_key_lookup() {
    wired_flow_tracker::params p;
    p.history_min_packets = 1;
    wired_flow_tracker t(p, test_seed);

    t.add(obs(5, 1000, base_time));
    auto v = all_flows(t);
    CHECK(v.size() == 1);
    const auto text = wired_flow_tracker::format_key(v[0].k, v[0].serial);

    wired_flow_tracker::key k;
    uint64_t serial = 0;
    wired_flow_tracker::flow f;
    flow_history h(0);
    CHECK(wired_flow_tracker::parse_key(text, k, serial) && serial == v[0].serial);
    CHECK(t.lookup(k, serial, base_time, f, &h) && f.packets_ab == 1 && f.history_time == base_time);
    CHECK(!t.lookup(k, serial + 1, base_time, f, &h));

    // The same addresses and ports later are a new flow, with a new key
    t.expire(base_time + 1000);
    CHECK(!t.lookup(k, serial, base_time + 1000, f, &h));
    t.add(obs(5, 1000, base_time + 1000));
    v = all_flows(t);
    CHECK(v.size() == 1 && v[0].serial != serial);
    CHECK(!t.lookup(k, serial, base_time + 1000, f, &h));
    CHECK(wired_flow_tracker::format_key(v[0].k, v[0].serial) != text);
    CHECK(t.lookup(v[0].k, v[0].serial, base_time + 1000, f, nullptr));
}

int main() {
    test_reference_model();
    test_known_values();
    test_backsteps();
    test_saturation();
    test_admission();
    test_pool_cap_and_release();
    test_evict_prefers_no_history();
    test_lookup();
    test_destruction();
    test_threads();
    test_key_known_values();
    test_key_round_trip();
    test_key_hostile();
    test_key_lookup();

    if (failures != 0) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("flow history tests passed (flow_history %zu bytes)\n", sizeof(flow_history));
    return 0;
}
