/* Micro-benchmark of wired_flow_tracker::add with and without flow history, and of the
 * expiry pass with a full history pool.  Out of body:
 *
 *   unit.sh <tree> test/ethernet/flow_bench.cc wired_flow_history.cc --set l3 --cflags -O3
 *
 * -DFLOW_BENCH_BASE builds it against a tracker without history, for A/B runs.
 */

#include "config.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <vector>

#include "wired_flow_tracker.h"

namespace {

constexpr int reps = 5;
constexpr time_t t0 = 1700000000;

wired_flow_tracker::observation obs(uint32_t flow, time_t seen) {
    wired_flow_tracker::observation o;
    o.src.family = o.dst.family = 4;
    o.src.a[0] = 10;
    o.src.a[1] = static_cast<uint8_t>(flow >> 16);
    o.src.a[2] = static_cast<uint8_t>(flow >> 8);
    o.src.a[3] = static_cast<uint8_t>(flow);
    o.dst.a[0] = 198; o.dst.a[1] = 51; o.dst.a[2] = 100; o.dst.a[3] = 1;
    o.proto = 17;
    o.sport = 40000;
    o.dport = 53;
    o.bytes = 512;
    o.ts = o.seen = seen;
    o.src_mac = 0x020000000001ULL;
    return o;
}

wired_flow_tracker::params make_params(bool history, size_t max_histories) {
    wired_flow_tracker::params p;
    p.max_flows = 16384;
#ifndef FLOW_BENCH_BASE
    p.max_histories = history ? max_histories : 0;
    p.history_min_packets = 1;
    p.history_idle = 10;
#else
    (void) history;
    (void) max_histories;
#endif
    return p;
}

double median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

template <typename F>
double time_ns(F&& f) {
    const auto a = std::chrono::steady_clock::now();
    f();
    const auto b = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::nano>(b - a).count();
}

// ns per add, median of reps; next(i) gives packet i
template <typename N>
double bench_adds(bool history, size_t max_histories, size_t n, size_t warm, N&& next) {
    std::vector<double> runs;
    for (int r = 0; r < reps; r++) {
        wired_flow_tracker t(make_params(history, max_histories), 0x5eed);
        for (size_t i = 0; i < warm; i++)
            t.add(next(i));
        runs.push_back(time_ns([&]() {
                    for (size_t i = warm; i < warm + n; i++)
                        t.add(next(i));
                    }) / static_cast<double>(n));
    }
    return median(runs);
}

// ns per expiry pass over 4096 flows with histories, the pool full
double bench_expire(bool history) {
    std::vector<double> runs;
    for (int r = 0; r < reps * 4; r++) {
        wired_flow_tracker t(make_params(history, 4096), 0x5eed);
        for (uint32_t f = 0; f < 4096; f++)
            t.add(obs(f, t0));
        runs.push_back(time_ns([&]() { t.expire(t0 + 30); }));
    }
    return median(runs);
}

}

int main() {
    constexpr size_t n = 2000000;

    for (bool history : { false, true }) {
#ifdef FLOW_BENCH_BASE
        if (history)
            break;
        const char *label = "base";
#else
        const char *label = history ? "history" : "off";
#endif
        const double a = bench_adds(history, 4096, n, 16, [](size_t) { return obs(1, t0); });
        const double b = bench_adds(history, 4096, n, 16, [](size_t i) { return obs(1, t0 + static_cast<time_t>(i)); });
        // 4096 flows qualify with the pool full, so every packet retries
        const double c = bench_adds(history, 1, n, 4096,
                [](size_t i) { return obs(static_cast<uint32_t>(i % 4096), t0 + static_cast<time_t>(i / 4096)); });
        const double d = bench_adds(history, 4096, n / 8, 4096,
                [](size_t i) { return obs(static_cast<uint32_t>(i % 4096), t0 + 86400 * static_cast<time_t>(i / 4096)); });
        const double e = bench_expire(history);

        printf("%-8s a same-second %.1f ns  b new-second %.1f ns  c pool-full %.1f ns  d day-gap %.1f ns  "
                "e expire-4096 %.0f ns\n", label, a, b, c, d, e);
    }

    return 0;
}
