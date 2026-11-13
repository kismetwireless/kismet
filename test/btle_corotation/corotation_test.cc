/* Tests for linking BTLE advertising sets which rotate together.  Synthetic keys and
 * timings only.
 *
 *   make test/btle_corotation/corotation_test && test/btle_corotation/corotation_test
 */

#include "config.h"

#include <cstdio>
#include <vector>

#include "btle_corotation.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

struct test_corotation : public btle_corotation {
    using btle_corotation::btle_corotation;
    size_t addr_count() const { return addrs_.size(); }
    size_t chain_count() const { return chains_.size(); }
};

using joins = std::vector<btle_corotation::join>;

static const btle_corotation::params params{1000, 8, 120 * 1000, 45 * 60 * 1000};
static constexpr int64_t cycle_ms = 15 * 60 * 1000;

/* Address n of set s, moment m */
static device_key k(uint64_t s, uint64_t m) {
    return device_key(0x42, (s << 16) | m);
}

static bool has(const joins& j, const device_key& key, const device_key& pred) {
    for (const auto& x : j)
        if (x.key == key && x.pred == pred)
            return true;
    return false;
}

struct set {
    uint64_t id;
    uint64_t structure;
    int signal;
    uint64_t source;
    // How long after the anchor this set rotates
    int64_t lag_ms;
};

/* Every set heard every 5 s through moment m's cycle, then rotating; returns the joins
 * once the linker would have settled the anchor's rotation, 30 s later */
static joins run_moment(btle_corotation& c, const std::vector<set>& sets, uint64_t m) {
    const int64_t start = (int64_t) m * cycle_ms, rot = start + cycle_ms;

    for (int64_t t = start; t < rot; t += 5000)
        for (const auto& s : sets)
            c.observe(k(s.id, m), t + s.lag_ms, s.structure, s.signal, s.source);

    /* The last frames right before the rotation, the first right after */
    for (const auto& s : sets)
        c.observe(k(s.id, m), rot - 200 + s.lag_ms, s.structure, s.signal, s.source);
    for (int64_t t = rot + 200; t < rot + 30000; t += 5000)
        for (const auto& s : sets)
            c.observe(k(s.id, m + 1), t + s.lag_ms, s.structure, s.signal, s.source);

    joins out;
    c.rotated(k(1, m + 1), k(1, m), out);
    return out;
}

static const set anchor{1, 101, -50, 7, 0};
static const set xset{2, 102, -52, 7, 100};
static const set yset{3, 103, -55, 7, -150};

static void test_one_phone() {
    btle_corotation c(params);
    const std::vector<set> phone{anchor, xset, yset};

    /* First moment: noted, not joined */
    CHECK(run_moment(c, phone, 0).empty());

    /* Second: both sets confirmed, both their addresses join the anchor's newest */
    auto j = run_moment(c, phone, 1);
    CHECK(j.size() == 4);
    CHECK(has(j, k(2, 1), k(1, 2)) && has(j, k(2, 2), k(1, 2)));
    CHECK(has(j, k(3, 1), k(1, 2)) && has(j, k(3, 2), k(1, 2)));

    /* Third: only the new addresses */
    j = run_moment(c, phone, 2);
    CHECK(j.size() == 2);
    CHECK(has(j, k(2, 3), k(1, 3)) && has(j, k(3, 3), k(1, 3)));
}

static void test_bystander() {
    /* Another phone rotates with the anchor once, then is gone by the next rotation:
     * it's never joined, and the phone's own set still is */
    btle_corotation c(params);
    const set other{4, 104, -53, 7, 50};

    CHECK(run_moment(c, { anchor, xset, other }, 0).empty());
    auto j = run_moment(c, { anchor, xset }, 1);
    CHECK(j.size() == 2 && has(j, k(2, 1), k(1, 2)) && has(j, k(2, 2), k(1, 2)));
    for (const auto& x : j)
        CHECK(!(x.key == k(4, 1)) && !(x.key == k(4, 2)));
}

static void test_ambiguous() {
    /* Two sets with one structure: no pairing, so nothing at the next moment either */
    btle_corotation c(params);
    const set twin{5, 102, -51, 7, 30};

    CHECK(run_moment(c, { anchor, xset, twin }, 0).empty());
    CHECK(run_moment(c, { anchor, xset, twin }, 1).empty());

    /* No structure never pairs */
    btle_corotation c2(params);
    const set bare{6, 0, -51, 7, 30};
    CHECK(run_moment(c2, { anchor, bare }, 0).empty());
    CHECK(run_moment(c2, { anchor, bare }, 1).empty());

    /* A new address with nothing quiet to match: sides differ, nothing */
    btle_corotation c3(params);
    CHECK(run_moment(c3, { anchor, xset }, 0).empty());
    for (int64_t t = cycle_ms * 2 - 100; t < cycle_ms * 2 + 25000; t += 5000)
        c3.observe(k(9, 9), t, 109, -51, 7);
    CHECK(run_moment(c3, { anchor, xset }, 1).empty());
}

static void test_other_source() {
    btle_corotation c(params);
    const set elsewhere{2, 102, -52, 8, 100};

    CHECK(run_moment(c, { anchor, elsewhere }, 0).empty());
    CHECK(run_moment(c, { anchor, elsewhere }, 1).empty());

    /* Too far off in signal */
    btle_corotation c2(params);
    const set faint{2, 102, -70, 7, 100};
    CHECK(run_moment(c2, { anchor, faint }, 0).empty());
    CHECK(run_moment(c2, { anchor, faint }, 1).empty());
}

static void test_window_edge() {
    for (int64_t lag : { (int64_t) 1000, (int64_t) 1001 }) {
        btle_corotation c(params);
        const set edge{2, 102, -52, 7, lag};
        run_moment(c, { anchor, edge }, 0);
        auto j = run_moment(c, { anchor, edge }, 1);
        CHECK(j.empty() == (lag > 1000));
    }
}

static void test_flood() {
    test_corotation c(params);

    for (uint64_t n = 0; n < 50000; n++)
        c.observe(device_key(0x99, n), (int64_t) n, n, -50, 7);
    CHECK(c.addr_count() <= btle_corotation::max_addrs);

    /* Rotations of many anchors keep the chains bounded */
    for (uint64_t n = 0; n < 500; n++) {
        joins j;
        c.rotated(device_key(0x99, n + 1), device_key(0x99, n), j);
    }
    CHECK(c.chain_count() <= btle_corotation::max_chains);

    /* Unknown addresses do nothing */
    joins j;
    c.rotated(device_key(0x77, 1), device_key(0x77, 2), j);
    CHECK(j.empty());
}

int main() {
    test_one_phone();
    test_bystander();
    test_ambiguous();
    test_other_source();
    test_window_edge();
    test_flood();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("ok\n");
    return 0;
}
