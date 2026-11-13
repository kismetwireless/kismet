/* Tests for linking BTLE advertising sets which rotate together.  Synthetic keys and
 * timings only.
 *
 *   make test/btle_corotation/corotation_test && test/btle_corotation/corotation_test
 */

#include "config.h"

#include <algorithm>
#include <cstdio>
#include <functional>
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
    size_t waiting_count() const { return waiting_.size(); }
};

using rotations = std::vector<btle_corotation::rotation>;

static const btle_corotation::params params{1000, 8, 5000, 120 * 1000, 45 * 60 * 1000};
static constexpr int64_t cycle_ms = 15 * 60 * 1000;

/* Address of set s in moment m */
static device_key k(uint64_t s, uint64_t m) {
    return device_key(0x42, (s << 16) | m);
}

struct set {
    uint64_t id;
    uint64_t structure;
    int signal;
    uint64_t source;
    // How long after the moment this set rotates
    int64_t lag_ms;
    // Also heard now and then here, 0 for nowhere else
    uint64_t source2 = 0;
};

static bool same(const std::vector<device_key>& v, std::vector<device_key> want) {
    std::sort(want.begin(), want.end());
    return v == want;
}

using extra_fn = std::function<void (btle_corotation&, int64_t t, int64_t rot, rotations&)>;

/* Every set heard each second through moment m's cycle, then rotating to its next
 * address, heard for 30 s; extra runs each second too.  Returns the rotations reported */
static rotations run_moment(btle_corotation& c, const std::vector<set>& sets, uint64_t m,
        const extra_fn& extra = nullptr) {
    const int64_t start = (int64_t) m * cycle_ms, rot = start + cycle_ms;
    rotations out;

    for (int64_t t = start; t < rot + 30000; t += 1000) {
        if (extra)
            extra(c, t, rot, out);

        for (const auto& s : sets) {
            const int64_t ts = t + s.lag_ms;
            const auto key = ts < rot + s.lag_ms ? k(s.id, m) : k(s.id, m + 1);
            c.observe(key, ts, s.structure, s.signal, s.source, out);
            if (s.source2 != 0 && t % 7000 == 0)
                c.observe(key, ts + 300, s.structure, s.signal - 10, s.source2, out);
        }
    }

    return out;
}

static const set nearby_a{1, 101, -50, 7, 0};
static const set nearby_b{2, 101, -51, 7, 20};
static const set other16{3, 103, -55, 7, 150};

static void test_one_phone() {
    /* Two sets sharing a structure and a third, as an iPhone sends them */
    btle_corotation c(params);
    const std::vector<set> phone{nearby_a, nearby_b, other16};

    /* First rotation: noted, not reported */
    CHECK(run_moment(c, phone, 0).empty());

    /* Second: the addresses that started together went quiet together */
    auto r = run_moment(c, phone, 1);
    CHECK(r.size() == 1);
    if (r.size() == 1) {
        CHECK(same(r[0].quiet, { k(1, 1), k(2, 1), k(3, 1) }));
        CHECK(same(r[0].fresh, { k(1, 2), k(2, 2), k(3, 2) }));
    }

    /* Third, and on */
    r = run_moment(c, phone, 2);
    CHECK(r.size() == 1 && same(r[0].fresh, { k(1, 3), k(2, 3), k(3, 3) }));
}

static void test_two_receivers() {
    /* Heard now and then on a second receiver too, as the HCI scanners do */
    btle_corotation c(params);
    set a = nearby_a, b = other16;
    a.source2 = 8;
    b.source2 = 8;

    CHECK(run_moment(c, { a, b }, 0).empty());
    auto r = run_moment(c, { a, b }, 1);
    CHECK(r.size() == 1 && same(r[0].fresh, { k(1, 2), k(3, 2) }));
}

static void test_bystander() {
    /* Another device rotates in the same moment once: that rotation isn't confirmed,
     * and it never joins */
    btle_corotation c(params);
    const set other{4, 101, -53, 7, 300};

    CHECK(run_moment(c, { nearby_a, other16, other }, 0).empty());
    CHECK(run_moment(c, { nearby_a, other16 }, 1).empty());
    auto r = run_moment(c, { nearby_a, other16 }, 2);
    CHECK(r.size() == 1);
    for (const auto& x : r)
        for (const auto& v : { x.quiet, x.fresh })
            for (const auto& key : v)
                CHECK(!(key == k(4, 0)) && !(key == k(4, 1)) && !(key == k(4, 2)));
}

static void test_no_match() {
    /* One set alone is any device's rotation */
    btle_corotation c(params);
    for (uint64_t m = 0; m < 3; m++)
        CHECK(run_moment(c, { nearby_a }, m).empty());

    /* Structures that differ across the rotation */
    btle_corotation c2(params);
    for (uint64_t m = 0; m < 3; m++) {
        set b = other16;
        b.structure = 200 + m;
        CHECK(run_moment(c2, { nearby_a, b }, m).empty());
    }

    /* No structure */
    btle_corotation c3(params);
    set bare = other16;
    bare.structure = 0;
    for (uint64_t m = 0; m < 3; m++)
        CHECK(run_moment(c3, { nearby_a, bare }, m).empty());

    /* Another receiver only, or too far off in signal */
    for (const auto& odd : { set{3, 103, -55, 8, 150}, set{3, 103, -70, 7, 150} }) {
        btle_corotation c4(params);
        for (uint64_t m = 0; m < 3; m++)
            CHECK(run_moment(c4, { nearby_a, odd }, m).empty());
    }
}

static void test_window_edge() {
    for (int64_t lag : { (int64_t) 1000, (int64_t) 1001 }) {
        btle_corotation c(params);
        const set edge{3, 103, -55, 7, lag};
        run_moment(c, { nearby_a, edge }, 0);
        auto r = run_moment(c, { nearby_a, edge }, 1);
        CHECK(r.empty() == (lag > 1000));
    }
}

static void test_not_quiet() {
    /* An old address heard again after the moment didn't rotate */
    btle_corotation c(params);

    for (uint64_t m = 0; m < 3; m++)
        CHECK(run_moment(c, { nearby_a, other16 }, m,
                    [m](btle_corotation& cc, int64_t t, int64_t rot, rotations& out) {
                        if (t == rot + 2000)
                            cc.observe(k(1, m), t + 500, 101, -50, 7, out);
                    }).empty());
}

static void test_scan_response_first() {
    /* A first frame without a structure gets one from the advertising after it */
    btle_corotation c(params);
    size_t n = 0;

    for (uint64_t m = 0; m < 3; m++)
        n += run_moment(c, { nearby_a, other16 }, m,
                [m](btle_corotation& cc, int64_t t, int64_t rot, rotations& out) {
                    if (t == rot)
                        cc.observe(k(1, m + 1), t - 10, 0, -50, 7, out);
                }).size();
    CHECK(n == 2);
}

static void test_flood() {
    test_corotation c(params);
    rotations out;

    for (uint64_t n = 0; n < 50000; n++)
        c.observe(device_key(0x99, n), (int64_t) n * 2, 100 + (n % 3), -50, 7, out);
    CHECK(c.addr_count() <= btle_corotation::max_addrs);
    CHECK(c.waiting_count() <= btle_corotation::max_addrs);
    CHECK(c.chain_count() <= btle_corotation::max_chains);

    /* Many devices rotating, each with two sets, keep the chains bounded */
    test_corotation c2(params);
    for (uint64_t d = 0; d < 300; d++) {
        const int64_t t = (int64_t) d * 20000;
        for (uint64_t s = 0; s < 2; s++) {
            c2.observe(device_key(0x98, d * 4 + s), t - 5000, 101 + s, -50, 7, out);
            c2.observe(device_key(0x98, d * 4 + s), t - 100, 101 + s, -50, 7, out);
            c2.observe(device_key(0x98, d * 4 + s + 2), t + 100, 101 + s, -50, 7, out);
        }
        c2.observe(device_key(0x98, d * 4), t + 6000, 101, -50, 7, out);
    }
    CHECK(c2.chain_count() <= btle_corotation::max_chains);
}

int main() {
    test_one_phone();
    test_two_receivers();
    test_bystander();
    test_no_match();
    test_window_edge();
    test_not_quiet();
    test_scan_response_first();
    test_flood();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("ok\n");
    return 0;
}
