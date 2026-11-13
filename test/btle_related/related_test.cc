/* Tests for grouping BTLE addresses by payload, and leaving out addresses whose payload
 * keeps changing.  Synthetic keys and fingerprints only.
 *
 *   make test/btle_related/related_test && test/btle_related/related_test
 */

#include "config.h"

#include <cstdio>
#include <vector>

#include "btle_related.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

struct test_tracker : public btle_related_tracker {
    using btle_related_tracker::btle_related_tracker;
    size_t group_count() const { return groups_.size(); }
    size_t addr_count() const { return addrs_.size(); }
};

using states = std::vector<btle_related_tracker::state>;

static device_key k(uint64_t n) {
    return device_key(0x42, n);
}

static btle_related_tracker::params params(time_t steady) {
    return btle_related_tracker::params{60, 128, 64, steady};
}

/* The state handed out for key in one observe */
static btle_related_tracker::state seen(btle_related_tracker& t, uint64_t fp, const device_key& key, time_t now) {
    states out;
    t.observe(fp, key, now, out);
    for (const auto& s : out)
        if (s.key == key)
            return s;
    return btle_related_tracker::state{key, 99, 99, false, device_key{}, false, 0};
}

static void test_grouped() {
    test_tracker t(params(60));
    seen(t, 100, k(1), 0);
    auto s = seen(t, 100, k(2), 1);
    CHECK(s.group != 0 && s.size == 2);
}

static void test_changing_payload() {
    /* Two sets of one device send the same payload, which changes every 5 s */
    test_tracker t(params(60));
    seen(t, 100, k(1), 0);
    const auto first = seen(t, 100, k(2), 0);
    CHECK(first.size == 2);

    for (time_t now = 5; now < 300; now += 5) {
        const uint64_t fp = 100 + now;
        auto a = seen(t, fp, k(1), now);
        auto b = seen(t, fp, k(2), now);
        CHECK(a.group == 0 && b.group == 0);
    }

    /* No group per payload: only the first, and it's emptied */
    CHECK(t.group_count() <= 1);
}

static void test_rejoin() {
    test_tracker t(params(60));
    seen(t, 100, k(1), 0);
    seen(t, 100, k(2), 0);

    /* Changes for a while, then settles on one payload */
    for (time_t now = 5; now <= 30; now += 5) {
        seen(t, 100 + now, k(1), now);
        seen(t, 100 + now, k(2), now);
    }

    btle_related_tracker::state a{}, b{};
    for (time_t now = 35; now <= 100; now += 5) {
        a = seen(t, 500, k(1), now);
        b = seen(t, 500, k(2), now);
        if (now - 35 < 60)
            CHECK(a.group == 0 && b.group == 0);
    }
    CHECK(a.group != 0 && a.group == b.group && b.size == 2);
}

static void test_short_payload_keeps_group() {
    test_tracker t(params(60));
    seen(t, 100, k(1), 0);
    const auto g = seen(t, 100, k(2), 0);

    for (time_t now = 1; now < 20; now++) {
        auto s = seen(t, now % 2 ? 0 : 100, k(2), now);
        CHECK(s.group == g.group && s.size == 2);
    }

    /* An address only ever sending short payloads has no group */
    CHECK(seen(t, 0, k(3), 20).group == 0);
}

static void test_steady_off() {
    test_tracker t(params(0));
    seen(t, 100, k(1), 0);
    seen(t, 100, k(2), 0);
    auto s = seen(t, 200, k(2), 5);
    CHECK(s.group != 0 && s.size == 1);
    CHECK(t.addr_count() == 0);
}

static void test_quiet_starts_over() {
    test_tracker t(params(60));
    seen(t, 100, k(1), 0);
    seen(t, 100, k(2), 0);
    CHECK(seen(t, 200, k(2), 5).group == 0);

    /* Quiet longer than the steady time: grouped at once with what it sends next */
    seen(t, 100, k(1), 70);
    auto s = seen(t, 100, k(2), 70);
    CHECK(s.group != 0 && s.size == 2);
}

static void test_bounded() {
    test_tracker t(params(60));
    for (uint64_t n = 0; n < 50000; n++)
        seen(t, 1000 + n, k(n), 0);
    CHECK(t.addr_count() <= btle_related_tracker::max_addrs);
    CHECK(t.group_count() <= 128);

    /* All forgotten once quiet */
    seen(t, 7, k(1), 100);
    CHECK(t.addr_count() == 1);
}

int main() {
    test_grouped();
    test_changing_payload();
    test_rejoin();
    test_short_payload_keeps_group();
    test_steady_off();
    test_quiet_starts_over();
    test_bounded();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("ok\n");
    return 0;
}
