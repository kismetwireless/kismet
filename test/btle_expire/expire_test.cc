/* Tests for btle_random_expire: which BTLE devices on rotating random addresses can be
 * forgotten.
 *
 *   make test/btle_expire/expire_test && test/btle_expire/expire_test
 */

#include "config.h"

#include <cstdio>

#include "btle_random_expire.h"

using namespace btle_random_expire;

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

// A one-packet rotating address, quiet past the window, that nothing correlated
static constexpr facts lone() {
    return facts{true, 1, 600, false, 1, false, false, 0, false, false};
}

static constexpr params p300{300, 2};

static_assert(judge(lone(), p300) == verdict::expire);
static_assert(effective_idle(0, true) == 0);
static_assert(effective_idle(60, true) == min_idle_linking);
static_assert(effective_idle(60, false) == 60);
static_assert(effective_idle(300, true) == 300);

static void test_expires() {
    CHECK(judge(lone(), p300) == verdict::expire);

    auto f = lone();
    f.packets = 2;
    CHECK(judge(f, p300) == verdict::expire);

    // Exactly at the idle time
    f = lone();
    f.idle = 300;
    CHECK(judge(f, p300) == verdict::expire);

    // A group of one is not a match
    f = lone();
    f.related_count = 1;
    CHECK(judge(f, p300) == verdict::expire);
    f.related_count = 0;
    CHECK(judge(f, p300) == verdict::expire);
}

static void test_keeps() {
    CHECK(judge(lone(), params{0, 2}) == verdict::keep_disabled);

    auto f = lone();
    f.rotating = false;
    CHECK(judge(f, p300) == verdict::keep_static);

    f = lone();
    f.packets = 3;
    CHECK(judge(f, p300) == verdict::keep_packets);

    f = lone();
    f.idle = 299;
    CHECK(judge(f, p300) == verdict::keep_recent);

    f = lone();
    f.linked = true;
    CHECK(judge(f, p300) == verdict::keep_linked);

    f = lone();
    f.related_count = 2;
    CHECK(judge(f, p300) == verdict::keep_related);

    f = lone();
    f.tracker = true;
    CHECK(judge(f, p300) == verdict::keep_tracker);

    f = lone();
    f.remoteid = true;
    CHECK(judge(f, p300) == verdict::keep_remoteid);

    f = lone();
    f.alerts = 1;
    CHECK(judge(f, p300) == verdict::keep_alerts);

    f = lone();
    f.named = true;
    CHECK(judge(f, p300) == verdict::keep_named);

    f = lone();
    f.saved_tag = true;
    CHECK(judge(f, p300) == verdict::keep_tagged);
}

// Each keep reason on its own is enough, whatever the others say
static void test_each_reason_alone() {
    for (int i = 0; i < 9; i++) {
        auto f = lone();
        switch (i) {
            case 0: f.rotating = false; break;
            case 1: f.packets = 100; break;
            case 2: f.idle = 0; break;
            case 3: f.linked = true; break;
            case 4: f.related_count = 5; break;
            case 5: f.tracker = true; break;
            case 6: f.remoteid = true; break;
            case 7: f.alerts = 3; break;
            case 8: f.named = true; f.saved_tag = true; break;
        }
        CHECK(judge(f, p300) != verdict::expire);
    }
}

int main() {
    test_expires();
    test_keeps();
    test_each_reason_alone();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("all btle random expire tests passed\n");
    return 0;
}
