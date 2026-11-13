/* Tests for the randomized address linker: Handoff-style sequence rules, the same
 * number on two sets, bounds, and the Wi-Fi rules it had before.  Synthetic keys only.
 *
 *   make test/randomized_alias/linker_test && test/randomized_alias/linker_test
 */

#include "config.h"

#include <cstdio>
#include <cstring>
#include <vector>

#include "randomized_alias.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

using linker = randomized_alias_linker;
using alias_link = linker::link;

/* Sizes of the state, which the bounds tests read */
struct test_linker : public linker {
    using linker::linker;
    size_t seen_count() const { return seen_.size(); }
    size_t pending_count() const { return pending_.size(); }
    size_t bucket_count() const { return recs_.size(); }
    size_t rec_count() const { return rec_count_; }
};

/* phy_btle's parameters and Handoff rules */
static const linker::params btle_params{15, 30, 0, "payload", 120, 8, 4};
static const linker::seq_rules handoff{65536, 4, "handoff", true, 2, "concurrent", 128};
static constexpr uint64_t handoff_fp = 0x48414e444f4646ULL;
static constexpr uint64_t src = 1;

static device_key k(uint64_t n) {
    return device_key(0x42, n);
}

static const alias_link *find(const std::vector<alias_link>& out, uint64_t key, uint64_t pred, const char *method) {
    for (const auto& l : out)
        if (l.key == k(key) && l.pred == k(pred) && l.method != nullptr && strcmp(l.method, method) == 0)
            return &l;
    return nullptr;
}

static size_t named(const std::vector<alias_link>& out) {
    size_t n = 0;
    for (const auto& l : out)
        if (l.method != nullptr)
            n++;
    return n;
}

/* The group the last link for key put it in */
static device_key final_group(const std::vector<alias_link>& out, uint64_t key) {
    device_key g;
    for (const auto& l : out)
        if (l.key == k(key))
            g = l.group;
    return g;
}

/* Something else heard at t, so pending links get looked at */
static void tick(linker& l, time_t t, std::vector<alias_link>& out) {
    l.observe(0x7777, k(9999), t, -1, out, linker::no_signal, 0);
}

static void hand(linker& l, uint64_t key, time_t t, int seq, std::vector<alias_link>& out,
        int signal = -50, uint64_t source = src) {
    l.observe(handoff_fp, k(key), t, seq, out, signal, source, handoff);
}

/* A heard until 10 with first, B from 12 with second; true if B is linked to A */
static bool rotation(int first, int second, const char *method = "handoff") {
    linker l(btle_params);
    std::vector<alias_link> out;
    for (time_t t = 0; t <= 10; t++)
        hand(l, 1, t, first, out);
    for (time_t t = 12; t <= 50; t++)
        hand(l, 2, t, second, out);
    return find(out, 2, 1, method) != nullptr;
}

static void test_counter() {
    CHECK(rotation(100, 101));
    CHECK(rotation(100, 104));
    CHECK(rotation(65535, 0));
    CHECK(rotation(65534, 1));

    CHECK(!rotation(100, 105));
    CHECK(!rotation(100, 100));
    CHECK(!rotation(100, 99));
    CHECK(!rotation(100, 30000));

    /* Out of range numbers are none, and link nothing */
    CHECK(!rotation(65536, 65537));
}

static void test_settle() {
    /* Not before the earlier address stays quiet for confirm */
    linker l(btle_params);
    std::vector<alias_link> out;
    hand(l, 1, 0, 7, out);
    hand(l, 2, 12, 8, out);
    tick(l, 41, out);
    CHECK(named(out) == 0);
    tick(l, 42, out);
    CHECK(find(out, 2, 1, "handoff") != nullptr);
    CHECK(out.size() == 1 && out[0].kind == linker::link_kind::carry && out[0].group == k(1));

    /* The earlier address heard again is another device */
    linker l2(btle_params);
    out.clear();
    hand(l2, 1, 0, 7, out);
    hand(l2, 2, 12, 8, out);
    hand(l2, 1, 20, 7, out);
    tick(l2, 60, out);
    CHECK(named(out) == 0);
}

static void test_only() {
    /* Under the Handoff rules a number that matches nothing links nothing, even with
     * one candidate around */
    CHECK(!rotation(100, 200, "payload"));
    CHECK(!rotation(100, 200, "handoff"));

    /* Without them the lone candidate links */
    linker l(btle_params);
    std::vector<alias_link> out;
    for (time_t t = 0; t <= 10; t++)
        l.observe(0x1234, k(1), t, -1, out, -50, src);
    for (time_t t = 12; t <= 50; t++)
        l.observe(0x1234, k(2), t, -1, out, -50, src);
    CHECK(find(out, 2, 1, "payload") != nullptr);

    /* A late frame doesn't move the number back */
    linker l2(btle_params);
    out.clear();
    hand(l2, 1, 0, 100, out);
    hand(l2, 1, 1, 99, out);
    hand(l2, 2, 12, 101, out);
    tick(l2, 50, out);
    CHECK(find(out, 2, 1, "handoff") != nullptr);
}

/* A phone sending two sets with one counter, then rotating both */
static void test_two_sets() {
    linker l(btle_params);
    std::vector<alias_link> out;

    for (time_t t = 0; t <= 20; t++) {
        hand(l, 1, t, 500, out, -50);
        hand(l, 2, t, 500, out, -53);
    }
    CHECK(find(out, 2, 1, "concurrent") != nullptr || find(out, 1, 2, "concurrent") != nullptr);
    for (const auto& x : out)
        if (x.method != nullptr)
            CHECK(x.kind == linker::link_kind::same);

    out.clear();
    for (time_t t = 22; t <= 70; t++) {
        hand(l, 3, t, 501, out, -51);
        hand(l, 4, t, 501, out, -52);
    }

    /* Each new address carries on from one of the two or pairs with the other, and
     * all four end in group 1 */
    CHECK(named(out) >= 2);
    for (uint64_t n : { 3, 4 }) {
        bool carried = find(out, n, 1, "handoff") != nullptr || find(out, n, 2, "handoff") != nullptr;
        bool paired = find(out, 3, 4, "concurrent") != nullptr || find(out, 4, 3, "concurrent") != nullptr;
        CHECK(carried || paired);
        CHECK(final_group(out, n) == k(1));
    }
}

static bool concurrent(int sig2, uint64_t src2, time_t gap) {
    linker l(btle_params);
    std::vector<alias_link> out;
    for (time_t t = 0; t <= 20; t++) {
        hand(l, 1, t, 500, out, -50, src);
        if (t >= gap)
            hand(l, 2, t, 500, out, sig2, src2);
    }
    return find(out, 2, 1, "concurrent") != nullptr;
}

static void test_concurrent_needs() {
    CHECK(concurrent(-55, src, 0));
    CHECK(!concurrent(-50, 2, 0));
    CHECK(!concurrent(-70, src, 0));

    /* Other numbers never pair */
    linker l(btle_params);
    std::vector<alias_link> out;
    for (time_t t = 0; t <= 20; t++) {
        hand(l, 1, t, 500, out);
        hand(l, 2, t, 501, out);
    }
    CHECK(named(out) == 0);

    /* Both must keep the number: one moving on drops the pair */
    linker l2(btle_params);
    out.clear();
    hand(l2, 1, 0, 500, out);
    hand(l2, 2, 0, 500, out);
    for (time_t t = 1; t <= 20; t++) {
        hand(l2, 1, t, 500, out);
        hand(l2, 2, t, 502, out);
    }
    CHECK(named(out) == 0);
}

static void test_ambiguous() {
    /* Two phones that went quiet with the same counter: a new one could be either */
    linker l(btle_params);
    std::vector<alias_link> out;
    hand(l, 1, 0, 300, out, -40);
    hand(l, 2, 0, 300, out, -80);
    hand(l, 3, 12, 301, out);
    tick(l, 60, out);
    CHECK(named(out) == 0);
}

static void test_handoff_beats_payload() {
    /* B has a lone payload candidate P and a Handoff match H; only H links */
    for (int order = 0; order < 2; order++) {
        linker l(btle_params);
        std::vector<alias_link> out;
        for (time_t t = 0; t <= 10; t++) {
            l.observe(0x5555, k(10), t, -1, out, -50, src);
            hand(l, 11, t, 40, out);
        }
        for (time_t t = 12; t <= 50; t++) {
            if (order == 0) {
                l.observe(0x5555, k(12), t, -1, out, -50, src);
                hand(l, 12, t, 41, out);
            } else {
                hand(l, 12, t, 41, out);
                l.observe(0x5555, k(12), t, -1, out, -50, src);
            }
        }
        CHECK(find(out, 12, 11, "handoff") != nullptr);
        CHECK(find(out, 12, 10, "payload") == nullptr);
    }
}

static void test_join() {
    linker l(btle_params);
    std::vector<alias_link> out;
    hand(l, 1, 0, 1, out);
    hand(l, 2, 0, 9000, out, -90, 2);
    l.join(k(2), k(1), "corotation", out);
    CHECK(out.size() == 1 && out[0].kind == linker::link_kind::join && out[0].group == k(1));
    CHECK(strcmp(out[0].method, "corotation") == 0);

    /* Already one group, or never heard: nothing */
    out.clear();
    l.join(k(2), k(1), "corotation", out);
    l.join(k(3), k(1), "corotation", out);
    CHECK(out.empty());
}

static void test_flood() {
    test_linker l(btle_params);
    std::vector<alias_link> out;

    /* 100k addresses with a new payload and counter each, over 10 seconds */
    for (uint64_t n = 0; n < 100000; n++) {
        const time_t t = 1000 + (time_t) (n / 10000);
        l.observe(0x100000 + n, k(100000 + n), t, -1, out, -50, src);
        hand(l, 100000 + n, t, (int) (n % 65536), out);
        CHECK(l.seen_count() <= linker::max_seen);
        CHECK(l.pending_count() <= linker::max_pending);
        CHECK(l.rec_count() <= linker::max_recs_total);
        if (failures)
            break;
    }
    CHECK(l.bucket_count() <= linker::max_recs_total);

    /* Later, a real rotation still links */
    out.clear();
    for (time_t t = 1200; t <= 1210; t++)
        hand(l, 1, t, 2000, out);
    for (time_t t = 1212; t <= 1250; t++)
        hand(l, 2, t, 2001, out);
    CHECK(find(out, 2, 1, "handoff") != nullptr);
}

/* The rules phy_80211 uses, unchanged */
static void test_wifi() {
    const linker::params p{60, 30, 64, "timing", 600, 0, 0};

    linker l(p);
    std::vector<alias_link> out;
    l.observe(0xabc, k(1), 0, 4090, out);
    l.observe(0xabc, k(2), 5, 3, out);
    l.observe(0xdef, k(9), 40, -1, out);
    CHECK(find(out, 2, 1, "sequence") != nullptr);

    linker l2(p);
    out.clear();
    l2.observe(0xabc, k(1), 0, 100, out);
    l2.observe(0xabc, k(2), 5, 900, out);
    l2.observe(0xdef, k(9), 40, -1, out);
    CHECK(find(out, 2, 1, "timing") != nullptr);

    /* Two devices around and no sequence match: nothing */
    linker l3(p);
    out.clear();
    for (time_t t = 0; t <= 3; t++) {
        l3.observe(0xabc, k(1), t, 100 + t, out);
        l3.observe(0xabc, k(2), t, 2000 + t, out);
    }
    l3.observe(0xabc, k(3), 5, 3000, out);
    l3.observe(0xdef, k(9), 40, -1, out);
    CHECK(named(out) == 0);
}

/* Payload with a fingerprint only this address sends, as encrypted Nearby Info does */
static void own_payload(linker& l, uint64_t key, time_t from, time_t to, std::vector<alias_link>& out) {
    for (time_t t = from; t <= to; t++)
        l.observe(0x1000 + key, k(key), t, -1, out, -50, src);
}

/* Handoff sent now and then: A sends it until 10 and other frames until quiet_at; B
 * starts at start and sends Handoff from first_ho; true if B is linked to A */
static bool intermittent(time_t quiet_at, time_t start, time_t first_ho) {
    linker l(btle_params);
    std::vector<alias_link> out;
    for (time_t t = 0; t <= 10; t++)
        hand(l, 1, t, 100, out);
    own_payload(l, 1, 0, quiet_at, out);
    own_payload(l, 2, start, first_ho - 1, out);
    for (time_t t = first_ho; t <= first_ho + 40; t++) {
        hand(l, 2, t, 101, out);
        own_payload(l, 2, t, t, out);
    }
    const bool linked = find(out, 2, 1, "handoff") != nullptr;
    CHECK(!linked || l.group(k(2)) == k(1));
    return linked;
}

static void test_intermittent() {
    /* Timed by when A went quiet and B started, not by their Handoff frames */
    CHECK(intermittent(200, 201, 300));
    CHECK(intermittent(200, 215, 215));

    /* A still heard after B started: another of the device's sets */
    CHECK(!intermittent(250, 201, 300));
    /* B started too long after A went quiet */
    CHECK(!intermittent(200, 216, 300));
    /* B's first Handoff after A was forgotten */
    CHECK(!intermittent(200, 201, 321));
}

/* One shared payload, as nearby Find My devices send; each frame's signal swings 6 dB
 * either side of mean, starting below it, or above with phase 1 */
static void shared(linker& l, uint64_t key, time_t from, time_t to, int mean,
        std::vector<alias_link>& out, uint64_t source = src, int phase = 0) {
    for (time_t t = from; t <= to; t++)
        l.observe(0x5150, k(key), t, -1, out, mean + ((t - from + phase) % 2 ? 6 : -6), source);
}

static void settle_all(linker& l, time_t until, std::vector<alias_link>& out) {
    for (time_t t = 0; t <= until; t++)
        tick(l, t, out);
}

static void test_signal() {
    /* Picked by averages: frame by frame, C's first (-57) is nearest B's last (-54),
     * and too far from A's (-44) */
    {
        linker l(btle_params);
        std::vector<alias_link> out;
        shared(l, 1, 0, 100, -50, out, src, 1);
        shared(l, 2, 0, 100, -60, out, src, 1);
        shared(l, 3, 102, 150, -51, out);
        settle_all(l, 150, out);
        CHECK(find(out, 3, 1, "signal") != nullptr && named(out) == 1);
    }

    /* Too close to tell apart */
    {
        linker l(btle_params);
        std::vector<alias_link> out;
        shared(l, 1, 0, 10, -50, out);
        shared(l, 2, 0, 10, -53, out);
        shared(l, 3, 12, 60, -51, out);
        settle_all(l, 60, out);
        CHECK(named(out) == 0);
    }

    /* A candidate heard again is another device, still there */
    {
        linker l(btle_params);
        std::vector<alias_link> out;
        shared(l, 1, 0, 10, -50, out);
        shared(l, 2, 0, 10, -62, out);
        shared(l, 3, 12, 60, -61, out);
        shared(l, 1, 20, 20, -50, out);
        settle_all(l, 60, out);
        CHECK(find(out, 3, 2, "signal") != nullptr && named(out) == 1);
    }

    /* Heard on another receiver: can't be ruled out */
    {
        linker l(btle_params);
        std::vector<alias_link> out;
        shared(l, 1, 0, 10, -50, out);
        shared(l, 2, 0, 10, -64, out, 2);
        shared(l, 3, 12, 60, -52, out);
        settle_all(l, 60, out);
        CHECK(named(out) == 0);
    }
}

static void test_findmy_quarter_hour() {
    /* Three devices rotating a second or two apart, as a capture showed: each new
     * address takes the earlier one still free that its average signal picks */
    linker l(btle_params);
    std::vector<alias_link> out;
    shared(l, 1, 0, 100, -64, out);
    shared(l, 2, 0, 101, -51, out);
    shared(l, 3, 0, 104, -64, out);
    shared(l, 4, 102, 160, -62, out);
    shared(l, 5, 103, 160, -53, out);
    shared(l, 6, 106, 160, -64, out);
    settle_all(l, 160, out);
    CHECK(find(out, 4, 1, "signal") != nullptr);
    CHECK(find(out, 5, 2, "signal") != nullptr);
    CHECK(find(out, 6, 3, "signal") != nullptr);
    CHECK(named(out) == 3);

    /* Two at the same moment at the same signal: nothing */
    linker l2(btle_params);
    out.clear();
    shared(l2, 1, 0, 100, -64, out);
    shared(l2, 2, 0, 100, -63, out);
    shared(l2, 3, 101, 160, -64, out);
    shared(l2, 4, 101, 160, -63, out);
    settle_all(l2, 160, out);
    CHECK(named(out) == 0);
}

int main() {
    test_signal();
    test_findmy_quarter_hour();
    test_intermittent();
    test_counter();
    test_settle();
    test_only();
    test_two_sets();
    test_concurrent_needs();
    test_ambiguous();
    test_handoff_beats_payload();
    test_join();
    test_flood();
    test_wifi();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("ok\n");
    return 0;
}
