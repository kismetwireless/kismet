/* Tests for the Continuity Handoff counter, with synthetic payloads only.
 *
 *   g++ -std=c++20 -Wall -g -fsanitize=address,undefined -I. test/btle_continuity/decoder_test.cc \
 *       bluetooth_parsers/btle_continuity.cc -o /tmp/btle_continuity_test && /tmp/btle_continuity_test
 */

#include <cstdio>
#include <vector>

#include "bluetooth_parsers/btle_continuity.h"

using namespace btle_continuity;

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

constexpr uint8_t handoff_type = 0x0c;
constexpr uint8_t nearby_info_type = 0x10;
constexpr uint8_t homekit_type = 0x06;

/* Manufacturer data: company 004C, then the messages */
static std::vector<uint8_t> apple() {
    return { 0x4c, 0x00 };
}

/* A Handoff message: clipboard status, counter (LE), then 11 bytes standing in for the payload */
static void add_handoff(std::vector<uint8_t>& v, uint16_t seq, uint8_t len = 14) {
    std::vector<uint8_t> val = { 0x00, (uint8_t) (seq & 0xff), (uint8_t) (seq >> 8) };
    for (uint8_t k = 0; k < 11; k++)
        val.push_back(0xa0 + k);
    val.resize(len < val.size() ? len : val.size());

    v.push_back(handoff_type);
    v.push_back(len);
    v.insert(v.end(), val.begin(), val.end());
}

static bool decode(const std::vector<uint8_t>& v, info& out) {
    return decode_manuf_data(v.data(), v.size(), out);
}

static bool saw_handoff(const info& i) {
    return i.seen_types & ((uint32_t) 1 << handoff_type);
}

static void test_counter() {
    for (const uint16_t seq : { (uint16_t) 0x0000, (uint16_t) 0x0001, (uint16_t) 0x1234,
            (uint16_t) 0xfffe, (uint16_t) 0xffff }) {
        auto v = apple();
        add_handoff(v, seq);

        info i;
        CHECK(decode(v, i));
        CHECK(i.handoff.present);
        CHECK(i.handoff.seq == seq);
        CHECK(saw_handoff(i));
    }

    /* Byte order: 0x34 0x12 is 0x1234 */
    std::vector<uint8_t> v = apple();
    v.insert(v.end(), { handoff_type, 0x03, 0x01, 0x34, 0x12 });
    info i;
    CHECK(decode(v, i));
    CHECK(i.handoff.present && i.handoff.seq == 0x1234);
}

static void test_short_values() {
    /* The counter needs 3 bytes of value; a shorter one is no Handoff, and isn't read past */
    for (uint8_t len = 0; len < 3; len++) {
        auto v = apple();
        add_handoff(v, 0x4242, len);

        info i;
        decode(v, i);
        CHECK(!i.handoff.present);
        CHECK(!saw_handoff(i));
    }

    /* Length byte claims more than the frame holds */
    auto v = apple();
    v.insert(v.end(), { handoff_type, 0x0e, 0x00, 0x01, 0x02 });
    info i;
    decode(v, i);
    CHECK(!i.handoff.present);
}

/* Every prefix of a full frame: no reads past the end, and the counter only once it's all there */
static void test_truncation() {
    auto full = apple();
    full.insert(full.end(), { nearby_info_type, 0x02, 0x01, 0x02 });
    add_handoff(full, 0xbeef);

    const size_t handoff_end = 2 + 4 + 2 + 14;

    for (size_t n = 0; n <= full.size(); n++) {
        std::vector<uint8_t> cut(full.begin(), full.begin() + n);
        info i;
        decode_manuf_data(cut.empty() ? nullptr : cut.data(), cut.size(), i);

        if (n >= handoff_end) {
            CHECK(i.handoff.present && i.handoff.seq == 0xbeef);
        } else {
            CHECK(!i.handoff.present);
        }
    }
}

static void test_first_wins() {
    auto v = apple();
    add_handoff(v, 0x0102);
    add_handoff(v, 0x0304);

    info i;
    CHECK(decode(v, i));
    CHECK(i.handoff.present && i.handoff.seq == 0x0102);

    /* A short first one doesn't count, so the next full one does */
    v = apple();
    add_handoff(v, 0x0102, 2);
    add_handoff(v, 0x0304);
    i = info{};
    CHECK(decode(v, i));
    CHECK(i.handoff.present && i.handoff.seq == 0x0304);
}

/* HomeKit's length byte carries flags in the top bits; the Handoff after it is still found */
static void test_after_homekit() {
    auto v = apple();
    v.insert(v.end(), { homekit_type, 0xed, 0x31, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
    add_handoff(v, 0x7777);

    info i;
    CHECK(decode(v, i));
    CHECK(i.handoff.present && i.handoff.seq == 0x7777);
}

static void test_reset() {
    auto v = apple();
    add_handoff(v, 0x1111);
    info i;
    CHECK(decode(v, i));

    /* A frame without a Handoff leaves none from the last one */
    v = apple();
    v.insert(v.end(), { nearby_info_type, 0x02, 0x01, 0x02 });
    CHECK(decode(v, i));
    CHECK(!i.handoff.present);
}

int main() {
    test_counter();
    test_short_values();
    test_truncation();
    test_first_wins();
    test_after_homekit();
    test_reset();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("ok\n");
    return 0;
}
