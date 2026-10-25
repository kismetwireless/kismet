/* Tests for the BTLE location tracker decoders, with synthetic payloads only.
 *
 *   g++ -std=c++17 -Wall -I. test/btle_tracker/decoder_test.cc \
 *       bluetooth_parsers/btle_tracker.cc -o /tmp/btle_tracker_test && /tmp/btle_tracker_test
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "bluetooth_parsers/btle_tracker.h"

using namespace btle_tracker;

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

/* Service data as it follows the 0x16 AD type: UUID FD5A, then a 20 byte payload */
static std::vector<uint8_t> smarttag(uint8_t byte0, uint8_t flags) {
    return {
        0x5a, 0xfd,
        byte0,
        0x56, 0x34, 0x12,                                   /* aging counter 0x123456 */
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,     /* privacy id */
        flags,
        0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,           /* undocumented */
    };
}

static bool decode(const std::vector<uint8_t>& v, smarttag_info& out) {
    return decode_samsung_smarttag(v.data(), v.size(), out);
}

int main() {
    smarttag_info i;

    /* Every state */
    const char *names[8] = { "unknown", "premature_offline", "offline", "overmature_offline",
        "connected", "connected", "connected", "unknown" };
    for (uint8_t s = 0; s < 8; s++) {
        smarttag_info st;
        CHECK(decode(smarttag(0x10 | s, 0x03), st));
        CHECK(st.state == s);
        CHECK(strcmp(smarttag_state_str(st.state), names[s]) == 0);
        CHECK(st.separated() == (s >= 1 && s <= 3));
    }

    /* Fields */
    CHECK(decode(smarttag(0x13, 0x07), i));
    CHECK(i.aging_counter == 0x123456);
    CHECK(i.privacy_id == std::string("\x01\x23\x45\x67\x89\xab\xcd\xef", 8));
    CHECK(i.flags == 0x07);
    CHECK(i.battery() == battery_level::full);
    CHECK(i.uwb());

    /* Battery and UWB bits */
    const char *levels[4] = { "very_low", "low", "medium", "full" };
    for (uint8_t b = 0; b < 4; b++) {
        smarttag_info bt;
        CHECK(decode(smarttag(0x13, b), bt));
        CHECK(strcmp(battery_level_str(bt.battery()), levels[b]) == 0);
        CHECK(!bt.uwb());
    }
    CHECK(decode(smarttag(0x13, 0xf8 | 0x01), i));
    CHECK(i.battery() == battery_level::low);
    CHECK(!i.uwb());
    CHECK(i.flags == 0xf9);

    /* Wrong UUID */
    auto v = smarttag(0x13, 0x03);
    v[0] = 0xfa;
    v[1] = 0xff;
    CHECK(!decode(v, i));
    v = smarttag(0x13, 0x03);
    std::swap(v[0], v[1]);
    CHECK(!decode(v, i));

    /* Wrong frame id; the lower 3 bits are the state */
    for (unsigned int b = 0; b < 256; b++) {
        smarttag_info f;
        bool ok = decode(smarttag((uint8_t) b, 0x03), f);
        CHECK(ok == ((b & 0xf8) == 0x10));
    }

    /* Length: UUID plus 13 bytes is the shortest frame */
    v = smarttag(0x13, 0x03);
    for (size_t len = 0; len < 2 + smarttag_min_len; len++)
        CHECK(!decode_samsung_smarttag(v.data(), len, i));
    CHECK(decode_samsung_smarttag(v.data(), 2 + smarttag_min_len, i));
    CHECK(i.flags == 0x03);
    CHECK(!decode_samsung_smarttag(nullptr, v.size(), i));

    /* Type names */
    CHECK(strcmp(tracker_type_str(tracker_type::samsung_smarttag), "samsung_smarttag") == 0);
    CHECK(strcmp(tracker_type_str(tracker_type::none), "unknown") == 0);

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }

    printf("btle_tracker decoder: all tests passed\n");
    return 0;
}
