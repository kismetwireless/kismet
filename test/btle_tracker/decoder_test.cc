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

/* Manufacturer data as it follows the 0xFF AD type: company 004C, then the Find My frame */
static std::vector<uint8_t> findmy(bool separated, uint8_t status) {
    std::vector<uint8_t> v = { 0x4c, 0x00, 0x12 };
    if (separated) {
        v.push_back(0x19);
        v.push_back(status);
        for (uint8_t k = 0; k < 22; k++)                    /* key bytes 6-27 */
            v.push_back(0xa0 + k);
        v.push_back(0x02);                                  /* top bits of key byte 0 */
        v.push_back(0x00);                                  /* hint */
    } else {
        v.push_back(0x02);
        v.push_back(status);
        v.push_back(0x01);
    }
    return v;
}

/* Service data: UUID FEAA, frame type, ephemeral id, optional hashed flags */
static std::vector<uint8_t> fmdn(uint8_t frame, size_t eid_len, bool flags) {
    std::vector<uint8_t> v = { 0xaa, 0xfe, frame };
    for (size_t k = 0; k < eid_len; k++)
        v.push_back((uint8_t) (0x10 + k));
    if (flags)
        v.push_back(0x5c);
    return v;
}

/* Service data: UUID FCB2, network id, near-owner byte, proprietary payload */
static std::vector<uint8_t> dult(uint8_t network_id, uint8_t status, size_t extra) {
    std::vector<uint8_t> v = { 0xb2, 0xfc, network_id, status };
    for (size_t k = 0; k < extra; k++)
        v.push_back((uint8_t) (0xe0 + k));
    return v;
}

static void test_findmy() {
    findmy_info i;
    std::vector<uint8_t> v;

    /* Both frames; status 0x50 = AirTag (bits 4-5 = 1), battery medium (bits 6-7 = 1) */
    v = findmy(true, 0x50);
    CHECK(decode_apple_findmy(v.data(), v.size(), i));
    CHECK(i.separated());
    CHECK(i.status == 0x50);
    CHECK(i.device_type() == findmy_device_airtag);
    CHECK(i.location_tracker());
    CHECK(i.battery() == battery_level::medium);
    CHECK(strcmp(separated_state_str(i.separated()), "separated") == 0);

    findmy_info n;
    v = findmy(false, 0x30);
    CHECK(decode_apple_findmy(v.data(), v.size(), n));
    CHECK(!n.separated());
    CHECK(n.device_type() == findmy_device_airpods);
    CHECK(n.battery() == battery_level::full);
    CHECK(strcmp(separated_state_str(n.separated()), "near_owner") == 0);

    /* Device types and battery levels */
    const char *types[4] = { "apple_device", "airtag", "findmy_accessory", "airpods" };
    const battery_level levels[4] = { battery_level::full, battery_level::medium,
        battery_level::low, battery_level::very_low };
    for (uint8_t t = 0; t < 4; t++) {
        for (uint8_t b = 0; b < 4; b++) {
            findmy_info s;
            v = findmy(true, (uint8_t) ((b << 6) | (t << 4) | 0x04));
            CHECK(decode_apple_findmy(v.data(), v.size(), s));
            CHECK(s.device_type() == t);
            CHECK(strcmp(findmy_device_type_str(s.device_type()), types[t]) == 0);
            CHECK(s.location_tracker() == (t != findmy_device_apple));
            CHECK(s.battery() == levels[b]);
        }
    }

    /* Other company, other Apple type, other length */
    v = findmy(true, 0x50);
    v[0] = 0x75;
    CHECK(!decode_apple_findmy(v.data(), v.size(), i));
    v = findmy(true, 0x50);
    v[2] = 0x10;
    CHECK(!decode_apple_findmy(v.data(), v.size(), i));
    for (unsigned int l = 0; l < 256; l++) {
        if (l == 0x19 || l == 0x02)
            continue;
        v = findmy(true, 0x50);
        v[3] = (uint8_t) l;
        CHECK(!decode_apple_findmy(v.data(), v.size(), i));
    }

    /* Truncated frames: the length byte counts the bytes after it */
    v = findmy(true, 0x50);
    CHECK(v.size() == 2 + 2 + 0x19);
    for (size_t len = 0; len < v.size(); len++)
        CHECK(!decode_apple_findmy(v.data(), len, i));
    v = findmy(false, 0x50);
    for (size_t len = 0; len < v.size(); len++)
        CHECK(!decode_apple_findmy(v.data(), len, i));
    CHECK(decode_apple_findmy(v.data(), v.size(), i));
    CHECK(!decode_apple_findmy(nullptr, v.size(), i));
}

static void test_fmdn() {
    fmdn_info i;
    std::vector<uint8_t> v;

    /* 160-bit and 256-bit, with and without the hashed flags */
    const size_t eids[2] = { fmdn_eid_len_160, fmdn_eid_len_256 };
    for (size_t e : eids) {
        for (int f = 0; f < 2; f++) {
            for (uint8_t frame : { fmdn_frame, fmdn_frame_utp }) {
                fmdn_info s;
                v = fmdn(frame, e, f == 1);
                CHECK(decode_google_fmdn(v.data(), v.size(), s));
                CHECK(s.frame_type == frame);
                CHECK(s.ephemeral_id.size() == e);
                CHECK((uint8_t) s.ephemeral_id[0] == 0x10);
                CHECK((uint8_t) s.ephemeral_id[e - 1] == (uint8_t) (0x10 + e - 1));
                CHECK(s.hashed_flags == (f == 1));
                CHECK(s.unwanted_tracking_protection() == (frame == fmdn_frame_utp));
                CHECK(strcmp(fmdn_state_str(s), frame == fmdn_frame_utp ?
                            "unwanted_tracking_protection" : "normal") == 0);
            }
        }
    }

    /* Eddystone frames (UID 0x00, URL 0x10, TLM 0x20, EID 0x30) and any other frame type */
    for (unsigned int b = 0; b < 256; b++) {
        fmdn_info s;
        v = fmdn((uint8_t) b, fmdn_eid_len_160, true);
        CHECK(decode_google_fmdn(v.data(), v.size(), s) == (b == 0x40 || b == 0x41));
    }

    /* Only the documented lengths */
    for (size_t e = 0; e < 40; e++) {
        for (int f = 0; f < 2; f++) {
            fmdn_info s;
            v = fmdn(fmdn_frame, e, f == 1);
            size_t plen = 1 + e + (size_t) f;
            bool ok = plen == 21 || plen == 22 || plen == 33 || plen == 34;
            CHECK(decode_google_fmdn(v.data(), v.size(), s) == ok);
        }
    }

    /* Other UUID */
    v = fmdn(fmdn_frame, fmdn_eid_len_160, false);
    v[0] = 0x5a;
    v[1] = 0xfd;
    CHECK(!decode_google_fmdn(v.data(), v.size(), i));
    CHECK(!decode_google_fmdn(nullptr, 23, i));
    v = fmdn(fmdn_frame, fmdn_eid_len_160, false);
    for (size_t len = 0; len < 3; len++)
        CHECK(!decode_google_fmdn(v.data(), len, i));
}

static void test_dult() {
    dult_info i;
    std::vector<uint8_t> v;

    v = dult(0x02, 0x00, 0);
    CHECK(decode_dult(v.data(), v.size(), i));
    CHECK(i.network_id == 0x02);
    CHECK(i.separated());
    CHECK(!i.near_owner());

    /* Only bit 0 is the near-owner bit; the reserved bits do not matter */
    for (unsigned int b = 0; b < 256; b++) {
        dult_info s;
        v = dult(0x07, (uint8_t) b, 6);
        CHECK(decode_dult(v.data(), v.size(), s));
        CHECK(s.status == b);
        CHECK(s.near_owner() == ((b & 1) == 1));
        CHECK(s.separated() == ((b & 1) == 0));
    }

    /* The proprietary payload is optional and of any length */
    for (size_t extra = 0; extra <= 22; extra++) {
        dult_info s;
        v = dult(0x01, 0x01, extra);
        CHECK(decode_dult(v.data(), v.size(), s));
        CHECK(s.network_id == 0x01);
        CHECK(s.near_owner());
    }

    /* UUID plus network ID and near-owner byte is the shortest frame */
    v = dult(0x02, 0x00, 0);
    for (size_t len = 0; len < 2 + dult_min_len; len++)
        CHECK(!decode_dult(v.data(), len, i));
    v[0] = 0xb3;
    CHECK(!decode_dult(v.data(), v.size(), i));
    CHECK(!decode_dult(nullptr, 4, i));

    /* Not the other decoders' frames */
    smarttag_info st;
    fmdn_info fm;
    v = dult(0x02, 0x00, 20);
    CHECK(!decode_samsung_smarttag(v.data(), v.size(), st));
    CHECK(!decode_google_fmdn(v.data(), v.size(), fm));
    v = fmdn(fmdn_frame, fmdn_eid_len_160, true);
    CHECK(!decode_dult(v.data(), v.size(), i));
    CHECK(!decode_samsung_smarttag(v.data(), v.size(), st));
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

    test_findmy();
    test_fmdn();
    test_dult();

    /* Type names */
    CHECK(strcmp(tracker_type_str(tracker_type::samsung_smarttag), "samsung_smarttag") == 0);
    CHECK(strcmp(tracker_type_str(tracker_type::apple_findmy), "apple_findmy") == 0);
    CHECK(strcmp(tracker_type_str(tracker_type::google_fmdn), "google_fmdn") == 0);
    CHECK(strcmp(tracker_type_str(tracker_type::dult), "dult") == 0);
    CHECK(strcmp(tracker_type_str(tracker_type::none), "unknown") == 0);

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }

    printf("btle_tracker decoder: all tests passed\n");
    return 0;
}
