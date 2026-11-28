/* Tests for the 802.11 PHY rate decoders (dot11_phy_rate.cc): known rates from the 802.11
 * rate tables for HT, VHT, HE, EHT, S1G and legacy rates, every width, GI, RU and stream
 * count, reserved and unknown values, EHT TLV lengths, multi-user frames, the PPI 802.11n
 * field from bytes, the PPI logger's rate field, and the per-header collector (last field
 * wins, bad PLCP, EHT with U-SIG in either order, OpenBSD bit 14).
 *
 *   tools/unit.sh <tree> test/dot11_rate/rate_test.cc dot11_phy_rate.cc --flavor ubsan
 */

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

#include "dot11_phy_rate.h"
#include "radiotap_walk.h"

namespace {

int failures = 0;
int checks = 0;
std::string current_case;

#define CHECK(cond) do { \
    checks++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s [%s]\n", __FILE__, __LINE__, #cond, current_case.c_str()); \
        failures++; \
    } \
} while (0)

#define CHECK_EQ(a, b) do { \
    checks++; \
    const auto va_ = (a); \
    const auto vb_ = (b); \
    if (!(va_ == vb_)) { \
        fprintf(stderr, "FAIL %s:%d: %s == %s (%llu vs %llu) [%s]\n", __FILE__, __LINE__, #a, #b, \
                (unsigned long long) va_, (unsigned long long) vb_, current_case.c_str()); \
        failures++; \
    } \
} while (0)

using bytes = std::vector<uint8_t>;

void put16(bytes& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v));
    b.push_back(static_cast<uint8_t>(v >> 8));
}

void put32(bytes& b, uint32_t v) {
    for (int i = 0; i < 4; i++)
        b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

bytes mcs_field(uint8_t known, uint8_t flags, uint8_t idx) {
    return {known, flags, idx};
}

bytes vht_field(uint16_t known, uint8_t flags, uint8_t bw, std::array<uint8_t, 4> mcs_nss,
        uint8_t coding = 0, uint8_t group = 0) {
    bytes b;
    put16(b, known);
    b.push_back(flags);
    b.push_back(bw);
    for (auto u : mcs_nss)
        b.push_back(u);
    b.push_back(coding);
    b.push_back(group);
    put16(b, 0);
    return b;
}

bytes he_field(uint16_t d1, uint16_t d2, uint16_t d3, uint16_t d5, uint16_t d6) {
    bytes b;
    for (auto v : {d1, d2, d3, uint16_t{0}, d5, d6})
        put16(b, v);
    return b;
}

bytes eht_tlv(uint32_t known, uint32_t d0, uint32_t d1, std::vector<uint32_t> users) {
    bytes b;
    put32(b, known);
    put32(b, d0);
    put32(b, d1);
    // data[2] - data[8]
    for (int i = 0; i < 7; i++)
        put32(b, 0);
    for (auto u : users)
        put32(b, u);
    return b;
}

bytes usig_tlv(uint32_t common) {
    bytes b;
    put32(b, common);
    put32(b, 0);
    put32(b, 0);
    return b;
}

bytes s1g_tlv(uint16_t known, uint16_t d1) {
    bytes b;
    put16(b, known);
    put16(b, d1);
    put16(b, 0);
    return b;
}

// Rate tables: data bits per OFDM symbol for one stream, 802.11-2020 tables 19-27..19-30
// (HT) and 21-30.. (VHT), and the RU tables of 802.11ax 27.5 / 802.11be 36.5
constexpr std::array<uint32_t, 8> ht20_ndbps = {{ 26, 52, 78, 104, 156, 208, 234, 260 }};
constexpr std::array<uint32_t, 8> ht40_ndbps = {{ 54, 108, 162, 216, 324, 432, 486, 540 }};

constexpr uint32_t expected(uint64_t bits_per_symbol, uint32_t tsym_ns) {
    return static_cast<uint32_t>(bits_per_symbol * 1'000'000 / tsym_ns);
}

void case_ht() {
    // MCS, BW, GI known
    constexpr uint8_t known = 0x01 | 0x02 | 0x04;

    for (unsigned int idx = 0; idx < 32; idx++) {
        for (const bool forty : {false, true}) {
            for (const bool sgi : {false, true}) {
                current_case = "HT MCS " + std::to_string(idx) + (forty ? " 40" : " 20") + (sgi ? " SGI" : " LGI");
                const uint8_t flags = static_cast<uint8_t>((forty ? 1 : 0) | (sgi ? 0x04 : 0));
                const auto f = mcs_field(known, flags, static_cast<uint8_t>(idx));
                const auto r = dot11_rate_radiotap_mcs(f);

                const uint32_t nss = idx / 8 + 1;
                const uint32_t ndbps = (forty ? ht40_ndbps : ht20_ndbps)[idx % 8] * nss;

                CHECK(r.mode == dot11_phy_mode::ht);
                CHECK_EQ(r.mcs, idx % 8);
                CHECK_EQ(r.nss, nss);
                CHECK_EQ(r.bw_mhz, forty ? 40u : 20u);
                CHECK(r.gi_code == (sgi ? dot11_gi::gi_0_4 : dot11_gi::gi_0_8));
                CHECK_EQ(r.rate_kbps, expected(ndbps, sgi ? 3600 : 4000));
            }
        }
    }

    current_case = "HT published values";
    CHECK_EQ(dot11_rate_radiotap_mcs(mcs_field(known, 0, 0)).rate_kbps, 6500u);
    CHECK_EQ(dot11_rate_radiotap_mcs(mcs_field(known, 0x04, 7)).rate_kbps, 72222u);
    CHECK_EQ(dot11_rate_radiotap_mcs(mcs_field(known, 0x05, 31)).rate_kbps, 600000u);

    // 20L and 20U are 20 MHz
    CHECK_EQ(dot11_rate_radiotap_mcs(mcs_field(known, 2, 7)).bw_mhz, 20u);
    CHECK_EQ(dot11_rate_radiotap_mcs(mcs_field(known, 3, 7)).rate_kbps, 65000u);

    current_case = "HT MCS 32";
    auto r = dot11_rate_radiotap_mcs(mcs_field(known, 1, 32));
    CHECK(r.mode == dot11_phy_mode::ht);
    CHECK_EQ(r.mcs, 0u);
    CHECK_EQ(r.nss, 1u);
    CHECK_EQ(r.bw_mhz, 40u);
    CHECK(r.flags & dot11_phy_flag::ht_mcs32);
    CHECK_EQ(r.rate_kbps, 6000u);
    CHECK_EQ(dot11_rate_radiotap_mcs(mcs_field(known, 0x05, 32)).rate_kbps, 6666u);

    current_case = "HT unequal modulation";
    for (unsigned int idx = 33; idx <= 76; idx++) {
        r = dot11_rate_radiotap_mcs(mcs_field(known, 1, static_cast<uint8_t>(idx)));
        CHECK(r.mode == dot11_phy_mode::ht);
        CHECK_EQ(r.rate_kbps, 0u);
        CHECK_EQ(r.nss, idx <= 38 ? 2u : idx <= 52 ? 3u : 4u);
        CHECK_EQ(r.mcs, 0u);
    }

    current_case = "HT reserved index";
    for (unsigned int idx = 77; idx < 256; idx++) {
        r = dot11_rate_radiotap_mcs(mcs_field(known, 1, static_cast<uint8_t>(idx)));
        CHECK(r.mode == dot11_phy_mode::ht);
        CHECK_EQ(r.rate_kbps, 0u);
        CHECK_EQ(r.nss, 0u);
    }

    current_case = "HT unknowns";
    r = dot11_rate_radiotap_mcs(mcs_field(0x01 | 0x04, 0, 7));
    CHECK(r.mode == dot11_phy_mode::ht);
    CHECK_EQ(r.rate_kbps, 0u);
    CHECK_EQ(r.nss, 0u);
    CHECK_EQ(dot11_rate_radiotap_mcs(mcs_field(0x02 | 0x04, 0, 7)).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_mcs(mcs_field(0x01 | 0x02, 0, 7)).rate_kbps, 0u);
    // MCS 32 doesn't need the width
    CHECK_EQ(dot11_rate_radiotap_mcs(mcs_field(0x02 | 0x04, 0, 32)).rate_kbps, 6000u);

    current_case = "HT flags";
    r = dot11_rate_radiotap_mcs(mcs_field(known | 0x08 | 0x10 | 0x20, 0x08 | 0x10 | 0x20, 3));
    CHECK(r.flags & dot11_phy_flag::greenfield);
    CHECK(r.flags & dot11_phy_flag::ldpc);
    CHECK(r.flags & dot11_phy_flag::stbc);
    // Flags without their known bits don't count
    r = dot11_rate_radiotap_mcs(mcs_field(known, 0x08 | 0x10 | 0x20, 3));
    CHECK_EQ(r.flags, 0u);

    current_case = "HT wrong size";
    CHECK(dot11_rate_radiotap_mcs(bytes{0x07, 0}).mode == dot11_phy_mode::none);
}

constexpr uint16_t vht_known = 0x0004 | 0x0040;

void case_vht() {
    // Data subcarriers per width, and per-MCS bits x rate as numerator/denominator
    constexpr std::array<std::pair<uint8_t, uint32_t>, 4> widths = {{ {0, 52}, {1, 108}, {4, 234}, {11, 468} }};
    constexpr std::array<std::array<uint32_t, 2>, 12> mod = {{
        {1, 2}, {2, 2}, {6, 4}, {4, 2}, {12, 4}, {12, 3}, {18, 4}, {30, 6}, {24, 4}, {40, 6}, {30, 4}, {50, 6},
    }};
    constexpr std::array<uint16_t, 4> mhz = {{ 20, 40, 80, 160 }};

    for (size_t w = 0; w < widths.size(); w++) {
        for (unsigned int mcs = 0; mcs < 12; mcs++) {
            for (unsigned int nss = 1; nss <= 8; nss++) {
                for (const bool sgi : {false, true}) {
                    current_case = "VHT " + std::to_string(mhz[w]) + " MCS " + std::to_string(mcs) +
                        " NSS " + std::to_string(nss) + (sgi ? " SGI" : "");
                    const auto f = vht_field(vht_known, sgi ? 0x04 : 0, widths[w].first,
                            {static_cast<uint8_t>((mcs << 4) | nss), 0, 0, 0});
                    const auto r = dot11_rate_radiotap_vht(f);

                    const uint64_t bits = uint64_t{widths[w].second} * mod[mcs][0] * nss;
                    CHECK(r.mode == dot11_phy_mode::vht);
                    CHECK_EQ(r.mcs, mcs);
                    CHECK_EQ(r.nss, nss);
                    CHECK_EQ(r.bw_mhz, mhz[w]);
                    CHECK_EQ(r.rate_kbps, static_cast<uint32_t>(bits * 1'000'000 / (mod[mcs][1] * (sgi ? 3600u : 4000u))));
                }
            }
        }
    }

    current_case = "VHT published values";
    CHECK_EQ(dot11_rate_radiotap_vht(vht_field(vht_known, 0x04, 4, {0x91, 0, 0, 0})).rate_kbps, 433333u);
    CHECK_EQ(dot11_rate_radiotap_vht(vht_field(vht_known, 0, 4, {0x91, 0, 0, 0})).rate_kbps, 390000u);
    CHECK_EQ(dot11_rate_radiotap_vht(vht_field(vht_known, 0x04, 11, {0x98, 0, 0, 0})).rate_kbps, 6933333u);
    CHECK_EQ(dot11_rate_radiotap_vht(vht_field(vht_known, 0, 0, {0x81, 0, 0, 0})).rate_kbps, 78000u);

    current_case = "VHT sideband widths";
    constexpr std::array<uint16_t, 26> bw_of = {{
        20, 40, 20, 20, 80, 40, 40, 20, 20, 20, 20, 160, 80, 80, 40, 40, 40, 40, 20, 20, 20, 20, 20, 20, 20, 20,
    }};
    for (uint8_t code = 0; code < 32; code++) {
        const auto r = dot11_rate_radiotap_vht(vht_field(vht_known, 0, code, {0x01, 0, 0, 0}));
        if (code < bw_of.size()) {
            CHECK_EQ(r.bw_mhz, bw_of[code]);
            CHECK(r.rate_kbps > 0);
        } else {
            CHECK_EQ(r.bw_mhz, 0u);
            CHECK_EQ(r.rate_kbps, 0u);
        }
    }

    current_case = "VHT unknowns and reserved";
    CHECK_EQ(dot11_rate_radiotap_vht(vht_field(0x0040, 0, 0, {0x01, 0, 0, 0})).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_vht(vht_field(0x0004, 0, 0, {0x01, 0, 0, 0})).rate_kbps, 0u);
    // MCS 15 is unknown, 12-14 not defined, NSS above 8
    auto r = dot11_rate_radiotap_vht(vht_field(vht_known, 0, 0, {0xf1, 0, 0, 0}));
    CHECK_EQ(r.rate_kbps, 0u);
    CHECK_EQ(r.mcs, 0u);
    CHECK_EQ(r.nss, 1u);
    CHECK_EQ(dot11_rate_radiotap_vht(vht_field(vht_known, 0, 0, {0xc1, 0, 0, 0})).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_vht(vht_field(vht_known, 0, 0, {0x09, 0, 0, 0})).rate_kbps, 0u);
    r = dot11_rate_radiotap_vht(vht_field(vht_known, 0, 0, {0, 0, 0, 0}));
    CHECK(r.mode == dot11_phy_mode::vht);
    CHECK_EQ(r.rate_kbps, 0u);

    current_case = "VHT MU";
    r = dot11_rate_radiotap_vht(vht_field(vht_known | 0x0080, 0, 4, {0x51, 0x72, 0, 0}, 0, 5));
    CHECK(r.mode == dot11_phy_mode::vht);
    CHECK(r.flags & dot11_phy_flag::mu);
    CHECK_EQ(r.rate_kbps, 0u);
    // One user of an MU group: its own rate
    r = dot11_rate_radiotap_vht(vht_field(vht_known | 0x0080, 0, 4, {0, 0, 0x52, 0}, 0x04, 5));
    CHECK(r.flags & dot11_phy_flag::mu);
    CHECK(r.flags & dot11_phy_flag::ldpc);
    CHECK_EQ(r.nss, 2u);
    CHECK_EQ(r.rate_kbps, 468000u);

    current_case = "VHT flags";
    r = dot11_rate_radiotap_vht(vht_field(vht_known | 0x0001, 0x01, 0, {0x31, 0, 0, 0}, 0x01, 63));
    CHECK(r.flags & dot11_phy_flag::stbc);
    CHECK(r.flags & dot11_phy_flag::ldpc);
    CHECK(!(r.flags & dot11_phy_flag::mu));

    current_case = "VHT wrong size";
    CHECK(dot11_rate_radiotap_vht(bytes(11, 0xff)).mode == dot11_phy_mode::none);
}

constexpr uint16_t he_d1_known = 0x0020 | 0x4000;
constexpr uint16_t he_d2_gi = 0x0002;

// RU data subcarriers: 26, 52, 106, 242, 484, 996, 2x996
constexpr std::array<uint32_t, 7> he_ru_ndsc = {{ 24, 48, 102, 234, 468, 980, 1960 }};
constexpr std::array<std::array<uint32_t, 2>, 12> he_mod = {{
    {1, 2}, {2, 2}, {6, 4}, {4, 2}, {12, 4}, {12, 3}, {18, 4}, {30, 6}, {24, 4}, {40, 6}, {30, 4}, {50, 6},
}};
constexpr std::array<uint32_t, 3> he_tsym = {{ 13600, 14400, 16000 }};

void case_he() {
    for (unsigned int code = 0; code <= 10; code++) {
        const uint32_t ndsc = code < 4 ? he_ru_ndsc[code + 3] : he_ru_ndsc[code - 4];

        for (unsigned int mcs = 0; mcs < 12; mcs++) {
            for (unsigned int gi = 0; gi < 3; gi++) {
                for (const bool dcm : {false, true}) {
                    for (const unsigned int nsts : {1u, 2u, 8u}) {
                        current_case = "HE code " + std::to_string(code) + " MCS " + std::to_string(mcs) + " GI " +
                            std::to_string(gi) + " NSTS " + std::to_string(nsts) + (dcm ? " DCM" : "");
                        const auto f = he_field(he_d1_known | 0x0040, he_d2_gi,
                                static_cast<uint16_t>((mcs << 8) | (dcm ? 0x1000 : 0)),
                                static_cast<uint16_t>(code | (gi << 4)), static_cast<uint16_t>(nsts));
                        const auto r = dot11_rate_radiotap_he(f);

                        const uint64_t bits = uint64_t{ndsc} * he_mod[mcs][0] * nsts;
                        CHECK(r.mode == dot11_phy_mode::he);
                        CHECK_EQ(r.mcs, mcs);
                        CHECK_EQ(r.nss, nsts);
                        CHECK_EQ(dot11_gi_ns(r.mode, r.gi_code), (gi == 0 ? 800u : gi == 1 ? 1600u : 3200u));
                        CHECK_EQ(r.rate_kbps, static_cast<uint32_t>(bits * 1'000'000 /
                                    (uint64_t{he_mod[mcs][1]} * he_tsym[gi] * (dcm ? 2 : 1))));
                        if (code < 4) {
                            CHECK(r.ru_code == dot11_ru::full);
                            CHECK_EQ(r.bw_mhz, (code == 0 ? 20u : code == 1 ? 40u : code == 2 ? 80u : 160u));
                        } else {
                            CHECK_EQ(static_cast<unsigned int>(r.ru_code),
                                    static_cast<unsigned int>(dot11_ru::ru26) + code - 4);
                            CHECK_EQ(r.bw_mhz, 0u);
                        }
                    }
                }
            }
        }
    }

    current_case = "HE published values";
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0x0b00, 2, 1)).rate_kbps, 600490u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0x0000, 0, 1)).rate_kbps, 8602u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0x0b00, 3, 2)).rate_kbps, 2401960u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0x0b00, 0x22, 1)).rate_kbps, 510416u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0x0000, 4, 1)).rate_kbps, 882u);

    current_case = "HE STBC";
    // NSTS 2 with STBC is one stream; mac80211 writes NSTS 1 for STBC, also one stream
    auto r = dot11_rate_radiotap_he(he_field(he_d1_known | 0x0200, he_d2_gi, 0x8000, 0, 2));
    CHECK(r.flags & dot11_phy_flag::stbc);
    CHECK_EQ(r.nss, 1u);
    CHECK_EQ(r.rate_kbps, 8602u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known | 0x0200, he_d2_gi, 0x8000, 0, 1)).nss, 1u);
    // STBC bit without its known bit
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0x8000, 0, 2)).nss, 2u);

    current_case = "HE reserved and unknown";
    for (uint16_t code = 11; code < 16; code++)
        CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0, code, 1)).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0, 0x30, 1)).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, 0, 0, 0, 1)).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(0x4000, he_d2_gi, 0, 0, 1)).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(0x0020, he_d2_gi, 0, 0, 1)).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0, 0, 0)).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0x0c00, 0, 1)).rate_kbps, 0u);

    current_case = "HE MU and flags";
    r = dot11_rate_radiotap_he(he_field(he_d1_known | 0x0002 | 0x0080, he_d2_gi, 0x2000 | 0x0700, 5, 1));
    CHECK(r.flags & dot11_phy_flag::mu);
    CHECK(r.flags & dot11_phy_flag::ldpc);
    CHECK(r.ru_code == dot11_ru::ru52);
    CHECK(r.rate_kbps > 0);
    // DCM without its known bit
    r = dot11_rate_radiotap_he(he_field(he_d1_known, he_d2_gi, 0x1000, 0, 1));
    CHECK(!(r.flags & dot11_phy_flag::dcm));
    CHECK_EQ(r.rate_kbps, 8602u);

    current_case = "HE wrong size";
    CHECK(dot11_rate_radiotap_he(bytes(13, 0)).mode == dot11_phy_mode::none);
}

constexpr uint32_t eht_known_gi = 0x00000004;
constexpr uint32_t eht_known_ru = 0x00400000;
// MCS, coding and NSS known
constexpr uint32_t eht_user_known = 0x02 | 0x04 | 0x10;

constexpr uint32_t eht_user(unsigned int mcs, unsigned int nss) {
    return eht_user_known | (mcs << 20) | ((nss - 1) << 24);
}

constexpr uint32_t usig_bw(unsigned int code) {
    return 0x00000002 | (code << 15);
}

void case_eht() {
    constexpr std::array<std::array<uint32_t, 2>, 14> mod = {{
        {1, 2}, {2, 2}, {6, 4}, {4, 2}, {12, 4}, {12, 3}, {18, 4}, {30, 6}, {24, 4}, {40, 6}, {30, 4}, {50, 6},
        {36, 4}, {60, 6},
    }};
    constexpr std::array<uint32_t, 5> full_ndsc = {{ 234, 468, 980, 1960, 3920 }};
    constexpr std::array<uint16_t, 6> bw_mhz = {{ 20, 40, 80, 160, 320, 320 }};

    for (unsigned int code = 0; code < 6; code++) {
        for (unsigned int mcs = 0; mcs < 14; mcs++) {
            for (unsigned int gi = 0; gi < 3; gi++) {
                for (const unsigned int nss : {1u, 4u, 16u}) {
                    current_case = "EHT bw " + std::to_string(code) + " MCS " + std::to_string(mcs) + " GI " +
                        std::to_string(gi) + " NSS " + std::to_string(nss);
                    const auto t = eht_tlv(eht_known_gi, gi << 7, 0, {eht_user(mcs, nss)});
                    const auto r = dot11_rate_radiotap_eht(t, usig_tlv(usig_bw(code)));

                    const uint64_t bits = uint64_t{full_ndsc[std::min(code, 4u)]} * mod[mcs][0] * nss;
                    CHECK(r.mode == dot11_phy_mode::eht);
                    CHECK_EQ(r.mcs, mcs);
                    CHECK_EQ(r.nss, nss);
                    CHECK_EQ(r.bw_mhz, bw_mhz[code]);
                    CHECK_EQ(r.rate_kbps, static_cast<uint32_t>(bits * 1'000'000 / (uint64_t{mod[mcs][1]} * he_tsym[gi])));
                }
            }
        }
    }

    current_case = "EHT published values";
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(13, 1)}), usig_tlv(usig_bw(4))).rate_kbps,
            2882352u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(12, 1)}), usig_tlv(usig_bw(5))).rate_kbps,
            2594117u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(13, 16)}), usig_tlv(usig_bw(4))).rate_kbps,
            46117647u);

    current_case = "EHT MCS 14 and 15";
    auto r = dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(15, 1)}), usig_tlv(usig_bw(0)));
    CHECK(r.flags & dot11_phy_flag::dcm);
    CHECK_EQ(r.rate_kbps, 4301u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(15, 2)}), usig_tlv(usig_bw(0))).rate_kbps, 0u);
    r = dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(14, 1)}), usig_tlv(usig_bw(2)));
    CHECK_EQ(r.mcs, 14u);
    CHECK_EQ(r.rate_kbps, 0u);

    current_case = "EHT RUs and MRUs";
    constexpr std::array<uint32_t, 16> ru_ndsc = {{
        24, 48, 102, 234, 468, 980, 1960, 3920, 72, 126, 702, 1448, 1682, 2428, 2940, 3408,
    }};
    for (unsigned int size = 0; size < 16; size++) {
        for (unsigned int gi = 0; gi < 3; gi++) {
            r = dot11_rate_radiotap_eht(eht_tlv(eht_known_gi | eht_known_ru, gi << 7, size, {eht_user(0, 1)}),
                    usig_tlv(usig_bw(4)));
            CHECK_EQ(static_cast<unsigned int>(r.ru_code), static_cast<unsigned int>(dot11_ru::ru26) + size);
            CHECK_EQ(r.rate_kbps, static_cast<uint32_t>(uint64_t{ru_ndsc[size]} * 1'000'000 / (2 * he_tsym[gi])));
        }
    }
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi | eht_known_ru, 0, 8, {eht_user(0, 1)}),
                usig_tlv(usig_bw(0))).rate_kbps, 2647u);
    for (unsigned int size = 16; size < 32; size++)
        CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi | eht_known_ru, 0, size, {eht_user(0, 1)}),
                    usig_tlv(usig_bw(0))).rate_kbps, 0u);

    current_case = "EHT without U-SIG";
    r = dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(7, 2)}), {});
    CHECK(r.mode == dot11_phy_mode::eht);
    CHECK_EQ(r.mcs, 7u);
    CHECK_EQ(r.nss, 2u);
    CHECK_EQ(r.bw_mhz, 0u);
    CHECK_EQ(r.rate_kbps, 0u);
    // ... but a known RU size gives the rate: RU 242, MCS 7, 2 streams, 0.8 us
    r = dot11_rate_radiotap_eht(eht_tlv(eht_known_gi | eht_known_ru, 0, 3, {eht_user(7, 2)}), {});
    CHECK_EQ(r.bw_mhz, 0u);
    CHECK(r.ru_code == dot11_ru::ru242);
    CHECK_EQ(r.rate_kbps, 172058u);
    // An MRU, and a reserved RU size
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi | eht_known_ru, 0, 8, {eht_user(0, 1)}), {}).rate_kbps, 2647u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi | eht_known_ru, 0, 16, {eht_user(0, 1)}), {}).rate_kbps, 0u);

    current_case = "EHT U-SIG reserved, unknown, bad CRC, short";
    for (unsigned int code = 6; code < 8; code++)
        CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1)}), usig_tlv(usig_bw(code))).bw_mhz, 0u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1)}), usig_tlv(2u << 15)).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1)}),
                usig_tlv(usig_bw(2) | 0x20)).rate_kbps, 0u);
    // U-SIG shorter than its field reads the rest as 0: 320 MHz is BW code 4 (bit 17, byte 2)
    const auto usig = usig_tlv(usig_bw(4));
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1)}),
                std::span<const uint8_t>(usig.data(), 1)).bw_mhz, 20u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1)}),
                std::span<const uint8_t>(usig.data(), 2)).bw_mhz, 20u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1)}),
                std::span<const uint8_t>(usig.data(), 3)).bw_mhz, 320u);

    current_case = "EHT GI and user fields unknown";
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(0, 0, 0, {eht_user(0, 1)}), usig_tlv(usig_bw(0))).rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 3u << 7, 0, {eht_user(0, 1)}), usig_tlv(usig_bw(0))).rate_kbps,
            0u);
    r = dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1) & ~0x10u}), usig_tlv(usig_bw(0)));
    CHECK_EQ(r.nss, 0u);
    CHECK_EQ(r.rate_kbps, 0u);
    CHECK_EQ(dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1) & ~0x02u}), usig_tlv(usig_bw(0))).rate_kbps,
            0u);
    r = dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, {eht_user(3, 1) | 0x00080000}), usig_tlv(usig_bw(0)));
    CHECK(r.flags & dot11_phy_flag::ldpc);

    current_case = "EHT TLV lengths";
    const auto one = eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1)});
    const auto u = usig_tlv(usig_bw(0));
    for (size_t len : {size_t{0}, size_t{40}, size_t{41}, size_t{43}})
        CHECK(dot11_rate_radiotap_eht(std::span<const uint8_t>(one.data(), len), u).mode == dot11_phy_mode::none);
    CHECK_EQ(dot11_rate_radiotap_eht(one, u).rate_kbps, 8602u);

    auto padded = one;
    padded.push_back(0);
    CHECK(dot11_rate_radiotap_eht(padded, u).mode == dot11_phy_mode::none);

    // Two users, 17 users (past the cap): multi-user, no rate
    for (size_t n : {size_t{2}, size_t{16}, size_t{17}}) {
        current_case = "EHT " + std::to_string(n) + " users";
        r = dot11_rate_radiotap_eht(eht_tlv(eht_known_gi, 0, 0, std::vector<uint32_t>(n, eht_user(0, 1))), u);
        CHECK(r.mode == dot11_phy_mode::eht);
        CHECK(r.flags & dot11_phy_flag::mu);
        CHECK_EQ(r.rate_kbps, 0u);
    }
    current_case = "EHT user count cap";
    const auto many = dot11_rate_detail::parse_eht(eht_tlv(0, 0, 0, std::vector<uint32_t>(17, 0)));
    CHECK(many && many->n_users == 16);
}

constexpr uint16_t s1g_known = 0x0004 | 0x0008 | 0x0010 | 0x0020;

constexpr uint16_t s1g_d1(unsigned int mcs, unsigned int bw_code, unsigned int nss, bool sgi) {
    return static_cast<uint16_t>((mcs << 12) | (bw_code << 8) | ((nss - 1) << 6) | (sgi ? 0x20 : 0));
}

void case_s1g() {
    constexpr std::array<uint32_t, 5> ndsc = {{ 24, 52, 108, 234, 468 }};
    constexpr std::array<std::array<uint32_t, 2>, 10> mod = {{
        {1, 2}, {2, 2}, {6, 4}, {4, 2}, {12, 4}, {12, 3}, {18, 4}, {30, 6}, {24, 4}, {40, 6},
    }};
    constexpr std::array<uint16_t, 5> mhz = {{ 1, 2, 4, 8, 16 }};

    for (unsigned int bw = 0; bw < 5; bw++) {
        for (unsigned int mcs = 0; mcs < 10; mcs++) {
            for (unsigned int nss = 1; nss <= 4; nss++) {
                for (const bool sgi : {false, true}) {
                    current_case = "S1G " + std::to_string(mhz[bw]) + " MHz MCS " + std::to_string(mcs) + " NSS " +
                        std::to_string(nss) + (sgi ? " SGI" : "");
                    const auto r = dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(mcs, bw, nss, sgi)));
                    const uint64_t bits = uint64_t{ndsc[bw]} * mod[mcs][0] * nss;
                    CHECK(r.mode == dot11_phy_mode::s1g);
                    CHECK_EQ(r.mcs, mcs);
                    CHECK_EQ(r.nss, nss);
                    CHECK_EQ(r.bw_mhz, mhz[bw]);
                    CHECK_EQ(dot11_gi_ns(r.mode, r.gi_code), sgi ? 4000u : 8000u);
                    CHECK_EQ(r.rate_kbps, static_cast<uint32_t>(bits * 1'000'000 / (uint64_t{mod[mcs][1]} * (sgi ? 36000 : 40000))));
                }
            }
        }
    }

    current_case = "S1G published values";
    CHECK_EQ(dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(0, 0, 1, false))).rate_kbps, 300u);
    CHECK_EQ(dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(0, 1, 1, false))).rate_kbps, 650u);
    CHECK_EQ(dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(9, 4, 1, false))).rate_kbps, 78000u);
    CHECK_EQ(dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(9, 4, 1, true))).rate_kbps, 86666u);

    current_case = "S1G MCS 10";
    CHECK_EQ(dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(10, 0, 1, false))).rate_kbps, 150u);
    for (unsigned int bw = 1; bw < 5; bw++)
        CHECK_EQ(dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(10, bw, 1, false))).rate_kbps, 0u);
    // Single stream only; an unknown stream count is 1
    for (unsigned int nss = 2; nss <= 4; nss++)
        CHECK_EQ(dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(10, 0, nss, false))).rate_kbps, 0u);
    {
        const auto r = dot11_rate_radiotap_s1g(s1g_tlv(s1g_known & ~0x0008, s1g_d1(10, 0, 1, true)));
        CHECK_EQ(r.nss, 1u);
        CHECK_EQ(r.rate_kbps, 166u);
    }

    current_case = "S1G reserved and unknown";
    for (unsigned int mcs = 11; mcs < 16; mcs++)
        CHECK_EQ(dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(mcs, 0, 1, false))).rate_kbps, 0u);
    for (unsigned int bw = 5; bw < 16; bw++) {
        const auto r = dot11_rate_radiotap_s1g(s1g_tlv(s1g_known, s1g_d1(0, bw, 1, false)));
        CHECK_EQ(r.bw_mhz, 0u);
        CHECK_EQ(r.rate_kbps, 0u);
    }
    for (const uint16_t missing : {uint16_t{0x0004}, uint16_t{0x0010}, uint16_t{0x0020}})
        CHECK_EQ(dot11_rate_radiotap_s1g(s1g_tlv(s1g_known & ~missing, s1g_d1(0, 0, 1, false))).rate_kbps, 0u);
    // NSS unknown: no streams, no rate
    auto r = dot11_rate_radiotap_s1g(s1g_tlv(s1g_known & ~0x0008, s1g_d1(0, 0, 1, false)));
    CHECK_EQ(r.nss, 0u);
    CHECK_EQ(r.rate_kbps, 0u);

    current_case = "S1G short TLV";
    // The helper's TLV with no rate details, and TLVs shorter than the field
    r = dot11_rate_radiotap_s1g(s1g_tlv(0x0002 | 0x0040 | 0x0080, 0x0004));
    CHECK(r.mode == dot11_phy_mode::s1g);
    CHECK_EQ(r.rate_kbps, 0u);
    const auto full = s1g_tlv(s1g_known, s1g_d1(0, 0, 1, false));
    for (size_t len = 0; len < full.size(); len++) {
        r = dot11_rate_radiotap_s1g(std::span<const uint8_t>(full.data(), len));
        CHECK(r.mode == dot11_phy_mode::s1g);
        // The known bits fit in byte 0, and data1 of MCS 0 / 1 MHz / 1 stream / long GI is 0
        CHECK_EQ(r.rate_kbps, len == 0 ? 0u : 300u);
    }
}

void case_legacy() {
    current_case = "legacy";
    auto r = dot11_rate_legacy(12);
    CHECK(r.mode == dot11_phy_mode::legacy);
    CHECK_EQ(r.mcs, 0u);
    CHECK_EQ(r.nss, 1u);
    CHECK_EQ(r.rate_kbps, 6000u);
    CHECK_EQ(dot11_rate_legacy(11).rate_kbps, 5500u);
    CHECK_EQ(dot11_rate_legacy(108).rate_kbps, 54000u);
    CHECK(dot11_rate_legacy(0).mode == dot11_phy_mode::none);
    CHECK_EQ(dot11_rate_legacy(65535).rate_kbps, 32767500u);
}

void case_ppi() {
    current_case = "PPI flags from bytes";
    // Field header, then flags 0x00010002 little-endian: HT40 and a high bit a 16 bit read drops
    bytes f = {0x04, 0x00, 0x30, 0x00, 0x02, 0x00, 0x01, 0x00};
    auto flags = dot11_ppi_11n_flags(f);
    CHECK(flags && *flags == 0x00010002u);
    CHECK(flags && (*flags & ppi_11n_flag_ht40));

    f = {0x04, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x02};
    flags = dot11_ppi_11n_flags(f);
    CHECK(flags && *flags == 0x02000000u);
    CHECK(flags && !(*flags & ppi_11n_flag_ht40));

    CHECK(!dot11_ppi_11n_flags(bytes(7, 0)));

    current_case = "PPI 802.11n MAC+PHY";
    auto macphy = [](uint32_t field_flags, uint8_t mcs) {
        bytes b = {0x04, 0x00, 0x30, 0x00};
        put32(b, field_flags);
        put32(b, 0);
        b.push_back(0);
        b.push_back(mcs);
        b.resize(52, 0);
        return b;
    };

    auto r = dot11_rate_ppi_11n(macphy(ppi_11n_flag_ht40 | ppi_11n_flag_sgi, 15));
    CHECK(r.mode == dot11_phy_mode::ht);
    CHECK_EQ(r.bw_mhz, 40u);
    CHECK_EQ(r.mcs, 7u);
    CHECK_EQ(r.nss, 2u);
    CHECK_EQ(r.rate_kbps, 300000u);
    r = dot11_rate_ppi_11n(macphy(ppi_11n_flag_greenfield, 0));
    CHECK_EQ(r.bw_mhz, 20u);
    CHECK_EQ(r.rate_kbps, 6500u);
    CHECK(r.flags & dot11_phy_flag::greenfield);
    r = dot11_rate_ppi_11n(macphy(0, 255));
    CHECK(r.mode == dot11_phy_mode::ht);
    CHECK_EQ(r.rate_kbps, 0u);
    CHECK(dot11_rate_ppi_11n(bytes(13, 0)).mode == dot11_phy_mode::none);
    CHECK(dot11_rate_ppi_11n(bytes(14, 0)).mode == dot11_phy_mode::ht);

    current_case = "PPI 802.11n MAC";
    {
        bytes mac = {0x03, 0x00, 0x0c, 0x00};
        put32(mac, ppi_11n_flag_ht40 | ppi_11n_flag_sgi);
        mac.resize(16, 0);
        r = dot11_rate_ppi_11n_mac(mac);
        CHECK(r.mode == dot11_phy_mode::ht);
        CHECK_EQ(r.bw_mhz, 40u);
        CHECK(r.gi_code == dot11_gi::gi_0_4);
        CHECK_EQ(r.rate_kbps, 0u);
        CHECK_EQ(r.nss, 0u);
        mac[4] = 0x01;
        r = dot11_rate_ppi_11n_mac(mac);
        CHECK_EQ(r.bw_mhz, 20u);
        CHECK(r.flags & dot11_phy_flag::greenfield);
        CHECK(dot11_rate_ppi_11n_mac(bytes(7, 0)).mode == dot11_phy_mode::none);
    }

    current_case = "PPI logger rate";
    CHECK_EQ(dot11_ppi_rate_of(540), 108u);
    CHECK_EQ(dot11_ppi_rate_of(0), 0u);
    CHECK_EQ(dot11_ppi_rate_of(55), 11u);
    // Rounded to the nearest 500 kbps: 3.6 -> 3.5, 3.75 -> 4.0, 7.222 -> 7.0
    CHECK_EQ(dot11_ppi_rate_of(36), 7u);
    CHECK_EQ(dot11_ppi_rate_of(37.5), 8u);
    CHECK_EQ(dot11_ppi_rate_of(72.22), 14u);
    // S1G rates under 500 kbps: 150 kbps -> 0, 300 kbps -> 1 (500 kbps)
    CHECK_EQ(dot11_ppi_rate_of(dot11_datarate_of(150)), 0u);
    CHECK_EQ(dot11_ppi_rate_of(dot11_datarate_of(300)), 1u);
    CHECK_EQ(dot11_ppi_rate_of(327675), 65535u);
    CHECK_EQ(dot11_ppi_rate_of(327677), 65535u);
    CHECK_EQ(dot11_ppi_rate_of(327678), 0u);
    CHECK_EQ(dot11_ppi_rate_of(327680), 0u);
    CHECK_EQ(dot11_ppi_rate_of(1e9), 0u);
    CHECK_EQ(dot11_ppi_rate_of(1e300), 0u);
    CHECK_EQ(dot11_ppi_rate_of(-1), 0u);
    CHECK_EQ(dot11_ppi_rate_of(std::numeric_limits<double>::quiet_NaN()), 0u);
    CHECK_EQ(dot11_ppi_rate_of(std::numeric_limits<double>::infinity()), 0u);
    CHECK_EQ(dot11_ppi_rate_of(-std::numeric_limits<double>::infinity()), 0u);
    // The largest HT+ datarate (max_phy_rate_kbps) is past the field
    CHECK_EQ(dot11_ppi_rate_of(dot11_datarate_of(max_phy_rate_kbps)), 0u);

    current_case = "PPI common rate field: legacy only";
    CHECK_EQ(dot11_ppi_common_rate(540, dot11_rate_legacy(108)), 108u);
    CHECK_EQ(dot11_ppi_common_rate(540, dot11_phy_rate{}), 108u);
    for (const auto mode : {dot11_phy_mode::ht, dot11_phy_mode::vht, dot11_phy_mode::he, dot11_phy_mode::eht,
            dot11_phy_mode::s1g}) {
        dot11_phy_rate p;
        p.mode = mode;
        p.rate_kbps = 65000;
        CHECK_EQ(dot11_ppi_common_rate(650, p), 0u);
        // ... also when the rate wasn't known and the datarate came from elsewhere
        p.rate_kbps = 0;
        CHECK_EQ(dot11_ppi_common_rate(540, p), 0u);
    }
}

void case_collector() {
    using namespace kis_radiotap;

    const auto mcs7 = mcs_field(0x07, 0, 7);
    const bytes rate_6m = {0x8c};
    const auto vht = vht_field(vht_known, 0, 4, {0x91, 0, 0, 0});
    const auto s1g = s1g_tlv(s1g_known, s1g_d1(0, 0, 1, false));
    const auto eht = eht_tlv(eht_known_gi, 0, 0, {eht_user(0, 1)});
    const auto usig = usig_tlv(usig_bw(0));
    const bytes rx_badplcp = {0x02, 0x00};
    const bytes rx_ok = {0x01, 0x00};

    current_case = "collector legacy";
    {
        dot11_radiotap_rate c(false);
        c.field(bit_rate, rate_6m);
        CHECK(c.legacy_rate_seen());
        CHECK_EQ(c.finish().rate_kbps, 6000u);
        CHECK(c.finish().mode == dot11_phy_mode::legacy);
    }

    current_case = "collector MCS beats legacy";
    {
        dot11_radiotap_rate c(false);
        c.field(bit_rate, rate_6m);
        c.field(bit_mcs, mcs7);
        CHECK(c.legacy_rate_seen());
        CHECK_EQ(c.finish().rate_kbps, 65000u);
    }

    current_case = "collector rate field of 0 is no legacy rate";
    for (const uint8_t zero : {uint8_t{0x00}, uint8_t{0x80}}) {
        dot11_radiotap_rate c(false);
        c.field(bit_rate, bytes{zero});
        c.field(bit_mcs, mcs7);
        CHECK(!c.legacy_rate_seen());
        CHECK_EQ(c.finish().rate_kbps, 65000u);

        dot11_radiotap_rate c2(false);
        c2.field(bit_rate, bytes{zero});
        CHECK(!c2.legacy_rate_seen());
        CHECK(c2.finish().mode == dot11_phy_mode::none);
    }

    current_case = "collector nothing";
    {
        dot11_radiotap_rate c(false);
        c.field(bit_flags, bytes{0x10});
        c.field(bit_rx_flags, rx_ok);
        CHECK(c.finish().mode == dot11_phy_mode::none);
        CHECK(!c.legacy_rate_seen());
    }

    current_case = "collector bad PLCP";
    {
        dot11_radiotap_rate c(false);
        c.field(bit_rx_flags, rx_badplcp);
        c.field(bit_mcs, mcs7);
        c.tlv(32, s1g);
        CHECK(c.finish().mode == dot11_phy_mode::none);
        CHECK_EQ(c.finish().rate_kbps, 0u);
    }

    current_case = "collector OpenBSD bit 14 is its FCS";
    {
        dot11_radiotap_rate c(true);
        c.field(bit_openbsd_fcs, bytes{0x02, 0x00, 0x00, 0x00});
        c.field(bit_mcs, mcs7);
        CHECK_EQ(c.finish().rate_kbps, 65000u);
    }

    current_case = "collector S1G TLV after VHT (mm8108)";
    {
        dot11_radiotap_rate c(false);
        c.field(bit_vht, vht);
        c.tlv(32, s1g);
        const auto r = c.finish();
        CHECK(r.mode == dot11_phy_mode::s1g);
        CHECK_EQ(r.rate_kbps, 300u);
    }

    current_case = "collector S1G TLV without rate details still overrides VHT";
    {
        dot11_radiotap_rate c(false);
        c.field(bit_vht, vht);
        c.tlv(32, s1g_tlv(0x0002, 0));
        const auto r = c.finish();
        CHECK(r.mode == dot11_phy_mode::s1g);
        CHECK_EQ(r.rate_kbps, 0u);
    }

    current_case = "collector EHT then U-SIG, U-SIG then EHT";
    for (const bool usig_first : {false, true}) {
        dot11_radiotap_rate c(false);
        c.field(bit_he, he_field(he_d1_known, he_d2_gi, 0, 2, 1));
        if (usig_first)
            c.tlv(33, usig);
        c.tlv(34, eht);
        if (!usig_first)
            c.tlv(33, usig);
        const auto r = c.finish();
        CHECK(r.mode == dot11_phy_mode::eht);
        CHECK_EQ(r.rate_kbps, 8602u);
    }

    current_case = "collector S1G after EHT wins; bad EHT TLV leaves the field";
    {
        dot11_radiotap_rate c(false);
        c.tlv(34, eht);
        c.tlv(32, s1g);
        CHECK(c.finish().mode == dot11_phy_mode::s1g);

        dot11_radiotap_rate c2(false);
        c2.field(bit_vht, vht);
        c2.tlv(34, bytes(40, 0));
        CHECK(c2.finish().mode == dot11_phy_mode::vht);
    }

    current_case = "collector wrong field sizes";
    {
        dot11_radiotap_rate c(false);
        c.field(bit_rate, bytes{});
        c.field(bit_rx_flags, bytes{0x02});
        c.field(bit_mcs, bytes{0x07, 0});
        CHECK(c.finish().mode == dot11_phy_mode::none);
        CHECK(!c.legacy_rate_seen());
    }

    current_case = "GI in ns";
    CHECK_EQ(dot11_gi_ns(dot11_phy_mode::ht, dot11_gi::gi_0_4), 400u);
    CHECK_EQ(dot11_gi_ns(dot11_phy_mode::vht, dot11_gi::gi_0_8), 800u);
    CHECK_EQ(dot11_gi_ns(dot11_phy_mode::vht, dot11_gi::gi_3_2), 0u);
    CHECK_EQ(dot11_gi_ns(dot11_phy_mode::he, dot11_gi::gi_3_2), 3200u);
    CHECK_EQ(dot11_gi_ns(dot11_phy_mode::eht, dot11_gi::gi_0_4), 0u);
    CHECK_EQ(dot11_gi_ns(dot11_phy_mode::none, dot11_gi::gi_0_8), 0u);
}

}

int main() {
    case_ht();
    case_vht();
    case_he();
    case_eht();
    case_s1g();
    case_legacy();
    case_ppi();
    case_collector();

    if (failures) {
        printf("rate_test: %d of %d checks failed\n", failures, checks);
        return 1;
    }

    printf("rate_test: %d checks passed\n", checks);
    return 0;
}
