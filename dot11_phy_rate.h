/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __DOT11_PHY_RATE_H__
#define __DOT11_PHY_RATE_H__

// PHY rate of an 802.11 frame from its capture header: legacy rates, HT, VHT, HE, EHT and S1G
// MCS, streams, width and guard interval, and the data rate they give.  Field layouts are
// radiotap.org's (and PPI's 802.11n MAC+PHY field); every decoder takes the field's own bytes,
// reads them little-endian, and returns a zeroed record for anything it can't use.

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>

enum class dot11_phy_mode : uint8_t {
    none = 0, legacy = 1, ht = 2, vht = 3, he = 4, eht = 5, s1g = 6,
};

// S1G is VHT clocked down by 10, so its long and short GIs (8 and 4 us) are gi_0_8 and gi_0_4
enum class dot11_gi : uint8_t {
    gi_0_8 = 0, gi_0_4 = 1, gi_1_6 = 2, gi_3_2 = 3,
};

// HE and EHT resource units and EHT multiple RUs; full is the whole channel width
enum class dot11_ru : uint8_t {
    full = 0,
    ru26, ru52, ru106, ru242, ru484, ru996, ru2x996, ru4x996,
    mru52_26, mru106_26, mru484_242, mru996_484, mru996_484_242, mru2x996_484, mru3x996,
    mru3x996_484,
};

namespace dot11_phy_flag {
    constexpr uint8_t stbc = 0x01;
    constexpr uint8_t ldpc = 0x02;
    constexpr uint8_t dcm = 0x04;
    constexpr uint8_t mu = 0x08;
    constexpr uint8_t greenfield = 0x10;
    constexpr uint8_t ht_mcs32 = 0x20;
}

// All zero is unknown
struct dot11_phy_rate {
    dot11_phy_mode mode = dot11_phy_mode::none;
    // Per-stream MCS; HT index % 8 (0 for MCS 32 and the unequal modulation MCSs), legacy 0
    uint8_t mcs = 0;
    // Spatial streams, 1-16; 0 when not known
    uint8_t nss = 0;
    dot11_gi gi_code = dot11_gi::gi_0_8;
    // 20-320, S1G 1-16; 0 when not known (HE RU allocations don't carry the channel width)
    uint16_t bw_mhz = 0;
    dot11_ru ru_code = dot11_ru::full;
    uint8_t flags = 0;
    // 0 when it can't be computed: something unknown, a reserved value, or more than one user
    uint32_t rate_kbps = 0;
};

static_assert(std::is_trivially_copyable_v<dot11_phy_rate>);
static_assert(sizeof(dot11_phy_rate) == 12);

// Above any defined 802.11 rate (EHT tops out near 46 Gbps)
constexpr uint32_t max_phy_rate_kbps = 100'000'000;

// Guard interval in ns for a mode
uint32_t dot11_gi_ns(dot11_phy_mode mode, dot11_gi gi);

// Kismet's datarate units (100 kbps)
constexpr double dot11_datarate_of(uint32_t rate_kbps) {
    return rate_kbps / 100.0;
}

// The PPI common rate field (500 kbps units, rounded) for a datarate; 0 when out of its range
// or not a finite number
uint16_t dot11_ppi_rate_of(double datarate);

// The PPI 802.11-common rate field of a frame: it holds legacy rates only, so 0 for an HT or
// later frame (readers would take its rate as a legacy one)
uint16_t dot11_ppi_common_rate(double datarate, const dot11_phy_rate& phy);

// A legacy rate in 500 kbps units (radiotap's rate field without its basic rate bit, PPI's
// common rate)
dot11_phy_rate dot11_rate_legacy(uint16_t rate_500kbps);

// Radiotap fields MCS (bit 19, 3 bytes), VHT (bit 21, 12 bytes), HE (bit 23, 12 bytes)
dot11_phy_rate dot11_rate_radiotap_mcs(std::span<const uint8_t> field);
dot11_phy_rate dot11_rate_radiotap_vht(std::span<const uint8_t> field);
dot11_phy_rate dot11_rate_radiotap_he(std::span<const uint8_t> field);

// Radiotap TLVs S1G (type 32), and EHT (type 34) with the bandwidth from U-SIG (type 33,
// empty when the header has none); the spans are the TLV data after type and length
dot11_phy_rate dot11_rate_radiotap_s1g(std::span<const uint8_t> tlv);
dot11_phy_rate dot11_rate_radiotap_eht(std::span<const uint8_t> eht, std::span<const uint8_t> usig);

// The PPI 802.11n MAC and MAC+PHY fields' flags, from the whole field including its 4 byte
// field header; nullopt when too short
std::optional<uint32_t> dot11_ppi_11n_flags(std::span<const uint8_t> field);

// The PPI 802.11n MAC+PHY field, including its field header
dot11_phy_rate dot11_rate_ppi_11n(std::span<const uint8_t> field);

// The PPI 802.11n MAC field (no MCS): an HT frame of a known width, without a rate
dot11_phy_rate dot11_rate_ppi_11n_mac(std::span<const uint8_t> field);

constexpr uint32_t ppi_11n_flag_greenfield = 0x01;
// 1 = HT40, 0 = HT20
constexpr uint32_t ppi_11n_flag_ht40 = 0x02;
constexpr uint32_t ppi_11n_flag_sgi = 0x04;

namespace dot11_rate_detail {
    // The EHT TLV words the rate needs
    struct eht_words {
        uint32_t known = 0;
        uint32_t data0 = 0;
        uint32_t data1 = 0;
        size_t n_users = 0;
        uint32_t user0 = 0;
    };

    std::optional<eht_words> parse_eht(std::span<const uint8_t> tlv);
    std::optional<uint32_t> parse_usig(std::span<const uint8_t> tlv);
    dot11_phy_rate decode_eht(const eht_words& e, std::optional<uint32_t> usig_common);
}

// The rate of one radiotap header, fed its fields (radiotap namespace) and TLVs in order.
// The last MCS, VHT, HE, EHT or S1G field seen wins, a legacy rate only counts when none of
// them is there, and a frame flagged with a bad PLCP has no rate.  Nothing is kept from the
// spans after a call returns.
class dot11_radiotap_rate {
public:
    explicit dot11_radiotap_rate(bool openbsd_bits);

    void field(unsigned int bit, std::span<const uint8_t> data);
    void tlv(uint16_t type, std::span<const uint8_t> data);

    dot11_phy_rate finish() const;

    // The header had a legacy rate field with a rate in it
    bool legacy_rate_seen() const { return legacy_seen; }

private:
    bool openbsd;
    dot11_phy_rate legacy;
    bool legacy_seen = false;
    dot11_phy_rate rate;
    bool badplcp = false;
    // An EHT TLV after every other rate field, decoded at the end with U-SIG's bandwidth,
    // which may come before or after it
    std::optional<dot11_rate_detail::eht_words> eht;
    std::optional<uint32_t> usig_common;
};

#endif
