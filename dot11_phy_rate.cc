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

#include "config.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>

#include "dot11_phy_rate.h"
#include "radiotap_walk.h"

namespace {

constexpr uint16_t read_le16(std::span<const uint8_t> b, size_t off) {
    return static_cast<uint16_t>(b[off] | (b[off + 1] << 8));
}

constexpr uint32_t read_le32(std::span<const uint8_t> b, size_t off) {
    return static_cast<uint32_t>(b[off]) |
        (static_cast<uint32_t>(b[off + 1]) << 8) |
        (static_cast<uint32_t>(b[off + 2]) << 16) |
        (static_cast<uint32_t>(b[off + 3]) << 24);
}

// Bits per subcarrier and coding rate of MCS 0-13 (HT per stream, VHT, HE, EHT, S1G)
struct modulation {
    uint8_t bpscs;
    uint8_t r_num;
    uint8_t r_den;
};

constexpr std::array<modulation, 14> mcs_modulation = {{
    {1, 1, 2}, {2, 1, 2}, {2, 3, 4}, {4, 1, 2}, {4, 3, 4}, {6, 2, 3}, {6, 3, 4},
    {6, 5, 6}, {8, 3, 4}, {8, 5, 6}, {10, 3, 4}, {10, 5, 6}, {12, 3, 4}, {12, 5, 6},
}};

// Symbol times in ns: HT/VHT 3.2 us + GI; HE/EHT 12.8 us + GI; S1G is VHT clocked down by 10
constexpr uint32_t ht_tsym_ns = 4000;
constexpr uint32_t ht_tsym_sgi_ns = 3600;
constexpr uint32_t he_tsym_base_ns = 12800;
constexpr uint32_t s1g_tsym_ns = 40000;
constexpr uint32_t s1g_tsym_sgi_ns = 36000;

// Data subcarriers: legacy-style 20/40 MHz HT and VHT, VHT 80/160
constexpr uint32_t ndsc_ht20 = 52;
constexpr uint32_t ndsc_ht40 = 108;
constexpr uint32_t ndsc_vht80 = 234;
constexpr uint32_t ndsc_vht160 = 468;
// MCS 32: 40 MHz duplicate of a 48 subcarrier BPSK 1/2 symbol
constexpr uint32_t ndsc_ht_mcs32 = 48;

// HE/EHT data subcarriers per RU, indexed by dot11_ru (full width has its own table)
constexpr std::array<uint16_t, 17> ru_ndsc = {{
    0, 24, 48, 102, 234, 468, 980, 1960, 3920, 72, 126, 702, 1448, 1682, 2428, 2940, 3408,
}};
static_assert(ru_ndsc.size() == static_cast<size_t>(dot11_ru::mru3x996_484) + 1);

constexpr uint32_t he_full_ndsc(uint16_t bw_mhz) {
    switch (bw_mhz) {
        case 20: return ru_ndsc[static_cast<size_t>(dot11_ru::ru242)];
        case 40: return ru_ndsc[static_cast<size_t>(dot11_ru::ru484)];
        case 80: return ru_ndsc[static_cast<size_t>(dot11_ru::ru996)];
        case 160: return ru_ndsc[static_cast<size_t>(dot11_ru::ru2x996)];
        case 320: return ru_ndsc[static_cast<size_t>(dot11_ru::ru4x996)];
        default: return 0;
    }
}

constexpr uint32_t vht_ndsc(uint16_t bw_mhz) {
    switch (bw_mhz) {
        case 20: return ndsc_ht20;
        case 40: return ndsc_ht40;
        case 80: return ndsc_vht80;
        case 160: return ndsc_vht160;
        default: return 0;
    }
}

// S1G 1 MHz uses a 32 point FFT with 24 data subcarriers; 2-16 MHz are VHT 20-160
constexpr uint32_t s1g_ndsc(uint16_t bw_mhz) {
    switch (bw_mhz) {
        case 1: return 24;
        case 2: return ndsc_ht20;
        case 4: return ndsc_ht40;
        case 8: return ndsc_vht80;
        case 16: return ndsc_vht160;
        default: return 0;
    }
}

// ndsc x bits per subcarrier x coding rate x streams per symbol, in kbps; divisor halves
// the rate for DCM and S1G MCS 10 repetition
constexpr uint32_t ofdm_rate_kbps(uint32_t ndsc, unsigned int mcs, unsigned int nss,
        uint32_t tsym_ns, unsigned int divisor = 1) {
    if (mcs >= mcs_modulation.size() || nss == 0 || ndsc == 0 || tsym_ns == 0)
        return 0;

    const auto& m = mcs_modulation[mcs];
    const uint64_t bits = uint64_t{ndsc} * m.bpscs * m.r_num * nss * 1'000'000;
    const uint64_t den = uint64_t{m.r_den} * tsym_ns * divisor;

    return static_cast<uint32_t>(std::min<uint64_t>(bits / den, max_phy_rate_kbps));
}

static_assert(ofdm_rate_kbps(ndsc_ht20, 7, 1, ht_tsym_ns) == 65000);
static_assert(ofdm_rate_kbps(ndsc_ht40, 7, 4, ht_tsym_sgi_ns) == 600000);
static_assert(ofdm_rate_kbps(3920, 13, 16, he_tsym_base_ns + 800) < max_phy_rate_kbps);

constexpr uint32_t he_tsym_ns(dot11_gi gi) {
    switch (gi) {
        case dot11_gi::gi_0_8: return he_tsym_base_ns + 800;
        case dot11_gi::gi_1_6: return he_tsym_base_ns + 1600;
        case dot11_gi::gi_3_2: return he_tsym_base_ns + 3200;
        default: return 0;
    }
}

// HE and EHT GI codes: 0.8, 1.6, 3.2 us, 3 reserved
constexpr std::optional<dot11_gi> he_gi_of(unsigned int code) {
    switch (code) {
        case 0: return dot11_gi::gi_0_8;
        case 1: return dot11_gi::gi_1_6;
        case 2: return dot11_gi::gi_3_2;
        default: return std::nullopt;
    }
}

constexpr uint8_t ru_from(dot11_ru base, unsigned int offset) {
    return static_cast<uint8_t>(static_cast<unsigned int>(base) + offset);
}

// Radiotap MCS field (radiotap.org/fields/MCS)
namespace rt_mcs {
    constexpr uint8_t known_bw = 0x01;
    constexpr uint8_t known_mcs = 0x02;
    constexpr uint8_t known_gi = 0x04;
    constexpr uint8_t known_fmt = 0x08;
    constexpr uint8_t known_fec = 0x10;
    constexpr uint8_t known_stbc = 0x20;

    constexpr uint8_t flag_bw_mask = 0x03;
    constexpr uint8_t bw_40 = 1;
    constexpr uint8_t flag_sgi = 0x04;
    constexpr uint8_t flag_greenfield = 0x08;
    constexpr uint8_t flag_ldpc = 0x10;
    constexpr uint8_t flag_stbc_mask = 0x60;

    constexpr size_t len = 3;
}

// HT MCS 32 and the unequal modulation MCSs 33-76 (802.11-2020 19.5)
constexpr unsigned int ht_mcs32 = 32;
constexpr unsigned int ht_ueqm_last = 76;

constexpr uint8_t ht_ueqm_nss(unsigned int idx) {
    if (idx <= 38)
        return 2;
    if (idx <= 52)
        return 3;
    return 4;
}

// One HT index, with the width and GI if known
dot11_phy_rate ht_rate(unsigned int idx, std::optional<uint16_t> bw_mhz, std::optional<bool> sgi,
        uint8_t flags) {
    dot11_phy_rate r;
    r.mode = dot11_phy_mode::ht;
    r.flags = flags;

    if (sgi)
        r.gi_code = *sgi ? dot11_gi::gi_0_4 : dot11_gi::gi_0_8;
    if (bw_mhz)
        r.bw_mhz = *bw_mhz;

    if (idx < ht_mcs32) {
        r.mcs = static_cast<uint8_t>(idx % 8);
        r.nss = static_cast<uint8_t>(idx / 8 + 1);

        if (bw_mhz && sgi)
            r.rate_kbps = ofdm_rate_kbps(*bw_mhz == 40 ? ndsc_ht40 : ndsc_ht20, r.mcs, r.nss,
                    *sgi ? ht_tsym_sgi_ns : ht_tsym_ns);
    } else if (idx == ht_mcs32) {
        r.nss = 1;
        r.bw_mhz = 40;
        r.flags |= dot11_phy_flag::ht_mcs32;

        if (sgi)
            r.rate_kbps = ofdm_rate_kbps(ndsc_ht_mcs32, 0, 1, *sgi ? ht_tsym_sgi_ns : ht_tsym_ns);
    } else if (idx <= ht_ueqm_last) {
        // Unequal modulation: no single per-stream MCS, so no rate
        r.nss = ht_ueqm_nss(idx);
    }

    return r;
}

// Radiotap VHT field (radiotap.org/fields/VHT)
namespace rt_vht {
    constexpr uint16_t known_stbc = 0x0001;
    constexpr uint16_t known_gi = 0x0004;
    constexpr uint16_t known_bw = 0x0040;
    constexpr uint16_t known_group = 0x0080;

    constexpr uint8_t flag_stbc = 0x01;
    constexpr uint8_t flag_sgi = 0x04;

    constexpr uint8_t bw_mask = 0x1f;
    constexpr uint8_t mcs_unknown = 15;
    constexpr unsigned int max_mcs = 11;
    constexpr unsigned int max_nss = 8;

    // Group IDs 0 and 63 are SU
    constexpr uint8_t group_su_low = 0;
    constexpr uint8_t group_su_high = 63;

    constexpr size_t users = 4;
    constexpr size_t len = 12;

    // Bandwidth codes 0-25 to the width actually used (20L, 40U etc. are their sideband)
    constexpr std::array<uint16_t, 26> bw_mhz = {{
        20, 40, 20, 20, 80, 40, 40, 20, 20, 20, 20, 160, 80, 80, 40, 40, 40, 40,
        20, 20, 20, 20, 20, 20, 20, 20,
    }};
}

// Radiotap HE field (radiotap.org/fields/HE)
namespace rt_he {
    constexpr uint16_t d1_format_mask = 0x0003;
    constexpr uint16_t format_mu = 2;
    constexpr uint16_t d1_mcs_known = 0x0020;
    constexpr uint16_t d1_dcm_known = 0x0040;
    constexpr uint16_t d1_coding_known = 0x0080;
    constexpr uint16_t d1_stbc_known = 0x0200;
    constexpr uint16_t d1_bw_ru_known = 0x4000;

    constexpr uint16_t d2_gi_known = 0x0002;

    constexpr unsigned int d3_mcs_shift = 8;
    constexpr uint16_t d3_dcm = 0x1000;
    constexpr uint16_t d3_ldpc = 0x2000;
    constexpr uint16_t d3_stbc = 0x8000;

    constexpr uint16_t d5_bw_ru_mask = 0x000f;
    constexpr unsigned int d5_gi_shift = 4;

    constexpr uint16_t d6_nsts_mask = 0x000f;

    // BW/RU codes: 0-3 the channel width, 4-10 an RU
    constexpr std::array<uint16_t, 4> bw_mhz = {{ 20, 40, 80, 160 }};
    constexpr unsigned int ru_first = 4;
    constexpr unsigned int ru_last = 10;

    constexpr unsigned int max_mcs = 11;
    constexpr size_t len = 12;
}

// Radiotap EHT (radiotap.org/fields/EHT) and U-SIG (fields/U-SIG) TLVs
namespace rt_eht {
    constexpr uint32_t known_gi = 0x00000004;
    constexpr uint32_t known_ru_size = 0x00400000;

    constexpr unsigned int d0_gi_shift = 7;
    constexpr uint32_t d1_ru_size_mask = 0x1f;
    constexpr unsigned int ru_size_last = 15;

    constexpr uint32_t user_mcs_known = 0x00000002;
    constexpr uint32_t user_coding_known = 0x00000004;
    constexpr uint32_t user_nss_known = 0x00000010;
    constexpr uint32_t user_ldpc = 0x00080000;
    constexpr unsigned int user_mcs_shift = 20;
    constexpr unsigned int user_nss_shift = 24;

    // MCS 14 is BPSK-DCM with duplication; MCS 15 BPSK-DCM, single stream only
    constexpr unsigned int mcs_dup = 14;
    constexpr unsigned int mcs_dcm = 15;

    // known, data[9], then the user_info words
    constexpr size_t fixed_len = 40;
    constexpr size_t user_len = 4;
    constexpr size_t max_users = 16;

    constexpr uint32_t usig_bw_known = 0x00000002;
    constexpr uint32_t usig_bad_crc = 0x00000020;
    constexpr unsigned int usig_bw_shift = 15;
    // U-SIG BW: 20, 40, 80, 160, 320-1, 320-2; 6 and 7 aren't widths
    constexpr std::array<uint16_t, 6> usig_bw_mhz = {{ 20, 40, 80, 160, 320, 320 }};
}

// Radiotap S1G TLV (radiotap.org/fields/S1G)
namespace rt_s1g {
    constexpr uint16_t known_gi = 0x0004;
    constexpr uint16_t known_nss = 0x0008;
    constexpr uint16_t known_bw = 0x0010;
    constexpr uint16_t known_mcs = 0x0020;

    constexpr uint16_t d1_sgi = 0x0020;
    constexpr unsigned int d1_nss_shift = 6;
    constexpr unsigned int d1_bw_shift = 8;
    constexpr unsigned int d1_mcs_shift = 12;

    // 1, 2, 4, 8, 16 MHz; 5-15 reserved
    constexpr std::array<uint16_t, 5> bw_mhz = {{ 1, 2, 4, 8, 16 }};
    // MCS 10 is MCS 0 repeated twice, 1 MHz only
    constexpr unsigned int mcs_rep = 10;

    constexpr size_t len = 6;
}

// PPI 802.11n MAC+PHY: field header, flags u32, A-MPDU id u32, delimiters, MCS, streams
namespace ppi_11n {
    constexpr size_t flags_off = 4;
    constexpr size_t mcs_off = 13;
    constexpr uint8_t mcs_unknown = 255;
}

}

uint32_t dot11_gi_ns(dot11_phy_mode mode, dot11_gi gi) {
    switch (mode) {
        case dot11_phy_mode::legacy:
        case dot11_phy_mode::ht:
        case dot11_phy_mode::vht:
            if (gi == dot11_gi::gi_0_8)
                return 800;
            if (gi == dot11_gi::gi_0_4)
                return 400;
            return 0;
        case dot11_phy_mode::he:
        case dot11_phy_mode::eht: {
            const auto t = he_tsym_ns(gi);
            return t == 0 ? 0 : t - he_tsym_base_ns;
        }
        case dot11_phy_mode::s1g:
            if (gi == dot11_gi::gi_0_8)
                return 8000;
            if (gi == dot11_gi::gi_0_4)
                return 4000;
            return 0;
        default:
            return 0;
    }
}

uint16_t dot11_ppi_rate_of(double datarate) {
    if (!std::isfinite(datarate))
        return 0;

    const double r = std::round(datarate / 5);
    if (r < 0 || r > std::numeric_limits<uint16_t>::max())
        return 0;

    return static_cast<uint16_t>(r);
}

uint16_t dot11_ppi_common_rate(double datarate, const dot11_phy_rate& phy) {
    if (phy.mode != dot11_phy_mode::none && phy.mode != dot11_phy_mode::legacy)
        return 0;

    return dot11_ppi_rate_of(datarate);
}

dot11_phy_rate dot11_rate_legacy(uint16_t rate_500kbps) {
    dot11_phy_rate r;

    if (rate_500kbps == 0)
        return r;

    r.mode = dot11_phy_mode::legacy;
    r.nss = 1;
    r.rate_kbps = std::min<uint32_t>(uint32_t{rate_500kbps} * 500, max_phy_rate_kbps);
    return r;
}

dot11_phy_rate dot11_rate_radiotap_mcs(std::span<const uint8_t> field) {
    using namespace rt_mcs;

    if (field.size() != len)
        return {};

    const uint8_t known = field[0];
    const uint8_t flags = field[1];
    const uint8_t idx = field[2];

    uint8_t phy_flags = 0;
    if ((known & known_fmt) && (flags & flag_greenfield))
        phy_flags |= dot11_phy_flag::greenfield;
    if ((known & known_fec) && (flags & flag_ldpc))
        phy_flags |= dot11_phy_flag::ldpc;
    if ((known & known_stbc) && (flags & flag_stbc_mask))
        phy_flags |= dot11_phy_flag::stbc;

    if (!(known & known_mcs)) {
        dot11_phy_rate r;
        r.mode = dot11_phy_mode::ht;
        r.flags = phy_flags;
        return r;
    }

    std::optional<uint16_t> bw;
    if (known & known_bw)
        bw = (flags & flag_bw_mask) == bw_40 ? 40 : 20;

    std::optional<bool> sgi;
    if (known & known_gi)
        sgi = (flags & flag_sgi) != 0;

    return ht_rate(idx, bw, sgi, phy_flags);
}

dot11_phy_rate dot11_rate_radiotap_vht(std::span<const uint8_t> field) {
    using namespace rt_vht;

    if (field.size() != len)
        return {};

    const uint16_t known = read_le16(field, 0);
    const uint8_t flags = field[2];
    const uint8_t bw_code = field[3] & bw_mask;
    const uint8_t coding = field[8];
    const uint8_t group = field[9];

    dot11_phy_rate r;
    r.mode = dot11_phy_mode::vht;

    if ((known & known_stbc) && (flags & flag_stbc))
        r.flags |= dot11_phy_flag::stbc;
    if ((known & known_group) && group != group_su_low && group != group_su_high)
        r.flags |= dot11_phy_flag::mu;

    std::optional<size_t> user;
    for (size_t u = 0; u < users; u++) {
        if ((field[4 + u] & 0x0f) == 0)
            continue;

        if (user) {
            // More than one user present: whose rate is this frame's isn't known
            r.flags |= dot11_phy_flag::mu;
            return r;
        }
        user = u;
    }

    if (!user)
        return r;

    const unsigned int mcs = field[4 + *user] >> 4;
    const unsigned int nss = field[4 + *user] & 0x0f;

    r.nss = static_cast<uint8_t>(nss);
    if (mcs != mcs_unknown)
        r.mcs = static_cast<uint8_t>(mcs);
    if (coding & (1u << *user))
        r.flags |= dot11_phy_flag::ldpc;

    const bool gi_known = known & known_gi;
    if (gi_known && (flags & flag_sgi))
        r.gi_code = dot11_gi::gi_0_4;

    const bool bw_known = (known & known_bw) && bw_code < bw_mhz.size();
    if (bw_known)
        r.bw_mhz = bw_mhz[bw_code];

    if (mcs > max_mcs || nss > max_nss || !gi_known || !bw_known)
        return r;

    r.rate_kbps = ofdm_rate_kbps(vht_ndsc(r.bw_mhz), mcs, nss,
            r.gi_code == dot11_gi::gi_0_4 ? ht_tsym_sgi_ns : ht_tsym_ns);
    return r;
}

dot11_phy_rate dot11_rate_radiotap_he(std::span<const uint8_t> field) {
    using namespace rt_he;

    if (field.size() != len)
        return {};

    const uint16_t d1 = read_le16(field, 0);
    const uint16_t d2 = read_le16(field, 2);
    const uint16_t d3 = read_le16(field, 4);
    const uint16_t d5 = read_le16(field, 8);
    const uint16_t d6 = read_le16(field, 10);

    dot11_phy_rate r;
    r.mode = dot11_phy_mode::he;

    if ((d1 & d1_format_mask) == format_mu)
        r.flags |= dot11_phy_flag::mu;
    if ((d1 & d1_dcm_known) && (d3 & d3_dcm))
        r.flags |= dot11_phy_flag::dcm;
    if ((d1 & d1_coding_known) && (d3 & d3_ldpc))
        r.flags |= dot11_phy_flag::ldpc;
    const bool stbc = (d1 & d1_stbc_known) && (d3 & d3_stbc);
    if (stbc)
        r.flags |= dot11_phy_flag::stbc;

    // Space-time streams; with STBC two per spatial stream (mac80211 reports 1 for STBC with
    // one stream, which stays 1)
    const unsigned int nsts = d6 & d6_nsts_mask;
    r.nss = static_cast<uint8_t>(stbc ? std::max(1u, nsts / 2) : nsts);
    if (nsts == 0)
        r.nss = 0;

    const bool mcs_known = d1 & d1_mcs_known;
    if (mcs_known)
        r.mcs = static_cast<uint8_t>((d3 >> d3_mcs_shift) & 0x0f);

    std::optional<dot11_gi> gi;
    if (d2 & d2_gi_known)
        gi = he_gi_of((d5 >> d5_gi_shift) & 0x03);
    if (gi)
        r.gi_code = *gi;

    uint32_t ndsc = 0;
    if (d1 & d1_bw_ru_known) {
        const unsigned int code = d5 & d5_bw_ru_mask;

        if (code < bw_mhz.size()) {
            r.bw_mhz = bw_mhz[code];
            ndsc = he_full_ndsc(r.bw_mhz);
        } else if (code <= ru_last) {
            r.ru_code = static_cast<dot11_ru>(ru_from(dot11_ru::ru26, code - ru_first));
            ndsc = ru_ndsc[static_cast<size_t>(r.ru_code)];
        }
    }

    if (!mcs_known || r.mcs > max_mcs || !gi || ndsc == 0)
        return r;

    r.rate_kbps = ofdm_rate_kbps(ndsc, r.mcs, r.nss, he_tsym_ns(*gi),
            (r.flags & dot11_phy_flag::dcm) ? 2 : 1);
    return r;
}

std::optional<dot11_rate_detail::eht_words> dot11_rate_detail::parse_eht(std::span<const uint8_t> tlv) {
    using namespace rt_eht;

    if (tlv.size() < fixed_len + user_len || (tlv.size() % user_len) != 0)
        return std::nullopt;

    eht_words e;
    e.known = read_le32(tlv, 0);
    e.data0 = read_le32(tlv, 4);
    e.data1 = read_le32(tlv, 8);
    e.n_users = std::min((tlv.size() - fixed_len) / user_len, max_users);
    e.user0 = read_le32(tlv, fixed_len);
    return e;
}

std::optional<uint32_t> dot11_rate_detail::parse_usig(std::span<const uint8_t> tlv) {
    // Fewer bytes than the field are zero (radiotap.org/fields/TLV)
    uint32_t common = 0;
    for (size_t i = 0; i < 4 && i < tlv.size(); i++)
        common |= static_cast<uint32_t>(tlv[i]) << (8 * i);
    return common;
}

dot11_phy_rate dot11_rate_detail::decode_eht(const eht_words& e, std::optional<uint32_t> usig_common) {
    using namespace rt_eht;

    dot11_phy_rate r;
    r.mode = dot11_phy_mode::eht;

    if (e.n_users > 1) {
        r.flags |= dot11_phy_flag::mu;
        return r;
    }

    const uint32_t u = e.user0;

    const bool mcs_known = u & user_mcs_known;
    if (mcs_known)
        r.mcs = static_cast<uint8_t>((u >> user_mcs_shift) & 0x0f);
    if ((u & user_nss_known))
        r.nss = static_cast<uint8_t>(((u >> user_nss_shift) & 0x0f) + 1);
    if ((u & user_coding_known) && (u & user_ldpc))
        r.flags |= dot11_phy_flag::ldpc;
    if (mcs_known && (r.mcs == mcs_dup || r.mcs == mcs_dcm))
        r.flags |= dot11_phy_flag::dcm;

    std::optional<dot11_gi> gi;
    if (e.known & known_gi)
        gi = he_gi_of((e.data0 >> d0_gi_shift) & 0x03);
    if (gi)
        r.gi_code = *gi;

    if (usig_common && (*usig_common & usig_bw_known) && !(*usig_common & usig_bad_crc)) {
        const unsigned int code = (*usig_common >> usig_bw_shift) & 0x07;
        if (code < usig_bw_mhz.size())
            r.bw_mhz = usig_bw_mhz[code];
    }

    uint32_t ndsc = he_full_ndsc(r.bw_mhz);
    if (e.known & known_ru_size) {
        const unsigned int size = e.data1 & d1_ru_size_mask;
        if (size <= ru_size_last) {
            r.ru_code = static_cast<dot11_ru>(ru_from(dot11_ru::ru26, size));
            ndsc = ru_ndsc[static_cast<size_t>(r.ru_code)];
        } else {
            ndsc = 0;
        }
    }

    // The RU size gives the rate without a width; without either (no U-SIG), there's none
    if (!mcs_known || !gi || ndsc == 0 || r.mcs == mcs_dup)
        return r;

    if (r.mcs == mcs_dcm) {
        if (r.nss != 1)
            return r;
        r.rate_kbps = ofdm_rate_kbps(ndsc, 0, 1, he_tsym_ns(*gi), 2);
        return r;
    }

    r.rate_kbps = ofdm_rate_kbps(ndsc, r.mcs, r.nss, he_tsym_ns(*gi));
    return r;
}

dot11_phy_rate dot11_rate_radiotap_eht(std::span<const uint8_t> eht, std::span<const uint8_t> usig) {
    const auto e = dot11_rate_detail::parse_eht(eht);
    if (!e)
        return {};

    std::optional<uint32_t> common;
    if (!usig.empty())
        common = dot11_rate_detail::parse_usig(usig);

    return dot11_rate_detail::decode_eht(*e, common);
}

dot11_phy_rate dot11_rate_radiotap_s1g(std::span<const uint8_t> tlv) {
    using namespace rt_s1g;

    // Fewer bytes than the field are zero (radiotap.org/fields/TLV)
    std::array<uint8_t, len> b{};
    std::copy_n(tlv.begin(), std::min(tlv.size(), len), b.begin());

    const uint16_t known = read_le16(b, 0);
    const uint16_t d1 = read_le16(b, 2);

    dot11_phy_rate r;
    r.mode = dot11_phy_mode::s1g;

    const bool mcs_known = known & known_mcs;
    if (mcs_known)
        r.mcs = static_cast<uint8_t>(d1 >> d1_mcs_shift);
    if (known & known_nss)
        r.nss = static_cast<uint8_t>(((d1 >> d1_nss_shift) & 0x03) + 1);
    const bool gi_known = known & known_gi;
    if (gi_known && (d1 & d1_sgi))
        r.gi_code = dot11_gi::gi_0_4;
    if (known & known_bw) {
        const unsigned int code = (d1 >> d1_bw_shift) & 0x0f;
        if (code < bw_mhz.size())
            r.bw_mhz = bw_mhz[code];
    }

    if (!mcs_known || !gi_known || r.bw_mhz == 0)
        return r;

    const uint32_t tsym = r.gi_code == dot11_gi::gi_0_4 ? s1g_tsym_sgi_ns : s1g_tsym_ns;

    // MCS 10 is single stream by definition, so an unknown stream count is 1
    if (r.mcs == mcs_rep) {
        if (r.nss == 0)
            r.nss = 1;
        if (r.bw_mhz == 1 && r.nss == 1)
            r.rate_kbps = ofdm_rate_kbps(s1g_ndsc(1), 0, 1, tsym, 2);
        return r;
    }

    if (r.mcs < mcs_rep)
        r.rate_kbps = ofdm_rate_kbps(s1g_ndsc(r.bw_mhz), r.mcs, r.nss, tsym);

    return r;
}

std::optional<uint32_t> dot11_ppi_11n_flags(std::span<const uint8_t> field) {
    if (field.size() < ppi_11n::flags_off + 4)
        return std::nullopt;

    return read_le32(field, ppi_11n::flags_off);
}

dot11_phy_rate dot11_rate_ppi_11n_mac(std::span<const uint8_t> field) {
    const auto flags = dot11_ppi_11n_flags(field);
    if (!flags)
        return {};

    dot11_phy_rate r;
    r.mode = dot11_phy_mode::ht;
    r.bw_mhz = (*flags & ppi_11n_flag_ht40) ? 40 : 20;
    if (*flags & ppi_11n_flag_sgi)
        r.gi_code = dot11_gi::gi_0_4;
    if (*flags & ppi_11n_flag_greenfield)
        r.flags |= dot11_phy_flag::greenfield;
    return r;
}

dot11_phy_rate dot11_rate_ppi_11n(std::span<const uint8_t> field) {
    const auto flags = dot11_ppi_11n_flags(field);
    if (!flags || field.size() <= ppi_11n::mcs_off)
        return {};

    const uint8_t idx = field[ppi_11n::mcs_off];

    const uint8_t phy_flags = (*flags & ppi_11n_flag_greenfield) ? dot11_phy_flag::greenfield : 0;

    if (idx == ppi_11n::mcs_unknown) {
        dot11_phy_rate r;
        r.mode = dot11_phy_mode::ht;
        r.flags = phy_flags;
        return r;
    }

    const uint16_t bw_mhz = (*flags & ppi_11n_flag_ht40) ? 40 : 20;
    return ht_rate(idx, bw_mhz, (*flags & ppi_11n_flag_sgi) != 0, phy_flags);
}

dot11_radiotap_rate::dot11_radiotap_rate(bool openbsd_bits) :
    openbsd{openbsd_bits} { }

void dot11_radiotap_rate::field(unsigned int bit, std::span<const uint8_t> data) {
    dot11_phy_rate r;

    switch (bit) {
        case kis_radiotap::bit_rate:
            if (data.size() == 1) {
                // The top bit marks a basic rate
                legacy = dot11_rate_legacy(static_cast<uint16_t>(data[0] & 0x7f));
                // A rate of 0 is no rate, like PPI's common rate of 0
                legacy_seen = legacy.mode != dot11_phy_mode::none;
            }
            return;
        case kis_radiotap::bit_rx_flags: {
            // OpenBSD puts its FCS there
            constexpr uint16_t rx_flag_badplcp = 0x0002;
            if (!openbsd && data.size() == 2 && (read_le16(data, 0) & rx_flag_badplcp))
                badplcp = true;
            return;
        }
        case kis_radiotap::bit_mcs:
            r = dot11_rate_radiotap_mcs(data);
            break;
        case kis_radiotap::bit_vht:
            r = dot11_rate_radiotap_vht(data);
            break;
        case kis_radiotap::bit_he:
            r = dot11_rate_radiotap_he(data);
            break;
        default:
            return;
    }

    if (r.mode != dot11_phy_mode::none) {
        rate = r;
        eht.reset();
    }
}

void dot11_radiotap_rate::tlv(uint16_t type, std::span<const uint8_t> data) {
    constexpr uint16_t tlv_s1g = 32;
    constexpr uint16_t tlv_usig = 33;
    constexpr uint16_t tlv_eht = 34;

    switch (type) {
        case tlv_s1g:
            rate = dot11_rate_radiotap_s1g(data);
            eht.reset();
            break;
        case tlv_usig:
            usig_common = dot11_rate_detail::parse_usig(data);
            break;
        case tlv_eht:
            if (auto e = dot11_rate_detail::parse_eht(data); e)
                eht = e;
            break;
        default:
            break;
    }
}

dot11_phy_rate dot11_radiotap_rate::finish() const {
    if (badplcp)
        return {};

    if (eht)
        return dot11_rate_detail::decode_eht(*eht, usig_common);

    if (rate.mode != dot11_phy_mode::none)
        return rate;

    return legacy;
}
