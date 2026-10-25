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

    The testable decision layer of phy_cell -- see phy_cell_decisions.h for why
    these live here rather than as file-statics inside phy_cell.cc.

    These are the decisions json_to_cell makes, moved across a linkable
    boundary so a test can reach them without linking the device tracker. They
    are not a separate policy layer: phy_cell.cc must not make its own variant
    of any decision here.
*/

#include "config.h"

#include "phy_cell_decisions.h"

#include "fmt.h"

#include <vector>

namespace cell_decisions {

/* Convert an ARFCN/EARFCN/NR-ARFCN to a center frequency in kHz.
 *
 * LTE EARFCN:  3GPP TS 36.101 Table 5.7.3-1
 * NR-ARFCN:    3GPP TS 38.104 Table 5.4.2.1-1
 *
 * Returns 0 if the ARFCN cannot be converted.
 */
uint64_t arfcn_to_khz(const std::string& rat, uint32_t arfcn) {
    if (rat == "LTE") {
        /* LTE EARFCN → DL frequency
         * F_DL = F_DL_low + 0.1 * (EARFCN - N_Offs_DL)
         * Result in MHz, we return kHz.
         *
         * Covers the most common bands. */
        struct earfcn_band {
            uint32_t noffs_dl;
            uint32_t noffs_dl_max;
            double fdl_low_mhz;
        };
        static const struct earfcn_band lte_bands[] = {
            {    0,   599, 2110.0},   /* Band 1 */
            {  600,  1199, 1930.0},   /* Band 2 */
            { 1200,  1949, 1805.0},   /* Band 3 */
            { 1950,  2399, 2110.0},   /* Band 4 */
            { 2400,  2649,  869.0},   /* Band 5 */
            { 2650,  2749,  875.0},   /* Band 6 */
            { 2750,  3449, 2620.0},   /* Band 7 */
            { 3450,  3799,  925.0},   /* Band 8 */
            { 3800,  4149, 1844.9},   /* Band 9 */
            { 4150,  4749, 2110.0},   /* Band 10 */
            { 4750,  4949, 1475.9},   /* Band 11 */
            { 5010,  5179,  729.0},   /* Band 12 */
            { 5180,  5279,  746.0},   /* Band 13 */
            { 5280,  5379,  758.0},   /* Band 14 */
            /* Per TS 36.101 Table 5.7.3-1: B17 DL is 734-746, B18 is 860-875,
             * B19 is 875-890. An off-by-one here (each row carrying the next
             * row's F_DL_low) is easy to make and is load-bearing, because
             * derive_key() keys on the resolved frequency: B17 EARFCN 5820 at
             * 869.0 MHz would equal B5 EARFCN 2400's real frequency, merging
             * two unrelated cells that share a PCI into one device. Pinned by
             * test_lte_frequency_table_band_edges. */
            { 5730,  5849,  734.0},   /* Band 17 */
            { 5850,  5999,  860.0},   /* Band 18 */
            { 6000,  6149,  875.0},   /* Band 19 */
            { 6150,  6449,  791.0},   /* Band 20 */
            { 6450,  6599, 1495.9},   /* Band 21 */
            { 6600,  7399, 3510.0},   /* Band 22 */
            /* The same off-by-one hazard applies to every row below: shifted
             * one band, AT&T's B29 (EARFCN 9660) would compute as 2350 MHz,
             * B30 as 462.5 MHz, and every B28 cell would land at 717-762 MHz,
             * inside B12/B13/B17's spectrum, where a same-PCI cell would merge
             * through the frequency key. Values per TS 36.101 Table 5.7.3-1;
             * pinned by test_lte_frequency_table_b23_to_b32. */
            { 7500,  7699, 2180.0},   /* Band 23 */
            { 7700,  8039, 1525.0},   /* Band 24 */
            { 8040,  8689, 1930.0},   /* Band 25 */
            { 8690,  9039,  859.0},   /* Band 26 */
            { 9040,  9209,  852.0},   /* Band 27 */
            { 9210,  9659,  758.0},   /* Band 28 */
            { 9660,  9769,  717.0},   /* Band 29 (SDL) */
            { 9770,  9869, 2350.0},   /* Band 30 */
            { 9870,  9919,  462.5},   /* Band 31 */
            { 9920, 10359, 1452.0},   /* Band 32 (SDL) */
            {36000, 36199, 1900.0},   /* Band 33 */
            {36200, 36349, 2010.0},   /* Band 34 */
            {36350, 36949, 1850.0},   /* Band 35 */
            {36950, 37549, 1930.0},   /* Band 36 */
            {37550, 37749, 1910.0},   /* Band 37 */
            {37750, 38249, 2570.0},   /* Band 38 */
            {38250, 38649, 1880.0},   /* Band 39 */
            {38650, 39649, 2300.0},   /* Band 40 */
            {39650, 41589, 2496.0},   /* Band 41 */
            {41590, 43589, 3400.0},   /* Band 42 */
            {43590, 45589, 3600.0},   /* Band 43 */
            {45590, 46589,  703.0},   /* Band 44 */
            {46590, 46789, 1447.0},   /* Band 45 */
            {46790, 54539, 5150.0},   /* Band 46 */
            {54540, 55239, 5855.0},   /* Band 47 */
            {55240, 56739, 3550.0},   /* Band 48 */
            {56740, 58239, 3550.0},   /* Band 49 */
            {58240, 59089, 1432.0},   /* Band 50 */
            {59090, 59139, 1427.0},   /* Band 51 */
            {59140, 60139, 3300.0},   /* Band 52 */
            {60140, 60254, 2483.5},   /* Band 53 */
            {60255, 60304, 1670.0},   /* Band 54 */
            {65536, 66435,  2110.0},  /* Band 65 */
            {66436, 67335,  2110.0},  /* Band 66 */
            {67336, 67535,   738.0},  /* Band 67 (SDL) */
            {67536, 67835,   753.0},  /* Band 68 */
            {67836, 68335,  2570.0},  /* Band 69 (SDL) */
            {68336, 68585,  1995.0},  /* Band 70 */
            {68586, 68935,   617.0},  /* Band 71 */
            {68936, 68985,   461.0},  /* Band 72 */
            {68986, 69035,   460.0},  /* Band 73 */
            {69036, 69465,  1475.0},  /* Band 74 */
            {69466, 70315,  1432.0},  /* Band 75 (SDL) */
            {70316, 70365,  1427.0},  /* Band 76 (SDL) */
            {70366, 70545,   728.0},  /* Band 85 */
            /* There is no LTE band 86: 70546.. is B87 (TS 36.101
             * v20.0.0 Table 5.7.3-1; pinned by test_lte_frequency_table_b54_to_b111). */
            {70546, 70595,   420.0},  /* Band 87 */
            {70596, 70645,   422.0},  /* Band 88 */
            {70646, 70655,   757.0},  /* Band 103 */
            {70656, 70705,   935.0},  /* Band 106 */
            {73386, 73485,  1820.0},  /* Band 111 */
        };

        for (size_t i = 0; i < sizeof(lte_bands) / sizeof(lte_bands[0]); i++) {
            if (arfcn >= lte_bands[i].noffs_dl && arfcn <= lte_bands[i].noffs_dl_max) {
                double freq_mhz = lte_bands[i].fdl_low_mhz +
                    0.1 * (arfcn - lte_bands[i].noffs_dl);
                return (uint64_t)(freq_mhz * 1000.0);
            }
        }
        return 0;

    } else if (rat == "NR") {
        /* NR-ARFCN → frequency
         * 3GPP TS 38.104 Table 5.4.2.1-1:
         *   Range 0–599999:    ΔF_Global=5kHz,  F_OFFS=0,       N_OFFS=0
         *   Range 600000–2016666: ΔF_Global=15kHz, F_OFFS=3000MHz, N_OFFS=600000
         *   Range 2016667–3279165: ΔF_Global=60kHz, F_OFFS=24250.08MHz, N_OFFS=2016667
         */
        if (arfcn <= 599999) {
            return (uint64_t)arfcn * 5;                    /* 5 kHz steps */
        } else if (arfcn <= 2016666) {
            return 3000000 + (uint64_t)(arfcn - 600000) * 15;  /* 15 kHz steps */
        } else if (arfcn <= 3279165) {
            return 24250080 + (uint64_t)(arfcn - 2016667) * 60; /* 60 kHz steps */
        }
        return 0;

    } else if (rat == "WCDMA") {
        /* UARFCN → frequency (simplified: common bands only)
         * F_DL = UARFCN * 0.2 MHz for most bands */
        return (uint64_t)arfcn * 200;
    }

    return 0;
}

/* Derive LTE band number from EARFCN.
 * EARFCN ranges per 3GPP TS 36.101 Table 5.7.3-1.
 * Returns 0 if unknown.
 *
 * Must answer exactly as diagspec's lte_band::earfcn_to_band (the helper's
 * copy) for every EARFCN:
 * test_earfcn_to_band_matches_the_helper_table sweeps 0..80000, so the server
 * and the DIAG path cannot label the same cell with different bands. */
int earfcn_to_band(uint32_t earfcn) {
    struct { uint32_t lo; uint32_t hi; int band; } lte[] = {
        {    0,   599,  1}, {  600,  1199,  2}, { 1200,  1949,  3},
        { 1950,  2399,  4}, { 2400,  2649,  5}, { 2650,  2749,  6},
        { 2750,  3449,  7}, { 3450,  3799,  8}, { 3800,  4149,  9},
        { 4150,  4749, 10}, { 4750,  4949, 11}, { 5010,  5179, 12},
        { 5180,  5279, 13}, { 5280,  5379, 14}, { 5730,  5849, 17},
        { 5850,  5999, 18}, { 6000,  6149, 19}, { 6150,  6449, 20},
        { 6450,  6599, 21}, { 6600,  7399, 22}, { 7500,  7699, 23},
        { 7700,  8039, 24}, { 8040,  8689, 25}, { 8690,  9039, 26},
        { 9040,  9209, 27}, { 9210,  9659, 28}, { 9660,  9769, 29},
        { 9770,  9869, 30}, { 9870,  9919, 31}, { 9920, 10359, 32},
        {36000, 36199, 33},
        {36200, 36349, 34}, {36350, 36949, 35}, {36950, 37549, 36},
        {37550, 37749, 37}, {37750, 38249, 38}, {38250, 38649, 39},
        {38650, 39649, 40}, {39650, 41589, 41}, {41590, 43589, 42},
        {43590, 45589, 43}, {45590, 46589, 44}, {46590, 46789, 45},
        {46790, 54539, 46}, {54540, 55239, 47}, {55240, 56739, 48},
        {56740, 58239, 49}, {58240, 59089, 50}, {59090, 59139, 51},
        {59140, 60139, 52}, {60140, 60254, 53}, {60255, 60304, 54},
        {65536, 66435, 65},
        {66436, 67335, 66}, {67336, 67535, 67}, {67536, 67835, 68},
        {67836, 68335, 69}, {68336, 68585, 70}, {68586, 68935, 71},
        {68936, 68985, 72}, {68986, 69035, 73}, {69036, 69465, 74},
        {69466, 70315, 75}, {70316, 70365, 76}, {70366, 70545, 85},
        {70546, 70595, 87}, {70596, 70645, 88}, {70646, 70655, 103},
        {70656, 70705, 106}, {73386, 73485, 111},
    };
    for (size_t i = 0; i < sizeof(lte) / sizeof(lte[0]); i++) {
        if (earfcn >= lte[i].lo && earfcn <= lte[i].hi)
            return lte[i].band;
    }
    return 0;
}


std::string carrier_token(const std::string& rat, uint32_t earfcn) {
    /* The 'f' marks a frequency in kHz and the 'e' a raw ARFCN. The tag is
     * not decoration: an NR-ARFCN reaches 3279165, so a bare number would be
     * ambiguous between a raw-ARFCN key and a frequency one, and a stored
     * device or a log line keyed one way would silently read as the other. It also keeps the two forms below in disjoint namespaces. */
    const uint64_t freq_khz = arfcn_to_khz(rat, earfcn);

    if (freq_khz > 0)
        return fmt::format("f{}", freq_khz);

    /* An ARFCN outside every table range converts to 0. Keying that as f0
     * would merge every unconvertible ARFCN on a PCI into one device, and a
     * conflation is worse than a split because a reader cannot undo it. */
    return fmt::format("e{}", earfcn);
}

/* ------------------------------------------------------------------------
 * PLMN identity -- see the header for why the digit count is
 * data rather than formatting.
 * ------------------------------------------------------------------------ */

static bool all_digits(const std::string& s) {
    if (s.empty())
        return false;
    for (unsigned char c : s)
        if (c < '0' || c > '9')
            return false;
    return true;
}

bool mcc_has_three_digit_mnc(int64_t mcc) {
    /* WiGLE's determineMnc() consults a recognised-MNC table; the MCC-BLOCK
     * form of that table is below. These are the assignments that broadcast a
     * 3-digit MNC -- overwhelmingly ITU Region 2.
     *
     * A block table is an approximation of a per-PLMN table, and it is only
     * ever consulted when the digits were already destroyed upstream (see
     * plmn_from_numbers). Every source that can carry the broadcast string
     * must, and then this function is never reached. */
    if (mcc >= 310 && mcc <= 316)   /* United States */
        return true;
    switch (mcc) {
        case 302:                   /* Canada */
        case 334:                   /* Mexico */
        case 338:                   /* Jamaica */
        case 342: case 344: case 346: case 348:
        case 350: case 352: case 354: case 356: case 358:
        case 360: case 362: case 363: case 365: case 366:
        case 368: case 370: case 372: case 374: case 376:
                                    /* Caribbean */
        case 708:                   /* Honduras */
        case 722:                   /* Argentina */
        case 732:                   /* Colombia */
        case 750:                   /* Falkland Islands */
            return true;
        default:
            return false;
    }
}

plmn_t plmn_from_digits(const std::string& mcc, const std::string& mnc) {
    plmn_t out;

    if (!all_digits(mcc) || !all_digits(mnc))
        return out;
    if (mcc.size() > 3 || mnc.size() < 2 || mnc.size() > 3)
        return out;

    /* The MCC is three digits by 3GPP definition, so a shorter string can only
     * be a dropped leading zero -- pad it. The MNC is NOT padded: its length is
     * the thing being preserved. */
    out.mcc = std::string(3 - mcc.size(), '0') + mcc;
    out.mnc = mnc;
    out.present = true;
    return out;
}

plmn_t plmn_from_numbers(int64_t mcc, int64_t mnc) {
    plmn_t out;

    /* Matches derive_key's long-standing asymmetric bound: MNC 0 is a real
     * network (MCC 460 / MNC 00), MCC 0 is not a country. */
    if (mcc <= 0 || mcc > 999 || mnc < 0 || mnc > 999)
        return out;

    /* An MNC that needs three digits to be written at all gets three whatever
     * the block table says -- truncating 262/120 to "20" names a different
     * network, which is the failure this whole change is about. */
    const int digits = (mnc >= 100 || mcc_has_three_digit_mnc(mcc)) ? 3 : 2;

    return plmn_from_digits(fmt::format("{:03d}", mcc),
            fmt::format("{:0{}d}", mnc, digits));
}

plmn_t plmn_from_json(const nlohmann::json& j) {
    const auto mcc_j = j.contains("mcc") ? j["mcc"] : nlohmann::json();
    const auto mnc_j = j.contains("mnc") ? j["mnc"] : nlohmann::json();

    if (mcc_j.is_string() && mnc_j.is_string())
        return plmn_from_digits(mcc_j.get<std::string>(),
                mnc_j.get<std::string>());

    if (mcc_j.is_number() && mnc_j.is_number())
        return plmn_from_numbers(mcc_j.get<int64_t>(), mnc_j.get<int64_t>());

    if (mcc_j.is_string() && mnc_j.is_number())
        return plmn_from_numbers(
                strtoll(mcc_j.get<std::string>().c_str(), nullptr, 10),
                mnc_j.get<int64_t>());

    if (mcc_j.is_number() && mnc_j.is_string())
        return plmn_from_digits(fmt::format("{:03d}", mcc_j.get<int64_t>()),
                mnc_j.get<std::string>());

    return plmn_t();
}

int64_t lte_enb_id(int64_t eci) {
    return eci >> 8;
}

int64_t lte_sector(int64_t eci) {
    return eci & 0xff;
}

cell_key_t derive_key(const std::string& rat, int64_t mcc, int64_t mnc,
        int64_t tac, int64_t cid, int64_t pci, bool have_earfcn, uint32_t earfcn) {
    return derive_key(rat, plmn_from_numbers(mcc, mnc), tac, cid, pci,
            have_earfcn, earfcn);
}

cell_key_t derive_key(const std::string& rat, const plmn_t& plmn,
        int64_t tac, int64_t cid, int64_t pci, bool have_earfcn, uint32_t earfcn) {
    cell_key_t out;

    if (plmn.present && cid > 0) {
        /* An absent TAC encodes as 0 rather than being omitted, so the key keeps
         * a fixed shape. Two observations of the same cell, one with a TAC and
         * one without, therefore produce different keys and different devices --
         * pinned here so a change to it is a deliberate act rather than a side
         * effect. */
        /* WiGLE's key, with the MNC as broadcast and no re-padding. A
         * "{:03d}{:03d}_..." form would emit `234015_` for a network WiGLE
         * calls `23415_` -- a different operator to both the CSV importer and
         * the /api/v2/cell/search?cell_op= endpoint, for every 2-digit-MNC
         * PLMN. The digits come from plmn_t, which carries the broadcast
         * string rather than re-deriving it.
         *
         * The key is hashed into the device MAC (cell_key_to_mac_bytes), so
         * devices stored under a zero-padded key do not merge with these. A
         * key that agrees with WiGLE is worth that one-time split. */
        out.key = fmt::format("{}_{}_{}", plmn.joined(),
                (tac >= 0 ? tac : 0), cid);
        out.full_identity = true;
        out.valid = true;
    } else if (pci >= 0 && have_earfcn) {
        /* Keyed on the resolved downlink frequency, not the raw EARFCN.
         * LTE band 4 is a subset of band 66: the same 2145 MHz carrier is
         * EARFCN 2300 under B4 and 66786 under B66, and vendors disagree
         * about which to report -- Quectel's AT+QENG says B4/2300, Telit's
         * AT#MONI says B66/66786. Keying on the raw value would make two
         * modems (e.g. an EG25-G and an LM960A18 on the same network) track
         * one tower as two devices, splitting observation_count, min/max RSRP
         * and the seen_via provenance between the halves. B2/B25 and
         * B12/B17/B85 overlap the same way.
         *
         * arfcn_to_khz() resolves both spellings to 2145000 -- the frequency
         * is not in dispute, only the key. The reported
         * band/EARFCN stay on the record as display fields; they are genuine
         * per-vendor observation data, they just must not partition identity.
         * Full-identity cells are unaffected: they key on MCC_MNC_TAC_ECI,
         * which is already band-agnostic.
         *
         * The 'f' marks the value as a frequency in kHz; see carrier_token()
         * for why the tag matters. */
        out.key = fmt::format("{}_pci{}_{}", rat, pci,
                carrier_token(rat, earfcn));
        out.valid = true;
    }

    return out;
}

bool have_usable_rsrp(bool rsrp_is_number, int rsrp) {
    return rsrp_is_number && rsrp != 0;
}

std::string channel_string(const std::string& rat, int explicit_band,
        bool have_earfcn, uint32_t earfcn) {
    int band_num = 0;

    if (explicit_band > 0) {
        band_num = explicit_band;
    } else if (have_earfcn && rat == "LTE") {
        /* LTE only. An NR-ARFCN run through the LTE band table would land in
         * whichever LTE range happens to contain the integer and report a
         * fabricated band -- so NR without an explicit `band` key correctly
         * yields no channel string rather than a wrong one. */
        band_num = earfcn_to_band(earfcn);
    }

    if (band_num > 0)
        return fmt::format("{} B{}", rat, band_num);

    return std::string();
}

std::string device_name(const cell_key_t& key, const std::string& rat,
        int64_t pci, uint32_t earfcn, int band_num) {
    if (key.full_identity)
        return fmt::format("{} {}", rat, key.key);

    /* Partial identity -- built from components rather than from the key, which
     * would redundantly repeat the RAT. */
    if (band_num > 0)
        return fmt::format("{} PCI {} B{}", rat, pci, band_num);

    return fmt::format("{} PCI {} EARFCN {}", rat, pci, earfcn);
}

/* ------------------------------------------------------------------------
 * Provenance (seen_via) accumulation
 * ------------------------------------------------------------------------ */

const std::vector<std::string>& prov_field_keys() {
    /* Verbatim from prov_contributed_fields in phy_cell.cc. */
    static const std::vector<std::string> keys = {
        "rat", "mcc", "mnc", "tac", "cell_id", "pci", "earfcn",
        "band", "bandwidth", "rsrp", "rsrq", "sinr", "rssi",
        "operator_name", "duplex",
    };
    return keys;
}

std::vector<std::string> contributed_fields(const std::vector<std::string>& present) {
    std::vector<std::string> out;

    /* Walk the CANONICAL list and filter, not the caller's list -- see the
     * header. Same loop shape as the original, which iterated `keys` and asked
     * the JSON about each one. */
    for (const auto& k : prov_field_keys()) {
        for (const auto& p : present) {
            if (p == k) {
                out.push_back(k);
                break;
            }
        }
    }

    return out;
}

void merge_prov_fields(std::vector<std::string>& existing,
        const std::vector<std::string>& incoming) {
    for (const auto& f : incoming) {
        bool found = false;
        for (const auto& e : existing) {
            if (e == f) {
                found = true;
                break;
            }
        }
        if (!found)
            existing.push_back(f);
    }
}

bool prov_origin_wins(const std::string& incoming_origin) {
    return !incoming_origin.empty();
}

/* ------------------------------------------------------------------------
 * PCI <-> full-identity promotion
 * ------------------------------------------------------------------------ */

std::string promotion_map_key(const std::string& rat, int64_t pci,
        uint32_t earfcn) {
    return fmt::format("{}_{}_{}", rat, pci, carrier_token(rat, earfcn));
}

pci_promotion_t pci_promotion(const std::string& rat, int64_t pci,
        bool have_earfcn, uint32_t earfcn, bool full_identity) {
    pci_promotion_t out;

    if (pci < 0 || !have_earfcn)
        return out;

    out.active = true;

    /* The rat qualifier is required; see the header. It must match the
     * qualifier already present in peer_cell_key below, or direction 2 links
     * across RATs.
     *
     * Both keys go through carrier_token() for the band-overlap reason: a promotion
     * registered by a modem that calls the carrier B4/2300 must be findable by
     * one that calls it B66/66786, and peer_cell_key IS the device MAC, so if
     * it stopped matching derive_key()'s partial form the promotion would link
     * to a device that does not exist. That agreement is what
     * test_promotion_keys_agree_across_rats pins -- the two spellings drifting
     * apart is the bug, so there is only one spelling. */
    out.map_key = promotion_map_key(rat, pci, earfcn);

    if (full_identity) {
        out.register_self = true;
        out.peer_cell_key = fmt::format("{}_pci{}_{}", rat, pci,
                carrier_token(rat, earfcn));
    } else {
        out.consult_map = true;
    }

    return out;
}

void cell_key_to_mac_bytes(const std::string& cell_key, uint8_t out[6]) {
    /* FNV-1a, 64-bit. Chosen over an adler32 pair for the reason the header
     * gives: adler32's ls1 is a plain byte sum, so a constant salt adds a
     * constant and the low 16 bits of the address become a redundant copy of
     * the preceding 16. FNV-1a is eleven lines, needs no library, and its
     * avalanche puts real entropy in every one of the 48 bits we keep. */
    uint64_t h = 1469598103934665603ULL;          /* FNV offset basis */
    for (unsigned char c : cell_key) {
        h ^= (uint64_t)c;
        h *= 1099511628211ULL;                    /* FNV prime */
    }

    /* Take the HIGH 48 bits: FNV-1a's final multiply leaves the low byte the
     * least mixed, and byte 0 is where the two address bits get forced. */
    for (int i = 0; i < 6; i++)
        out[i] = (uint8_t)((h >> (8 * (7 - i))) & 0xFF);

    out[0] |= 0x02;   /* locally administered -- this address is synthetic */
    out[0] &= 0xFE;   /* unicast -- a group-bit address is not a device */
}

/* The single spelling of the relationship name. A typo at one of several call
 * sites would file a reverse edge under a different relationship, yielding a
 * link that resolves A->B and not B->A. There is one place to typo, and the
 * test asserts both edges read it. */
static const char kCellIdentityRelationship[] = "cell_identity";

std::vector<related_link_t> related_links(bool peer_resolved) {
    if (!peer_resolved)
        return {};

    /* Exactly two, exact reverses of each other, one relationship name. Both
     * promotion directions produce this same pair -- direction 1 links a fresh
     * full-identity device to an existing PCI-only one, direction 2 the reverse
     * discovery -- which is why one function serves both. */
    return {
        { true,  kCellIdentityRelationship },   /* self -> peer */
        { false, kCellIdentityRelationship },   /* peer -> self */
    };
}

map_claim_t pci_map_claim(bool slot_occupied, bool holder_is_self) {
    if (!slot_occupied)
        return map_claim_t::claim;
    if (holder_is_self)
        return map_claim_t::reaffirm;
    return map_claim_t::ambiguous;
}

}  // namespace cell_decisions
