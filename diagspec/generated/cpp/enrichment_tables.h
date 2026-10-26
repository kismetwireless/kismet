// SPDX-License-Identifier: GPL-2.0-or-later
// GENERATED FILE -- DO NOT EDIT BY HAND.
// Rendered from the table data the reference decoder also carries;
// a drift check keeps the two equal. Regenerate it rather than editing it.
#ifndef DIAGSPEC_GENERATED_ENRICHMENT_TABLES_H
#define DIAGSPEC_GENERATED_ENRICHMENT_TABLES_H

#include <array>
#include <map>
#include <string>

namespace diagspec {

namespace asn1 {

// Q-OffsetRange ENUMERATED -> dB offset (TS 36.331 6.3.4). 31 entries. Shared across LTE SIB3 / SIB4 / SIB5 neighbor-cell q-offset handling.
constexpr std::array<int, 31> kQOffsetRangeDb = {
    -24, -22, -20, -18, -16, -14, -12, -10, -8, -6,
    -5, -4, -3, -2, -1, 0, 1, 2, 3, 4,
    5, 6, 8, 10, 12, 14, 16, 18, 20, 22,
    24,
};

// PhysCellIdRange `range` ENUMERATED -> PCI count (TS 36.331 6.3.4). 16 entries; 504 repeats at indices 13..15 (spec-reserved slots == "all PCIs").
constexpr std::array<int, 16> kPhysCellIdRangeValues = {
    4, 8, 12, 16, 24, 32, 48, 64, 84, 96,
    128, 168, 252, 504, 504, 504,
};

// q-Hysteresis ENUMERATED -> dB (TS 36.331 6.3.4). 16 entries; non-uniform (unit steps in [0,6], then 2-dB steps to 24). Used by SIB3 cellReselectionInfoCommon.q-Hyst.
constexpr std::array<int, 16> kQHysteresisDb = {
    0, 1, 2, 3, 4, 5, 6, 8, 10, 12,
    14, 16, 18, 20, 22, 24,
};

// AllowedMeasBandwidth ENUMERATED -> RBs (TS 36.331). {mbw6..mbw100} -> 6 LTE RB widths. LTE-only -- NR uses carrierBandwidth instead.
constexpr std::array<int, 6> kAllowedMeasBandwidthRbs = {
    6, 15, 25, 50, 75, 100,
};

// NR SubcarrierSpacing ENUMERATED -> kHz (TS 38.331). {kHz15..kHz240}; the 3 spare slots are not modeled. NR-only -- LTE has a fixed 15 kHz SCS.
constexpr std::array<int, 5> kNrSubcarrierSpacingKhz = {
    15, 30, 60, 120, 240,
};

}  // namespace asn1

namespace lte_rrc {

// v20 byte[12] channel enum: BCCH-DL-SCH / PCCH / DL-CCCH / DL-DCCH / UL-CCCH / UL-DCCH at 2/5/6/7/8/9.
inline const std::map<int, std::string>& v20_channel_names() {
    static const std::map<int, std::string> kTable = {
        {2, "BCCH-DL-SCH"},
        {5, "PCCH"},
        {6, "DL-CCCH"},
        {7, "DL-DCCH"},
        {8, "UL-CCCH"},
        {9, "UL-DCCH"},
    };
    return kTable;
}

// Per-wire-version channel enums for the non-v20 parse path, each pinned by a byte-identical qcsuper GSMTAP byte-join. Only OBSERVED+joined channel_type values are mapped; extend a version only from a fresh join.
inline const std::map<int, std::map<int, std::string>>& nonv20_channel_names() {
    static const std::map<int, std::map<int, std::string>> kTable = {
        {2, {{2, "BCCH-DL-SCH"}, {4, "PCCH"}}},
        {7, {{2, "BCCH-DL-SCH"}, {4, "PCCH"}, {5, "DL-CCCH"}, {6, "DL-DCCH"}, {7, "UL-CCCH"}, {8, "UL-DCCH"}}},
        {9, {{9, "BCCH-DL-SCH"}, {11, "PCCH"}}},
        {12, {{9, "BCCH-DL-SCH"}, {11, "PCCH"}}},
        {13, {{4, "PCCH"}}},
        {14, {{5, "PCCH"}}},
        {15, {{2, "BCCH-DL-SCH"}, {5, "PCCH"}, {6, "DL-CCCH"}, {7, "DL-DCCH"}, {8, "UL-CCCH"}, {9, "UL-DCCH"}}},
        {24, {{2, "BCCH-DL-SCH"}, {5, "PCCH"}, {6, "DL-CCCH"}, {7, "DL-DCCH"}, {8, "UL-CCCH"}, {9, "UL-DCCH"}}},
        {26, {{3, "BCCH-DL-SCH"}, {7, "PCCH"}, {8, "DL-CCCH"}, {9, "DL-DCCH"}, {10, "UL-CCCH"}, {11, "UL-DCCH"}}},
        {27, {{3, "BCCH-DL-SCH"}, {7, "PCCH"}, {8, "DL-CCCH"}, {9, "DL-DCCH"}, {10, "UL-CCCH"}, {11, "UL-DCCH"}}},
        {30, {{3, "BCCH-DL-SCH"}, {7, "PCCH"}}},
    };
    return kTable;
}

}  // namespace lte_rrc

namespace nr_rrc {

// diag_0xb821._RRC_TYPE_MAPS, keyed by parser/wire version. Groups: pre-MCCH {7,9,12,14,17} (PCCH@5, RRC-RECONF/COMPLETE@9/10); v23 MCCH-noshift (MCCH@5, PCCH@6, DL/UL +1, RRC-RECONF/COMPLETE not yet corpus-grounded); v26 (MCCH@5, PCCH@6, RRC-RECONF/COMPLETE shifted to 11/12). v7 piggybacks the v9 map (SCAT does not parse pkt_ver=7; best-effort where pdu_id happens to match).
inline const std::map<int, std::map<int, std::string>>& channel_names_by_version() {
    static const std::map<int, std::map<int, std::string>> kTable = {
        {7, {{1, "BCCH-BCH"}, {2, "BCCH-DL-SCH"}, {3, "DL-CCCH"}, {4, "DL-DCCH"}, {5, "PCCH"}, {6, "UL-CCCH"}, {7, "UL-CCCH1"}, {8, "UL-DCCH"}, {9, "RRC-RECONF"}, {10, "RRC-RECONF-COMPLETE"}}},
        {9, {{1, "BCCH-BCH"}, {2, "BCCH-DL-SCH"}, {3, "DL-CCCH"}, {4, "DL-DCCH"}, {5, "PCCH"}, {6, "UL-CCCH"}, {7, "UL-CCCH1"}, {8, "UL-DCCH"}, {9, "RRC-RECONF"}, {10, "RRC-RECONF-COMPLETE"}}},
        {12, {{1, "BCCH-BCH"}, {2, "BCCH-DL-SCH"}, {3, "DL-CCCH"}, {4, "DL-DCCH"}, {5, "PCCH"}, {6, "UL-CCCH"}, {7, "UL-CCCH1"}, {8, "UL-DCCH"}, {9, "RRC-RECONF"}, {10, "RRC-RECONF-COMPLETE"}, {25, "RADIO-BEARER-CONFIG"}}},
        {14, {{1, "BCCH-BCH"}, {2, "BCCH-DL-SCH"}, {3, "DL-CCCH"}, {4, "DL-DCCH"}, {5, "PCCH"}, {6, "UL-CCCH"}, {7, "UL-CCCH1"}, {8, "UL-DCCH"}, {9, "RRC-RECONF"}, {10, "RRC-RECONF-COMPLETE"}}},
        {17, {{1, "BCCH-BCH"}, {2, "BCCH-DL-SCH"}, {3, "DL-CCCH"}, {4, "DL-DCCH"}, {5, "PCCH"}, {6, "UL-CCCH"}, {7, "UL-CCCH1"}, {8, "UL-DCCH"}, {9, "RRC-RECONF"}, {10, "RRC-RECONF-COMPLETE"}}},
        {23, {{1, "BCCH-BCH"}, {2, "BCCH-DL-SCH"}, {3, "DL-CCCH"}, {4, "DL-DCCH"}, {5, "MCCH"}, {6, "PCCH"}, {7, "UL-CCCH"}, {8, "UL-CCCH1"}, {9, "UL-DCCH"}}},
        {26, {{1, "BCCH-BCH"}, {2, "BCCH-DL-SCH"}, {3, "DL-CCCH"}, {4, "DL-DCCH"}, {5, "MCCH"}, {6, "PCCH"}, {7, "UL-CCCH"}, {8, "UL-CCCH1"}, {9, "UL-DCCH"}, {11, "RRC-RECONF"}, {12, "RRC-RECONF-COMPLETE"}}},
    };
    return kTable;
}

}  // namespace nr_rrc

namespace gnss {

// diag_0x1476 _V10_CONST_ID_NAMES. 0x03/0x07 are the measurement-engine (odd) tracks of GLONASS/Galileo; 0x02/0x04/0x06 are the acquisition (even) tracks; 0x0a is the SBAS/QZSS augmentation bucket.
inline const std::map<int, std::string>& constellation_names() {
    static const std::map<int, std::string> kTable = {
        {1, "GPS"},
        {2, "GLONASS"},
        {3, "GLONASS"},
        {4, "BeiDou"},
        {6, "Galileo"},
        {7, "Galileo"},
        {10, "SBAS"},
    };
    return kTable;
}

}  // namespace gnss

}  // namespace diagspec

#endif  // DIAGSPEC_GENERATED_ENRICHMENT_TABLES_H
