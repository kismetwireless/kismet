// SPDX-License-Identifier: GPL-2.0-or-later
// Linkable surface of the 0xB193 cell_observation enrichment leg.
//
// 0xB193 is LTE ML1 Serving Cell Measurement -- the serving-cell measurement
// code, and the largest single share of the celldiag mask's live output. With
// this leg, alongside 0xB192, 0xB195, 0xB0C0-identity and 0xB97F, every code in
// the Kismet cell contract decodes in-process.
//
// The .ksy leaves the per-cell array opaque, and that does not block this leg.
// The per-cell punt is not a gap -- it is the layout / enrichment line drawn
// where it belongs:
//
//   * WHAT IS LAYOUT, and the .ksy owns it: the carrier header size (8 B, 12 B on
//     v48, 4 B on v3), num_cells, the DERIVED per-cell stride, the cell array's
//     base, and the v3/v18 inline-serving scalars. All present as accessors.
//   * WHAT IS ENRICHMENT, and this leg owns it: which in-cell offset holds the
//     PCI for a given subpacket version, the bitpacked v59-family field
//     extraction, the per-version signal SCALES, and the closed version allowlist.
//
// That is the same division 0xB97F's leg makes for the /128 scale and the
// PCI-matched is_serving derivation, and 0xB192's for its plausibility gates.
// Typing the drifting in-cell offsets INTO the .ksy would assert a layout the
// corpus does not support -- which is precisely what the punt exists to avoid.
//
// WHAT MAKES 0xB193 GENUINELY HARDER THAN ITS FOUR SIBLINGS. Its per-cell layout
// is keyed on the SUBPACKET version (byte[5], which tracks the chipset), not on
// the outer log version -- and nine versions are corpus-observed. Three distinct
// record shapes fall out of that:
//
//   * v3 (MDM9200), v6 (MDM9625) and v18 (MDM9207/MDM9230) have NO cell array
//     at all. The serving cell is packed inline in the carrier header, and the
//     v3 family's (v3/v6) EARFCN is a u16 where every other version carries a
//     u32-low18.
//   * v48 (SDX55) is the ONLY version with a 12-byte carrier header, so its cell
//     array both STARTS and is STRIDED four bytes later than the rest.
//   * v40 (SDX24) is the only FIXED-stride array (4 x 132 B slots); every other
//     version derives its stride from the body length and num_cells.
//   * v50/v56/v59 (the "v59 family") bitpack RSRP and RSRQ into 12-bit slices of
//     u32 words at cell+44 and cell+56, and put the PCI at cell+8 rather than
//     cell+0.
//
// Signal is shipped only where a scale is grounded, and this leg must reproduce
// exactly where that is. v22/v35's old `-raw/10` dBm was refuted against F3 (it
// is wideband RSSI); their real x16 RSRP/RSRQ (cell+32 / cell+44) is decoded for
// SINGLE-cell records only. v18's x16 block (sp+32 / sp+40) is decoded on its
// inline serving cell, and so is v3/v6's (the same block 8 bytes earlier,
// sp+24 / sp+32). v36's equivalent slot was refuted for the same reason and its real
// RSRP sits 36 bytes earlier, decoded for SINGLE-cell records only; v40/v41
// carry theirs at cell+36 / cell+48, also SINGLE-cell only; v48's x16
// scale is pinned for SINGLE-cell records only and reads +1947 dBm on a
// multi-cell one; and v59's cell+44/+56 are ground-truth-validated only for the
// serving cell, reading 3-8 dB low on neighbours. A leg that "helpfully" emitted
// a number in any of those cases would be emitting a plausible-but-wrong dBm.
// The VERIFIED pci/earfcn identity still ships in every one of those cases -- the
// row is emitted with the signal absent, never dropped.
//
// EQUIVALENCE CONTRACT: the (pci, earfcn, is_serving, rsrp, rsrq) tuples this leg
// emits must equal the reference decoder's 0xB193 observations over every
// committed lte_ml1_serving_b193_*.bin fixture,
// which between them walk v3 / v6 / v18 / v22 / v35 / v36 / v40 / v41 / v48 /
// v50 / v56 / v59 / v60 -- so no switch arm ships unexercised.
#ifndef DIAGSPEC_DIAG_0XB193_OBSERVATION_H
#define DIAGSPEC_DIAG_0XB193_OBSERVATION_H

#include <cstdint>
#include <string>
#include <vector>

namespace diag_0xb193_observation {

// One LTE cell observation from the ML1 serving-cell measurement.
//
// rsrp/rsrq are OPTIONAL and usually ABSENT -- see the header note above. A
// consumer MUST check has_rsrp before reading rsrp; treating 0.0 as a reading
// would put every unscaled version's cells at a fabricated 0 dBm.
//
// is_serving is a derived rule, not a wire field: prefer the parser's grounded
// serving_flag (v59 bit15 of the PCI word; and the single-cell v50/v56 cell, which
// IS the serving cell), and fall back to "index 0" ONLY where no flag is grounded.
// The fallback is positional and known-imperfect; it is kept because the
// contract is equality with the reference decoder, not improvement on it.
// Why observations() returned what it did. kRefused is exactly a record
// the reference parser refuses outright: the census counts it DROPPED. kNone is a
// completed parse, whatever its row count, and is counted decoded. The out-param
// is additive: `observations(payload)` behaves byte-for-byte as before.
enum class Decline {
    kNone = 0,
    kRefused,
};
bool is_refusal(Decline d);

struct CellObservation {
    int32_t pci;
    int32_t earfcn;
    bool is_serving;
    bool has_rsrp;
    double rsrp;         // dBm, only meaningful when has_rsrp
    bool has_rsrq;
    double rsrq;         // dB,  only meaningful when has_rsrq
};

// Decode a raw 0xB193 LOG_F payload (log-code-stripped) into zero or more LTE
// cell observations.
//
// Returns an empty vector for anything the reference parser refuses (short
// payload, outer version != 1, a v3/v48-family payload too short for its carrier
// header) AND for the cases where the parser returns a record carrying no entries
// (num_subpackets == 0, an un-RE'd subpacket version, num_cells == 0, a derived
// stride below the 4-byte minimum). Both collapse to "no observations" in the
// emitted stream -- the distinction between them is visible in the parser's raw
// view (and in `why`), not in the cell_observation contract.
std::vector<CellObservation> observations(const std::string& payload,
                                          Decline* why = nullptr);

}  // namespace diag_0xb193_observation

#endif  // DIAGSPEC_DIAG_0XB193_OBSERVATION_H
