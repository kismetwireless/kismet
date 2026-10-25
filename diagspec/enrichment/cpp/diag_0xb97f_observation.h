// SPDX-License-Identifier: GPL-2.0-or-later
// Linkable surface of the 0xB97F cell_observation enrichment leg.
//
// The NR cell_observation leg. 0xB97F is the ONLY NR cell-measurement code in the
// celldiag mask (DIAG_TARGET_CODES), i.e. the sole source of NR PCI / NR-ARFCN /
// RSRP for the Kismet cell contract. This leg lets the celldiag capture helper
// decode 0xB97F in-process (pure C++), behind a
// (log_code, payload) -> cell_observation contract.
//
// The .ksy types the per-CC `cells[]` arrays because 0xB97F's in-cell offsets
// are version-INDEPENDENT (pci u16@+0, ssb_index u16@+2, num_beams u32@+4, rsrp
// s32@+8, rsrq s32@+12 on every version; `cell_size` 60-vs-100 changes only the
// STRIDE and beam-tail run). That separates it from 0xB193, whose in-cell
// offsets drift per subpacket version and stay opaque in its .ksy.
//
// WHAT THIS LEG OWNS THAT THE GENERATED PARSER DOES NOT. The .ksy is layout-only,
// deliberately: three things here are decode ENRICHMENT and had to be
// re-implemented, not read off an accessor --
//   1. the /128 dBm|dB scale on rsrp_raw / rsrq_raw, plus the plausibility band-gate
//      that maps a firmware "no measurement" sentinel to absent rather than to a
//      real floor reading (RSRP band is (-140, -30]  -- lo EXCLUSIVE so the v7
//      0xFFFFBA00 == -140.0 sentinel resolves to absent; RSRQ band is [-43, 3]
//      -- lo INCLUSIVE. That asymmetry is deliberate, and it is load-bearing);
//   2. `is_serving`, which is NOT on the wire: a cell is serving iff its pci equals
//      its CC's serving_pci, matched BY PCI not by position (the serving cell is not
//      always cells[0]), and never when serving_pci == 0xFFFF (no-serving sentinel);
//   3. two record-level guards Kaitai cannot express -- the u16@0 version enum gate
//      and the 1 <= num_cc <= 12 sanity check (see the .cpp).
//
// EQUIVALENCE CONTRACT: the (pci, earfcn, is_serving, rsrp, rsrq) tuples this leg
// emits must equal the reference decoder's 0xB97F observations over every
// committed nr5g_*b97f_*.bin fixture, walking EVERY carrier (not a CC0-only
// view) so carrier-aggregated neighbours are not dropped.
#ifndef DIAGSPEC_DIAG_0XB97F_OBSERVATION_H
#define DIAGSPEC_DIAG_0XB97F_OBSERVATION_H

#include <cstdint>
#include <string>
#include <vector>

namespace diag_0xb97f_observation {

// One NR cell observation from the ML1 measurement database. `earfcn` carries the
// CC's NR-ARFCN (the observation reuses the `earfcn` key for NR and disambiguates
// with rat:"NR", so the (pci, earfcn) enrich key matches the 0xB821-fed NR sib1_map).
// rsrp/rsrq are OPTIONAL: the observation carries them only when the parser produced a
// value, so an out-of-band / sentinel measurement still emits PCI+ARFCN identity
// rather than a plausible-but-wrong signal number (the 0xB192 rule).
// The contract subset of one SSB beam: ssb_index plus the RSRP/RSRQ a/b pairs,
// each omitted when unbound. Read from the cell's beam_words run by the
// version's beam layout: the 44-B beam (v0x07/v0x09) has no per-beam RSRQ.
struct Beam {
    int64_t ssb_index = 0;  // i32 @beam+0 on the 44-B beam; low u16 on the 84-B one
    bool has_rsrp_a = false;
    double rsrp_a = 0.0;    // i32 @beam+20 / 128, band (-140, -30]
    bool has_rsrp_b = false;
    double rsrp_b = 0.0;    // i32 @beam+24 / 128
    bool has_rsrq_a = false;
    double rsrq_a = 0.0;    // i32 @beam+28 / 128, band [-43, 3]; 84-B beam only
    bool has_rsrq_b = false;
    double rsrq_b = 0.0;    // i32 @beam+32 / 128; 84-B beam only
};

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
    int32_t earfcn;      // NR-ARFCN
    bool is_serving;     // derived: pci == this CC's serving_pci (PCI-matched)
    bool has_rsrp;
    double rsrp;         // dBm, rsrp_raw / 128.0, only meaningful when has_rsrp
    bool has_rsrq;
    double rsrq;         // dB,  rsrq_raw / 128.0, only meaningful when has_rsrq
    // --- the three keys emitted after rsrq ---
    // `beams`: the decode reads the FIRST beam block of every cell on a
    // known version, so a row carries exactly one beam, serving or neighbour.
    bool has_beam = false;
    Beam beam;
    // `serving_ssb_index`: the CC's flags nibble (bits[3:0] on v0x07/v0x09,
    // bits[11:8] on v0x00/v0x0A), 0xF == NA. Serving rows only.
    bool has_serving_ssb_index = false;
    int serving_ssb_index = 0;
    // `ssb_periodicity_ms`: config_word bits[15:8], omitted when 0. Serving
    // rows only, and independent of serving_ssb_index.
    bool has_ssb_periodicity_ms = false;
    int ssb_periodicity_ms = 0;
};

// Decode a raw 0xB97F LOG_F payload (log-code-stripped) into zero or more NR cell
// observations, across ALL component carriers. Returns an empty vector for
// anything the reference parser refuses (short payload, unknown version,
// implausible num_cc) -- no cells reach the sink in that case.
std::vector<CellObservation> observations(const std::string& payload,
                                          Decline* why = nullptr);

}  // namespace diag_0xb97f_observation

#endif  // DIAGSPEC_DIAG_0XB97F_OBSERVATION_H
