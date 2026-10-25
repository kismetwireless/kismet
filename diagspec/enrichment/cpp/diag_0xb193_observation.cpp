// SPDX-License-Identifier: GPL-2.0-or-later
// 0xB193 cell_observation enrichment leg — see diag_0xb193_observation.h.
//
// Turns the generated Kaitai raw view (diag_0xb193_t) into the LTE cell observations
// the celldiag datasource emits, in pure C++.
//
// Output contract (pinned by the equivalence harness against the reference
// decoder):
//   * earfcn     == body.earfcn()   (u16 on v3, u32-low18 elsewhere; carrier-level,
//                                    shared by every cell of the record)
//   * pci        == (u32 @ cell_offset + version_pci_off) & 0x1FF, gated to <= 503
//   * is_serving == serving_flag == 1 where a flag is GROUNDED, else index == 0
//   * rsrp/rsrq  == present only on the version/shape combinations with an RE'd
//                   scale (see the header) — absent, never 0.0, everywhere else
//   * a payload the reference parser refuses, or that yields no entries, -> zero observations
//
// DIVISION OF LABOUR WITH THE .ksy. The generated parser supplies every LAYOUT
// quantity: the version bytes, earfcn, num_cells, the version-dependent cell base
// (8 / 12 on v48 / 4 on v3), the DERIVED per-cell stride, and the v3/v18 inline
// serving PCIs. This file supplies the ENRICHMENT: which in-cell offset holds the
// PCI on a given subpacket version, the v59-family bitpacked field extraction, the
// per-version signal scales and their refutation gates, and the closed version
// allowlist. In-cell reads go to ABSOLUTE offsets in the subpacket rather than into
// the .ksy's opaque per-cell slices, because that is how the reference parser reads them —
// its `min_cell_record` bound is against len(sp), not against the stride, so a
// slice-relative read would differ on a final cell whose fields run past its own
// stride. Equality with the reference is the contract; matching its addressing is
// how that is obtained by construction rather than by testing.

#include "diag_0xb193_observation.h"

#include <cmath>
#include <cstddef>
#include <string>
#include <vector>

#include "kaitai/kaitaistream.h"
#include "diag_0xb193.h"

namespace diag_0xb193_observation {

namespace {

void note(Decline* why, Decline d) {
    if (why != nullptr)
        *why = d;
}

const size_t kMinPayload = 14;
const size_t kSubpacketHeaderOffset = 4;   // id, version, size(u16)
const size_t kSubpacketDataOffset = 8;
const size_t kMinStride = 4;

const uint8_t kV3 = 3;
const uint8_t kV6 = 6;
const uint8_t kV18 = 18;
const uint8_t kV22 = 22;
const uint8_t kV35 = 35;
const uint8_t kV36 = 36;
const uint8_t kV40 = 40;
const uint8_t kV41 = 41;
const uint8_t kV48 = 48;
const uint8_t kV50 = 50;
const uint8_t kV56 = 56;
const uint8_t kV59 = 59;
// v60 (SDX72 T99W640): v59 family on a new chipset. Its u16 at sp+4
// carries an unidentified flag at bit3 (reads 9 on single-cell records), so the
// count is bits0..2 — read raw, the derived stride would be 148 / 9 = 16. The
// mask is the .ksy's (`cell_count`), not restated here.
const uint8_t kV60 = 60;

// v59-family bitpacked field words, and the in-cell PCI offsets.
const size_t kV59PciOff = 8;
const size_t kV59RsrpWordOff = 44;   // u32; bits 12..23 are the combined RSRP
const size_t kV59RsrqWordOff = 56;   // u32; bits 20..31 are the RSRQ
const size_t kV59MinCellRecord = 60; // need the full u32 at cell+56

const size_t kV48PciOff = 0;
const size_t kV48RsrpOff = 24;       // over v48's TRUE 12 B base

// v36 (SDX20 LM960 / EG18-NA) — RE'd on a 45 dB wide-sweep wardrive.
// Same x16 idiom as the v59 family, different geometry. NB the widths
// differ per field and are NOT both 12: bit-occupancy over 2,055 records shows
// cell+36's bit9 never set while bits10..15 vary independently, so RSRQ is a
// 10-bit field, not a 12-bit one. Reading it as 12 bits pulls in a neighbouring
// field and yields RSRQ up to +186 dB. Full evidence trail (own-F3 tick-paired
// max err 0.032 dB; AT#LAPS -0.31/+0.05 dB; the truth-free TS 36.214 closure onto
// N_RB 100.0/50.1) lives with the reference parser's v36 constants.
const size_t kV36PciOff = 0;
const size_t kV36RsrpOff = 20;       // u16, bits0..11, raw/16 - 180 dBm (rx0)
const size_t kV36RsrqOff = 36;       // u16, bits0..9,  raw/16 -  30 dB
const uint16_t kV36RsrpMask = 0x0FFFu;
const uint16_t kV36RsrqMask = 0x03FFu;
const double kV36RsrpBase = -180.0;
const double kV36RsrqBase = -30.0;

// v18 (MDM9x07: EG25-G, EG95, RC400L, SIM7600, MC7455/EM7455, ...): the serving
// cell is inline (no num_cells), and its signal block is v6's x16 block at +8.
// Best-Rx RSRP u32 @sp+32 bits0..11, RSRQ u32 @sp+40 bits0..9. Within 1 LSB of
// same-cycle 0xB17F on 30,991/30,991 pairs over 80.6 dB, 17 models (parser v37;
// the evidence trail is on the reference parser's v18 constants). Read only when the body holds
// the full u32 at sp+40, else identity only.
const size_t kV18RsrpOff = 32;
const size_t kV18RsrqOff = 40;
const size_t kV18MinBody = 44;

// v3 (MDM9200: Sierra MC7700, BandLuxe C505) and v6 (MDM9625: Foxconn
// T77W595) -- the SMALL 4-byte-header family. The serving cell is inline (u16
// EARFCN @sp+0, u16 PCI @sp+2, both off the .ksy) and its signal block is v6's:
// best-Rx RSRP u32 @sp+24 bits0..11 (raw/16 - 180), RSRQ u32 @sp+32 bits0..9
// (raw/16 - 30). v3 IS v6's 84 B layout one chipset generation earlier, so
// the reference parser reads both through one branch (parser v33 for v6, v35
// for v3; the evidence trail is on its v3 / v6 constants: own F3, same-cycle
// 0xB17F / 0xB196). That branch needs the whole block, so a body shorter than
// the u32 at sp+32 is REFUSED, even though the identity would fit in 4.
const size_t kV6RsrpOff = 24;
const size_t kV6RsrqOff = 32;
const size_t kV6MinBody = 36;

// v35 (MDM9x50 / SDX12) and v22 (MDM9240 EP06-A, decoded through v35's
// arm): PCI low-9 @cell+0, RSRP u32 @cell+32 bits0..11 (raw/16 - 180), RSRQ
// u32 @cell+44 bits0..9 (raw/16 - 30). Own-F3 and same-cycle 0xB17F grounded
// (the reference parser's v35 / v22 constants). SINGLE-CELL ONLY, as on
// v36/v48/v50. The cell must hold the full u32 at cell+44 even for its identity
// to ship: that is the minimum cell record, so a shorter cell is not emitted at all.
const size_t kV35RsrpWordOff = 32;
const size_t kV35RsrqWordOff = 44;

// v40 (SDX24: Quectel EM120R-GL / EM160R-GL) is a FIXED 4 x 132 B cell array:
// the stride is 132 whatever num_cells says, NOT the derived (len - 8) /
// num_cells (which reads cell[1] of a 2-cell record 132 bytes late). PCI low-9
// @cell+0, RSRP u32 @cell+36 bits0..11 (raw/16 - 180), RSRQ u32 @cell+48
// bits20..31 (raw/16 - 30): the TOP 12 bits, unlike every other version's
// bits0..9. Same-tick 0xB17F within 1 LSB / bit-exact on 551/551 (the
// reference parser's v40 constants). SINGLE-CELL ONLY. The 132 B stride is the .ksy's
// (`cell_stride` / `is_fixed_slots`), not restated here.
const size_t kV40RsrpWordOff = 36;
const size_t kV40RsrqWordOff = 48;

// v41 (SDX50M + SM8150: Inseego M1000) is v35's layout with 4 bytes inserted
// after the PCI word: RSRP u32 @cell+36 bits0..11, RSRQ u32 @cell+48 bits0..9,
// on the DERIVED stride. Same-cycle 0xB17F within 1 LSB on 134/134 over two
// units / two networks (the reference parser's v41 constants). SINGLE-CELL ONLY.
const size_t kV41RsrpWordOff = 36;
const size_t kV41RsrqWordOff = 48;

const uint32_t kX16RsrpMask = 0xFFFu;   // bits0..11
const uint32_t kX16RsrqMask = 0x3FFu;   // bits0..9

// Plausibility bands. RSRP failing its band DROPS the whole entry (the parser
// `continue`s); RSRQ failing its band only clears the RSRQ, keeping the identity.
// That asymmetry is deliberate and load-bearing — keeping it is the point.
const double kRsrpLo = -140.0, kRsrpHi = -30.0;
const double kRsrqLo = -34.0, kRsrqHi = 2.5;

const uint16_t kMaxPci = 503;        // 3GPP: PCI is 0..503

bool is_v59_family(uint8_t v) {
    return v == kV50 || v == kV56 || v == kV59 || v == kV60;
}

// v3 and v6 share the small-header layout (the .ksy's is_v3_family).
bool is_v3_family(uint8_t v) {
    return v == kV3 || v == kV6;
}

bool is_decoded_version(uint8_t v) {
    return is_v3_family(v) || v == kV18 || v == kV22 || v == kV35 || v == kV36 ||
           v == kV40 || v == kV41 || v == kV48 || is_v59_family(v);
}

// round(x, 2) with round-half-to-EVEN on the exact value — not C's
// std::round, which rounds half AWAY from zero.
//
// This matters here and did not for the 0xB97F leg, which has no rounding at all.
// Every scale on this code is a 1/16 quantum, so the values land on k/16 steps and
// x*100 is exactly representable; a tie at 2 dp therefore occurs whenever k % 4 ==
// 2 (…, -101.125, -101.375, …), which is roughly a quarter of all decoded readings.
// std::round would resolve those the other way and the equivalence compare would
// fail on 0.01 dB — a difference small enough to be dismissed as float noise and
// large enough to be a real divergence. nearbyint under the default FE_TONEAREST
// is round-half-to-even, exactly the rule required.
double round2(double x) { return std::nearbyint(x * 100.0) / 100.0; }

bool read_u16le(const std::string& s, size_t off, uint16_t* out) {
    if (off + 2 > s.size())
        return false;
    *out = static_cast<uint16_t>(static_cast<unsigned char>(s[off]) |
                                 (static_cast<unsigned char>(s[off + 1]) << 8));
    return true;
}

bool read_u32le(const std::string& s, size_t off, uint32_t* out) {
    if (off + 4 > s.size())
        return false;
    *out = static_cast<uint32_t>(static_cast<unsigned char>(s[off])) |
           (static_cast<uint32_t>(static_cast<unsigned char>(s[off + 1])) << 8) |
           (static_cast<uint32_t>(static_cast<unsigned char>(s[off + 2])) << 16) |
           (static_cast<uint32_t>(static_cast<unsigned char>(s[off + 3])) << 24);
    return true;
}

// A decoded cell before the index-based is_serving fallback is applied.
// serving_flag is TRI-state: grounded-1, grounded-0, or not grounded at all. The
// third is not "0" — a cell with no grounded flag falls back to its index, and
// collapsing the two would make cell[0] of a v48 record non-serving.
struct Entry {
    int32_t pci;
    int32_t earfcn;
    bool has_serving_flag;
    int serving_flag;
    bool has_rsrp;
    double rsrp;
    bool has_rsrq;
    double rsrq;
};

// The 0xB193 emit rule: emit every entry, attach the signal only where the
// parser produced one, and resolve is_serving from the grounded flag where there
// is one and from the position where there is not.
std::vector<CellObservation> to_observations(const std::vector<Entry>& entries) {
    std::vector<CellObservation> out;
    out.reserve(entries.size());
    for (size_t i = 0; i < entries.size(); i++) {
        const Entry& e = entries[i];
        CellObservation obs;
        obs.pci = e.pci;
        obs.earfcn = e.earfcn;
        obs.is_serving = e.has_serving_flag ? (e.serving_flag == 1) : (i == 0);
        obs.has_rsrp = e.has_rsrp;
        obs.rsrp = e.has_rsrp ? e.rsrp : 0.0;
        obs.has_rsrq = e.has_rsrq;
        obs.rsrq = e.has_rsrq ? e.rsrq : 0.0;
        out.push_back(obs);
    }
    return out;
}

}  // namespace

std::vector<CellObservation> observations(const std::string& payload, Decline* why) {
    note(why, Decline::kNone);
    std::vector<CellObservation> out;
    std::vector<Entry> entries;

    // ---- Record-level guards, in the reference parser's order ---------------
    // None of these is expressible in the .ksy (Kaitai has no "reject the record"
    // verb), so they live here. The version allowlist below is the load-bearing
    // one: applying a known version's in-cell offsets to an un-RE'd version
    // fabricates a PCI and a dBm from whatever bytes happen to be there — exactly
    // which is what an `elif >= 48` catch-all does to a real FN980 v50.
    if (payload.size() < kMinPayload)
        { note(why, Decline::kRefused); return out; }
    if (static_cast<unsigned char>(payload[0]) != 1)
        { note(why, Decline::kRefused); return out; }                                  // outer version gate

    try {
        kaitai::kstream ks(payload);
        diag_0xb193_t rec(&ks);

        if (rec.num_subpackets() < 1)
            return out;                              // record, but no entries

        // A record shorter than the subpacket size it declares was truncated.
        // The size (u16 @6) counts its own 4-byte header and runs to the end
        // of the record, so the derived per-cell stride would floor-divide the
        // loss away; the record is refused.
        uint16_t subpacket_size = 0;
        if (!read_u16le(payload, 6, &subpacket_size) ||
            payload.size() < kSubpacketHeaderOffset + subpacket_size)
            { note(why, Decline::kRefused); return out; }

        const uint8_t sp_ver = rec.subpacket_version();
        diag_0xb193_t::serving_body_t* body = rec.body();
        if (body == nullptr)
            { note(why, Decline::kRefused); return out; }

        // `sp` is the subpacket body: payload[8:]. Every in-cell offset below is
        // relative to it, matching the parser.
        const size_t sp_off = kSubpacketDataOffset;
        const size_t sp_len = payload.size() - sp_off;

        // Minimum body sizes, checked in the reference parser's order: the
        // v3/v6 small-header branch is tested BEFORE the general 8-byte gate.
        // v3 and v6 are read through v6's signal block, so the record needs
        // the whole block (kV6MinBody, sp+32's u32) and is refused for a shorter
        // body, even though the inline identity would fit in 4 bytes.
        const size_t kCarrierHeader = 8;
        if (is_v3_family(sp_ver)) {
            if (sp_len < kV6MinBody) {
                note(why, Decline::kRefused);
                return out;
            }
        } else if (sp_len < kCarrierHeader) {
            note(why, Decline::kRefused);
            return out;
        }

        const int32_t earfcn = body->earfcn();

        // ---- v3 / v6 / v18: no cell array; the serving cell is INLINE -------
        // All take their PCI straight off the .ksy (v3_pci covers the v3
        // family, v18_pci). Each carries one x16 signal block: v3/v6 at kV6*,
        // v18 at kV18* (v6's block shifted +8 by v18's wider header).
        if (is_v3_family(sp_ver) || sp_ver == kV18) {
            const bool v3_family = is_v3_family(sp_ver);
            int32_t pci;
            if (v3_family) {
                if (body->_is_null_v3_pci())
                    return out;
                pci = static_cast<int32_t>(body->v3_pci());
            } else {
                if (body->_is_null_v18_pci())
                    return out;
                pci = body->v18_pci();
            }
            const size_t rsrp_off = v3_family ? kV6RsrpOff : kV18RsrpOff;
            const size_t rsrq_off = v3_family ? kV6RsrqOff : kV18RsrqOff;
            const size_t min_body = v3_family ? kV6MinBody : kV18MinBody;
            if (pci <= static_cast<int32_t>(kMaxPci)) {
                Entry e;
                e.pci = pci;
                e.earfcn = earfcn;
                e.has_serving_flag = false;
                e.serving_flag = 0;
                e.has_rsrp = false;
                e.rsrp = 0.0;
                e.has_rsrq = false;
                e.rsrq = 0.0;
                uint32_t rsrp_word = 0, rsrq_word = 0;
                if (sp_len >= min_body &&
                    read_u32le(payload, sp_off + rsrp_off, &rsrp_word) &&
                    read_u32le(payload, sp_off + rsrq_off, &rsrq_word)) {
                    const uint32_t rsrp_raw = rsrp_word & kX16RsrpMask;
                    const uint32_t rsrq_raw = rsrq_word & kX16RsrqMask;
                    if (rsrp_raw) {
                        e.rsrp = round2(rsrp_raw / 16.0 - 180.0);
                        e.has_rsrp = true;
                    }
                    if (rsrq_raw) {
                        e.rsrq = round2(rsrq_raw / 16.0 - 30.0);
                        e.has_rsrq = true;
                    }
                    // The inline path's gates differ from the cell loop's: an
                    // implausible dBm drops only the dBm, never the verified
                    // identity (the v3/v6 and v18 branches).
                    if (e.has_rsrp && !(kRsrpLo <= e.rsrp && e.rsrp <= kRsrpHi)) {
                        e.has_rsrp = false;
                        e.rsrp = 0.0;
                    }
                    if (e.has_rsrq && !(kRsrqLo <= e.rsrq && e.rsrq <= kRsrqHi)) {
                        e.has_rsrq = false;
                        e.rsrq = 0.0;
                    }
                }
                entries.push_back(e);
            }
            return to_observations(entries);
        }

        // ---- un-RE'd subpacket version: carrier header only, never guessed ----
        if (!is_decoded_version(sp_ver))
            return out;

        // The count and the stride are LAYOUT, so they come from the generated
        // parser: `cell_count` carries v60's bits0..2 mask, and
        // `cell_stride` is v40's fixed 132 B slot or the derived
        // (len(sp) - cell_base) / cell_count. The .ksy's body runs to end of
        // payload (size-eos), so its _io.size is this leg's sp_len. cell_stride
        // is null exactly when cell_count == 0 or the body ends at cell_base,
        // the case that yields no entries.
        if (body->_is_null_cell_count())
            return out;
        const int32_t cell_count = body->cell_count();
        if (cell_count <= 0 || body->_is_null_cell_stride())
            return out;
        const uint16_t num_cells = static_cast<uint16_t>(cell_count);
        const size_t cell_base = static_cast<size_t>(body->cell_base());

        // The stride is DERIVED (the wire carries no stride field), so a garbage
        // num_cells floor-divides toward 0 and every "cell" would re-read offset 0,
        // emitting num_cells IDENTICAL duplicates. Reject below the 4-byte minimum
        // rather than ship fabricated rows. v40's slots are FIXED, and the parser
        // substitutes them BEFORE this floor, so v40 never trips it: a garbage
        // count there is bounded by the per-cell length check below instead.
        // The floor stays HERE: the .ksy gates only its `cells` slices on it,
        // and cell_stride itself is non-null below 4.
        const size_t stride = static_cast<size_t>(body->cell_stride());
        if (stride < kMinStride)
            return out;

        // ---- per-version in-cell geometry (a CLOSED allowlist) ----------------
        size_t pci_off;
        size_t min_cell_record;
        if (is_v59_family(sp_ver)) {
            pci_off = kV59PciOff;
            min_cell_record = kV59MinCellRecord;
        } else if (sp_ver == kV48) {
            pci_off = kV48PciOff;
            min_cell_record = kV48RsrpOff + 2;       // need the full u16 at cell+24
        } else if (sp_ver == kV36) {
            pci_off = kV36PciOff;
            min_cell_record = kV36RsrqOff + 2;       // need the full u16 at cell+36
        } else if (sp_ver == kV40) {
            pci_off = 0;
            min_cell_record = kV40RsrqWordOff + 4;   // need the full u32 at cell+48
        } else if (sp_ver == kV41) {
            pci_off = 0;
            min_cell_record = kV41RsrqWordOff + 4;   // need the full u32 at cell+48
        } else {
            pci_off = 0;                             // v22 / v35
            min_cell_record = kV35RsrqWordOff + 4;   // need the full u32 at cell+44
        }

        for (uint16_t i = 0; i < num_cells; i++) {
            const size_t cell_offset = cell_base + static_cast<size_t>(i) * stride;
            if (cell_offset + min_cell_record > sp_len)
                break;

            uint32_t pci_raw = 0;
            if (!read_u32le(payload, sp_off + cell_offset + pci_off, &pci_raw))
                break;
            const uint32_t pci = pci_raw & 0x1FFu;
            if (pci > kMaxPci)
                continue;

            bool has_serving_flag = false;
            int serving_flag = 0;
            bool has_rsrp = false, has_rsrq = false;
            double rsrp = 0.0, rsrq = 0.0;

            if (is_v59_family(sp_ver)) {
                uint32_t rsrp_word = 0, rsrq_word = 0;
                if (!read_u32le(payload, sp_off + cell_offset + kV59RsrpWordOff,
                                &rsrp_word) ||
                    !read_u32le(payload, sp_off + cell_offset + kV59RsrqWordOff,
                                &rsrq_word))
                    break;
                // Bit-exact 12-bit fields. raw == 0 means the field is
                // unpopulated -> absent, keeping pci/earfcn.
                const uint32_t rsrp_raw = (rsrp_word >> 12) & 0xFFFu;
                const uint32_t rsrq_raw = rsrq_word >> 20;
                if (rsrp_raw) {
                    rsrp = round2(rsrp_raw / 16.0 - 180.0);
                    has_rsrp = true;
                }
                if (rsrq_raw) {
                    rsrq = round2(rsrq_raw / 16.0 - 30.0);
                    has_rsrq = true;
                }

                if (sp_ver == kV59) {
                    // v59 ONLY: bit15 of the PCI word is the serving/primary flag.
                    // cell+44/+56 are ground-truth-validated only for the SERVING
                    // cell; neighbours read 3-8 dB low vs concurrent AT+QENG
                    // -> gate their signal off. The
                    // identity stays: pci/earfcn ARE valid on a neighbour.
                    has_serving_flag = true;
                    serving_flag = static_cast<int>((pci_raw >> 15) & 1u);
                    if (serving_flag != 1) {
                        has_rsrp = false;
                        has_rsrq = false;
                    }
                } else {
                    // v50/v56: bit15 is NOT a serving flag (the AT-matched serving
                    // cell has bit15=0 on all 1,408 grounded records), so the v59
                    // neighbour gate must NOT be applied. Every corpus v50/v56
                    // record is single-cell and that cell IS serving (AT #RFSTS,
                    // median delta -0.31 dB). A MULTI-cell v50/v56 is unvalidated.
                    if (num_cells == 1) {
                        has_serving_flag = true;
                        serving_flag = 1;
                    } else {
                        has_rsrp = false;
                        has_rsrq = false;
                    }
                }
            } else if (sp_ver == kV48) {
                // SDX55 v48: x16 fixed-point per-Rx RSRP @cell+24, -180 + raw/16,
                // pinned against the modem's own F3 (resid 0.14 dB).
                //
                // Single-cell only. On a multi-cell record the same slot reads
                // raw 34043 -> +1947 dBm on cell 0 — wrong even for the SERVING
                // cell, so this is not a neighbour-only drift. Gate to absent and
                // ship the verified pci/earfcn, as the v50/v56 arm above does.
                if (num_cells <= 1) {
                    uint16_t rsrp_raw = 0;
                    if (!read_u16le(payload, sp_off + cell_offset + kV48RsrpOff,
                                    &rsrp_raw))
                        break;
                    if (rsrp_raw) {
                        rsrp = round2(-180.0 + rsrp_raw / 16.0);
                        has_rsrp = true;
                    }
                }
                // RSRQ stays absent on v48: candidates located, not locked.
            } else if (sp_ver == kV36) {
                // SDX20 v36 — x16 fixed-point RSRP @cell+20 bits0..11 and RSRQ
                // @cell+36 bits0..9. See the kV36* constants block.
                //
                // Single-cell only, same discipline as v48/v50 above: all
                // grounding is on num_cells == 1, and neighbour-cell signal has
                // read several dB low on every version where it was measured.
                // Multi-cell gates the dBm off, identity still ships.
                if (num_cells <= 1) {
                    uint16_t rsrp_raw = 0, rsrq_raw = 0;
                    if (!read_u16le(payload, sp_off + cell_offset + kV36RsrpOff,
                                    &rsrp_raw) ||
                        !read_u16le(payload, sp_off + cell_offset + kV36RsrqOff,
                                    &rsrq_raw))
                        break;
                    rsrp_raw &= kV36RsrpMask;
                    rsrq_raw &= kV36RsrqMask;
                    // raw == 0 means the slot is unpopulated -> absent.
                    if (rsrp_raw) {
                        rsrp = round2(rsrp_raw / 16.0 + kV36RsrpBase);
                        has_rsrp = true;
                    }
                    if (rsrq_raw) {
                        rsrq = round2(rsrq_raw / 16.0 + kV36RsrqBase);
                        has_rsrq = true;
                    }
                }
            } else if (sp_ver == kV40 || sp_ver == kV41) {
                // v40 (SDX24) / v41 (SDX50M): RSRP @cell+36 bits0..11 on both;
                // RSRQ @cell+48 is bits20..31 on v40 and bits0..9 on v41. See
                // the kV40* / kV41* blocks. SINGLE-CELL ONLY, as v35/v36/v48.
                if (num_cells <= 1) {
                    const bool v40 = (sp_ver == kV40);
                    uint32_t rsrp_word = 0, rsrq_word = 0;
                    if (!read_u32le(payload, sp_off + cell_offset +
                                    (v40 ? kV40RsrpWordOff : kV41RsrpWordOff),
                                    &rsrp_word) ||
                        !read_u32le(payload, sp_off + cell_offset +
                                    (v40 ? kV40RsrqWordOff : kV41RsrqWordOff),
                                    &rsrq_word))
                        break;
                    const uint32_t rsrp_raw = rsrp_word & kX16RsrpMask;
                    const uint32_t rsrq_raw =
                        v40 ? (rsrq_word >> 20) : (rsrq_word & kX16RsrqMask);
                    if (rsrp_raw) {
                        rsrp = round2(rsrp_raw / 16.0 - 180.0);
                        has_rsrp = true;
                    }
                    if (rsrq_raw) {
                        rsrq = round2(rsrq_raw / 16.0 - 30.0);
                        has_rsrq = true;
                    }
                }
            } else {
                // v22 / v35 -- x16 RSRP @cell+32 bits0..11 and RSRQ @cell+44
                // bits0..9 (see kV35*). The old `-raw/10` u16 at cell+56 was
                // never RSRP (it is the RSSI word at the wrong scale) and is not
                // read. SINGLE-CELL ONLY: multi-cell ships identity, no dBm.
                if (num_cells <= 1) {
                    uint32_t rsrp_word = 0, rsrq_word = 0;
                    if (!read_u32le(payload, sp_off + cell_offset + kV35RsrpWordOff,
                                    &rsrp_word) ||
                        !read_u32le(payload, sp_off + cell_offset + kV35RsrqWordOff,
                                    &rsrq_word))
                        break;
                    const uint32_t rsrp_raw = rsrp_word & kX16RsrpMask;
                    const uint32_t rsrq_raw = rsrq_word & kX16RsrqMask;
                    if (rsrp_raw) {
                        rsrp = round2(rsrp_raw / 16.0 - 180.0);
                        has_rsrp = true;
                    }
                    if (rsrq_raw) {
                        rsrq = round2(rsrq_raw / 16.0 - 30.0);
                        has_rsrq = true;
                    }
                }
            }

            // RSRP plausibility filter — only versions that decode a dBm can trip
            // it, and tripping DROPS the entry (not just the field).
            if (has_rsrp && !(kRsrpLo <= rsrp && rsrp <= kRsrpHi))
                continue;
            // RSRQ plausibility filter clears only the field, keeping the identity.
            if (has_rsrq && !(kRsrqLo <= rsrq && rsrq <= kRsrqHi))
                has_rsrq = false;

            Entry e;
            e.pci = static_cast<int32_t>(pci);
            e.earfcn = earfcn;
            e.has_serving_flag = has_serving_flag;
            e.serving_flag = serving_flag;
            e.has_rsrp = has_rsrp;
            e.rsrp = has_rsrp ? round2(rsrp) : 0.0;
            e.has_rsrq = has_rsrq;
            e.rsrq = has_rsrq ? round2(rsrq) : 0.0;
            entries.push_back(e);
        }
    } catch (const std::exception&) {
        // A malformed record whose .ksy instances read past the payload. Drop the
        // whole record rather than emit a partially-walked cell list.
        note(why, Decline::kRefused);
        return std::vector<CellObservation>();
    }

    return to_observations(entries);
}

bool is_refusal(Decline d) {
    return d == Decline::kRefused;
}

}  // namespace diag_0xb193_observation
