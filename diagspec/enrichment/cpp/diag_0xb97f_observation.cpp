// SPDX-License-Identifier: GPL-2.0-or-later
// 0xB97F cell_observation enrichment leg — see diag_0xb97f_observation.h.
//
// Turns the generated Kaitai raw view (diag_0xb97f_t) into the NR cell observations
// the celldiag datasource emits, in pure C++.
//
// Output contract (pinned by the equivalence harness over the 12 committed
// nr5g_*b97f_*.bin fixtures, spanning all four corpus-observed versions):
//   * one observation per (carrier, cell) — EVERY carrier, not a CC0-only
//     view, so carrier-aggregated neighbours are not dropped
//   * pci        == cell.pci()                      (u16, straight off the wire)
//   * earfcn     == carrier.nr_arfcn()              (CC scalar, shared by its cells)
//   * is_serving == (cc.serving_pci() != 0xFFFF && cell.pci() == cc.serving_pci())
//   * rsrp       == cell.rsrp_raw() / 128.0, present iff -140 <  v <= -30
//   * rsrq       == cell.rsrq_raw() / 128.0, present iff  -43 <= v <=   3
//   * a cell whose pci is outside the 3GPP 0..1007 range is DROPPED
//   * a payload the reference parser refuses yields zero observations
//
// The /128 divisor is a power of two, so the scale is EXACT in IEEE-754 double on
// both sides — the equivalence compare can use equality, not a tolerance.

#include "diag_0xb97f_observation.h"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "kaitai/kaitaistream.h"
#include "diag_0xb97f.h"

namespace diag_0xb97f_observation {

namespace {

void note(Decline* why, Decline d) {
    if (why != nullptr)
        *why = d;
}

// Plausible physical-quantity bands (RSRP and RSRQ lo/hi). Outside
// the band -> the value is ABSENT, not clamped: the firmware "no measurement"
// sentinels are 0xFFFFBA00 (v7, exactly -140.0) and 0xFFFFB2xx (v9/v0A, <= -156),
// so the RSRP low bound is EXCLUSIVE to make -140.0 resolve to absent. The RSRQ low
// bound is INCLUSIVE. That asymmetry is deliberate — keeping it exactly is the
// whole point of this leg.
const double kRsrpLo = -140.0, kRsrpHi = -30.0;
const double kRsrqLo = -43.0, kRsrqHi = 3.0;
const double kRsrpScale = 128.0, kRsrqScale = 128.0;

const uint16_t kNoServing = 0xFFFF;   // serving_pci sentinel

// Per-version record geometry (the reference parser's per-version table). Only what the
// record-level guards below need: the header size and the CC meas-header size. The
// generated parser owns the rest (and derives the same numbers internally).
struct VersionGeom {
    uint16_t version;
    size_t rec_hdr;
    size_t cc_meas;
    size_t nc_off;       // num_cells byte within the CC id block
    size_t cell_size;    // a one-beam cell
    size_t beam_extra;   // each further beam; 0 = single-beam only
};
const VersionGeom kVersions[] = {
    {0x00, 20, 28, 5, 100, 84},   // SDX72 RG650V-NA (sub_version 3)
    {0x07, 16, 20, 4, 60, 0},     // SDX55 RM500Q-AE — the one 16-byte-header version
    {0x09, 20, 20, 5, 60, 0},     // SDX62 RM520N-GL
    {0x0A, 20, 20, 5, 100, 0},    // SDX72 T99W640
};

const size_t kCcIdBlock = 12;    // CC id block size
const size_t kCellPrefix = 16;   // cell fixed prefix: pci, pbch_sfn, num_beams, rsrp, rsrq

// The truncation declines, walked with the reference parser's own position
// arithmetic: a declared CC whose id+meas block overruns the payload, a
// cell whose fixed prefix or (beam-bearing) stride overruns it, or, on a
// multi-beam version, trailing slack that is not a whole number of beam slots.
// Each one REFUSES the record, never clamps it to the cells that fit.
bool walk_truncated(const std::string& p, const VersionGeom& g, uint32_t num_cc) {
    auto u32 = [&p](size_t off) {
        return static_cast<uint32_t>(static_cast<unsigned char>(p[off])) |
               (static_cast<uint32_t>(static_cast<unsigned char>(p[off + 1])) << 8) |
               (static_cast<uint32_t>(static_cast<unsigned char>(p[off + 2])) << 16) |
               (static_cast<uint32_t>(static_cast<unsigned char>(p[off + 3])) << 24);
    };
    const size_t n = p.size();
    size_t pos = g.rec_hdr;
    for (uint32_t cc = 0; cc < num_cc; cc++) {
        if (pos + kCcIdBlock + g.cc_meas > n)
            return true;
        const unsigned declared = static_cast<unsigned char>(p[pos + g.nc_off]);
        pos += kCcIdBlock + g.cc_meas;
        for (unsigned ci = 0; ci < declared; ci++) {
            if (pos + kCellPrefix > n)
                return true;
            const uint32_t n_beams = u32(pos + 4);
            if (n_beams == 0) {
                pos += kCellPrefix;
                continue;
            }
            const size_t stride = g.cell_size + g.beam_extra * (n_beams - 1);
            if (pos + stride > n)
                return true;
            pos += stride;
        }
    }
    return pos != n && g.beam_extra != 0 && (n - pos) % g.beam_extra != 0;
}

// Per-version beam layout + serving-SSB flag position. The 84-B beam (v0x00/v0x0A) reads
// ssb_index as a u16 and carries a per-beam RSRQ pair; the 44-B beam does not.
bool is_84b_beam(uint16_t version) {
    return version == 0x00 || version == 0x0A;
}

// Beam fields as indices into the cell's beam_words run, which starts at cell+16
// == beam+0: rsrp_a/b @beam+20/+24, rsrq_a/b @beam+28/+32.
const size_t kBeamRsrpA = 5, kBeamRsrpB = 6, kBeamRsrqA = 7, kBeamRsrqB = 8;

// Beam RSRP / RSRQ scaling: the same bands the cell rsrp/rsrq use below.
bool scale_rsrp(int32_t raw, double* out) {
    const double v = raw / kRsrpScale;
    *out = v;
    return kRsrpLo < v && v <= kRsrpHi;
}

bool scale_rsrq(int32_t raw, double* out) {
    const double v = raw / kRsrqScale;
    *out = v;
    return kRsrqLo <= v && v <= kRsrqHi;
}

const VersionGeom* lookup_version(uint16_t version) {
    for (const VersionGeom& g : kVersions)
        if (g.version == version)
            return &g;
    return nullptr;
}

uint16_t read_u16le(const std::string& s, size_t off) {
    return static_cast<uint16_t>(static_cast<unsigned char>(s[off]) |
                                 (static_cast<unsigned char>(s[off + 1]) << 8));
}

uint32_t read_u32le(const std::string& s, size_t off) {
    return static_cast<uint32_t>(static_cast<unsigned char>(s[off])) |
           (static_cast<uint32_t>(static_cast<unsigned char>(s[off + 1])) << 8) |
           (static_cast<uint32_t>(static_cast<unsigned char>(s[off + 2])) << 16) |
           (static_cast<uint32_t>(static_cast<unsigned char>(s[off + 3])) << 24);
}

}  // namespace

std::vector<CellObservation> observations(const std::string& payload, Decline* why) {
    note(why, Decline::kNone);
    std::vector<CellObservation> out;

    // ---- Record-level guards -------------------------------------------------
    // These are the three checks applied BEFORE decoding anything,
    // and none of them is expressible in the .ksy (Kaitai has no "reject the whole
    // record" verb here), so they live in the leg. Skipping them is not a
    // theoretical risk: without the version gate a future chipset generation's
    // u16@0 would be decoded with whichever geometry the switch happens to fall
    // through to, producing plausible-looking PCIs from the wrong offsets — the
    // silent mis-parse the Layer-1 version gate exists to prevent.
    if (payload.size() < 4)
        { note(why, Decline::kRefused); return out; }

    const VersionGeom* geom = lookup_version(read_u16le(payload, 0));
    if (geom == nullptr)
        { note(why, Decline::kRefused); return out; }                                   // unknown version -> refused

    const size_t kCcIdSize = 12;
    if (payload.size() < geom->rec_hdr + kCcIdSize + geom->cc_meas)
        { note(why, Decline::kRefused); return out; }                                   // too short for one CC

    // config_word's LOW BYTE is the component-carrier count. Its
    // offset is @4 on v7 (which has no counter word) and @8 elsewhere; both are
    // inside the rec_hdr the length check above already guaranteed.
    const size_t cfg_off = (geom->version == 0x07) ? 4 : 8;
    const uint32_t config_word = read_u32le(payload, cfg_off);
    const uint32_t num_cc = config_word & 0xFFu;
    // ssb_periodicity_ms: config_word bits[15:8].
    const int ssb_periodicity_ms = static_cast<int>((config_word >> 8) & 0xFFu);
    const bool beam_84b = is_84b_beam(geom->version);
    const unsigned ssb_shift = beam_84b ? 8 : 0;
    if (num_cc < 1 || num_cc > 12)
        { note(why, Decline::kRefused); return out; }                                   // implausible CC count -> refused
    if (walk_truncated(payload, *geom, num_cc)) {
        note(why, Decline::kRefused);                // truncated -> refused
        return out;
    }

    // ---- Raw parse + enrichment ---------------------------------------------
    // One divergence from the reference parser, in a case the corpus does not
    // contain: the parser BREAKS out of the CC loop (keeping the carriers decoded so far) when a
    // CC's own 12+cc_meas header does not fit, whereas Kaitai's repeat-expr is
    // evaluated once up front and will throw on the short read. A 15-capture /
    // 13,433-record validation recorded ZERO CC-boundary breaks, so this path is
    // unexercised in practice; catching keeps a malformed live record from throwing
    // into the capture helper. The per-CELL truncation case — the one that DOES
    // occur (F3-dual-mask captures) — is handled inside the .ksy by a fits-clamp
    // that mirrors the parser's `pos + cell_size > len(data)` break exactly, so a
    // truncated final cell yields fewer cells here too, not an exception.
    try {
        kaitai::kstream ks(payload);
        diag_0xb97f_t rec(&ks);

        std::vector<std::unique_ptr<diag_0xb97f_t::cc_block_t>>* carriers =
            rec.carriers();
        if (carriers == nullptr)
            return out;

        for (const auto& cc : *carriers) {
            const int32_t earfcn = static_cast<int32_t>(cc->nr_arfcn());
            const uint16_t serving_pci = cc->serving_pci();
            const unsigned ssb_nibble = (cc->flags() >> ssb_shift) & 0xFu;

            std::vector<std::unique_ptr<diag_0xb97f_t::nr_cell_t>>* cells =
                cc->cells();
            if (cells == nullptr)
                continue;

            for (const auto& cell : *cells) {
                // Spec invariant: NR PCI is 0..1007 (38.211 §7.4.2.1 — 3 SSS
                // sequences x 336 PSS groups). A value outside that range is not a
                // cell, it is a decode that walked off its stride, so emitting it
                // would put a fabricated tower in the dataset. The row is
                // dropped; without this guard the leg admits exactly the
                // observations the guard exists to exclude.
                //
                // The RM520N-GL (SDX62, v9) intermittently emits short bursts of
                // cells with pci in the 51372-51828 range on one ARFCN. Dropping
                // (not clamping) is deliberate: the stride is wrong, so `earfcn`
                // and the signal fields from the same row are equally
                // untrustworthy.
                //
                // No committed fixture carries an out-of-range PCI
                // (`test_diag_0xb97f_observation_slice.py` asserts every fixture
                // is in range), so `test_out_of_range_pci_is_dropped_by_both_sides`
                // is what pins this guard.
                //
                // The drop is deliberately NOT announced on stderr: this leg is
                // linked into the capture helper, whose stderr is not a
                // diagnostic channel. The per-(code,version) census serves that
                // purpose: it counts a dropped row as decoded-but-not-emitted,
                // so a stride bug firing is still visible. stderr is not part of
                // the observation contract the equivalence compare covers.
                const uint16_t raw_pci = cell->pci();
                if (raw_pci > 1007)
                    continue;

                CellObservation obs;
                obs.pci = static_cast<int32_t>(cell->pci());
                obs.earfcn = earfcn;
                // PCI-matched, never positional; a no-serving CC has no serving cell.
                obs.is_serving =
                    (serving_pci != kNoServing && cell->pci() == serving_pci);

                const double rsrp = cell->rsrp_raw() / kRsrpScale;
                obs.has_rsrp = (kRsrpLo < rsrp && rsrp <= kRsrpHi);
                obs.rsrp = obs.has_rsrp ? rsrp : 0.0;

                const double rsrq = cell->rsrq_raw() / kRsrqScale;
                obs.has_rsrq = (kRsrqLo <= rsrq && rsrq <= kRsrqHi);
                obs.rsrq = obs.has_rsrq ? rsrq : 0.0;

                // The first beam block (the decode reads exactly one). The
                // run always holds it -- 11 words on a 60-B cell, 21 on a 100-B
                // one -- but a short run skips the beam rather than reading past.
                const std::vector<int32_t>* words = cell->beam_words();
                const size_t need = beam_84b ? kBeamRsrqB + 1 : kBeamRsrpB + 1;
                if (words != nullptr && words->size() >= need) {
                    const std::vector<int32_t>& w = *words;
                    Beam& b = obs.beam;
                    obs.has_beam = true;
                    b.ssb_index = beam_84b
                        ? static_cast<int64_t>(static_cast<uint32_t>(w[0]) & 0xFFFFu)
                        : static_cast<int64_t>(w[0]);
                    b.has_rsrp_a = scale_rsrp(w[kBeamRsrpA], &b.rsrp_a);
                    b.has_rsrp_b = scale_rsrp(w[kBeamRsrpB], &b.rsrp_b);
                    if (beam_84b) {
                        b.has_rsrq_a = scale_rsrq(w[kBeamRsrqA], &b.rsrq_a);
                        b.has_rsrq_b = scale_rsrq(w[kBeamRsrqB], &b.rsrq_b);
                    }
                }
                if (obs.is_serving && ssb_nibble != 0xFu) {
                    obs.has_serving_ssb_index = true;
                    obs.serving_ssb_index = static_cast<int>(ssb_nibble);
                }
                if (obs.is_serving && ssb_periodicity_ms != 0) {
                    obs.has_ssb_periodicity_ms = true;
                    obs.ssb_periodicity_ms = ssb_periodicity_ms;
                }

                out.push_back(obs);
            }
        }
    } catch (const std::exception&) {
        // Malformed record (CC header past the end of the payload). Drop the whole
        // record rather than emit a partially-walked carrier list — see above.
        out.clear();
    }

    return out;
}

bool is_refusal(Decline d) {
    return d == Decline::kRefused;
}

}  // namespace diag_0xb97f_observation
