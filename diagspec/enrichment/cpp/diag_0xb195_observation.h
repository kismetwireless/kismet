// SPDX-License-Identifier: GPL-2.0-or-later
// Linkable surface of the 0xB195 cell_observation enrichment leg.
//
// A cell_observation (AT-parity PCI/EARFCN) enrichment leg like 0xB192's,
// targeting the `cell_observation` sink the Kismet datasource turns into `Cellular`
// devices. It lets the celldiag capture helper decode 0xB195 in-process
// (pure C++), behind a (log_code, payload) -> cell_observation contract.
//
// 0xB195 is the CONNECTED-mode neighbor sibling of the idle-mode 0xB192; its per-cell
// record layout is byte-identical and version-INDEPENDENT, so the generated
// Kaitai parser `diag_0xb195_t` exposes response_body::earfcn() and cells()[i]->pci()
// directly. The count is the low 7 bits of the u16 at sp+4 (sp+2 on the 4 B
// sp.v3 header), clamped to what the body holds; the .ksy computes
// `min(word & 0x7f, (body-hdr)/52)`, so this leg
// just walks cells() and needs no count logic of its own.
//
// EQUIVALENCE CONTRACT: the (pci, earfcn) set this leg emits must equal the
// reference decoder's 0xB195 observations over every committed
// lte_ml1_conn_neighbor_b195_*.bin fixture. RSRP is deliberately NOT emitted:
// 0xB195's per-cell energy words are AGC-flattened, NOT calibrated dBm (the old
// -raw/10 decode is refuted), so no observation carries an rsrp — PCI/EARFCN
// only, no plausible-but-wrong signal.
#ifndef DIAGSPEC_DIAG_0XB195_OBSERVATION_H
#define DIAGSPEC_DIAG_0XB195_OBSERVATION_H

#include <cstdint>
#include <string>
#include <vector>

namespace diag_0xb195_observation {

// One AT-parity cell observation: LTE connected-mode neighbor cell identity. rat is
// always "LTE" and is_serving always false for 0xB195 (connected NEIGHBOR meas); no
// rsrp (see the header note). earfcn is the response_body carrier scalar, shared by
// every cell in the record; pci is per-cell.
struct CellObservation {
    int32_t pci;
    int32_t earfcn;
};

// Why decline is an observable.
//
// Every decline path on this leg produces the same empty vector. Remove the
// min-payload guard and a short payload simply throws in the walk instead, and
// the catch returns the same `[]`. Guard, guard and catch collapse onto one
// observable, so an oracle that is the observation list can only pin the
// composite: either structural guard (min-payload, num_subpackets) can be
// deleted with the equivalence suite green, and no fixture can change that.
//
// The gates are kept because they make the decline explicit and cheap instead
// of exception-driven, in the reference parser's early-return order. That
// is a property of which path ran, so the leg reports the path and tests hold
// it to it.
//
// `Decline` is that report. It is a strictly ADDITIVE out-param with a default
// of `nullptr`: every existing call site (`observations(payload)`) compiles and
// behaves identically, byte for byte, and the returned vector is untouched. The
// enum is the leg's decline vocabulary, in the order the paths are taken.
enum class Decline {
    kNone = 0,              // the walk completed — `out` is the answer
    kShortPayload,          // payload.size() < kMinPayload
    kOuterVersion,          // payload[0] != kOuterVersion
    kNumSubpackets,         // payload[1] < 1
    kNotResponseSubpacket,  // the picked subpacket is not id=31
    kNullCells,             // the response body exposed no cell array
    kThrew,                 // the Kaitai walk threw; the catch answered
};

// Stable lowercase name for a Decline, for drivers and diagnostics. Never null.
const char* decline_name(Decline d);

// True exactly when the decline is a record the reference parser refuses
// outright: the native census then counts the record DROPPED. Every other
// decline is a completed parse that emitted nothing, and is counted decoded.
bool is_refusal(Decline d);

// Decode a raw 0xB195 LOG_F payload (log-code-stripped) into zero or more
// connected-mode neighbor cell observations. Returns an empty vector when the
// picked subpacket is not the id=31 response subpacket (the whole record is
// refused in that case — no cells reach the sink).
//
// When `why` is non-null it receives the path taken. An empty vector with
// `*why == kNone` is a legitimate zero-cell decode, NOT a decline — the two read
// identically in the return value, which is the whole point of this parameter.
std::vector<CellObservation> observations(const std::string& payload,
                                          Decline* why = nullptr);

}  // namespace diag_0xb195_observation

#endif  // DIAGSPEC_DIAG_0XB195_OBSERVATION_H
