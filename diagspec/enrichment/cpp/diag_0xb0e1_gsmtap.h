// SPDX-License-Identifier: GPL-2.0-or-later
// Datasource-facing adapter for 0xB0E1 (LTE NAS/ESM OTA Outgoing) — a vertical slice for the
// 0xB0E1 PoC code. LTE NAS rides plain GSMTAP (type 0x12, LTE_NAS); the
// nas-eps dissector reads the NAS security header out of the PDU bytes itself, so
// GSMTAP wrapping needs only the raw OTA PDU + a plain-vs-protected sub-type flag
// — NO L3 field decode, NO enrichment leg. This is the ONE function a
// Kismet capture-source calls per 0xB0E1 record; it chains the parity-pinned legs:
//
//   DIAG 0xB0E1 payload
//     -> diag_0xb0e1_t                       (generated Kaitai raw parse, MIT rt)
//     -> nas_pdu()                             (verbatim OTA LTE NAS PDU blob)
//     -> gsmtap::encode_lte_nas                (enrichment/cpp/gsmtap)
//     -> GsmtapFrame::serialize                (GSMTAP LTE_NAS frame)
//
// Its output bytes are pinned against the reference encoder by
// tests/test_diag_0xb0e1_gsmtap_slice.py.
#ifndef DIAGSPEC_DIAG_0XB0E1_GSMTAP_H
#define DIAGSPEC_DIAG_0XB0E1_GSMTAP_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace diagspec {
namespace celldiag {

// Decode a single raw 0xB0E1 log payload (bytes AFTER the DIAG log-container
// header, i.e. starting at the 4/5-byte DIAG NAS wrapper) and frame it as a
// GSMTAP LTE_NAS frame. On success fills `out_frame` and returns true; returns
// false — DECLINING exactly where the reference encoder declines — when the payload
// does not parse or carries no PDU bytes.
bool diag_0xb0e1_to_gsmtap(const uint8_t* payload, std::size_t len,
                             std::vector<uint8_t>& out_frame);

}  // namespace celldiag
}  // namespace diagspec

#endif  // DIAGSPEC_DIAG_0XB0E1_GSMTAP_H
