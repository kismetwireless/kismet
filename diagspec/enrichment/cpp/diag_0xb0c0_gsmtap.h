// SPDX-License-Identifier: GPL-2.0-or-later
// Datasource-facing adapter for 0xB0C0 (LTE RRC OTA): raw DIAG payload bytes in
// → a Wireshark-decodable GSMTAP frame out, with nothing between the Kaitai raw
// decode and the GSMTAP sink.
//
// This is the ONE function a Kismet capture-source (datasource_cell_diag.cc)
// calls per 0xB0C0 record. It chains the three already-parity-pinned legs:
//
//   DIAG 0xB0C0 payload
//     → diag_0xb0c0_t          (generated Kaitai raw parse, MIT runtime)
//     → channel_name()          (enrichment/cpp/diag_0xb0c0_enrich)
//     → gsmtap::encode_lte_rrc  (enrichment/cpp/gsmtap)
//     → GsmtapFrame::serialize  (16-byte GSMTAP header + raw RRC PDU)
//
// The GSMTAP payload is the RAW RRC message; Wireshark's LTE-RRC ASN.1 dissector
// does the field decode — so this adapter needs NO C++ ASN.1/UPER stack (the
// RRC decoders are not on this path). The output bytes are pinned against the
// reference encoder for the same payload by
// tests/test_diag_0xb0c0_gsmtap_slice.py over the nine committed
// real/reproduced payloads.
#ifndef DIAGSPEC_DIAG_0XB0C0_GSMTAP_H
#define DIAGSPEC_DIAG_0XB0C0_GSMTAP_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace diagspec {
namespace celldiag {

// Decode a single raw 0xB0C0 log payload (the code-specific bytes AFTER the DIAG
// log-container header, i.e. starting at the version byte) and frame it as a
// GSMTAP LTE-RRC packet.
//
// On success: fills `out_frame` with the serialized 16-byte GSMTAP header + RRC
// PDU and returns true. Returns false — DECLINING the record exactly where the
// reference encoder declines — when the payload does not parse, carries no
// PDU bytes, or resolves to a channel name with no GSMTAP LTE-RRC sub-type
// (BCCH-BCH / non-RRC channels). A declined record is normal, not an error.
bool diag_0xb0c0_to_gsmtap(const uint8_t* payload, std::size_t len,
                           std::vector<uint8_t>& out_frame);

}  // namespace celldiag
}  // namespace diagspec

#endif  // DIAGSPEC_DIAG_0XB0C0_GSMTAP_H
