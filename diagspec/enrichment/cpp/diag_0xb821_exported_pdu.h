// SPDX-License-Identifier: GPL-2.0-or-later
// Datasource-facing adapter for 0xB821 (NR RRC OTA) — the NR sibling of the
// 0xB0C0→GSMTAP adapter. 5G NR RRC bytes cannot ride plain GSMTAP (no NR type in
// the public gsmtap.h range), so NR frames as a Wireshark Exported-PDU record
// (DLT_WIRESHARK_UPPER_PDU = 252) tagged with the stock per-channel nr-rrc
// dissector name, with nothing between the Kaitai raw decode and the
// Exported-PDU sink.
//
// This is the ONE function a Kismet capture-source (datasource_cell_diag.cc)
// calls per 0xB821 record. It chains the three already-parity-pinned legs:
//
//   DIAG 0xB821 payload
//     → diag_0xb821_t                       (generated Kaitai raw parse, MIT rt)
//     → channel_name()                       (diag_0xb821_enrich)
//     → exported_pdu::encode_nr_rrc          (enrichment/cpp/exported_pdu)
//     → ExportedPduFrame::serialize          (dissector-name tag + raw RRC PDU)
//
// The Exported-PDU payload is the RAW ASN.1 PER RRC message; Wireshark's
// nr-rrc.<channel> dissector does the field decode — so this slice needs NO C++
// ASN.1/UPER stack. The output bytes are pinned against the reference encoder
// for the same payload by tests/test_diag_0xb821_exported_pdu_slice.py over the
// committed per-version payloads.
#ifndef DIAGSPEC_DIAG_0XB821_EXPORTED_PDU_H
#define DIAGSPEC_DIAG_0XB821_EXPORTED_PDU_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace diagspec {
namespace celldiag {

// Decode a single raw 0xB821 log payload (the code-specific bytes AFTER the DIAG
// log-container header, i.e. starting at the version u32) and frame it as a
// Wireshark Exported-PDU NR-RRC record.
//
// On success: fills `out_frame` with the serialized dissector-name tag + RRC PDU
// and returns true. Returns false — DECLINING the record exactly where the
// reference encoder declines — when the payload does not parse, carries no PDU bytes,
// or resolves to a channel name with no nr-rrc.<channel> dissector (unmapped /
// unsupported version). A declined record is normal, not an error.
bool diag_0xb821_to_exported_pdu(const uint8_t* payload, std::size_t len,
                                 std::vector<uint8_t>& out_frame);

}  // namespace celldiag
}  // namespace diagspec

#endif  // DIAGSPEC_DIAG_0XB821_EXPORTED_PDU_H
