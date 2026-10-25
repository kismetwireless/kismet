// SPDX-License-Identifier: GPL-2.0-or-later
// Datasource-facing adapter for 0xB808 (NR5G NAS 5GMM Security-Protected OTA
// Incoming) — the NR-NAS sibling of the 0xB821 NR-RRC adapter. 5G NR NAS bytes
// cannot ride plain GSMTAP (no NR type in the public gsmtap.h range), so —
// exactly like NR RRC — NR NAS frames
// as a Wireshark Exported-PDU record (DLT_WIRESHARK_UPPER_PDU = 252). But unlike
// NR RRC, 5GS NAS is a SINGLE dissector tag (nas-5gs): the dissector reads the
// 5GMM/5GSM EPD and (for the security-protected codes) the outer 5GS security
// header out of the PDU bytes itself, so there is NO per-channel routing and thus
// NO enrichment leg, and nothing sits between the Kaitai raw decode and the
// Exported-PDU sink.
//
// This is the ONE function a Kismet capture-source (datasource_cell_diag.cc)
// calls per 0xB808 record. It chains the already-parity-pinned legs:
//
//   DIAG 0xB808 payload
//     → diag_0xb808_t                        (generated Kaitai raw parse, MIT rt)
//     → nas_pdu()                             (the verbatim OTA NAS PDU blob)
//     → exported_pdu::encode_nr_nas           (enrichment/cpp/exported_pdu)
//     → ExportedPduFrame::serialize           (nas-5gs dissector tag + raw NAS PDU)
//
// The Exported-PDU payload is the RAW OTA NAS PDU (starting at the EPD, including
// any 5GS security header); Wireshark's nas-5gs dissector does the field decode —
// so this slice needs NO C++ NAS stack. A ciphered inner (sec_hdr_type 2/4) stays
// opaque but its security header still dissects — correct behavior. The output
// bytes are pinned against the reference encoder for the same payload by
// tests/test_diag_0xb808_exported_pdu_slice.py over the committed branch fixtures.
#ifndef DIAGSPEC_DIAG_0XB808_EXPORTED_PDU_H
#define DIAGSPEC_DIAG_0XB808_EXPORTED_PDU_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace diagspec {
namespace celldiag {

// Decode a single raw 0xB808 log payload (the code-specific bytes AFTER the DIAG
// log-container header, i.e. starting at the 7-byte NR5G-NAS-OTA wrapper) and
// frame it as a Wireshark Exported-PDU NR-NAS record tagged with the nas-5gs
// dissector.
//
// On success: fills `out_frame` with the serialized dissector-name tag + NAS PDU
// and returns true. Returns false — DECLINING the record exactly where the
// reference encoder declines — when the payload does not parse or carries no PDU bytes
// (an empty/truncated nas_pdu). A declined record is normal, not an error.
bool diag_0xb808_to_exported_pdu(const uint8_t* payload, std::size_t len,
                                 std::vector<uint8_t>& out_frame);

}  // namespace celldiag
}  // namespace diagspec

#endif  // DIAGSPEC_DIAG_0XB808_EXPORTED_PDU_H
