// SPDX-License-Identifier: GPL-2.0-or-later
// Linkable surface of the 0xB821 (NR RRC OTA) C++ enrichment leg — the NR
// sibling of diag_0xb0c0_enrich.h (0xB0C0 feeds LTE→GSMTAP; 0xB821 feeds
// NR→Exported-PDU the same way).
//
// The generated Kaitai raw parser (generated/cpp/diag_0xb821) exposes only the
// per-version integer pdu_id() (the channel discriminator) and version(), never
// the resolved 3GPP TS 38.331 channel NAME the Exported-PDU dissector selection
// keys on (as with 0xB0C0). So the name resolution lives here,
// declared once and reused by both the standalone enrich runner and the
// datasource-facing adapter (diag_0xb821_exported_pdu).
#ifndef DIAGSPEC_DIAG_0XB821_ENRICH_H
#define DIAGSPEC_DIAG_0XB821_ENRICH_H

#include <cstdint>
#include <string>

namespace diag_0xb821_enrich {

// Version-keyed pdu_id -> canonical NR RRC channel_name via the generated
// enrichment tables (diagspec::nr_rrc::channel_names_by_version, single-sourced
// from shared_data/enrichment_tables.yaml). Returns "" — the UNMAPPED signal —
// when the version is unsupported or pdu_id is outside that version's map (NB:
// unlike 0xB0C0's channel_name, there is NO hex fallback here; the caller
// declines the record on empty).
std::string channel_name(uint32_t version, uint8_t pdu_id);

// True when the 0xB821 parse refuses this payload, i.e. when the
// native census must count the record DROPPED, not decoded. Exactly the
// parser's three declines: shorter than the u32 version, a version outside
// its header-size table (v7 included) or shorter than that header, or shorter
// than header_size + the declared msg_length (truncated RRC PDU). Every 0xB821
// leg reports the same refusal, because they all front the same parser.
bool record_refused(const std::string& payload);

}  // namespace diag_0xb821_enrich

#endif  // DIAGSPEC_DIAG_0XB821_ENRICH_H
