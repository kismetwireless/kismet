// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ Wireshark Exported-PDU sink — the NR-signalling sibling of the
// GSMTAP sink (gsmtap.{h,cpp}).
//
// 5G NR RRC / NR NAS OTA bytes cannot ride plain GSMTAP (the public gsmtap.h
// type range has no NR type), so NR gets a second framing: a Wireshark
// Exported-PDU record (DLT_WIRESHARK_UPPER_PDU = 252) tagged with the stock NR
// dissector name (nr-rrc.<channel> / nas-5gs). The encoder does NO field decode
// — it wraps the parser's verbatim OTA PDU and the stock dissector decodes it.
//
// This is OUR enrichment code. The Exported-PDU tag layout is read
// from the PUBLIC epan/exported_pdu.h constants and the dissector names from
// `tshark -G dissectors` (facts, not copied code); qcsuper/SCAT/Wireshark are an
// output oracle, never a source. Zero dependencies beyond the STL. Equivalence
// is diffed at the serialized-byte level (harness/gsmtap_verify.py).
#ifndef DIAGSPEC_EXPORTED_PDU_H
#define DIAGSPEC_EXPORTED_PDU_H

#include <cstdint>
#include <string>
#include <vector>

namespace diagspec {
namespace exported_pdu {

// ---- Exported-PDU constants (public epan/exported_pdu.h) ------------------
// libpcap link-layer header type for a Wireshark Upper-PDU export.
constexpr uint16_t kDltWiresharkUpperPdu = 252;

// Option tags. A record is a sequence of (u16 type, u16 length, value) options
// terminated by an END_OF_OPT tag (type 0, length 0); the verbatim PDU follows.
constexpr uint16_t kTagEndOfOpt = 0;
constexpr uint16_t kTagDissectorName = 12;  // target dissector by short name

// Build one Exported-PDU record: a dissector-name tag + the verbatim PDU.
//
//     [u16 kTagDissectorName][u16 len][name bytes]
//     [u16 kTagEndOfOpt      ][u16 0  ]
//     [verbatim PDU ...]
//
// All multi-byte fields are big-endian; tag values are NOT padded (the stock
// packet-exported_pdu dissector advances by each tag's declared length).
std::vector<uint8_t> exported_pdu_block(const std::string& dissector_name,
                                        const std::vector<uint8_t>& pdu);

// ---- ExportedPduFrame: a dissector-name tag + verbatim PDU ----------------
struct ExportedPduFrame {
  std::string dissector_name;
  std::vector<uint8_t> payload;

  std::vector<uint8_t> serialize() const {
    return exported_pdu_block(dissector_name, payload);
  }
};

// NR RRC canonical channel NAME → stock per-channel dissector name, or "" when
// the name is not a known NR-RRC channel (the caller then declines the record).
// Keyed on the name (version-robust), mirroring the LTE-RRC encoder.
std::string nr_rrc_dissector(const std::string& channel_name);

// Encode a decoded NR RRC OTA record (0xB821) into `out`. Returns false —
// declining the record — when there are no PDU bytes or the channel maps to
// no nr-rrc.<channel> dissector.
bool encode_nr_rrc(const std::string& channel_name,
                   const std::vector<uint8_t>& msg_data,
                   ExportedPduFrame& out);

// Encode a decoded NR NAS OTA record (the 0xB80x family) into `out`. Returns
// false when there are no PDU bytes. 5GS NAS is a single dissector tag
// (nas-5gs) — no per-channel routing, unlike NR RRC.
bool encode_nr_nas(const std::vector<uint8_t>& nas_pdu, ExportedPduFrame& out);

}  // namespace exported_pdu
}  // namespace diagspec

#endif  // DIAGSPEC_EXPORTED_PDU_H
