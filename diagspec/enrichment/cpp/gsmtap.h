// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ GSMTAP sink — the wire-encoding half of the GSMTAP output (the
// pure GsmtapFrame serializer + the per-log-code encoders that package a
// decoded LTE RRC / LTE NAS record for Wireshark). The NR-signalling sibling lives in exported_pdu.{h,cpp}. This
// file only PACKAGES RRC/NAS PDU bytes; it does no ASN.1 decode itself.
//
// This is OUR enrichment code, NOT kaitai-struct-compiler output and
// not the vendored MIT runtime. The 16-byte GSMTAP header layout and the LTE
// RRC/NAS sub-type constants are taken from the PUBLIC Osmocom GSMTAP spec
// (`gsmtap.h`), as the reference decoder's are — never from the qcsuper/SCAT
// black boxes (those are an output oracle only). Zero dependencies beyond the
// STL.
//
// Equivalence to the reference decoder's sink is diffed at the SERIALIZED-BYTE
// level (harness/gsmtap_verify.py): GSMTAP is an on-wire framing, so the oracle
// is the exact byte stream, not a raw-field scalar. Identifiers are chosen for a
// C++ reader: `serialize()`, `encode_lte_rrc`, `encode_lte_nas`.
#ifndef DIAGSPEC_GSMTAP_H
#define DIAGSPEC_GSMTAP_H

#include <cstdint>
#include <string>
#include <vector>

namespace diagspec {
namespace gsmtap {

// ---- GSMTAP header constants (Osmocom gsmtap.h, public spec) --------------
constexpr uint16_t kUdpPort = 4729;
constexpr uint8_t kVersion = 0x02;
constexpr uint8_t kHdrLenWords = 4;  // header length in 32-bit words = 16 bytes

// arfcn flag bits: bit 14 marks an uplink PDU.
constexpr uint16_t kArfcnUplink = 0x4000;
constexpr uint32_t kU16Max = 0xFFFF;

constexpr uint8_t kTypeLteRrc = 0x0D;
constexpr uint8_t kTypeLteNas = 0x12;

// LTE NAS sub-types — a plain-vs-security-protected selector only; Wireshark's
// nas-eps dissector reads the NAS security header out of the PDU bytes itself.
constexpr uint8_t kLteNasPlain = 0;
constexpr uint8_t kLteNasSecHeader = 1;

// LTE RRC sub-types (logical channel) — Osmocom gsmtap.h.
constexpr uint8_t kLteRrcSubDlCcch = 0;
constexpr uint8_t kLteRrcSubDlDcch = 1;
constexpr uint8_t kLteRrcSubUlCcch = 2;
constexpr uint8_t kLteRrcSubUlDcch = 3;
constexpr uint8_t kLteRrcSubBcchBch = 4;
constexpr uint8_t kLteRrcSubBcchDlSch = 5;
constexpr uint8_t kLteRrcSubPcch = 6;
constexpr uint8_t kLteRrcSubMcch = 7;

// ---- GsmtapFrame: a 16-byte header + inner PDU payload --------------------
//
// The scalar defaults are all zero so an encoder need only set the fields it
// cares about. `signal_dbm` / `snr_db` are SIGNED (packed as signed bytes on the
// wire), so they are int8_t here.
struct GsmtapFrame {
  uint8_t type = 0;
  uint8_t sub_type = 0;
  std::vector<uint8_t> payload;
  uint16_t arfcn = 0;
  uint32_t frame_number = 0;
  uint8_t timeslot = 0;
  int8_t signal_dbm = 0;
  int8_t snr_db = 0;

  // Serialise to the 16-byte big-endian GSMTAP header followed by the payload.
  // Layout (big-endian): u8 version, u8 hdr_len, u8 type, u8 timeslot,
  // u16 arfcn, s8 signal_dbm, s8 snr_db, u32 frame_number, u8 sub_type,
  // u8 antenna, u8 sub_slot, u8 reserved — then the payload.
  std::vector<uint8_t> serialize() const;
};

// LTE RRC canonical channel NAME → GSMTAP sub-type, or -1 when the name is not
// a known LTE-RRC channel (the caller then declines the record). Keyed on the
// name (not the raw per-version channel integer) so it is version-robust.
int lte_rrc_subtype(const std::string& channel_name);

// Encode a decoded LTE RRC OTA record (0xB0C0) into `out`. Returns false —
// declining the record (no frame is produced) — when there are no PDU
// bytes or the channel name maps to no GSMTAP sub-type. `earfcn` is taken as a
// wide signed value and clamped to 0 when outside the u16 arfcn range (band-66
// EARFCNs exceed 65535); it is informational only, not needed for dissection.
bool encode_lte_rrc(const std::string& channel_name, long earfcn,
                    uint32_t sfn, const std::vector<uint8_t>& msg_data,
                    GsmtapFrame& out);

// Encode a decoded LTE NAS OTA record (the 0xB0Ex family) into `out`. Returns
// false when there are no PDU bytes. `has_sec_hdr` distinguishes "the record
// exposes a sec_hdr_type" from "it does not" (0xB0E1's bare ESM PDU carries no
// EMM security header → treated as plain); a protected sec_hdr_type (1/2/3/4/12)
// selects the security-header sub-type. `is_uplink` sets the uplink arfcn flag.
bool encode_lte_nas(bool has_sec_hdr, int sec_hdr_type, bool is_uplink,
                    const std::vector<uint8_t>& nas_pdu, GsmtapFrame& out);

}  // namespace gsmtap
}  // namespace diagspec

#endif  // DIAGSPEC_GSMTAP_H
