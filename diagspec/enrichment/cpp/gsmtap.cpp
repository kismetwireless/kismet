// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ GSMTAP sink. See gsmtap.h.
#include "gsmtap.h"

namespace diagspec {
namespace gsmtap {

namespace {

// Append a big-endian (network-order) u16 / u32. Kept local so the byte order
// lives in exactly one place.
void put_be16(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void put_be32(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

// The 0xB0C0 encoder keys on the canonical channel NAME. Table order and
// membership match the reference encoder's channel → sub-type table exactly.
struct ChannelSub {
  const char* name;
  uint8_t sub;
};
const ChannelSub kLteRrcChannelSubs[] = {
    {"BCCH-BCH", kLteRrcSubBcchBch},   {"BCCH-DL-SCH", kLteRrcSubBcchDlSch},
    {"PCCH", kLteRrcSubPcch},          {"DL-CCCH", kLteRrcSubDlCcch},
    {"DL-DCCH", kLteRrcSubDlDcch},     {"UL-CCCH", kLteRrcSubUlCcch},
    {"UL-DCCH", kLteRrcSubUlDcch},
};

// NAS sec_hdr_type values that select the security-header sub-type — the
// set {1, 2, 3, 4, 12} (12 = service request).
bool nas_sec_hdr_protected(int sec_hdr_type) {
  return sec_hdr_type == 1 || sec_hdr_type == 2 || sec_hdr_type == 3 ||
         sec_hdr_type == 4 || sec_hdr_type == 12;
}

}  // namespace

std::vector<uint8_t> GsmtapFrame::serialize() const {
  std::vector<uint8_t> out;
  out.reserve(16 + payload.size());
  out.push_back(kVersion);
  out.push_back(kHdrLenWords);
  out.push_back(type);
  out.push_back(timeslot);
  put_be16(out, arfcn);
  // Signed int8 → its two's-complement byte, matching struct.pack("b", v).
  out.push_back(static_cast<uint8_t>(signal_dbm));
  out.push_back(static_cast<uint8_t>(snr_db));
  put_be32(out, frame_number);
  out.push_back(sub_type);
  out.push_back(0);  // antenna_nr
  out.push_back(0);  // sub_slot
  out.push_back(0);  // res
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

int lte_rrc_subtype(const std::string& channel_name) {
  for (const ChannelSub& cs : kLteRrcChannelSubs) {
    if (channel_name == cs.name) return cs.sub;
  }
  return -1;
}

bool encode_lte_rrc(const std::string& channel_name, long earfcn,
                    uint32_t sfn, const std::vector<uint8_t>& msg_data,
                    GsmtapFrame& out) {
  if (msg_data.empty()) return false;
  int sub = lte_rrc_subtype(channel_name);
  if (sub < 0) return false;
  // Clamp an out-of-range EARFCN to 0 (band-66 EARFCNs exceed u16).
  long arfcn = (earfcn >= 0 && earfcn <= static_cast<long>(kU16Max)) ? earfcn : 0;
  out = GsmtapFrame();
  out.type = kTypeLteRrc;
  out.sub_type = static_cast<uint8_t>(sub);
  out.payload = msg_data;
  out.arfcn = static_cast<uint16_t>(arfcn);
  out.frame_number = sfn;
  return true;
}

bool encode_lte_nas(bool has_sec_hdr, int sec_hdr_type, bool is_uplink,
                    const std::vector<uint8_t>& nas_pdu, GsmtapFrame& out) {
  if (nas_pdu.empty()) return false;
  uint8_t sub = (has_sec_hdr && nas_sec_hdr_protected(sec_hdr_type))
                    ? kLteNasSecHeader
                    : kLteNasPlain;
  out = GsmtapFrame();
  out.type = kTypeLteNas;
  out.sub_type = sub;
  out.payload = nas_pdu;
  out.arfcn = is_uplink ? kArfcnUplink : 0;
  return true;
}

}  // namespace gsmtap
}  // namespace diagspec
