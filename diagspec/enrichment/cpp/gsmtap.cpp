// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ GSMTAP sink. See gsmtap.h.
#include "gsmtap.h"

#include <algorithm>

namespace diagspec {
namespace gsmtap {

namespace {

// Write a big-endian (network-order) u16 / u32 at p. Kept local so the byte
// order lives in exactly one place.
void put_be16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[1] = static_cast<uint8_t>(v & 0xFF);
}

void put_be32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[3] = static_cast<uint8_t>(v & 0xFF);
}

constexpr size_t kHdrLen = kHdrLenWords * 4;

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

// Sized once and written in place; appending byte by byte trips a gcc 14
// -Wfree-nonheap-object false positive in the inlined vector growth path.
std::vector<uint8_t> GsmtapFrame::serialize() const {
  std::vector<uint8_t> out(kHdrLen + payload.size());
  uint8_t* p = out.data();
  p[0] = kVersion;
  p[1] = kHdrLenWords;
  p[2] = type;
  p[3] = timeslot;
  put_be16(p + 4, arfcn);
  // Signed int8 → its two's-complement byte, matching struct.pack("b", v).
  p[6] = static_cast<uint8_t>(signal_dbm);
  p[7] = static_cast<uint8_t>(snr_db);
  put_be32(p + 8, frame_number);
  p[12] = sub_type;
  // antenna_nr, sub_slot and res stay 0
  std::copy(payload.begin(), payload.end(), out.begin() + kHdrLen);
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
