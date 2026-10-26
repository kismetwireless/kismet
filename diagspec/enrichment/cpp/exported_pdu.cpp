// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ Exported-PDU sink. See
// exported_pdu.h.
#include "exported_pdu.h"

namespace diagspec {
namespace exported_pdu {

namespace {

void put_be16(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

// NR RRC channel NAME → stock per-channel dissector. Membership matches the
// reference encoder's channel → dissector table.
struct ChannelDissector {
  const char* name;
  const char* dissector;
};
const ChannelDissector kNrRrcChannelDissectors[] = {
    {"BCCH-BCH", "nr-rrc.bcch.bch"},   {"BCCH-DL-SCH", "nr-rrc.bcch.dl.sch"},
    {"DL-CCCH", "nr-rrc.dl.ccch"},     {"DL-DCCH", "nr-rrc.dl.dcch"},
    {"UL-CCCH", "nr-rrc.ul.ccch"},     {"UL-DCCH", "nr-rrc.ul.dcch"},
    {"PCCH", "nr-rrc.pcch"},           {"MCCH", "nr-rrc.mcch"},
    // SCAT's pdu_id map names two records by MESSAGE TYPE rather than logical
    // channel — pdu_id 9/10 -> RRC-RECONF / RRC-RECONF-COMPLETE. The payload is
    // a *bare* RRCReconfiguration / RRCReconfigurationComplete, routing to the
    // stock message-level dissectors (nr-rrc.rrc_reconf / nr-rrc.rrc_reconf_compl).
    {"RRC-RECONF", "nr-rrc.rrc_reconf"},
    {"RRC-RECONF-COMPLETE", "nr-rrc.rrc_reconf_compl"},
};

// The single 5GS NAS dissector tag — no per-channel routing.
const char* const kNas5gsDissector = "nas-5gs";

}  // namespace

std::vector<uint8_t> exported_pdu_block(const std::string& dissector_name,
                                        const std::vector<uint8_t>& pdu) {
  std::vector<uint8_t> out;
  out.reserve(4 + dissector_name.size() + 4 + pdu.size());
  put_be16(out, kTagDissectorName);
  put_be16(out, static_cast<uint16_t>(dissector_name.size()));
  out.insert(out.end(), dissector_name.begin(), dissector_name.end());
  put_be16(out, kTagEndOfOpt);
  put_be16(out, 0);
  out.insert(out.end(), pdu.begin(), pdu.end());
  return out;
}

std::string nr_rrc_dissector(const std::string& channel_name) {
  for (const ChannelDissector& cd : kNrRrcChannelDissectors) {
    if (channel_name == cd.name) return cd.dissector;
  }
  return "";
}

bool encode_nr_rrc(const std::string& channel_name,
                   const std::vector<uint8_t>& msg_data,
                   ExportedPduFrame& out) {
  if (msg_data.empty()) return false;
  std::string dissector = nr_rrc_dissector(channel_name);
  if (dissector.empty()) return false;
  out.dissector_name = dissector;
  out.payload = msg_data;
  return true;
}

bool encode_nr_nas(const std::vector<uint8_t>& nas_pdu, ExportedPduFrame& out) {
  if (nas_pdu.empty()) return false;
  out.dissector_name = kNas5gsDissector;
  out.payload = nas_pdu;
  return true;
}

}  // namespace exported_pdu
}  // namespace diagspec
