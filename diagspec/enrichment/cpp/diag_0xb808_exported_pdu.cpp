// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the 0xB808 → Exported-PDU datasource adapter. See the
// header. Simpler than the 0xB821 sibling: 5GS NAS is a
// single nas-5gs dissector tag, so there is NO enrichment/channel_name leg — the
// adapter wraps the verbatim OTA nas_pdu and Wireshark does the field decode.
#include "diag_0xb808_exported_pdu.h"

#include <exception>
#include <string>

#include "kaitai/kaitaistream.h"
#include "diag_0xb808.h"
#include "exported_pdu.h"

namespace diagspec {
namespace celldiag {

bool diag_0xb808_to_exported_pdu(const uint8_t* payload, std::size_t len,
                                 std::vector<uint8_t>& out_frame) {
  // Kaitai throws (std::exception subclasses) on a truncated / malformed buffer;
  // a capture source must never let one bad record abort the stream, so a parse
  // failure DECLINES the record rather than propagating.
  try {
    std::string blob(reinterpret_cast<const char*>(payload), len);
    kaitai::kstream ks(blob);
    diag_0xb808_t rec(&ks);

    // nas_pdu() is the raw OTA 5GS NAS PDU (Kaitai returns it as a std::string of
    // bytes under KS_STR_ENCODING_NONE); it starts at the EPD and includes any
    // 5GS security header. An empty PDU makes the encoder decline — so a
    // wrapper-only/truncated record yields no frame.
    const std::string& pdu = rec.nas_pdu();
    std::vector<uint8_t> msg(pdu.begin(), pdu.end());

    exported_pdu::ExportedPduFrame frame;
    if (!exported_pdu::encode_nr_nas(msg, frame)) {
      return false;
    }
    out_frame = frame.serialize();
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace celldiag
}  // namespace diagspec
