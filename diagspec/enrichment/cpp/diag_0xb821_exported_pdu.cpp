// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the 0xB821 → Exported-PDU datasource adapter. See the
// header.
#include "diag_0xb821_exported_pdu.h"

#include <exception>
#include <string>

#include "kaitai/kaitaistream.h"
#include "diag_0xb821.h"
#include "diag_0xb821_enrich.h"
#include "exported_pdu.h"

namespace diagspec {
namespace celldiag {

bool diag_0xb821_to_exported_pdu(const uint8_t* payload, std::size_t len,
                                 std::vector<uint8_t>& out_frame) {
  // Kaitai throws (std::exception subclasses) on a truncated / malformed buffer;
  // a capture source must never let one bad record abort the stream, so a parse
  // failure DECLINES the record rather than propagating.
  try {
    std::string blob(reinterpret_cast<const char*>(payload), len);
    // The 0xB821 parse refuses (so nothing is framed) a record whose
    // version is outside its declared set, v7 included, and a record shorter
    // than header_size + msg_length. The .ksy still lays out v7 and the channel
    // map still names its pdu_ids, so without this gate a v7 BCCH-BCH or
    // RRC-reconfiguration-complete record would be framed here and nowhere in
    // any other output. Same refusal the observation and identity legs use.
    if (diag_0xb821_enrich::record_refused(blob)) {
      return false;
    }
    kaitai::kstream ks(blob);
    diag_0xb821_t rec(&ks);

    // channel_name is resolved off the per-version pdu_id by the enrichment leg;
    // the nr-rrc.<channel> dissector selection keys on the NAME. An
    // unmapped (version, pdu_id) yields "" and the encoder declines.
    const std::string chan =
        diag_0xb821_enrich::channel_name(rec.version(), rec.pdu_id());

    // msg_data() is the raw ASN.1 PER RRC PDU (Kaitai returns it as a
    // std::string of bytes under KS_STR_ENCODING_NONE); an empty PDU makes the
    // encoder decline.
    const std::string& pdu = rec.msg_data();
    std::vector<uint8_t> msg(pdu.begin(), pdu.end());

    exported_pdu::ExportedPduFrame frame;
    if (!exported_pdu::encode_nr_rrc(chan, msg, frame)) {
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
