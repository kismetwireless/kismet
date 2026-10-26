// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the 0xB0C0 → GSMTAP datasource adapter. See the header.
#include "diag_0xb0c0_gsmtap.h"

#include <exception>
#include <string>

#include "kaitai/kaitaistream.h"
#include "diag_0xb0c0.h"
#include "diag_0xb0c0_enrich.h"
#include "gsmtap.h"

namespace diagspec {
namespace celldiag {

bool diag_0xb0c0_to_gsmtap(const uint8_t* payload, std::size_t len,
                           std::vector<uint8_t>& out_frame) {
  // Kaitai throws (std::exception subclasses) on a truncated / malformed
  // buffer; a capture source must never let one bad record abort the stream, so
  // a parse failure DECLINES the record rather than propagating.
  try {
    std::string blob(reinterpret_cast<const char*>(payload), len);
    kaitai::kstream ks(blob);
    diag_0xb0c0_t rec(&ks);

    // channel_name is resolved off the per-version channel_type enum by the
    // enrichment leg; GSMTAP sub-type selection keys on the NAME.
    const std::string chan =
        diag_0xb0c0_enrich::channel_name(rec.version(), rec.channel_type());

    // msg_data() is the raw RRC PDU (Kaitai returns it as a std::string of
    // bytes under KS_STR_ENCODING_NONE); an empty PDU makes the encoder decline.
    const std::string& pdu = rec.msg_data();
    std::vector<uint8_t> msg(pdu.begin(), pdu.end());

    gsmtap::GsmtapFrame frame;
    if (!gsmtap::encode_lte_rrc(chan, static_cast<long>(rec.earfcn()),
                                static_cast<uint32_t>(rec.sfn()), msg, frame)) {
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
