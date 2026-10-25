// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the 0xB0E2 -> GSMTAP datasource adapter. See the
// header for the seam it closes. Channel-less like the NR-NAS adapters: the
// nas-eps dissector reads the NAS fields, so this wraps the verbatim OTA nas_pdu.
#include "diag_0xb0e2_gsmtap.h"

#include <exception>
#include <string>
#include <vector>

#include "kaitai/kaitaistream.h"
#include "diag_0xb0e2.h"
#include "gsmtap.h"
#include "lte_nas_structure.h"

namespace diagspec {
namespace celldiag {

bool diag_0xb0e2_to_gsmtap(const uint8_t* payload, std::size_t len,
                             std::vector<uint8_t>& out_frame) {
  // A capture source must never let one bad record abort the stream, so a Kaitai
  // parse failure DECLINES the record rather than propagating.
  try {
    std::string blob(reinterpret_cast<const char*>(payload), len);
    kaitai::kstream ks(blob);
    diag_0xb0e2_t rec(&ks);

    const std::string& pdu = rec.nas_pdu();
    std::vector<uint8_t> msg(pdu.begin(), pdu.end());

    // The wrapper has no length field, so a truncated record is caught from
    // the NAS message's own structure, as the reference decoder's shared NAS-OTA
    // framer does: a PDU that provably cannot hold what it declares is DECLINED
    // (no record). Not checkable (unknown type, protected header) keeps
    // framing.
    if (lte_nas::structurally_complete(msg.data(), msg.size(),
                                       /*is_uplink=*/false) ==
        lte_nas::Complete::kNo) {
      return false;
    }

    // sec_hdr_type is an `if:`-gated instance (null on ESM / absent branch); the
    // GSMTAP sub-type is SEC_HEADER only when it is present AND protected
    // (1-4/12), else PLAIN — i.e. exactly `sec_hdr_type in {1,2,3,4,12}`.
    const bool has_sec = !rec._is_null_sec_hdr_type();
    const int sec_hdr_type = has_sec ? rec.sec_hdr_type() : 0;

    gsmtap::GsmtapFrame frame;
    if (!gsmtap::encode_lte_nas(has_sec, sec_hdr_type, /*is_uplink=*/false, msg,
                                frame)) {
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
