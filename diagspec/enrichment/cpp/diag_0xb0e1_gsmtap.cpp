// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the 0xB0E1 -> GSMTAP datasource adapter. See the
// header for the seam it closes. Channel-less like the NR-NAS adapters: the
// nas-eps dissector reads the NAS fields, so this wraps the verbatim OTA nas_pdu.
#include "diag_0xb0e1_gsmtap.h"

#include <exception>
#include <string>
#include <vector>

#include "kaitai/kaitaistream.h"
#include "diag_0xb0e1.h"
#include "gsmtap.h"

namespace diagspec {
namespace celldiag {

bool diag_0xb0e1_to_gsmtap(const uint8_t* payload, std::size_t len,
                             std::vector<uint8_t>& out_frame) {
  // A capture source must never let one bad record abort the stream, so a Kaitai
  // parse failure DECLINES the record rather than propagating.
  try {
    // The 0xB0E1 parse gates, in order: the 4-octet wrapper plus the
    // 6-octet security header plus at least 3 octets of inner message, the
    // byte-0 version, then "integrity protected and ciphered" (sec_hdr_type 2)
    // over the EMM protocol discriminator. Anything else is declined.
    if (len < 4 + 6 + 3) return false;
    std::string blob(reinterpret_cast<const char*>(payload), len);
    kaitai::kstream ks(blob);
    diag_0xb0e1_t rec(&ks);
    if (rec.version() != 1) return false;
    if (rec.sec_hdr_type() != 2 || rec.prot_disc() != 7) return false;

    // nas_pdu is the whole security-protected PDU, from the security-header
    // octet to the end of the record: what GSMTAP frames, so nas-eps can
    // dissect the MAC and sequence number.
    const std::string pdu = rec.nas_pdu();
    std::vector<uint8_t> msg(pdu.begin(), pdu.end());

    // 0xB0E1 is the security-protected outer message: it
    // exposes sec_hdr_type 2, so the sub-type is SEC_HEADER, and it is the
    // UE's send path, so the frame carries the uplink flag.
    const bool has_sec = true;
    const int sec_hdr_type = rec.sec_hdr_type();

    gsmtap::GsmtapFrame frame;
    if (!gsmtap::encode_lte_nas(has_sec, sec_hdr_type, /*is_uplink=*/true, msg,
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
