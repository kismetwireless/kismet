// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ LTE RRC SIB1 decoder (see lte_rrc_sib.h).
// Ported behavior-for-behavior from the reference decoder's
// decode_sib1_cell_access. Equivalence is diffed at
// the field-value level (harness/lte_rrc_sib_verify.py).
//
// ASN.1 shape decoded (3GPP TS 36.331 §6.2.2):
//   BCCH-DL-SCH-MessageType ::= CHOICE { c1 CHOICE { systemInformation,
//                                        systemInformationBlockType1 },
//                                        messageClassExtension SEQUENCE {} }
//   SystemInformationBlockType1 ::= SEQUENCE {  -- no extension marker
//     cellAccessRelatedInfo SEQUENCE {           -- 1 OPTIONAL: csg-Identity
//       plmn-IdentityList    SEQUENCE (SIZE (1..6)) OF PLMN-IdentityInfo,
//       trackingAreaCode     BIT STRING (SIZE (16)),
//       cellIdentity         BIT STRING (SIZE (28)),
//       cellBarred           ENUMERATED { barred, notBarred },
//       intraFreqReselection ENUMERATED { allowed, notAllowed },
//       csg-Indication       BOOLEAN,
//       csg-Identity         OPTIONAL, not decoded },
//     p-Max, tdd-Config, nonCriticalExtension  -- 3 OPTIONALs, not decoded
//     ... }
#include "lte_rrc_sib.h"

#include <cstdint>

namespace diagspec {
namespace lte_rrc {

using asn1::UnalignedPerReader;
using asn1::decode_plmn_identity;

bool decode_sib1_cell_access(const std::vector<uint8_t>& msg_data,
                             Sib1CellIdentity& out) {
  // SIB1 needs at least ~30 bytes on the wire; the gate at 10 is a cheap
  // reject of obviously-too-short blobs. The UPER reader itself reads past-end
  // as 0 (no exception), so there is no out-of-range exception to guard — the
  // size gate and the field sanity checks below carry the load.
  if (msg_data.size() < 10) return false;

  UnalignedPerReader r(msg_data);

  // BCCH-DL-SCH-MessageType: CHOICE { c1(0), messageClassExtension(1) }.
  if (r.read_choice(2) != 0) return false;  // not c1
  // c1: CHOICE { systemInformation(0), systemInformationBlockType1(1) }.
  if (r.read_choice(2) != 1) return false;  // not SIB1

  // SystemInformationBlockType1 has no extension marker and 3 OPTIONALs;
  // cellAccessRelatedInfo has no extension marker and 1 OPTIONAL (csg-Identity,
  // after csg-Indication, not read). The two presence bitmaps are adjacent:
  // p-Max | tdd-Config | nonCriticalExtension | csg-Identity (verified with
  // stock tshark; there is no leading extension bit before the 3 optionals).
  r.read_bits(3);  // SIB1 presence bitmap
  r.read_bits(1);  // cellAccessRelatedInfo presence bitmap (csg-Identity)

  // plmn-IdentityList: SEQUENCE (SIZE (1..6)) OF PLMN-IdentityInfo.
  const uint64_t num_plmns = r.read_length(1, 6);

  Sib1CellIdentity decoded;
  decoded.plmn_list.reserve(static_cast<size_t>(num_plmns));
  for (uint64_t i = 0; i < num_plmns; ++i) {
    // PLMN-IdentityInfo ::= SEQUENCE { plmn-Identity PLMN-Identity,
    //                       cellReservedForOperatorUse ENUMERATED {reserved,
    //                       notReserved} }.
    decoded.plmn_list.push_back(decode_plmn_identity(r));
    r.read_enum(2);  // cellReservedForOperatorUse (1 bit, discarded)
  }

  decoded.tracking_area_code = static_cast<uint32_t>(r.read_bits(16));
  decoded.cell_identity = static_cast<uint32_t>(r.read_bits(28));
  decoded.cell_barred = (r.read_enum(2) == 0);  // barred(0) / notBarred(1)
  r.read_enum(2);                               // intraFreqReselection (skipped)
  decoded.csg_indication = r.read_bool();

  // Sanity: a valid SIB1 has a 3-digit MCC on the first
  // PLMN and non-zero TAC + CellID. These reject a non-SIB1 body that happened
  // to survive the CHOICE walk (garbage bits still decode to *some* values).
  if (decoded.plmn_list.empty() || decoded.plmn_list[0].mcc.size() != 3) {
    return false;
  }
  if (decoded.tracking_area_code == 0 || decoded.cell_identity == 0) {
    return false;
  }

  out = decoded;
  return true;
}

}  // namespace lte_rrc
}  // namespace diagspec
