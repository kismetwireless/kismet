// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ LTE RRC SIB decode — port of the reference decoder's SIB1
// cellAccessRelatedInfo path. The highest-value (PLMN / TAC /
// cell-id) unit of the LTE RRC decoder suite; the 0xB0C0 enrichment leg in
// diag_0xb0c0_enrich.cpp stops at the opaque msg_data blob this decodes.
//
// This is OUR enrichment code, NOT kaitai-struct-compiler output and
// not the vendored MIT runtime: `.ksy` is layout-only and cannot express PER.
// It rides the UPER reader (uper.h) and the ASN.1 helpers (asn1_helpers.h), so
// it re-derives no PLMN decode and no §11.9 length logic.
//
// Equivalence to the reference decoder is diffed at the FIELD-VALUE level
// (harness/lte_rrc_sib_verify.py), so identifiers are chosen for a C++ reader,
// not mechanically mirrored from it — the spec term
// `decode_sib1_cell_access` is kept because it reads best.
//
// Live-path note: this is the SIB1 decode the 0xB0C0 path actually runs — it
// calls decode_sib1_cell_access on the BCCH-DL-SCH msg_data to populate
// sib1_mcc/mnc/tac/cell_id — not an unreferenced helper.
#ifndef DIAGSPEC_LTE_RRC_SIB_H
#define DIAGSPEC_LTE_RRC_SIB_H

#include <cstdint>
#include <vector>

#include "asn1_helpers.h"
#include "uper.h"

namespace diagspec {
namespace lte_rrc {

// SystemInformationBlockType1.cellAccessRelatedInfo, the surfaced fields
// (TS 36.331 §6.2.2). The remaining SIB1 fields (p-Max, tdd-Config,
// schedulingInfoList, …) are not decoded — the decode deliberately stops at
// this seam.
struct Sib1CellIdentity {
  std::vector<asn1::PlmnIdentity> plmn_list;
  uint32_t tracking_area_code = 0;  // TrackingAreaCode BIT STRING (SIZE (16))
  uint32_t cell_identity = 0;       // CellIdentity BIT STRING (SIZE (28))
  bool cell_barred = false;         // cellBarred == ENUMERATED barred(0)
  bool csg_indication = false;      // csg-Indication BOOLEAN
};

// Decode SIB1 cellAccessRelatedInfo from a BCCH-DL-SCH UPER bitstream. Returns
// true and fills `out` on success; returns false (leaving `out` untouched) when
// the message is not SIB1 or fails the sanity checks. Navigates:
//   BCCH-DL-SCH-Message → message → c1 → systemInformationBlockType1
//   → cellAccessRelatedInfo → plmn-IdentityList, TAC, cellIdentity, …
bool decode_sib1_cell_access(const std::vector<uint8_t>& msg_data,
                             Sib1CellIdentity& out);

}  // namespace lte_rrc
}  // namespace diagspec

#endif  // DIAGSPEC_LTE_RRC_SIB_H
