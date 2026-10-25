// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ NR5G RRC decoders (see nr5g_rrc.h). Ported
// behavior-for-behavior from the reference decoder's MIB and SIB1 decodes.
// Equivalence is diffed at the field-value level (harness/nr5g_rrc_verify.py).
//
// No exception guard: the UPER reader reads past end-of-buffer as 0 rather than
// throwing (see uper.h), so a
// truncated payload degrades into zero-filled fields that the size gate + the
// sanity checks reject — the same discipline the LTE unit (lte_rrc_sib.cpp)
// documents. Fixtures are well-formed; reject cases fail at a CHOICE or a sanity
// check, never by running off the end mid-field.
#include "nr5g_rrc.h"

#include <cstdint>

namespace diagspec {
namespace nr5g_rrc {

using asn1::UnalignedPerReader;
using asn1::PlmnIdentity;
using asn1::decode_plmn_identity;
using asn1::skip_extension_additions;

namespace {

// SubcarrierSpacingCommon ENUMERATED (MIB-only 2-value form; distinct from the
// 8-value SubcarrierSpacing used elsewhere). FR1 uses the first of each kHz
// pair, FR2 the second.
const char* scs_common_name(uint64_t ordinal) {
  return ordinal == 0 ? "scs15or60" : "scs30or120";
}

// DMRS-TypeA-Position ENUMERATED — front-loaded DMRS symbol for mapping type A
// (38.211 §7.4.1.1.2).
const char* dmrs_type_a_name(uint64_t ordinal) {
  return ordinal == 0 ? "pos2" : "pos3";
}

// CellSelectionInfo SEQUENCE (TS 38.331), skipped whole. Not extensible in the
// base spec; 4 OPTIONAL fields after the mandatory q-RxLevMin, skipped
// field-for-field.
void skip_cell_selection_info(UnalignedPerReader& r) {
  uint64_t opt = r.read_bits(4);          // 4 OPTIONAL presence flags
  r.read_constrained_int(-70, -22);       // q-RxLevMin (mandatory)
  if ((opt >> 3) & 1) r.read_constrained_int(1, 8);      // q-RxLevMinOffset
  if ((opt >> 2) & 1) r.read_constrained_int(-70, -22);  // q-RxLevMinSUL
  if ((opt >> 1) & 1) r.read_constrained_int(-43, -12);  // q-QualMin
  if (opt & 1)        r.read_constrained_int(1, 8);      // q-QualMinOffset
}

}  // namespace

bool decode_mib(const std::vector<uint8_t>& msg_data, NrMib& out) {
  // MIB content is 24 bits; the size gate is 3 bytes.
  if (msg_data.size() < 3) return false;

  UnalignedPerReader r(msg_data);

  // BCCH-BCH-MessageType: CHOICE { mib(0), messageClassExtension(1) }.
  if (r.read_choice(2) != 0) return false;  // messageClassExtension → no MIB

  NrMib m;
  m.system_frame_number = static_cast<uint8_t>(r.read_bits(6));
  const uint64_t scs = r.read_bits(1);
  m.sub_carrier_spacing_common = static_cast<uint8_t>(scs);
  m.sub_carrier_spacing_common_name = scs_common_name(scs);
  m.ssb_subcarrier_offset =
      static_cast<uint8_t>(r.read_constrained_int(0, 15));
  const uint64_t dmrs = r.read_bits(1);
  m.dmrs_type_a_position = static_cast<uint8_t>(dmrs);
  m.dmrs_type_a_position_name = dmrs_type_a_name(dmrs);
  m.control_resource_set_zero =
      static_cast<uint8_t>(r.read_constrained_int(0, 15));
  m.search_space_zero = static_cast<uint8_t>(r.read_constrained_int(0, 15));
  // cellBarred ENUMERATED { barred(0), notBarred(1) }; store barred polarity.
  m.cell_barred = !r.read_bool();
  // intraFreqReselection ENUMERATED { allowed(0), notAllowed(1) }.
  m.intra_freq_reselection_allowed = (r.read_bits(1) == 0);
  m.spare = static_cast<uint8_t>(r.read_bits(1));

  out = m;
  return true;
}

bool decode_sib1_cell_id(const std::vector<uint8_t>& msg_data,
                         NrSib1CellId& out) {
  if (msg_data.size() < 10) return false;

  UnalignedPerReader r(msg_data);

  // BCCH-DL-SCH-MessageType: CHOICE { c1(0), messageClassExtension(1) }.
  if (r.read_choice(2) != 0) return false;
  // c1: CHOICE { systemInformation(0), systemInformationBlockType1(1) } — 1 bit.
  if (r.read_choice(2) != 1) return false;

  // SIB1 is NOT extensible in the published 38.331 ASN.1 (it uses an explicit
  // nonCriticalExtension chain, not a `...` marker; pycrate-verified), so
  // the 11-bit root OPTIONAL bitmap starts immediately — there is no extension
  // bit at this position. cellAccessRelatedInfo is MANDATORY (not in the bitmap).
  const uint64_t opt_bitmap = r.read_bits(11);
  const bool has_cell_sel = (opt_bitmap >> 10) & 1;  // cellSelectionInfo (MSB)
  if (has_cell_sel) skip_cell_selection_info(r);

  // CellAccessRelatedInfo ::= SEQUENCE { plmn-IdentityInfoList, ... } — extensible
  // with 1 OPTIONAL (cellReservedForOtherUse). The extension marker is kept for
  // the servingCellConfigCommon walk, which must skip the additions.
  const bool cari_has_ext = r.read_bool();
  r.read_bits(1);  // 1 OPTIONAL presence flag

  // plmn-IdentityInfoList: SEQUENCE (SIZE (1..12)) OF PLMN-IdentityInfo.
  const int64_t num_plmn_entries = r.read_constrained_int(1, 12);

  NrSib1CellId decoded;
  for (int64_t entry_idx = 0; entry_idx < num_plmn_entries; ++entry_idx) {
    // PLMN-IdentityInfo ::= SEQUENCE { ... } — extensible; 2 OPTIONALs
    // (trackingAreaCode, ranac).
    const bool pii_has_ext = r.read_bool();
    const uint64_t pii_opt = r.read_bits(2);
    const bool has_tac = (pii_opt >> 1) & 1;
    const bool has_ranac = pii_opt & 1;

    // plmn-IdentityList: SEQUENCE (SIZE (1..12)) OF PLMN-Identity.
    const int64_t num_plmns = r.read_constrained_int(1, 12);
    std::vector<PlmnIdentity> plmns;
    plmns.reserve(static_cast<size_t>(num_plmns));
    for (int64_t i = 0; i < num_plmns; ++i) {
      plmns.push_back(decode_plmn_identity(r));
    }

    uint32_t tac = 0;
    if (has_tac) tac = static_cast<uint32_t>(r.read_bits(24));  // BIT STRING(24)
    if (has_ranac) r.read_constrained_int(0, 255);              // ranac (skipped)

    const uint64_t cell_id = r.read_bits(36);  // cellIdentity BIT STRING(36)
    r.read_enum(2);                            // cellReservedForOperatorUse

    if (pii_has_ext) skip_extension_additions(r);

    if (entry_idx == 0) {
      if (!plmns.empty()) {
        decoded.mcc = plmns[0].mcc;
        decoded.mnc = plmns[0].mnc;
        for (size_t i = 1; i < plmns.size(); ++i) {
          decoded.additional_plmns.push_back(plmns[i]);
        }
      }
      decoded.tracking_area_code = tac;
      decoded.tac_present = has_tac;
      decoded.cell_identity = cell_id;
    } else {
      for (const auto& p : plmns) decoded.additional_plmns.push_back(p);
    }
  }

  // Sanity: a valid SIB1 has a 3-digit primary MCC and non-zero
  // NCI. (NR does NOT reject on zero TAC — TAC is OPTIONAL on the wire.)
  if (decoded.mcc.size() != 3 || decoded.cell_identity == 0) return false;

  // Root bitmap bit 7 is servingCellConfigCommon; a walk failure keeps
  // the identity and names the stop in scc.walk_stopped_at.
  if ((opt_bitmap >> 7) & 1)
    nr_rrc::walk_serving_cell_config_common(
        r, msg_data.size() * 8, cari_has_ext, ((opt_bitmap >> 9) & 1) != 0,
        ((opt_bitmap >> 8) & 1) != 0, decoded.scc);

  out = decoded;
  return true;
}

}  // namespace nr5g_rrc
}  // namespace diagspec
