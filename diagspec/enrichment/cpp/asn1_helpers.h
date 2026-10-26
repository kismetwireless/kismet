// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ ASN.1 / UPER decode helpers — port of the reference decoder's
// ASN.1 helpers. The shared decode layer on top of the UPER reader
// (uper.h), so the LTE RRC and NR RRC decoders don't each re-derive PLMN
// decode, the extension-additions skip, or the ENUMERATED value tables.
//
// This is OUR enrichment code, NOT kaitai-struct-compiler output and
// not the vendored MIT runtime: `.ksy` is layout-only and cannot express PER.
// Zero dependencies beyond the STL and uper.h.
//
// Equivalence to the reference decoder is diffed at the FIELD-VALUE level
// (harness/asn1_verify.py), so identifiers are chosen for a C++ reader, not
// mechanically mirrored — spec terms (decode_plmn_identity) are
// kept where they read best; table constants get descriptive C++ names.
//
// Single-source invariant: the §11.9
// length-determinant / open-type bit logic lives ONLY in the UPER reader — a
// decoder here never re-derives it inline. `read_open_type_length` delegates to
// `UnalignedPerReader::read_length`; it does not re-implement the byte forms.
#ifndef DIAGSPEC_ASN1_HELPERS_H
#define DIAGSPEC_ASN1_HELPERS_H

#include <array>
#include <cstdint>
#include <string>

#include "uper.h"

// The ENUMERATED ordinal→value tables (kQOffsetRangeDb,
// kPhysCellIdRangeValues, kQHysteresisDb, kAllowedMeasBandwidthRbs,
// kNrSubcarrierSpacingKhz) are not hand-ported here; they are emitted into diagspec::asn1 by the shared-table codegen from
// shared_data/enrichment_tables.yaml. The relative path resolves against this
// file's directory, so it needs no extra -I on the g++ verify compiles. Drift
// vs. the reference decoder's copy of the tables is caught by
// the shared-table drift check.
#include "../../generated/cpp/enrichment_tables.h"

namespace diagspec {
namespace asn1 {

// 3GPP PLMN identity — the UPER encoding is identical between LTE (TS 36.331)
// and NR (TS 38.331). `mcc` is empty when the OPTIONAL MCC field is omitted
// (e.g. MeasurementReport additional-PLMN lists); SIB1 always carries it.
struct PlmnIdentity {
  std::string mcc;  // 3-digit MCC, or "" if the OPTIONAL field was absent
  std::string mnc;  // 2- or 3-digit MNC
};

// Open-type / OCTET-STRING length determinant (whole bytes), X.691 §11.9.
// Delegates to the reader's fragmentation-aware read_length — it does NOT
// re-derive the §11.9 byte forms (the single-source invariant: a re-derived
// `first & 0x3F` here would drift from the reader's fragmentation handling).
inline uint64_t read_open_type_length(UnalignedPerReader& r) { return r.read_length(); }

// Skip a UPER extension-additions block (open-type wrappers), X.691 §9.3.10 /
// §11.5. Reads the addition count (normally-small-length), then a presence
// bitmap of count+1 bits, then skips each present addition's open-type payload.
// Extension-additions are forward-compat carriers, so the payloads are opaque
// and discarded.
void skip_extension_additions(UnalignedPerReader& r);

// Decode a PLMN-Identity (SEQUENCE { mcc MCC OPTIONAL, mnc MNC }) from a UPER
// bitstream. MCC-MNC-Digit ::= INTEGER (0..9); MNC length is a constrained
// integer in [2, 3].
PlmnIdentity decode_plmn_identity(UnalignedPerReader& r);

// ---- ENUMERATED ordinal → value lookup tables ---------------------------
//
// The kQOffsetRangeDb / kPhysCellIdRangeValues / kQHysteresisDb /
// kAllowedMeasBandwidthRbs / kNrSubcarrierSpacingKhz `constexpr std::array`s
// live in this same diagspec::asn1 namespace, but are GENERATED — see the
// `#include "../../generated/cpp/enrichment_tables.h"` above. Each is indexed by
// the ENUMERATED ordinal exactly as encoded in UPER (via
// UnalignedPerReader::read_enum(table.size())). To change a value, edit
// shared_data/enrichment_tables.yaml (and the reference decoder's copy) and
// regenerate — never hand-edit the generated header.

}  // namespace asn1
}  // namespace diagspec

#endif  // DIAGSPEC_ASN1_HELPERS_H
