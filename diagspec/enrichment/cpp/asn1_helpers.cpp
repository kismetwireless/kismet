// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ ASN.1 / UPER decode helpers (see
// asn1_helpers.h). Ported behavior-for-behavior from the reference
// decoder's ASN.1 helpers. Equivalence is diffed at
// the field-value level (harness/asn1_verify.py).
#include "asn1_helpers.h"

#include <cstdint>
#include <vector>

namespace diagspec {
namespace asn1 {

void skip_extension_additions(UnalignedPerReader& r) {
  // 1. Addition count (normally-small-length, §11.9.3.4-style marker): marker
  //    bit 0 → 6-bit count (0..63); marker bit 1 → 8-bit count (the simplified
  //    >63 form, matching every record in the corpus).
  uint64_t num_ext = (r.read_bits(1) == 0) ? r.read_bits(6) : r.read_bits(8);

  // 2. Presence bitmap of num_ext + 1 bits. Read bit-by-bit into a buffer
  //    rather than as one wide integer: read_bits caps at 64 bits, but a
  //    count from the 8-bit branch can make the bitmap wider than that. Reading
  //    the whole bitmap FIRST (before any payload skip) keeps the stream
  //    position identical to a single wide read — the payloads follow
  //    the entire bitmap, not each bit.
  std::vector<uint8_t> present;
  present.reserve(static_cast<size_t>(num_ext) + 1);
  for (uint64_t i = 0; i <= num_ext; ++i) {
    present.push_back(static_cast<uint8_t>(r.read_bits(1)));
  }

  // 3. For each present addition: an open-type length determinant (bytes) then
  //    that many bytes of opaque payload, which we skip. Bit index i (i==0 is
  //    the first/MSB bit) equals (bitmap >> (num_ext - i)) & 1.
  for (uint64_t i = 0; i <= num_ext; ++i) {
    if (present[i]) {
      uint64_t length = read_open_type_length(r);
      r.skip_bits(static_cast<int>(length * 8));
    }
  }
}

PlmnIdentity decode_plmn_identity(UnalignedPerReader& r) {
  // PLMN-Identity ::= SEQUENCE { mcc MCC OPTIONAL, mnc MNC }
  // MCC ::= SEQUENCE (SIZE (3)) OF MCC-MNC-Digit
  // MNC ::= SEQUENCE (SIZE (2..3)) OF MCC-MNC-Digit
  // MCC-MNC-Digit ::= INTEGER (0..9)
  PlmnIdentity out;

  if (r.read_bool()) {  // OPTIONAL MCC presence bit
    for (int i = 0; i < 3; ++i) {
      out.mcc += static_cast<char>('0' + r.read_constrained_int(0, 9));
    }
  }

  // MNC length: a constrained whole number in [2, 3] (the SIZE(2..3) SEQUENCE-OF
  // determinant, §11.9 small-range → constrained form).
  int64_t mnc_len = r.read_constrained_int(2, 3);
  for (int64_t i = 0; i < mnc_len; ++i) {
    out.mnc += static_cast<char>('0' + r.read_constrained_int(0, 9));
  }

  return out;
}

}  // namespace asn1
}  // namespace diagspec
