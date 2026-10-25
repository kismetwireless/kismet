// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ UPER bit reader — port of the reference decoder's UPER reader
// (X.691 §11 primitive catalog). The foundation every RRC / SIB / MeasurementReport
// decode in the Kismet-side C++ datasource rides on.
//
// This is OUR code, NOT kaitai-struct-compiler output and NOT the
// vendored MIT runtime/cpp/. `.ksy` is layout-only and cannot express PER, so a
// UPER reader is enrichment code. It has no dependencies beyond
// <cstdint>/<utility>/<vector>: no pycrate equivalent and no ASN.1 library, by
// design.
//
// Equivalence to the reference decoder is diffed at the field-value level
// (harness/uper_verify.py), so identifiers are chosen for a C++ reader — spec
// terms (read_constrained_int) are kept because they ARE the clearest name; the
// class is spelled out as `UnalignedPerReader`.
//
// Scope (YAGNI): read_bits width is bounded at 64 —
// every integer / length / bit-string form seen in real captures fits (the
// widest is LTE SIB16 timeInfoUTC, 0..549755813887 → 40 bits). A BIT STRING wider
// than 64 bits is not yet exercised and is intentionally not ported.
#ifndef DIAGSPEC_UPER_H
#define DIAGSPEC_UPER_H

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace diagspec {
namespace asn1 {

// X.691 §11.9: a length determinant whose constrained SIZE range fits in 64K is
// a constrained whole number; a larger/unbounded range uses the fragmented form
// (§11.9.3.8). Governs ONLY the length-form decision — NOT value integers, which
// are always min-bits for any range (see read_constrained_int).
constexpr uint64_t kLargeRangeThreshold = 1ull << 16;  // 65536

// X.691 §11.9.3.8 fragmentation unit: lengths ≥ 16384 are emitted as one or more
// k*16384 fragments (k ∈ 1..4) followed by a final non-fragmented determinant.
constexpr uint64_t kFragmentUnit = 16u * 1024u;  // 16384

// Unaligned PER (X.691) bit reader. Reads bits and multi-bit fields MSB-first
// from a byte buffer. Primitive-for-primitive with the reference decoder's reader.
class UnalignedPerReader {
 public:
  explicit UnalignedPerReader(std::vector<uint8_t> data)
      : data_(std::move(data)), bit_pos_(0) {}
  UnalignedPerReader(const uint8_t* data, size_t len)
      : data_(data, data + len), bit_pos_(0) {}

  size_t bit_pos() const { return bit_pos_; }

  // -- core bit access (X.691 §3, MSB-first) --------------------------------
  // Reads n bits (0..64) as an unsigned integer. Bits past end-of-buffer read
  // as 0 (an out-of-range bit just shifts in a zero: val <<= 1).
  uint64_t read_bits(int n);
  bool read_bool() { return read_bits(1) == 1; }
  void skip_bits(int n) { bit_pos_ += static_cast<size_t>(n); }

  // -- ENUMERATED / CHOICE (§13 / §23) --------------------------------------
  uint64_t read_enum(uint64_t n_values);
  uint64_t read_choice(uint64_t n_alternatives) { return read_enum(n_alternatives); }

  // -- INTEGER forms --------------------------------------------------------
  // Constrained whole number (§11.5.7.1). UNALIGNED variant: ALWAYS the minimum
  // bit-field for the range, for ANY range however large — no octet form. An
  // APER-style large-range branch silently mis-decodes NR-ARFCNs and SIB16
  // timeInfoUTC.
  int64_t read_constrained_int(int64_t lo, int64_t hi);
  // Semi-constrained (§11.6): length determinant (octet count) then the unsigned
  // offset value-lo in that many octets.
  int64_t read_semi_constrained_int(int64_t lo);
  // Unconstrained (§11.4 / §10.8): length determinant then a two's-complement
  // signed integer in that many octets.
  int64_t read_unconstrained_int();

  // -- length determinants (§11.9) ------------------------------------------
  // Total item count, fully handling fragmentation (sums the k*16384 fragments)
  // — for contiguous OCTET/BIT/open-type byte or bit counts.
  uint64_t read_length();
  uint64_t read_length(int64_t lo, int64_t hi);
  // Each fragment's item count — for SEQUENCE OF / SET OF, where the caller
  // decodes that many variable-size elements between successive length reads.
  std::vector<uint64_t> iter_length_fragments();
  std::vector<uint64_t> iter_length_fragments(int64_t lo, int64_t hi);

  // -- BIT STRING (§15) -----------------------------------------------------
  // Fixed-width BIT STRING of nbits bits, MSB-first, as an integer.
  uint64_t read_bitstring(int nbits) { return read_bits(nbits); }
  // Variable-length (unconstrained-size) BIT STRING (§15.11): a length
  // determinant in BITS then that many bits. Returns {value, nbits} — a
  // leading-zero bit string is otherwise ambiguous.
  std::pair<uint64_t, uint64_t> read_bitstring_unconstrained();

 private:
  // One length-determinant chunk → {count, is_fragment}. Three encodings keyed
  // on the first byte: <0x80 → 7-bit final; 0x80..0xBF → 14-bit final; ≥0xC0 →
  // (first & 0x3F)*16384 items, MORE fragments follow.
  std::pair<uint64_t, bool> read_length_chunk();

  std::vector<uint8_t> data_;
  size_t bit_pos_;
};

}  // namespace asn1
}  // namespace diagspec

#endif  // DIAGSPEC_UPER_H
