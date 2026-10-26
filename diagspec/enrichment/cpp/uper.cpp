// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ UPER bit reader (see uper.h). Ported
// primitive-for-primitive from the reference decoder's UPER reader.
#include "uper.h"

namespace diagspec {
namespace asn1 {

namespace {
// Bits needed to represent x (0 → 0), i.e. the integer's bit length.
int bit_length(uint64_t x) {
  int n = 0;
  while (x) {
    ++n;
    x >>= 1;
  }
  return n;
}
}  // namespace

uint64_t UnalignedPerReader::read_bits(int n) {
  uint64_t val = 0;
  for (int i = 0; i < n; ++i) {
    size_t byte_idx = bit_pos_ / 8;
    int bit_idx = 7 - static_cast<int>(bit_pos_ % 8);
    uint64_t bit = 0;
    if (byte_idx < data_.size()) {
      bit = (static_cast<uint64_t>(data_[byte_idx]) >> bit_idx) & 1u;
    }
    val = (val << 1) | bit;  // past end-of-buffer: bit stays 0
    ++bit_pos_;
  }
  return val;
}

uint64_t UnalignedPerReader::read_enum(uint64_t n_values) {
  if (n_values <= 1) return 0;
  return read_bits(bit_length(n_values - 1));
}

int64_t UnalignedPerReader::read_constrained_int(int64_t lo, int64_t hi) {
  int64_t range_val = hi - lo;
  if (range_val <= 0) return lo;
  return lo + static_cast<int64_t>(read_bits(bit_length(static_cast<uint64_t>(range_val))));
}

int64_t UnalignedPerReader::read_semi_constrained_int(int64_t lo) {
  uint64_t n_octets = read_length();
  return lo + static_cast<int64_t>(read_bits(static_cast<int>(n_octets * 8)));
}

int64_t UnalignedPerReader::read_unconstrained_int() {
  uint64_t n_octets = read_length();
  if (n_octets == 0) return 0;
  int total_bits = static_cast<int>(n_octets * 8);
  uint64_t raw = read_bits(total_bits);
  uint64_t sign_bit = 1ull << (total_bits - 1);
  if (raw & sign_bit) {
    // Two's-complement sign extension (X.691 §10.8). For total_bits == 64 the
    // 1<<64 wrap is well-defined on the unsigned value and reinterprets negative.
    return static_cast<int64_t>(raw - (total_bits >= 64 ? 0ull : (1ull << total_bits)));
  }
  return static_cast<int64_t>(raw);
}

std::pair<uint64_t, bool> UnalignedPerReader::read_length_chunk() {
  uint64_t first = read_bits(8);
  if (first < 0x80) return {first, false};
  if (first < 0xC0) {
    uint64_t second = read_bits(8);
    return {((first & 0x3F) << 8) | second, false};
  }
  return {(first & 0x3F) * kFragmentUnit, true};
}

std::vector<uint64_t> UnalignedPerReader::iter_length_fragments(int64_t lo, int64_t hi) {
  // Signed compare, `(hi - lo) < THRESHOLD` (a hi<lo caller takes the
  // constrained branch, not the fragment loop).
  if ((hi - lo) < static_cast<int64_t>(kLargeRangeThreshold)) {
    return {static_cast<uint64_t>(read_constrained_int(lo, hi))};
  }
  return iter_length_fragments();
}

std::vector<uint64_t> UnalignedPerReader::iter_length_fragments() {
  std::vector<uint64_t> out;
  for (;;) {
    std::pair<uint64_t, bool> chunk = read_length_chunk();
    out.push_back(chunk.first);
    if (!chunk.second) return out;
  }
}

uint64_t UnalignedPerReader::read_length(int64_t lo, int64_t hi) {
  if ((hi - lo) < static_cast<int64_t>(kLargeRangeThreshold)) {  // signed compare
    return static_cast<uint64_t>(read_constrained_int(lo, hi));
  }
  return read_length();
}

uint64_t UnalignedPerReader::read_length() {
  uint64_t total = 0;
  for (uint64_t frag : iter_length_fragments()) total += frag;
  return total;
}

std::pair<uint64_t, uint64_t> UnalignedPerReader::read_bitstring_unconstrained() {
  uint64_t nbits = read_length();
  uint64_t value = read_bits(static_cast<int>(nbits));
  return {value, nbits};
}

}  // namespace asn1
}  // namespace diagspec
