// SPDX-License-Identifier: GPL-2.0-or-later
// TS 24.301 structural-completeness check -- see lte_nas_structure.h. Every
// table below is a transcription of the matching table in the reference
// decoder; tests/test_lte_nas_structure_cpp_equivalence.py holds the two to
// identical answers.
#include "lte_nas_structure.h"


namespace diagspec {
namespace lte_nas {
namespace {

// A mandatory-part token: a fixed number of octets (V fields, or two
// half-octet V IEs packed in one), LV (1-octet length + value) or LV-E
// (2-octet big-endian length + value).
constexpr int kLV = -1;
constexpr int kLVE = -2;
constexpr int kEnd = -99;     // terminates a layout row

struct Layout {
  int msg_type;
  int tok[5];                 // up to 4 tokens, kEnd-terminated
};

// TS 24.301 §8.2 EMM mandatory parts (after the 2-octet sec_hdr|PD + msg type).
constexpr Layout kEmmMandatory[] = {
    {0x41, {1, kLV, kLV, kLVE, kEnd}},  // Attach request
    {0x42, {1, 1, kLV, kLVE, kEnd}},    // Attach accept
    {0x43, {kLVE, kEnd}},               // Attach complete
    {0x44, {1, kEnd}},                  // Attach reject
    {0x46, {kEnd}},                     // Detach accept
    {0x48, {1, kLV, kEnd}},             // TAU request
    {0x49, {1, kEnd}},                  // TAU accept
    {0x4A, {kEnd}},                     // TAU complete
    {0x4B, {1, kEnd}},                  // TAU reject
    {0x4C, {1, kLV, kEnd}},             // Extended service request
    {0x4D, {1, kEnd}},                  // Control plane service request
    {0x4E, {1, kEnd}},                  // Service reject
    {0x4F, {kEnd}},                     // Service accept
    {0x50, {kLV, kEnd}},                // GUTI reallocation command
    {0x51, {kEnd}},                     // GUTI reallocation complete
    {0x52, {1, 16, kLV, kEnd}},         // Authentication request
    {0x53, {kLV, kEnd}},                // Authentication response
    {0x54, {kEnd}},                     // Authentication reject
    {0x55, {1, kEnd}},                  // Identity request
    {0x56, {kLV, kEnd}},                // Identity response
    {0x5C, {1, kEnd}},                  // Authentication failure
    {0x5D, {1, 1, kLV, kEnd}},          // Security mode command
    {0x5E, {kEnd}},                     // Security mode complete
    {0x5F, {1, kEnd}},                  // Security mode reject
    {0x60, {1, kEnd}},                  // EMM status
    {0x61, {kEnd}},                     // EMM information
    {0x62, {kLV, kEnd}},                // Downlink NAS transport
    {0x63, {kLV, kEnd}},                // Uplink NAS transport
    {0x64, {1, kEnd}},                  // CS service notification
    {0x68, {1, kLVE, kEnd}},            // Downlink generic NAS transport
    {0x69, {1, kLVE, kEnd}},            // Uplink generic NAS transport
};

// Detach request (0x45) is direction-dependent (TS 24.301 §8.2.11): UL / DL.
constexpr Layout kEmmDetachRequestUl = {0x45, {1, kLV, kEnd}};
constexpr Layout kEmmDetachRequestDl = {0x45, {1, kEnd}};

// EMM type-3 (TV) optional IEIs -> value length.
constexpr int kEmmTv[][2] = {
    {0x13, 5}, {0x17, 1}, {0x19, 3}, {0x46, 1}, {0x47, 7}, {0x52, 5},
    {0x53, 1}, {0x55, 4}, {0x56, 4}, {0x59, 1}, {0x5A, 1}, {0x5B, 1},
    {0x5C, 2}, {0x61, 1}, {0x62, 1},
};

// EMM type-4 (TLV) optional IEIs.
constexpr uint8_t kEmmTlv[] = {
    0x10, 0x11, 0x16, 0x1D, 0x1E, 0x20, 0x23, 0x30, 0x31, 0x32, 0x34, 0x35,
    0x36, 0x38, 0x40, 0x43, 0x45, 0x49, 0x4A, 0x4F, 0x50, 0x54, 0x57, 0x58,
    0x5D, 0x5E, 0x5F, 0x60, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x6A, 0x6B,
    0x6C, 0x6D, 0x6E, 0x6F,
};

// TS 24.301 §8.3 ESM mandatory parts (after the 3-octet EBI|PD, PTI, msg
// type).
constexpr Layout kEsmMandatory[] = {
    {0xC1, {kLV, kLV, kLV, kEnd}},      // Act. default bearer req
    {0xC2, {kEnd}},                     // Act. default bearer accept
    {0xC3, {1, kEnd}},                  // Act. default bearer reject
    {0xC5, {1, kLV, kLV, kEnd}},        // Act. dedicated bearer req
    {0xC6, {kEnd}},                     // Act. dedicated bearer accept
    {0xC7, {1, kEnd}},                  // Act. dedicated bearer reject
    {0xC9, {kEnd}},                     // Modify bearer req
    {0xCA, {kEnd}},                     // Modify bearer accept
    {0xCB, {1, kEnd}},                  // Modify bearer reject
    {0xCD, {1, kEnd}},                  // Deactivate bearer req
    {0xCE, {kEnd}},                     // Deactivate bearer accept
    {0xD0, {1, kEnd}},                  // PDN connectivity req
    {0xD1, {1, kEnd}},                  // PDN connectivity reject
    {0xD2, {1, kEnd}},                  // PDN disconnect req
    {0xD3, {1, kEnd}},                  // PDN disconnect reject
    {0xD4, {1, kLV, kLV, kEnd}},        // Bearer resource allocation req
    {0xD5, {1, kEnd}},                  // Bearer resource allocation reject
    {0xD6, {1, kLV, kEnd}},             // Bearer resource modification req
    {0xD7, {1, kEnd}},                  // Bearer resource modification reject
    {0xD9, {kEnd}},                     // ESM information request
    {0xDA, {kEnd}},                     // ESM information response
    {0xDB, {kLV, kEnd}},                // Notification
    {0xDC, {kEnd}},                     // ESM dummy message
    {0xE8, {1, kEnd}},                  // ESM status
    {0xEB, {kLVE, kEnd}},               // ESM data transport
};

// ESM type-3 (TV) optional IEIs -> value length.
constexpr int kEsmTv[][2] = {
    {0x32, 1}, {0x58, 1},
};

// ESM type-4 (TLV) optional IEIs.
constexpr uint8_t kEsmTlv[] = {
    0x27, 0x28, 0x30, 0x33, 0x34, 0x36, 0x37, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x66, 0x6B, 0x6E,
};

template <std::size_t N>
const Layout* find_layout(const Layout (&table)[N], int mt) {
  for (const Layout& l : table)
    if (l.msg_type == mt) return &l;
  return nullptr;
}

template <std::size_t N>
int tv_len(const int (&table)[N][2], int iei) {
  for (const auto& e : table)
    if (e[0] == iei) return e[1];
  return -1;
}

template <std::size_t N>
bool in_set(const uint8_t (&set)[N], int iei) {
  for (uint8_t v : set)
    if (v == iei) return true;
  return false;
}

}  // namespace

Complete structurally_complete(const uint8_t* p, std::size_t n, bool is_uplink) {
  // Positions are size_t; a declared length can push `pos` far past `n`, and
  // every such case is a `pos > n` -> kNo.
  if (n < 1) return Complete::kNo;
  const int pd = p[0] & 0x0F;
  const Layout* layout = nullptr;
  bool emm = false;
  std::size_t pos;
  if (pd == 7) {
    if (n < 2) return Complete::kNo;
    if (((p[0] >> 4) & 0x0F) != 0) return Complete::kNotCheckable;
    const int mt = p[1];
    if (mt == 0x45)
      layout = is_uplink ? &kEmmDetachRequestUl : &kEmmDetachRequestDl;
    else
      layout = find_layout(kEmmMandatory, mt);
    emm = true;
    pos = 2;
  } else if (pd == 2) {
    if (n < 3) return Complete::kNo;
    layout = find_layout(kEsmMandatory, p[2]);
    pos = 3;
  } else {
    return Complete::kNotCheckable;
  }
  if (layout == nullptr) return Complete::kNotCheckable;

  for (int i = 0; layout->tok[i] != kEnd; i++) {
    const int tok = layout->tok[i];
    if (tok == kLV) {
      if (pos + 1 > n) return Complete::kNo;
      pos += 1 + static_cast<std::size_t>(p[pos]);
    } else if (tok == kLVE) {
      if (pos + 2 > n) return Complete::kNo;
      pos += 2 + ((static_cast<std::size_t>(p[pos]) << 8) | p[pos + 1]);
    } else {
      pos += static_cast<std::size_t>(tok);
    }
    if (pos > n) return Complete::kNo;
  }
  while (pos < n) {
    const int iei = p[pos];
    const int tv = emm ? tv_len(kEmmTv, iei) : tv_len(kEsmTv, iei);
    if (iei & 0x80) {                         // type 1 / type 2: one octet
      pos += 1;
    } else if (tv >= 0) {                     // type 3: fixed value length
      pos += 1 + static_cast<std::size_t>(tv);
    } else if (iei >= 0x70 && iei <= 0x7F) {  // type 6: TLV-E
      if (pos + 3 > n) return Complete::kNo;
      pos += 3 + ((static_cast<std::size_t>(p[pos + 1]) << 8) | p[pos + 2]);
    } else if (emm ? in_set(kEmmTlv, iei) : in_set(kEsmTlv, iei)) {  // type 4
      if (pos + 2 > n) return Complete::kNo;
      pos += 2 + static_cast<std::size_t>(p[pos + 1]);
    } else {                                  // not a known optional IE: stop
      return Complete::kYes;
    }
    if (pos > n) return Complete::kNo;
  }
  return Complete::kYes;
}

}  // namespace lte_nas
}  // namespace diagspec
