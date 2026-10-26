// SPDX-License-Identifier: GPL-2.0-or-later
// LTE RRC security-relevant decoders -- see the header.
//
// ASN.1 shapes decoded (TS 36.331 §6.2.2):
//   DL-DCCH-MessageType ::= CHOICE { c1 CHOICE (16) { ..., rrcConnectionRelease
//                                    (5), securityModeCommand (6), ... },
//                                    messageClassExtension }
//   SecurityModeCommand ::= SEQUENCE { rrc-TransactionIdentifier (0..3),
//     criticalExtensions CHOICE { c1 CHOICE (4) { securityModeCommand-r8, ... },
//                                 criticalExtensionsFuture } }
//   SecurityModeCommand-r8-IEs ::= SEQUENCE { securityConfigSMC,
//                                  nonCriticalExtension OPTIONAL }
//   SecurityConfigSMC ::= SEQUENCE { securityAlgorithmConfig, ... }
//   SecurityAlgorithmConfig ::= SEQUENCE {
//     cipheringAlgorithm ENUMERATED (8, ...), integrityProtAlgorithm
//     ENUMERATED (8, ...) }
//   RRCConnectionRelease-r8-IEs ::= SEQUENCE { releaseCause ENUMERATED (4),
//     redirectedCarrierInfo OPTIONAL, idleModeMobilityControlInfo OPTIONAL,
//     nonCriticalExtension OPTIONAL }
//   RedirectedCarrierInfo ::= CHOICE { eutra (0..65535), geran
//     CarrierFreqsGERAN, utra-FDD (0..16383), utra-TDD (0..16383),
//     cdma2000-HRPD, cdma2000-1xRTT, ... }
#include "lte_rrc_security.h"

#include "uper.h"

namespace diagspec {
namespace lte_rrc {

using asn1::UnalignedPerReader;

namespace {

constexpr int kDlDcchRelease = 5;
constexpr int kDlDcchSecurityModeCommand = 6;

// DL-DCCH c1 index of msg, or -1 for messageClassExtension.
int dl_dcch_c1(UnalignedPerReader& r) {
  if (r.read_choice(2) != 0) return -1;
  return static_cast<int>(r.read_choice(16));
}

// An ENUMERATED with an extension marker: -1 for an extension value.
int read_ext_enum(UnalignedPerReader& r, uint64_t n_root) {
  if (r.read_bool()) return -1;
  return static_cast<int>(r.read_enum(n_root));
}

}  // namespace

bool decode_security_mode_command(const std::vector<uint8_t>& msg,
                                  SecurityAlgorithms& out) {
  // 20 bits of choices, transaction id, presence and both algorithms.
  if (msg.size() < 3) return false;

  UnalignedPerReader r(msg);
  if (dl_dcch_c1(r) != kDlDcchSecurityModeCommand) return false;
  r.read_constrained_int(0, 3);              // rrc-TransactionIdentifier
  if (r.read_choice(2) != 0) return false;   // criticalExtensionsFuture
  if (r.read_choice(4) != 0) return false;   // spare, not -r8
  r.read_bits(1);                            // nonCriticalExtension present
  r.read_bits(1);                            // SecurityConfigSMC extension bit;
                                             // additions follow the root

  SecurityAlgorithms a;
  a.ciphering = read_ext_enum(r, 8);
  a.integrity = read_ext_enum(r, 8);
  if (r.bit_pos() > r.bit_size()) return false;
  out = a;
  return true;
}

bool decode_connection_release(const std::vector<uint8_t>& msg,
                               ConnectionRelease& out) {
  if (msg.size() < 2) return false;

  UnalignedPerReader r(msg);
  if (dl_dcch_c1(r) != kDlDcchRelease) return false;
  r.read_constrained_int(0, 3);              // rrc-TransactionIdentifier
  if (r.read_choice(2) != 0) return false;
  if (r.read_choice(4) != 0) return false;   // rrcConnectionRelease-r8

  const uint64_t opts = r.read_bits(3);
  ConnectionRelease rel;
  rel.release_cause = static_cast<int>(r.read_enum(4));

  if (opts & 0x4) {
    if (r.read_bool()) {
      rel.redirect = RedirectRat::kExtension;
    } else {
      switch (r.read_choice(6)) {
        case 0:
          rel.redirect = RedirectRat::kEutra;
          rel.arfcn = static_cast<int32_t>(r.read_constrained_int(0, 65535));
          break;
        case 1:
          rel.redirect = RedirectRat::kGeran;
          rel.arfcn = static_cast<int32_t>(r.read_constrained_int(0, 1023));
          rel.geran_band = static_cast<int>(r.read_enum(2));
          break;
        case 2:
          rel.redirect = RedirectRat::kUtraFdd;
          rel.arfcn = static_cast<int32_t>(r.read_constrained_int(0, 16383));
          break;
        case 3:
          rel.redirect = RedirectRat::kUtraTdd;
          rel.arfcn = static_cast<int32_t>(r.read_constrained_int(0, 16383));
          break;
        case 4:
          rel.redirect = RedirectRat::kCdma2000Hrpd;
          break;
        case 5:
          rel.redirect = RedirectRat::kCdma2000OneX;
          break;
        default:
          return false;                      // 6, 7 are not root alternatives
      }
    }
  }

  if (r.bit_pos() > r.bit_size()) return false;
  out = rel;
  return true;
}

const char *redirect_rat_name(RedirectRat rat) {
  switch (rat) {
    case RedirectRat::kNone: return "none";
    case RedirectRat::kEutra: return "eutra";
    case RedirectRat::kGeran: return "geran";
    case RedirectRat::kUtraFdd: return "utra-fdd";
    case RedirectRat::kUtraTdd: return "utra-tdd";
    case RedirectRat::kCdma2000Hrpd: return "cdma2000-hrpd";
    case RedirectRat::kCdma2000OneX: return "cdma2000-1xrtt";
    case RedirectRat::kExtension: return "extension";
  }
  return "unknown";
}

bool is_connection_request(const std::vector<uint8_t>& msg) {
  // UL-CCCH-MessageType: c1(0) holds both requests; messageClassExtension(1)
  // holds the r13 resume request, which is not a new attach.
  return !msg.empty() && (msg[0] & 0x80) == 0;
}

}  // namespace lte_rrc
}  // namespace diagspec
