// SPDX-License-Identifier: GPL-2.0-or-later
// LTE RRC fields behind the cell security events (lte_security_events.h): the
// SecurityModeCommand algorithms and the RRCConnectionRelease redirect target,
// both DL-DCCH (TS 36.331 §6.2.2), and the UL-CCCH connection request.
//
// Whole-message decoders like lte_rrc_sib: each walks the CHOICE tree from bit
// 0 and returns false for any other message, or for a PDU too short to hold
// the fields it reads (the UPER reader reads past the end as zeros, and eea0 /
// eia0 are zeros, so a truncated PDU must never decode).
#ifndef DIAGSPEC_LTE_RRC_SECURITY_H
#define DIAGSPEC_LTE_RRC_SECURITY_H

#include <cstdint>
#include <vector>

namespace diagspec {
namespace lte_rrc {

// SecurityModeCommand-r8 securityConfigSMC.securityAlgorithmConfig. An
// algorithm is -1 when its value is an extension the decoder does not know.
struct SecurityAlgorithms {
  int ciphering = -1;   // CipheringAlgorithm-r12: 0 eea0 .. 3 eea3, 4-7 spare
  int integrity = -1;   // 0 eia0 .. 3 eia3, 4-7 spare
};

bool decode_security_mode_command(const std::vector<uint8_t>& msg,
                                  SecurityAlgorithms& out);

// RRCConnectionRelease-r8 redirectedCarrierInfo.
enum class RedirectRat : uint8_t {
  kNone,          // release carries no redirect
  kEutra,
  kGeran,
  kUtraFdd,
  kUtraTdd,
  kCdma2000Hrpd,
  kCdma2000OneX,
  kExtension,     // an extension alternative (utra-TDD-r10, nr-r15, ...)
};

struct ConnectionRelease {
  int release_cause = -1;   // 0 loadBalancingTAUrequired, 1 other,
                            // 2 cs-FallbackHighPriority, 3 rrc-Suspend
  RedirectRat redirect = RedirectRat::kNone;
  int32_t arfcn = -1;       // the redirect carrier, where its type has one
  int geran_band = -1;      // 0 dcs1800, 1 pcs1900
};

bool decode_connection_release(const std::vector<uint8_t>& msg,
                               ConnectionRelease& out);

const char *redirect_rat_name(RedirectRat rat);

// UL-CCCH c1: rrcConnectionReestablishmentRequest or rrcConnectionRequest.
bool is_connection_request(const std::vector<uint8_t>& msg);

}  // namespace lte_rrc
}  // namespace diagspec

#endif  // DIAGSPEC_LTE_RRC_SECURITY_H
