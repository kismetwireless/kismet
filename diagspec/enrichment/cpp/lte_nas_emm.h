// SPDX-License-Identifier: GPL-2.0-or-later
// TS 24.301 EPS mobility management: which plain EMM message a NAS PDU is,
// and the few fields the cell security events (lte_security_events.h) read.
#ifndef DIAGSPEC_LTE_NAS_EMM_H
#define DIAGSPEC_LTE_NAS_EMM_H

#include <cstddef>
#include <cstdint>

namespace diagspec {
namespace lte_nas {

enum class EmmType : uint8_t {
  kOther,
  kAttachRequest,
  kAttachComplete,
  kAttachReject,
  kDetachRequest,
  kTauReject,
  kExtServiceRequest,
  kServiceReject,
  kAuthResponse,
  kIdentityRequest,
  kSecurityModeCommand,
};

struct EmmMessage {
  EmmType type = EmmType::kOther;
  int ciphering = -1;      // SMC: 0 EEA0 .. 7
  int integrity = -1;      // SMC: 0 EIA0 .. 7
  int identity_type = -1;  // identity request: 1 IMSI, 2 IMEI, 3 IMEISV, 4 TMSI
  int emm_cause = -1;      // attach / TAU / service reject
};

// Classify an EMM PDU, plain or integrity-protected (the inner message of
// security header types 1 and 3 is plaintext). False for ESM, a ciphered
// message, or a PDU too short for the fields its type carries.
bool classify_emm(const uint8_t* pdu, std::size_t n, EmmMessage& out);

const char* identity_type_name(int identity_type);

}  // namespace lte_nas
}  // namespace diagspec

#endif  // DIAGSPEC_LTE_NAS_EMM_H
