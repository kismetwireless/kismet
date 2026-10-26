// SPDX-License-Identifier: GPL-2.0-or-later
// EMM message classification -- see the header. Message types and layouts are
// TS 24.301 §8.2 and §9.8.
#include "lte_nas_emm.h"

namespace diagspec {
namespace lte_nas {

namespace {

constexpr uint8_t kPdEmm = 0x07;
// Security header + MAC (4) + sequence number (1) before the inner message.
constexpr std::size_t kSecHeaderLen = 6;

}  // namespace

bool classify_emm(const uint8_t* pdu, std::size_t n, EmmMessage& out) {
  if (pdu == nullptr || n < 2 || (pdu[0] & 0x0F) != kPdEmm) return false;

  const int sec = pdu[0] >> 4;
  if (sec == 1 || sec == 3) {
    if (n < kSecHeaderLen + 2) return false;
    pdu += kSecHeaderLen;
    n -= kSecHeaderLen;
    if (pdu[0] != kPdEmm) return false;
  } else if (sec != 0) {
    return false;            // ciphered, or a service request header
  }

  EmmMessage m;
  switch (pdu[1]) {
    case 0x41: m.type = EmmType::kAttachRequest; break;
    case 0x43: m.type = EmmType::kAttachComplete; break;
    case 0x44: m.type = EmmType::kAttachReject; break;
    case 0x45: m.type = EmmType::kDetachRequest; break;
    case 0x4B: m.type = EmmType::kTauReject; break;
    case 0x4C: m.type = EmmType::kExtServiceRequest; break;
    case 0x4E: m.type = EmmType::kServiceReject; break;
    case 0x53: m.type = EmmType::kAuthResponse; break;
    case 0x55: m.type = EmmType::kIdentityRequest; break;
    case 0x5D: m.type = EmmType::kSecurityModeCommand; break;
    default: break;
  }

  switch (m.type) {
    case EmmType::kAttachReject:
    case EmmType::kTauReject:
    case EmmType::kServiceReject:
      if (n < 3) return false;
      m.emm_cause = pdu[2];
      break;
    case EmmType::kIdentityRequest:
      if (n < 3) return false;
      m.identity_type = pdu[2] & 0x07;
      break;
    case EmmType::kSecurityModeCommand:
      // Selected NAS security algorithms: ciphering in bits 7-5, integrity in
      // bits 3-1. Then the key set identifier and the replayed UE security
      // capabilities (LV, 2-5 octets), which must be present for this to be
      // an SMC at all.
      if (n < 7) return false;
      m.ciphering = (pdu[2] >> 4) & 0x07;
      m.integrity = pdu[2] & 0x07;
      break;
    default:
      break;
  }

  out = m;
  return true;
}

const char* identity_type_name(int identity_type) {
  switch (identity_type) {
    case 1: return "IMSI";
    case 2: return "IMEI";
    case 3: return "IMEISV";
    case 4: return "TMSI";
    default: return "unknown";
  }
}

}  // namespace lte_nas
}  // namespace diagspec
