// SPDX-License-Identifier: GPL-2.0-or-later
// LTE EARFCN -> band and band -> duplex, for the native cell_observation path.
//
// earfcn_to_band() and band_to_duplex(), applied to EVERY LTE observation the
// datasource emits. Without them every LTE row would lack its band and duplex
// keys.
//
// One table, pinned. This is not a second opinion on TS 36.101 -- it is a port,
// held to the reference decoder's table by harness/lte_band_verify.py, which
// sweeps EVERY EARFCN 0..kSweepMax on both sides and compares (band, duplex)
// pairwise. A correction belongs in the reference table first; the sweep then
// fails here until this file follows. Two writers disagreeing on a pure
// function of the EARFCN is the failure one central band/duplex step prevents.
//
// Both functions answer "unknown" the same way: band 0 for an EARFCN in
// no range, and nullptr (absent) for a band with no TS 36.101 5.5-1 class --
// so a caller omits the key rather than emitting a plausible-but-wrong value.
#ifndef DIAGSPEC_LTE_BAND_H
#define DIAGSPEC_LTE_BAND_H

#include <cstdint>

namespace lte_band {

// EARFCN -> E-UTRA band number; 0 when the EARFCN is in no table range.
int earfcn_to_band(uint32_t earfcn);

// Band -> "TDD" / "FDD" / "SDL"; nullptr for band 0 or any unclassified band.
// The returned string is a static literal and is never freed.
const char* band_to_duplex(int band);

}  // namespace lte_band

#endif  // DIAGSPEC_LTE_BAND_H
