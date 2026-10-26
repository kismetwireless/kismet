// SPDX-License-Identifier: GPL-2.0-or-later
// Linkable surface of the 0xB0C0 C++ enrichment leg.
//
// The Kismet datasource needs a linkable symbol for the version-keyed
// channel-name lookup: the GSMTAP sub-type is selected off the canonical
// channel NAME, and the generated Kaitai raw parser only exposes
// channel_type() (the per-version integer), never the resolved name.
//
// So the name resolution lives here, declared once and reused by both the
// standalone enrich runner and the datasource-facing adapter (diag_0xb0c0_gsmtap).
#ifndef DIAGSPEC_DIAG_0XB0C0_ENRICH_H
#define DIAGSPEC_DIAG_0XB0C0_ENRICH_H

#include <cstdint>
#include <string>
#include <vector>

namespace diag_0xb0c0_enrich {

// Version-keyed channel_type → canonical channel_name via the generated
// enrichment tables (v20 has its own byte[12] enum; every other version has its
// own oracle-pinned enum). An unmapped value falls back to the honest hex string
// "0x%02X" (upper-case, two hex digits).
std::string channel_name(uint8_t version, uint8_t ct);

// Derived logic: sib_mask bit N (1..31) set <=> SIB N present. bit0 unused.
std::vector<int> sibs_present(uint32_t sib_mask);

}  // namespace diag_0xb0c0_enrich

#endif  // DIAGSPEC_DIAG_0XB0C0_ENRICH_H
