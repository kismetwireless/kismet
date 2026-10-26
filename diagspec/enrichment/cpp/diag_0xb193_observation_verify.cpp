// SPDX-License-Identifier: GPL-2.0-or-later
// Standalone runner for the 0xB193 cell_observation enrichment leg.
// Emits one JSON cell_observation per line — the SAME shape the datasource
// emits for 0xB193 — so the equivalence harness can diff this output against
// the reference decoder for the committed fixtures. The prov block is reduced to a
// deterministic {"origin":"0xB193"} here (a full prov carries a wall-clock
// captured_at + imei that are runtime-varying and not part of the
// decode-equivalence contract).
//
// rsrp/rsrq are OMITTED when absent, exactly as the emitted observation omits
// them — the key's presence, not a sentinel value, is the contract. On
// 0xB193 absence is the COMMON case, not the exception: v22/v35/v36 (a large
// share of real records) have no confirmed scale, v3/v18 have no reverse-engineered
// scale, and v48/v59 are gated to single-cell / serving-cell respectively. A driver that printed 0.0 instead of
// omitting would make every one of those look like a 0 dBm reading.
//
// Values print at max double precision so the equivalence compare is exact
// rather than tolerant. Both sides land on the same double because both round to
// 2 dp with round-half-to-EVEN — the leg uses nearbyint under the default
// FE_TONEAREST precisely for that; std::round would diverge by 0.01 dB on
// roughly a quarter of decoded readings (every 1/16 quantum where k % 4 == 2).
//
// Compile (adds the leg + generated parser + vendored runtime to the link line):
//   g++ -std=c++11 -DKS_STR_ENCODING_NONE -I<runtime/cpp> -I<generated/cpp> \
//       diag_0xb193_observation_verify.cpp diag_0xb193_observation.cpp \
//       <generated/cpp>/diag_0xb193.cpp <runtime>/kaitai/kaitaistream.cpp -o obs
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "diag_0xb193_observation.h"

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: obs <fixture.bin>\n"; return 2; }
    std::ifstream f(argv[1], std::ios::binary);
    std::stringstream ss; ss << f.rdbuf();
    std::string blob = ss.str();

    std::vector<diag_0xb193_observation::CellObservation> obs =
        diag_0xb193_observation::observations(blob);

    std::cout << std::setprecision(std::numeric_limits<double>::max_digits10);
    for (const auto& o : obs) {
        std::cout << "{"
                  << "\"rat\":\"NR\""
                  << ",\"pci\":" << o.pci
                  << ",\"earfcn\":" << o.earfcn
                  << ",\"observation_type\":\""
                  << (o.is_serving ? "serving" : "observation") << "\""
                  << ",\"is_serving\":" << (o.is_serving ? "true" : "false");
        if (o.has_rsrp)
            std::cout << ",\"rsrp\":" << o.rsrp;
        if (o.has_rsrq)
            std::cout << ",\"rsrq\":" << o.rsrq;
        std::cout << ",\"origin\":\"0xB193\"" << "}" << std::endl;
    }
    return 0;
}
