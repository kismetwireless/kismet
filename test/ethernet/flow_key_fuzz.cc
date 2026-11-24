/* libFuzzer harness for the flow key text (wired_flow_tracker::parse_key, the :key of
 * /phy/ethernet/flows/by-key/): every input is rejected, or prints back as the same text.
 * Build as frame_fuzz.cc, with wired_flow_history.cc.
 */

#include <cstdint>
#include <cstdlib>
#include <string_view>

#include "wired_flow_tracker.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const std::string_view text(reinterpret_cast<const char *>(data), size);

    wired_flow_tracker::key k;
    uint64_t serial = 0;
    if (!wired_flow_tracker::parse_key(text, k, serial))
        return 0;

    if (serial == 0 || (k.family != 4 && k.family != 6) || wired_flow_tracker::format_key(k, serial) != text)
        abort();

    // Bytes past an IPv4 address stay zero, as add() keys them
    if (k.family == 4) {
        for (size_t i = 4; i < k.addr_a.size(); i++)
            if (k.addr_a[i] != 0 || k.addr_b[i] != 0)
                abort();
    }

    return 0;
}
