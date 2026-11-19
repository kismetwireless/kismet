/* libFuzzer harness for the DHCPv4 and DHCPv6 parsers in kis_l3_parse.  The first byte picks
 * the parser, the rest is the UDP payload.  Build as frame_fuzz.cc; run 10M iterations.
 */

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "kis_l3_parse.h"

using namespace kis_l3;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return 0;

    std::vector<uint8_t> buf(data + 1, data + size);
    const uint8_t *p = buf.empty() ? nullptr : buf.data();

    frame f;

    if (data[0] & 1) {
        if (p != nullptr || buf.empty())
            parse_dhcp6(p, buf.size(), f);

        const auto& d = f.dhcp6;
        if (d.client_duid.len > max_duid || d.server_duid.len > max_duid || d.fqdn.len > max_dns_name ||
                d.vendor.len > max_opt_string || d.n_oro > max_oro || d.n_ia_addrs > max_ia_addrs)
            abort();
        if (d.has_fqdn && d.fqdn.empty())
            abort();
    } else {
        parse_dhcp4(p, buf.size(), f);

        const auto& d = f.dhcp4;
        if (d.hostname.len > max_opt_string || d.vendor.len > max_opt_string ||
                d.client_id.len > max_opt_string || d.prl.len > max_opt_string ||
                d.fqdn.len > max_dns_name || d.n_dns > max_dns_servers || d.overload > 3)
            abort();
        if (d.valid && buf.size() < 240)
            abort();
        if (d.has_fqdn && d.fqdn.empty())
            abort();
    }

    return 0;
}
