/* libFuzzer harness for kis_l3::parse_frame, the wired frame decoder.  The first byte picks
 * the DLT (Ethernet, SLL, SLL2), the rest is the captured frame.
 *
 *   SAN="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all"
 *   clang++ -std=c++20 $SAN -fsanitize=fuzzer -I. test/ethernet/frame_fuzz.cc kis_l3_parse.cc \
 *       wired_flow_tracker.cc -o <scratch>/frame_fuzz
 *   <scratch>/frame_fuzz <corpus dir>
 *
 * Seed the corpus with frames from test/ethernet/eth_pcaps.py.
 */

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "kis_l3_parse.h"

using namespace kis_l3;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return 0;

    static constexpr int dlts[3] = {dlt_en10mb, dlt_linux_sll, dlt_linux_sll2};
    const int dlt = dlts[data[0] % 3];

    // A copy of exactly the captured bytes, so ASan sees any read past them
    std::vector<uint8_t> buf(data + 1, data + size);

    frame f;
    parse_frame(dlt, buf.empty() ? nullptr : buf.data(), buf.size(), f);

    if (f.n_tags > max_vlan_tags || f.n_ext > max_ipv6_ext + 1)
        abort();
    if (f.dhcp4.hostname.len > max_opt_string || f.dhcp4.vendor.len > max_opt_string ||
            f.dhcp4.client_id.len > max_opt_string || f.dhcp4.prl.len > max_opt_string ||
            f.dhcp4.fqdn.len > max_dns_name || f.dhcp4.n_dns > max_dns_servers)
        abort();
    if (f.dhcp6.client_duid.len > max_duid || f.dhcp6.server_duid.len > max_duid ||
            f.dhcp6.fqdn.len > max_dns_name || f.dhcp6.vendor.len > max_opt_string ||
            f.dhcp6.n_oro > max_oro || f.dhcp6.n_ia_addrs > max_ia_addrs)
        abort();
    // Nothing past the link header without one
    if (!f.l2_ok && (f.l3 != l3_type::none || f.l4_ok))
        abort();
    if (f.l4_ok && f.l3 != l3_type::ipv4 && f.l3 != l3_type::ipv6)
        abort();
    if ((f.dhcp4.valid || f.dhcp6.valid) && !f.l4_ok)
        abort();
    if (f.fragment && f.l4_ok)
        abort();
    if (f.ip_src.set() && f.ip_src.family != 4 && f.ip_src.family != 6)
        abort();

    // Escaping arbitrary bytes, not only the valid UTF-8 it's meant for, stays in bounds and
    // only ever adds
    const std::string raw(buf.begin(), buf.end());
    if (escape_hidden(raw).size() < raw.size())
        abort();

    return 0;
}
