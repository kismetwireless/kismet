/* libFuzzer harness for wired_flow_tracker: a stream of packets, expiries and snapshots from
 * the input, against a small table.  Build as frame_fuzz.cc.
 */

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "wired_flow_tracker.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    wired_flow_tracker::params p;
    p.max_flows = 64;
    p.tcp_idle = 30;
    p.tcp_closed_idle = 2;
    p.udp_idle = 10;
    p.other_idle = 10;
    wired_flow_tracker t(p);

    time_t now = 0;
    std::vector<wired_flow_tracker::flow> out;

    for (size_t i = 0; i + 8 <= size; i += 8) {
        const uint8_t *r = data + i;

        if ((r[0] & 0x0f) == 0x0f) {
            now += r[1];
            t.expire(now);
        } else if ((r[0] & 0x0f) == 0x0e) {
            wired_flow_tracker::filter f;
            if (r[1] & 1)
                f.vlan = r[2] & 0x0f;
            if (r[1] & 2)
                f.mac = 0x020000000000ULL | r[3];
            size_t total = 0;
            t.snapshot(f, r[4], r[5], out, total);
            if (out.size() > total || out.size() > p.max_flows || (r[5] != 0 && out.size() > r[5]))
                abort();
            for (size_t k = 1; k < out.size(); k++)
                if (out[k - 1].last_time < out[k].last_time)
                    abort();
        } else {
            wired_flow_tracker::observation o;
            o.src.family = o.dst.family = (r[0] & 0x10) ? 6 : 4;
            o.src.a[0] = r[1] & 0x07;
            o.dst.a[0] = r[2] & 0x07;
            o.proto = (r[0] & 0x20) ? 6 : 17;
            o.sport = r[3] & 0x03;
            o.dport = r[4] & 0x03;
            o.tcp_flags = r[5];
            o.vlan = wired_flow_tracker::vlan_key(r[6] & 1, r[6] >> 4, 0);
            o.src_mac = 0x020000000000ULL | r[1];
            o.bytes = r[7];
            o.ts = (r[7] & 0x80) ? INT64_C(0x7fffffff) * (r[7] & 0x03) : now + (r[7] & 0x03);
            o.seen = now;
            t.add(o);
        }

        if (t.get_stats().flows > p.max_flows)
            abort();
    }

    t.expire(now + 1000);
    if (t.get_stats().flows != 0)
        abort();

    return 0;
}
