/* libFuzzer harness for wired_flow_tracker: a stream of packets, expiries, snapshots and
 * lookups from the input, against a small table.  The first byte picks the full-table policy
 * and eviction idle times, the second the history pool.  Build as frame_fuzz.cc, with
 * wired_flow_history.cc.
 */

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "wired_flow_tracker.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return 0;

    wired_flow_tracker::params p;
    p.max_flows = 64;
    p.tcp_idle = 30;
    p.tcp_closed_idle = 2;
    p.udp_idle = 10;
    p.other_idle = 10;
    p.on_full = (data[0] & 1) ? wired_flow_tracker::full_policy::drop : wired_flow_tracker::full_policy::evict;
    p.evict_idle = (data[0] >> 1) & 0x07;
    p.evict_closed_idle = (data[0] >> 4) & 0x03;
    p.max_histories = data[1] & 0x1f;
    p.history_min_packets = (data[1] >> 5) & 0x03;
    p.history_idle = (data[1] & 0x80) ? 1 : 10;
    // A fixed seed keeps runs reproducible
    wired_flow_tracker t(p, 0x5eed);

    data += 2;
    size -= 2;

    // Server time starts past 0, so history_time 0 always means none
    time_t now = 1000000;
    std::vector<wired_flow_tracker::flow> out;

    for (size_t i = 0; i + 8 <= size; i += 8) {
        const uint8_t *r = data + i;

        if ((r[0] & 0x0f) == 0x0f) {
            now += r[1];
            t.expire(now);
        } else if ((r[0] & 0x0f) == 0x0d) {
            // Hours to years, across every history tier
            now += static_cast<time_t>(r[1]) * ((r[2] & 1) ? 86400 * 400 : 3600);
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

            // Every listed flow is found by its key and serial, and only by that serial
            wired_flow_tracker::flow fl;
            flow_history h(0);
            for (const auto& o : out) {
                if (o.serial == 0 || !t.lookup(o.k, o.serial, now, fl, &h) || fl.serial != o.serial)
                    abort();
                if (t.lookup(o.k, o.serial + 1, now, fl, nullptr))
                    abort();
                if (fl.history_time != 0 && (h.last_time() < now ||
                            h.day_total(flow_history::series::bytes_ab) > fl.bytes_ab ||
                            h.day_total(flow_history::series::bytes_ba) > fl.bytes_ba ||
                            h.day_total(flow_history::series::packets_ab) > fl.packets_ab ||
                            h.day_total(flow_history::series::packets_ba) > fl.packets_ba))
                    abort();
            }
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
            // Packet threads read the clock a little apart; 80 s back restarts a history
            o.seen = now - 20 * ((r[6] >> 1) & 0x07);
            t.add(o);
        }

        const auto st = t.get_stats();
        if (st.flows > p.max_flows || st.created - st.evicted - st.expired != st.flows)
            abort();
        if (p.on_full == wired_flow_tracker::full_policy::drop && st.evicted != 0)
            abort();
        if (st.histories > p.max_histories || st.histories > st.flows)
            abort();
    }

    size_t total = 0, with_history = 0;
    t.snapshot({}, 0, 0, out, total);
    for (const auto& o : out)
        if (o.history_time != 0)
            with_history++;
    if (with_history != t.get_stats().histories)
        abort();

    t.expire(now + 1000);
    if (t.get_stats().flows != 0 || t.get_stats().histories != 0)
        abort();

    return 0;
}
