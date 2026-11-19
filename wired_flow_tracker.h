/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __WIRED_FLOW_TRACKER_H__
#define __WIRED_FLOW_TRACKER_H__

// Bounded table of IP flows seen on the wire: plain structs, sharded by hash, never more
// than max_flows entries.  Past admit_pct of the cap a new flow is only admitted on its second
// packet (like conntrack's early drop), so a scan of single packets can't fill the table.
//
// Packet times are only shown; a flow goes idle by server time since its last packet, so a
// capture's clock (skewed, reordered, or days old in a replay) can't expire or keep flows.
// No Kismet dependencies, so the tests and fuzzers build it alone; hence std::mutex.

#include <array>
#include <atomic>
#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <vector>

#include "kis_l3_parse.h"
#include "unordered_dense.h"

class wired_flow_tracker {
public:
    struct params {
        size_t max_flows = 16384;
        time_t tcp_idle = 300;
        time_t tcp_closed_idle = 10;
        time_t udp_idle = 60;
        time_t other_idle = 60;
        unsigned int admit_pct = 90;
    };

    // Up to two VLAN IDs and the tag count, packed; 0 is untagged
    static constexpr uint64_t vlan_key(uint8_t n_tags, uint16_t outer, uint16_t inner) {
        return (static_cast<uint64_t>(n_tags) << 32) | (static_cast<uint64_t>(outer & 0xfff) << 12) |
            (inner & 0xfff);
    }

    struct key {
        uint8_t family = 0;
        uint8_t proto = 0;
        uint16_t port_a = 0, port_b = 0;
        uint64_t vlan = 0;
        std::array<uint8_t, 16> addr_a{}, addr_b{};

        bool operator==(const key& o) const {
            return family == o.family && proto == o.proto && port_a == o.port_a && port_b == o.port_b &&
                vlan == o.vlan && addr_a == o.addr_a && addr_b == o.addr_b;
        }
    };

    struct key_hash {
        using is_avalanching = void;
        uint64_t operator()(const key& k) const noexcept;
    };

    // One packet of a flow
    struct observation {
        kis_l3::ip_addr src, dst;
        uint8_t proto = 0;
        uint16_t sport = 0, dport = 0;
        uint8_t tcp_flags = 0;
        uint64_t vlan = 0;
        uint64_t src_mac = 0, dst_mac = 0;
        uint64_t bytes = 0;
        time_t ts = 0;                  // packet time, shown
        time_t seen = 0;                // server time, for idle expiry
    };

    // What the table stores per flow; the key is only the map's
    struct flow_state {
        // Side a is the lower address and port; initiator_a when a sent the first packet seen
        bool initiator_a = false;
        bool closed = false;            // a FIN or RST was seen
        uint8_t flags_ab = 0, flags_ba = 0;
        uint64_t mac_a = 0, mac_b = 0;
        uint64_t bytes_ab = 0, bytes_ba = 0;
        uint64_t packets_ab = 0, packets_ba = 0;
        time_t first_time = 0, last_time = 0;
        time_t seen = 0;
    };

    // A flow as snapshot() returns it
    struct flow : flow_state {
        key k;
    };

    enum class result : uint8_t { updated, created, deferred, dropped, ignored };

    struct stats {
        size_t flows = 0;
        uint64_t created = 0;
        uint64_t expired = 0;
        uint64_t dropped_full = 0;
        uint64_t deferred = 0;
    };

    struct filter {
        uint64_t mac = 0;               // 0 for any
        kis_l3::ip_addr ip;             // unset for any
        int vlan = -1;                  // a VLAN ID in either tag, -1 for any
    };

    explicit wired_flow_tracker(const params& p);

    result add(const observation& o);

    // Drops flows idle at server time now; returns how many
    size_t expire(time_t now);

    // Flows matching f, most recent packet first, from start (length 0 for all of them);
    // total_matched counts every match.  Only start + length flows are copied out of the table.
    void snapshot(const filter& f, size_t start, size_t length, std::vector<flow>& out,
            size_t& total_matched) const;

    stats get_stats() const;

    const params& get_params() const { return p; }

    static constexpr size_t n_shards = 16;
    static constexpr size_t pending_slots = 1024;

protected:
    struct shard {
        mutable std::mutex mutex;
        ankerl::unordered_dense::map<key, flow_state, key_hash> flows;
        // Hashes of flows waiting for a second packet, while the table is nearly full
        std::array<uint64_t, pending_slots> pending{};
    };

    params p;
    size_t admit_threshold;
    std::unique_ptr<shard[]> shards;

    std::atomic<size_t> n_flows{0};
    std::atomic<uint64_t> n_created{0}, n_expired{0}, n_dropped_full{0}, n_deferred{0};

    time_t idle_for(uint8_t proto, const flow_state& f) const;
};

#endif
