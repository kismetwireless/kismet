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
// With the table full, an admitted flow takes the place of an idle one in its shard (evict),
// or is dropped (drop).  Eviction looks at evict_samples entries from a cursor that walks the
// shard, and takes a closed TCP flow before an open one, then the longest idle.  A flow with a
// packet in the last evict_idle seconds (evict_closed_idle once closed) is never evicted; if
// every sampled flow is that recent, the new flow is dropped.  So a flood can only replace
// idle flows, at most one per admitted flow, and each admitted flow costs it two packets.
//
// Packet times are only shown; a flow goes idle by server time since its last packet, so a
// capture's clock (skewed, reordered, or days old in a replay) can't expire or keep flows.
// No Kismet dependencies, so the tests and fuzzers build it alone; hence std::mutex.
//
// Up to max_histories flows keep a traffic history (wired_flow_history.h), by server time.  A
// flow gets one on the packet that brings it to history_min_packets, if the pool has room;
// with the pool 90% full, the expiry pass takes them back from flows idle history_idle
// seconds.  With the table full, a flow without history is evicted before one with.

#include <array>
#include <atomic>
#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <vector>

#include "kis_l3_parse.h"
#include "unordered_dense.h"
#include "wired_flow_history.h"

class wired_flow_tracker {
public:
    enum class full_policy : uint8_t { evict, drop };

    struct params {
        size_t max_flows = 16384;
        time_t tcp_idle = 300;
        time_t tcp_closed_idle = 10;
        time_t udp_idle = 60;
        time_t other_idle = 60;
        unsigned int admit_pct = 90;
        full_policy on_full = full_policy::evict;
        // Seconds without a packet before a flow can be evicted
        time_t evict_idle = 10;
        time_t evict_closed_idle = 1;
        // Flows with a traffic history, at most max_flows; 0 for none
        size_t max_histories = 4096;
        // Packets, both ways, before a flow gets a history; at least 1
        uint64_t history_min_packets = 8;
        // Seconds idle before a flow gives its history back, with the pool 90% full
        time_t history_idle = 60;
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

    // Keyed by a secret seed, so flows that share a shard or a pending slot can't be computed
    // offline.  The default (seed 0) is only a placeholder until the tracker sets its own.
    struct key_hash {
        using is_avalanching = void;

        key_hash() : key_hash(0) { }
        explicit key_hash(uint64_t seed);

        uint64_t operator()(const key& k) const noexcept;

    private:
        std::array<uint64_t, 7> keys{};
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

    // A flow as snapshot() and lookup() return it
    struct flow : flow_state {
        key k;
        uint64_t serial = 0;            // nonzero, unique to this flow
        time_t history_time = 0;        // server time its history began, 0 for none
    };

    enum class result : uint8_t { updated, created, deferred, dropped, ignored };

    struct stats {
        size_t flows = 0;
        uint64_t created = 0;
        uint64_t expired = 0;
        uint64_t dropped_full = 0;
        uint64_t deferred = 0;
        uint64_t evicted = 0;
        size_t histories = 0;
        uint64_t histories_denied = 0;
        uint64_t histories_released = 0;
    };

    struct filter {
        uint64_t mac = 0;               // 0 for any
        kis_l3::ip_addr ip;             // unset for any
        int vlan = -1;                  // a VLAN ID in either tag, -1 for any
    };

    // Hashes with a random seed; tests pass their own to be repeatable
    explicit wired_flow_tracker(const params& p);
    wired_flow_tracker(const params& p, uint64_t hash_seed);
    ~wired_flow_tracker();

    result add(const observation& o);

    // Drops flows idle at server time now and, with the history pool nearly full, the
    // histories of flows idle history_idle; returns how many flows were dropped
    size_t expire(time_t now);

    // The flow k with this serial; its history too, moved forward to server time now, into
    // hist_out when that's set and the flow has one (out.history_time != 0).  False when
    // there's no such flow, or k is now a different flow.
    bool lookup(const key& k, uint64_t serial, time_t now, flow& out, flow_history* hist_out) const;

    // Flows matching f, most recent packet first, from start (length 0 for all of them);
    // total_matched counts every match.  Only start + length flows are copied out of the table.
    void snapshot(const filter& f, size_t start, size_t length, std::vector<flow>& out,
            size_t& total_matched) const;

    stats get_stats() const;

    const params& get_params() const { return p; }

    static constexpr size_t n_shards = 16;
    static constexpr size_t pending_slots = 1024;
    static constexpr size_t evict_samples = 8;

protected:
    // Frees a history and gives its place in the pool back
    struct history_release {
        void operator()(flow_history* h) const noexcept;
    };

    struct flow_entry : flow_state {
        uint64_t serial = 0;
        std::unique_ptr<flow_history, history_release> history;
    };

    struct shard {
        mutable std::mutex mutex;
        ankerl::unordered_dense::map<key, flow_entry, key_hash> flows;
        // Hashes of flows waiting for a second packet, while the table is nearly full
        std::array<uint64_t, pending_slots> pending{};
        // Where the next eviction starts looking in flows.values()
        size_t evict_cursor = 0;
    };

    params p;
    size_t admit_threshold;
    size_t release_threshold = 0;
    key_hash hasher;
    // Histories hold a pointer to n_histories, so the destructor frees shards first
    std::unique_ptr<shard[]> shards;

    std::atomic<size_t> n_flows{0};
    std::atomic<uint64_t> n_created{0}, n_expired{0}, n_dropped_full{0}, n_deferred{0}, n_evicted{0};
    std::atomic<size_t> n_histories{0};
    std::atomic<uint64_t> n_histories_denied{0}, n_histories_released{0};

    time_t idle_for(uint8_t proto, const flow_state& f) const;

    // Call with s.mutex held; removes one idle flow from s, false if none was found
    bool evict_one(shard& s, time_t now);

    // Call with the flow's shard mutex held, on a packet of a flow without history
    void admit_history(flow_entry& f, time_t now);

    static void to_flow(const key& k, const flow_entry& e, flow& out);
};

#endif
