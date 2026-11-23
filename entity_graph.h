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

#ifndef __ENTITY_GRAPH_H__
#define __ENTITY_GRAPH_H__

// Links between device records on different phys that are one physical device, such as a
// Wi-Fi client and the Ethernet record with the same MAC.  Records are never merged: each
// link (edge) carries its evidence and a confidence computed from it, and records joined by
// links at or above the threshold share an entity id.
//
// Pure and not thread safe: no tracker, packet or global state, so test/entity builds it
// alone.  entity_tracker holds it under its own mutex and is its only writer.  Every table
// keyed by device keys or MACs hashes with a seed chosen at startup.

#include <algorithm>
#include <array>
#include <cstdint>
#include <ctime>
#include <deque>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "unordered_dense.h"

namespace entity {

// MACs as mac_addr::longmac: bytes left aligned, the first byte in the top 8 bits
constexpr uint8_t mac_byte0(uint64_t mac) {
    return static_cast<uint8_t>(mac >> 56);
}

constexpr bool mac_is_local(uint64_t mac) {
    return mac_byte0(mac) & 0x02;
}

// No links for zero or group MACs, or for VRRP (00:00:5e:00:01:xx, 00:00:5e:00:02:xx) and
// HSRP (00:00:0c:07:ac:xx) virtual router MACs, which several hosts share by design
constexpr bool mac_excluded(uint64_t mac) {
    if (mac == 0 || (mac_byte0(mac) & 0x01))
        return true;

    const uint64_t oui5 = mac >> 24;
    return oui5 == 0x00005e0001ULL || oui5 == 0x00005e0002ULL || oui5 == 0x00000c07acULL;
}

constexpr uint64_t splitmix64(uint64_t h) {
    h ^= h >> 30;
    h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27;
    h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;
    return h;
}

// A device record, by the two halves of its device_key
struct node {
    uint64_t spkey = 0;
    uint64_t dkey = 0;

    bool operator==(const node& o) const { return spkey == o.spkey && dkey == o.dkey; }
    bool operator!=(const node& o) const { return !(*this == o); }
    bool operator<(const node& o) const { return spkey != o.spkey ? spkey < o.spkey : dkey < o.dkey; }
};

enum class relationship : uint8_t {
    none = 0,
    wired_same_mac = 1,     // a Wi-Fi client or AP and the Ethernet record with its MAC
    wired_bridged = 2,      // a host bridged onto Wi-Fi (from-DS or 4-address source) and its Ethernet record
};

std::string_view relationship_name(relationship r);

// What the Wi-Fi record with the shared MAC is; picks the base confidence
enum class wifi_kind : uint8_t {
    none = 0,
    inferred,       // only ever a destination, or an ad-hoc peer
    client_mgmt,    // a radio client heard only in management frames (probes, auth)
    client,         // a radio client with data or an association to a BSS
    bridged,        // a host behind a BSSID or a WDS radio: bridged onto Wi-Fi
    ap,             // an AP or a WDS radio
};

std::string_view wifi_kind_name(wifi_kind k);

// Evidence bits.  Each fact counts once, so repeating it can't raise the confidence.
namespace ev {
    inline constexpr uint16_t radio_client = 1 << 0;    // CLIENT basic type
    inline constexpr uint16_t associated = 1 << 1;      // data frames and a client record for a BSS
    inline constexpr uint16_t radio_ap = 1 << 2;        // AP basic type
    inline constexpr uint16_t wds_radio = 1 << 3;       // AP and peer: a WDS transmitter or receiver
    inline constexpr uint16_t bridged_from_ds = 1 << 4; // source of from-DS data an AP relayed
    inline constexpr uint16_t bridged_4addr = 1 << 5;   // source of 4-address frames from a WDS radio
    inline constexpr uint16_t local_mac = 1 << 6;       // locally administered (randomized, VM)
    inline constexpr uint16_t ip_match = 1 << 7;        // a Wi-Fi client IPv4 is on the Ethernet record
    // Reserved: 8-10 XID, timed XID, timed wake (P5b); 11 VLAN conflict (P5c); 15 external (T-43)

    inline constexpr std::array<std::pair<uint16_t, std::string_view>, 8> names{{
        {radio_client, "radio_client"}, {associated, "associated"}, {radio_ap, "radio_ap"},
        {wds_radio, "wds_radio"}, {bridged_from_ds, "bridged_from_ds"},
        {bridged_4addr, "bridged_4addr"}, {local_mac, "local_mac"}, {ip_match, "ip_match"},
    }};

    constexpr uint16_t all_of_names() {
        uint16_t a = 0;
        for (const auto& [bit, name] : names)
            a |= bit;
        return a;
    }

    inline constexpr uint16_t all = all_of_names();
}

inline constexpr uint8_t base_client = 80;
inline constexpr uint8_t base_client_local = 75;
inline constexpr uint8_t base_bridged = 70;
inline constexpr uint8_t base_ap = 70;
// Management-only and inferred records stay possible links even with every bonus: below
// default_min_confidence
inline constexpr uint8_t base_client_mgmt = 45;
inline constexpr uint8_t base_inferred = 40;
inline constexpr uint8_t bonus_ip_match = 10;
// 100 is kept for authoritative evidence (T-43)
inline constexpr uint8_t max_confidence = 95;
inline constexpr uint8_t default_min_confidence = 60;

constexpr wifi_kind kind_of(uint16_t evidence) {
    if (evidence & (ev::radio_ap | ev::wds_radio))
        return wifi_kind::ap;
    if (evidence & ev::radio_client)
        return (evidence & ev::associated) ? wifi_kind::client : wifi_kind::client_mgmt;
    if (evidence & (ev::bridged_from_ds | ev::bridged_4addr))
        return wifi_kind::bridged;
    return wifi_kind::inferred;
}

constexpr relationship relationship_of(wifi_kind k) {
    return k == wifi_kind::bridged ? relationship::wired_bridged : relationship::wired_same_mac;
}

constexpr uint8_t confidence_of(uint16_t evidence) {
    unsigned int c = 0;

    switch (kind_of(evidence)) {
        case wifi_kind::client:
            c = (evidence & ev::local_mac) ? base_client_local : base_client;
            break;
        case wifi_kind::client_mgmt:
            c = base_client_mgmt;
            break;
        case wifi_kind::bridged:
            c = base_bridged;
            break;
        case wifi_kind::ap:
            c = base_ap;
            break;
        case wifi_kind::inferred:
        case wifi_kind::none:
            c = base_inferred;
            break;
    }

    if (evidence & ev::ip_match)
        c += bonus_ip_match;

    return static_cast<uint8_t>(c > max_confidence ? max_confidence : c);
}

// The highest confidence any combination of evidence reaches; a threshold above it links nothing
constexpr uint8_t max_reachable_of_table() {
    uint8_t m = 0;
    for (unsigned int e = 0; e <= ev::all; e++)
        if ((e & ~static_cast<unsigned int>(ev::all)) == 0)
            m = std::max(m, confidence_of(static_cast<uint16_t>(e)));
    return m;
}

inline constexpr uint8_t max_reachable_confidence = max_reachable_of_table();

static_assert(default_min_confidence <= max_reachable_confidence && max_reachable_confidence <= max_confidence);
static_assert(base_client_mgmt + bonus_ip_match < default_min_confidence &&
        base_inferred + bonus_ip_match < default_min_confidence);

std::vector<std::string_view> evidence_names(uint16_t evidence);

// Whether a Wi-Fi client IPv4 (a dot11 ipdata address: the first octet in the top byte) is
// among an Ethernet record's addresses (network order bytes); 0.0.0.0 and 255.255.255.255
// never match
bool ipv4_match(const std::vector<uint32_t>& wifi_ipdata, const std::vector<std::array<uint8_t, 4>>& wired);

// BSSIDs or WDS radios a bridged or client record was heard behind
inline constexpr size_t max_via = 4;

struct link_info {
    relationship rel = relationship::none;
    wifi_kind kind = wifi_kind::none;
    uint16_t evidence = 0;
    uint8_t confidence = 0;
    bool conflicted = false;        // P5c
    uint8_t n_via = 0;
    std::array<uint64_t, max_via> via{};

    // The BSSIDs compare as a set: their order (newest first) moves with traffic, the link doesn't
    bool operator==(const link_info& o) const {
        return rel == o.rel && kind == o.kind && evidence == o.evidence && confidence == o.confidence &&
            conflicted == o.conflicted && n_via == o.n_via && via_within(o) && o.via_within(*this);
    }
    bool operator!=(const link_info& o) const { return !(*this == o); }

    bool via_within(const link_info& o) const {
        const auto ov = std::span(o.via).first(std::min<size_t>(o.n_via, max_via));
        for (size_t i = 0; i < n_via && i < max_via; i++)
            if (std::ranges::find(ov, via[i]) == ov.end())
                return false;
        return true;
    }
};

// The link for one shared MAC, from the facts read off the Wi-Fi record
link_info evaluate(uint16_t evidence, const std::array<uint64_t, max_via>& via, uint8_t n_via);

struct edge {
    node a, b;                      // a < b
    uint64_t a_iid = 0, b_iid = 0;  // record ids when linked: a record made again under the same key is new
    uint64_t mac = 0;               // the shared MAC
    link_info info;
    bool linked = false;            // at or above the threshold, not conflicted, in a component under the cap
    time_t first_time = 0;          // server time the edge was made
    time_t last_time = 0;           // server time it was last confirmed
};

struct params {
    size_t max_edges = 65536;
    size_t max_edges_per_node = 16;
    size_t max_component = 32;
    uint8_t min_confidence = default_min_confidence;
};

struct stats {
    size_t edges = 0;
    size_t linked = 0;
    size_t nodes = 0;
    size_t entities = 0;
    uint64_t refused_cap = 0;
    uint64_t refused_node_cap = 0;
    uint64_t component_capped = 0;
};

class graph {
public:
    graph(const params& p, uint64_t seed);

    enum class upsert_result : uint8_t {
        added, updated, unchanged, refused_cap, refused_node_cap, invalid,
    };

    // Make or update the edge between two records.  A node already known with a different
    // record id is a new record: its old edges go first.
    upsert_result upsert(const node& a, uint64_t a_iid, const node& b, uint64_t b_iid, uint64_t mac,
            const link_info& info, time_t now);

    bool remove_edge(const node& a, const node& b);

    // Forget a record and every edge it had; returns the edges removed
    size_t remove_node(const node& n);

    // Records whose entity id or linked peers changed since the last call, with the record id
    // they had, so the caller only writes to that same record
    void take_dirty(std::vector<std::pair<node, uint64_t>>& out);

    // Dirty records taken by a pass that failed before writing them all; a record marked
    // dirty again since keeps the newer record id
    void restore_dirty(const std::vector<std::pair<node, uint64_t>>& taken);

    // What a record should show: its entity id (0 when not linked) and its linked peers
    struct mirror {
        uint64_t entity_id = 0;
        std::vector<std::pair<relationship, node>> linked;
    };
    mirror desired(const node& n) const;

    bool has_node(const node& n) const;
    uint64_t node_iid(const node& n) const;
    uint64_t entity_of(const node& n) const;
    void edges_of(const node& n, std::vector<edge>& out) const;

    // The next n edges in table order, wrapping; for the sweep
    void sweep(size_t n, std::vector<edge>& out);

    // Edges at or above min_conf, in table order; total counts every match.  Reads at most
    // start + length edges, and only length when min_conf is 0.
    void page(size_t start, size_t length, uint8_t min_conf, std::vector<edge>& out, size_t& total) const;

    // Edges removed so far: room for an edge refused at a cap can only come from a removal
    uint64_t removals() const { return n_removals; }

    stats get_stats() const;
    const params& get_params() const { return prm; }

    // Every invariant: symmetric adjacency, caps, components and ids; for the tests
    bool check(std::string& why) const;

protected:
    struct seeded_node_hash {
        using is_avalanching = void;
        uint64_t seed = 0;
        uint64_t operator()(const node& n) const noexcept {
            return splitmix64(splitmix64(n.spkey + seed) ^ n.dkey);
        }
    };

    struct edge_key {
        node a, b;
        bool operator==(const edge_key& o) const { return a == o.a && b == o.b; }
    };

    struct seeded_edge_hash {
        using is_avalanching = void;
        uint64_t seed = 0;
        uint64_t operator()(const edge_key& k) const noexcept {
            const uint64_t ha = splitmix64(splitmix64(k.a.spkey + seed) ^ k.a.dkey);
            return splitmix64(splitmix64(ha ^ k.b.spkey) ^ k.b.dkey);
        }
    };

    struct node_state {
        uint64_t iid = 0;
        uint64_t entity = 0;
        std::vector<node> peers;
    };

    static edge_key key_of(const node& a, const node& b) {
        return b < a ? edge_key{b, a} : edge_key{a, b};
    }

    bool qualifies(const link_info& i) const {
        return !i.conflicted && i.confidence >= prm.min_confidence;
    }

    bool edge_linked(const node& a, const node& b) const;

    // Records reachable over linked edges, stopping after limit
    void component(const node& start, size_t limit, std::vector<node>& out) const;

    void link(edge& e);
    void unlink(const node& a, const node& b);
    void set_entity(const node& n, uint64_t id);
    void mark_dirty(const node& n);
    void drop_if_isolated(const node& n);

    void add_confidence(uint8_t c) { by_confidence[c]++; }
    void drop_confidence(uint8_t c) {
        if (by_confidence[c] > 0)
            by_confidence[c]--;
    }

    params prm;
    uint64_t next_entity = 1;
    size_t n_linked = 0;
    size_t sweep_pos = 0;
    uint64_t n_removals = 0;
    uint64_t refused_cap = 0, refused_node_cap = 0, component_capped = 0;

    // Edges by confidence, for page totals without a walk
    std::array<size_t, 256> by_confidence{};

    ankerl::unordered_dense::map<node, node_state, seeded_node_hash> nodes;
    ankerl::unordered_dense::map<edge_key, edge, seeded_edge_hash> edges;
    ankerl::unordered_dense::map<node, uint64_t, seeded_node_hash> dirty;
    ankerl::unordered_dense::map<uint64_t, size_t> entity_sizes;
};

// MACs that have an Ethernet record, and the queue of MACs whose records changed.  Each MAC
// is queued at most once until it's taken, so the queue never holds more than the index.
//
// Two ways a MAC waits for room, so nothing refused at a cap stays unlinked once there is
// room: a MAC refused while the index was full is found again by a rescan of the Ethernet
// records (rescan_due), and an indexed MAC whose link was refused at a graph cap is deferred
// until the graph removes an edge (requeue_deferred).  Deferred MACs are indexed MACs, so
// they're bounded by the index.
class mac_index {
public:
    mac_index(size_t in_cap, uint64_t seed);

    enum class add_result : uint8_t { added, present, full, excluded };

    // An Ethernet record with this MAC exists; queues it
    add_result add(uint64_t mac);

    // As add, for a rescan: a MAC already indexed isn't queued again
    add_result add_missing(uint64_t mac);

    // A MAC was refused since rescan_started(), and there's room now
    bool rescan_due() const { return refused_pending && index.size() < cap; }
    void rescan_started() { refused_pending = false; }
    // A rescan stopped at a full index: due again once there's room
    void rescan_unfinished() { refused_pending = true; }

    // Queue an indexed MAC; false when it isn't indexed
    bool touch(uint64_t mac);

    bool contains(uint64_t mac) const;

    // Up to n queued MACs, oldest first.  Each leaves the queue and can be queued again.
    void take(size_t n, std::vector<uint64_t>& out);

    // Forget a MAC unless it was queued again after it was taken
    bool erase_if_idle(uint64_t mac);

    // Hold an indexed MAC whose link was refused; false when it isn't indexed or already held
    bool defer(uint64_t mac);

    // Queue up to n held MACs again, oldest first; returns how many were released
    size_t requeue_deferred(size_t n);

    // A held MAC was linked anyway (read again for another reason after room came): stop
    // holding it; false when it wasn't held
    bool release(uint64_t mac);

    // MACs a failed pass took; each indexed one is queued again
    void requeue(const std::vector<uint64_t>& macs);

    size_t size() const { return index.size(); }
    size_t queued() const { return queue.size(); }
    size_t deferred() const { return deferred_set.size(); }
    size_t capacity() const { return cap; }
    uint64_t refused() const { return n_refused; }

    // Every invariant: queues match the flags and stay bounded; for the tests
    bool check(std::string& why) const;

protected:
    struct seeded_mac_hash {
        using is_avalanching = void;
        uint64_t seed = 0;
        uint64_t operator()(uint64_t m) const noexcept { return splitmix64(m + seed); }
    };

    add_result insert(uint64_t mac, bool requeue);
    void compact_deferred();

    size_t cap;
    uint64_t n_refused = 0;
    bool refused_pending = false;
    ankerl::unordered_dense::map<uint64_t, bool, seeded_mac_hash> index;  // MAC -> queued
    std::deque<uint64_t> queue;

    // The set says what's held; the queue keeps the order and may hold stale entries for
    // MACs forgotten while held, which are skipped, and compacted past twice the set
    ankerl::unordered_dense::set<uint64_t, seeded_mac_hash> deferred_set;
    std::deque<uint64_t> deferred_queue;
};

// Where the rescan walk stands after a batch.  A walk with no view to read never counts as
// finished, and one stopped by a full index is due again.
enum class rescan_state : uint8_t { more, finished, unfinished };

constexpr rescan_state rescan_after(bool read_view, bool more, bool full) {
    if (!read_view || full)
        return rescan_state::unfinished;
    return more ? rescan_state::more : rescan_state::finished;
}

}

#endif
