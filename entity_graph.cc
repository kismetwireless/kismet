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

#include "entity_graph.h"

#include <algorithm>

namespace entity {

std::string_view relationship_name(relationship r) {
    switch (r) {
        case relationship::wired_same_mac:
            return "wired_same_mac";
        case relationship::wired_bridged:
            return "wired_bridged";
        case relationship::none:
            break;
    }
    return "none";
}

std::string_view wifi_kind_name(wifi_kind k) {
    switch (k) {
        case wifi_kind::inferred:
            return "inferred";
        case wifi_kind::client_mgmt:
            return "client_mgmt";
        case wifi_kind::client:
            return "client";
        case wifi_kind::bridged:
            return "bridged";
        case wifi_kind::ap:
            return "ap";
        case wifi_kind::none:
            break;
    }
    return "none";
}

std::vector<std::string_view> evidence_names(uint16_t evidence) {
    std::vector<std::string_view> r;
    for (const auto& [bit, name] : ev::names)
        if (evidence & bit)
            r.push_back(name);
    return r;
}

bool ipv4_match(const std::vector<uint32_t>& wifi_ipdata, const std::vector<std::array<uint8_t, 4>>& wired) {
    for (const auto s : wifi_ipdata) {
        if (s == 0 || s == 0xffffffffU)
            continue;

        const std::array<uint8_t, 4> b{static_cast<uint8_t>(s >> 24), static_cast<uint8_t>(s >> 16),
            static_cast<uint8_t>(s >> 8), static_cast<uint8_t>(s)};

        if (std::find(wired.begin(), wired.end(), b) != wired.end())
            return true;
    }

    return false;
}

link_info evaluate(uint16_t evidence, const std::array<uint64_t, max_via>& via, uint8_t n_via) {
    link_info i;
    i.evidence = evidence;
    i.kind = kind_of(evidence);
    i.rel = relationship_of(i.kind);
    i.confidence = confidence_of(evidence);
    i.n_via = static_cast<uint8_t>(std::min<size_t>(n_via, max_via));
    for (size_t v = 0; v < i.n_via; v++)
        i.via[v] = via[v];
    return i;
}

graph::graph(const params& p, uint64_t seed) :
    prm{p},
    nodes{0, seeded_node_hash{seed}},
    edges{0, seeded_edge_hash{seed}},
    dirty{0, seeded_node_hash{seed}} { }

bool graph::edge_linked(const node& a, const node& b) const {
    const auto ei = edges.find(key_of(a, b));
    return ei != edges.end() && ei->second.linked;
}

void graph::component(const node& start, size_t limit, std::vector<node>& out) const {
    out.clear();
    out.push_back(start);

    // Components are small (max_component), so a linear visited check is cheaper than a set
    for (size_t i = 0; i < out.size() && out.size() < limit; i++) {
        const auto ni = nodes.find(out[i]);
        if (ni == nodes.end())
            continue;

        for (const auto& p : ni->second.peers) {
            if (out.size() >= limit)
                break;
            if (std::find(out.begin(), out.end(), p) != out.end())
                continue;
            if (edge_linked(out[i], p))
                out.push_back(p);
        }
    }
}

void graph::mark_dirty(const node& n) {
    const auto ni = nodes.find(n);
    if (ni != nodes.end())
        dirty[n] = ni->second.iid;
}

void graph::set_entity(const node& n, uint64_t id) {
    auto ni = nodes.find(n);
    if (ni == nodes.end() || ni->second.entity == id)
        return;

    auto& s = ni->second;

    if (s.entity != 0) {
        auto si = entity_sizes.find(s.entity);
        if (si != entity_sizes.end() && --si->second == 0)
            entity_sizes.erase(si);
    }

    s.entity = id;

    if (id != 0)
        entity_sizes[id]++;

    dirty[n] = s.iid;
}

void graph::link(edge& e) {
    std::vector<node> ca, cb;

    component(e.a, prm.max_component + 1, ca);

    if (std::find(ca.begin(), ca.end(), e.b) == ca.end()) {
        component(e.b, prm.max_component + 1, cb);

        if (ca.size() + cb.size() > prm.max_component) {
            component_capped++;
            return;
        }

        const uint64_t ida = entity_of(e.a);
        const uint64_t idb = entity_of(e.b);
        uint64_t keep;

        // The larger group keeps its id, or the older one on a tie
        if (ida == 0 && idb == 0)
            keep = next_entity++;
        else if (ida == 0)
            keep = idb;
        else if (idb == 0)
            keep = ida;
        else if (ca.size() != cb.size())
            keep = ca.size() > cb.size() ? ida : idb;
        else
            keep = std::min(ida, idb);

        for (const auto& n : ca)
            set_entity(n, keep);
        for (const auto& n : cb)
            set_entity(n, keep);
    }

    e.linked = true;
    n_linked++;
    mark_dirty(e.a);
    mark_dirty(e.b);
}

void graph::unlink(const node& a, const node& b) {
    auto ei = edges.find(key_of(a, b));
    if (ei == edges.end() || !ei->second.linked)
        return;

    ei->second.linked = false;
    n_linked--;
    mark_dirty(a);
    mark_dirty(b);

    const size_t limit = nodes.size() + 1;
    std::vector<node> ca, cb;

    component(a, limit, ca);
    if (std::find(ca.begin(), ca.end(), b) != ca.end())
        return;

    component(b, limit, cb);

    // The larger part keeps the id; the other gets a new one, and a lone record none
    const uint64_t old = entity_of(a);
    const bool a_keeps = ca.size() > cb.size() || (ca.size() == cb.size() && a < b);
    auto& keeper = a_keeps ? ca : cb;
    auto& other = a_keeps ? cb : ca;

    const uint64_t keep_id = keeper.size() > 1 ? old : 0;
    for (const auto& n : keeper)
        set_entity(n, keep_id);

    const uint64_t other_id = other.size() > 1 ? next_entity++ : 0;
    for (const auto& n : other)
        set_entity(n, other_id);
}

void graph::drop_if_isolated(const node& n) {
    auto ni = nodes.find(n);
    if (ni == nodes.end() || !ni->second.peers.empty())
        return;

    set_entity(n, 0);
    dirty[n] = ni->second.iid;
    nodes.erase(n);
}

graph::upsert_result graph::upsert(const node& a, uint64_t a_iid, const node& b, uint64_t b_iid,
        uint64_t mac, const link_info& info, time_t now) {
    if (a == b)
        return upsert_result::invalid;

    if (const auto ni = nodes.find(a); ni != nodes.end() && ni->second.iid != a_iid)
        remove_node(a);
    if (const auto ni = nodes.find(b); ni != nodes.end() && ni->second.iid != b_iid)
        remove_node(b);

    const auto k = key_of(a, b);
    auto ei = edges.find(k);
    auto result = upsert_result::unchanged;
    bool rel_changed = false;

    if (ei == edges.end()) {
        if (edges.size() >= prm.max_edges) {
            refused_cap++;
            return upsert_result::refused_cap;
        }

        const auto na = nodes.find(a);
        const auto nb = nodes.find(b);
        if ((na != nodes.end() && na->second.peers.size() >= prm.max_edges_per_node) ||
                (nb != nodes.end() && nb->second.peers.size() >= prm.max_edges_per_node) ||
                prm.max_edges_per_node == 0) {
            refused_node_cap++;
            return upsert_result::refused_node_cap;
        }

        edge e;
        e.a = k.a;
        e.b = k.b;
        e.a_iid = k.a == a ? a_iid : b_iid;
        e.b_iid = k.b == b ? b_iid : a_iid;
        e.mac = mac;
        e.info = info;
        e.first_time = now;
        e.last_time = now;

        auto& sa = nodes[a];
        sa.iid = a_iid;
        sa.peers.push_back(b);
        auto& sb = nodes[b];
        sb.iid = b_iid;
        sb.peers.push_back(a);

        ei = edges.emplace(k, e).first;
        add_confidence(info.confidence);
        result = upsert_result::added;
    } else {
        auto& e = ei->second;
        rel_changed = e.info.rel != info.rel;

        if (e.info != info) {
            drop_confidence(e.info.confidence);
            add_confidence(info.confidence);
            result = upsert_result::updated;
        }

        // Equal links may still list their BSSIDs in a newer order
        e.info = info;
        e.mac = mac;
        e.last_time = std::max(e.last_time, now);
    }

    auto& e = ei->second;
    const bool want = qualifies(e.info);

    if (want && !e.linked) {
        link(e);
    } else if (!want && e.linked) {
        unlink(e.a, e.b);
    } else if (e.linked && rel_changed) {
        // Records show only the entity id and the relationship, so nothing else rewrites them
        mark_dirty(e.a);
        mark_dirty(e.b);
    }

    return result;
}

bool graph::remove_edge(const node& a, const node& b) {
    const auto k = key_of(a, b);
    const auto ei = edges.find(k);

    if (ei == edges.end())
        return false;

    drop_confidence(ei->second.info.confidence);
    unlink(k.a, k.b);
    edges.erase(k);
    n_removals++;

    for (const auto& [n, p] : {std::make_pair(k.a, k.b), std::make_pair(k.b, k.a)}) {
        auto ni = nodes.find(n);
        if (ni != nodes.end())
            std::erase(ni->second.peers, p);
    }

    drop_if_isolated(k.a);
    drop_if_isolated(k.b);

    return true;
}

size_t graph::remove_node(const node& n) {
    const auto ni = nodes.find(n);
    if (ni == nodes.end())
        return 0;

    const auto peers = ni->second.peers;
    size_t removed = 0;

    for (const auto& p : peers)
        if (remove_edge(n, p))
            removed++;

    // A node with no peers left was dropped with its last edge
    drop_if_isolated(n);

    return removed;
}

void graph::take_dirty(std::vector<std::pair<node, uint64_t>>& out) {
    out.clear();
    out.reserve(dirty.size());
    for (const auto& [n, iid] : dirty)
        out.emplace_back(n, iid);
    dirty.clear();
}

void graph::restore_dirty(const std::vector<std::pair<node, uint64_t>>& taken) {
    for (const auto& [n, iid] : taken)
        dirty.try_emplace(n, iid);
}

graph::mirror graph::desired(const node& n) const {
    mirror m;

    const auto ni = nodes.find(n);
    if (ni == nodes.end())
        return m;

    m.entity_id = ni->second.entity;

    for (const auto& p : ni->second.peers) {
        const auto ei = edges.find(key_of(n, p));
        if (ei != edges.end() && ei->second.linked)
            m.linked.emplace_back(ei->second.info.rel, p);
    }

    return m;
}

bool graph::has_node(const node& n) const {
    return nodes.find(n) != nodes.end();
}

uint64_t graph::node_iid(const node& n) const {
    const auto ni = nodes.find(n);
    return ni == nodes.end() ? 0 : ni->second.iid;
}

uint64_t graph::entity_of(const node& n) const {
    const auto ni = nodes.find(n);
    return ni == nodes.end() ? 0 : ni->second.entity;
}

void graph::edges_of(const node& n, std::vector<edge>& out) const {
    out.clear();

    const auto ni = nodes.find(n);
    if (ni == nodes.end())
        return;

    for (const auto& p : ni->second.peers) {
        const auto ei = edges.find(key_of(n, p));
        if (ei != edges.end())
            out.push_back(ei->second);
    }
}

void graph::sweep(size_t n, std::vector<edge>& out) {
    out.clear();

    const auto& v = edges.values();
    const size_t count = std::min(n, v.size());

    for (size_t i = 0; i < count; i++) {
        if (sweep_pos >= v.size())
            sweep_pos = 0;
        out.push_back(v[sweep_pos].second);
        sweep_pos++;
    }
}

void graph::page(size_t start, size_t length, uint8_t min_conf, std::vector<edge>& out,
        size_t& total) const {
    out.clear();
    total = 0;

    for (size_t c = min_conf; c < by_confidence.size(); c++)
        total += by_confidence[c];

    if (start >= total || length == 0)
        return;

    const auto& v = edges.values();

    // Every edge matches: total is the table size, and start is inside it
    if (min_conf == 0) {
        if (start >= v.size())
            return;
        const size_t end = start + std::min(length, v.size() - start);
        for (size_t i = start; i < end; i++)
            out.push_back(v[i].second);
        return;
    }

    size_t matched = 0;
    for (const auto& [k, e] : v) {
        if (e.info.confidence < min_conf)
            continue;
        if (matched++ < start)
            continue;
        out.push_back(e);
        if (out.size() >= length)
            break;
    }
}

stats graph::get_stats() const {
    stats s;
    s.edges = edges.size();
    s.linked = n_linked;
    s.nodes = nodes.size();
    s.entities = entity_sizes.size();
    s.refused_cap = refused_cap;
    s.refused_node_cap = refused_node_cap;
    s.component_capped = component_capped;
    return s;
}

bool graph::check(std::string& why) const {
    if (edges.size() > prm.max_edges) {
        why = "edges over the cap";
        return false;
    }

    size_t linked = 0;

    for (const auto& [k, e] : edges.values()) {
        if (!(e.a < e.b) || k.a != e.a || k.b != e.b) {
            why = "edge endpoints out of order";
            return false;
        }

        const auto na = nodes.find(e.a);
        const auto nb = nodes.find(e.b);
        if (na == nodes.end() || nb == nodes.end()) {
            why = "edge to a missing node";
            return false;
        }

        const auto& pa = na->second.peers;
        const auto& pb = nb->second.peers;
        if (std::find(pa.begin(), pa.end(), e.b) == pa.end() ||
                std::find(pb.begin(), pb.end(), e.a) == pb.end()) {
            why = "adjacency not symmetric";
            return false;
        }

        if (na->second.iid != e.a_iid || nb->second.iid != e.b_iid) {
            why = "edge record id differs from its node";
            return false;
        }

        if (e.linked) {
            linked++;
            if (!qualifies(e.info)) {
                why = "linked edge below the threshold";
                return false;
            }
        }
    }

    if (linked != n_linked) {
        why = "linked count drifted";
        return false;
    }

    std::array<size_t, 256> conf{};
    for (const auto& [k, e] : edges.values())
        conf[e.info.confidence]++;
    if (conf != by_confidence) {
        why = "confidence counts drifted";
        return false;
    }

    ankerl::unordered_dense::map<uint64_t, size_t> sizes;
    std::vector<node> comp;

    for (const auto& [n, s] : nodes.values()) {
        if (s.peers.empty()) {
            why = "isolated node kept";
            return false;
        }

        if (s.peers.size() > prm.max_edges_per_node) {
            why = "node over the per-record cap";
            return false;
        }

        for (const auto& p : s.peers) {
            if (std::count(s.peers.begin(), s.peers.end(), p) != 1 || edges.find(key_of(n, p)) == edges.end()) {
                why = "peer list doesn't match the edges";
                return false;
            }
        }

        component(n, nodes.size() + 1, comp);

        if (comp.size() > prm.max_component) {
            why = "component over the cap";
            return false;
        }

        if ((comp.size() == 1) != (s.entity == 0)) {
            why = "entity id on a lone record, or missing on a linked one";
            return false;
        }

        for (const auto& c : comp) {
            if (entity_of(c) != s.entity) {
                why = "one component with two entity ids";
                return false;
            }
        }

        if (s.entity != 0)
            sizes[s.entity]++;
    }

    // Two components sharing an id would show here as a size bigger than the component
    for (const auto& [n, s] : nodes.values()) {
        if (s.entity == 0)
            continue;
        component(n, nodes.size() + 1, comp);
        if (sizes[s.entity] != comp.size()) {
            why = "two components share an entity id";
            return false;
        }
    }

    if (sizes.size() != entity_sizes.size()) {
        why = "entity count drifted";
        return false;
    }

    for (const auto& [id, n] : sizes) {
        const auto si = entity_sizes.find(id);
        if (si == entity_sizes.end() || si->second != n) {
            why = "entity size drifted";
            return false;
        }
    }

    return true;
}

mac_index::mac_index(size_t in_cap, uint64_t seed) :
    cap{in_cap},
    index{0, seeded_mac_hash{seed}},
    deferred_set{0, seeded_mac_hash{seed}} { }

mac_index::add_result mac_index::insert(uint64_t mac, bool requeue) {
    if (mac_excluded(mac))
        return add_result::excluded;

    auto ii = index.find(mac);

    if (ii != index.end()) {
        if (requeue && !ii->second) {
            ii->second = true;
            queue.push_back(mac);
        }
        return add_result::present;
    }

    if (index.size() >= cap) {
        n_refused++;
        refused_pending = true;
        return add_result::full;
    }

    index.emplace(mac, true);
    queue.push_back(mac);
    return add_result::added;
}

mac_index::add_result mac_index::add(uint64_t mac) {
    return insert(mac, true);
}

mac_index::add_result mac_index::add_missing(uint64_t mac) {
    return insert(mac, false);
}

bool mac_index::touch(uint64_t mac) {
    auto ii = index.find(mac);
    if (ii == index.end())
        return false;

    if (!ii->second) {
        ii->second = true;
        queue.push_back(mac);
    }

    return true;
}

bool mac_index::contains(uint64_t mac) const {
    return index.find(mac) != index.end();
}

void mac_index::take(size_t n, std::vector<uint64_t>& out) {
    out.clear();

    while (out.size() < n && !queue.empty()) {
        const uint64_t m = queue.front();
        queue.pop_front();

        auto ii = index.find(m);
        if (ii == index.end())
            continue;

        ii->second = false;
        out.push_back(m);
    }
}

bool mac_index::erase_if_idle(uint64_t mac) {
    const auto ii = index.find(mac);
    if (ii == index.end() || ii->second)
        return false;

    index.erase(ii);

    if (deferred_set.erase(mac) != 0 && deferred_queue.size() > 2 * deferred_set.size() + 64)
        compact_deferred();

    return true;
}

bool mac_index::defer(uint64_t mac) {
    if (index.find(mac) == index.end())
        return false;

    if (!deferred_set.insert(mac).second)
        return false;

    deferred_queue.push_back(mac);
    return true;
}

size_t mac_index::requeue_deferred(size_t n) {
    size_t released = 0;

    while (released < n && !deferred_queue.empty()) {
        const uint64_t m = deferred_queue.front();
        deferred_queue.pop_front();

        // Stale: forgotten while held, or a second entry for a MAC held again since
        if (deferred_set.erase(m) == 0)
            continue;

        released++;
        touch(m);
    }

    if (deferred_queue.size() > 2 * deferred_set.size() + 64)
        compact_deferred();

    return released;
}

bool mac_index::release(uint64_t mac) {
    if (deferred_set.erase(mac) == 0)
        return false;

    if (deferred_queue.size() > 2 * deferred_set.size() + 64)
        compact_deferred();

    return true;
}

void mac_index::requeue(const std::vector<uint64_t>& macs) {
    for (const auto m : macs)
        touch(m);
}

// Drops what requeue_deferred would skip, keeping the order it releases in
void mac_index::compact_deferred() {
    ankerl::unordered_dense::set<uint64_t, seeded_mac_hash> kept{0, deferred_set.hash_function()};
    std::deque<uint64_t> q;

    for (const auto m : deferred_queue)
        if (deferred_set.contains(m) && kept.insert(m).second)
            q.push_back(m);

    deferred_queue.swap(q);
}

bool mac_index::check(std::string& why) const {
    if (index.size() > cap) {
        why = "index over its capacity";
        return false;
    }

    size_t flagged = 0;
    for (const auto& [m, q] : index.values())
        if (q)
            flagged++;

    if (flagged != queue.size()) {
        why = "queue doesn't match the queued flags";
        return false;
    }

    for (const auto m : queue) {
        const auto ii = index.find(m);
        if (ii == index.end() || !ii->second) {
            why = "queued MAC not indexed or not flagged";
            return false;
        }
    }

    for (const auto m : deferred_set.values()) {
        if (index.find(m) == index.end()) {
            why = "deferred MAC not indexed";
            return false;
        }
        if (std::find(deferred_queue.begin(), deferred_queue.end(), m) == deferred_queue.end()) {
            why = "deferred MAC missing from its queue";
            return false;
        }
    }

    if (deferred_queue.size() > 2 * deferred_set.size() + 64) {
        why = "deferred queue not compacted";
        return false;
    }

    return true;
}

}
