/* Tests for entity_graph: the confidence table, MAC exclusions, links and entity ids, caps,
 * re-created records, the sweep and paging, the wired MAC index with its rescans and held
 * MACs, retries after a cap, and the seeded hashes.
 *
 *   make test/entity/graph_test && test/entity/graph_test
 *
 * Every test that changes the graph also runs graph::check() on it.
 */

#include "config.h"

#include <algorithm>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "entity_graph.h"

using namespace entity;

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

#define CHECK_GRAPH(g) do { \
    std::string why_; \
    if (!(g).check(why_)) { \
        fprintf(stderr, "%s:%d: graph check failed: %s\n", __FILE__, __LINE__, why_.c_str()); \
        failures++; \
    } \
} while (0)

// 6 byte MACs as mac_addr::longmac lays them out
static constexpr uint64_t mac(uint64_t m48) { return m48 << 16; }

// Wi-Fi and Ethernet records for one MAC; the phy halves differ like real device keys
static node wifi(uint64_t m) { return node{0x1111, m}; }
static node wire(uint64_t m) { return node{0x2222, m}; }

static link_info info_of(uint16_t evidence) {
    return evaluate(evidence, {}, 0);
}

static const uint16_t client_ev = ev::radio_client | ev::associated;

static void test_macs() {
    CHECK(mac_excluded(0));
    CHECK(mac_excluded(mac(0xffffffffffffULL)));
    CHECK(mac_excluded(mac(0x01005e000001ULL)));        // IPv4 multicast
    CHECK(mac_excluded(mac(0x333300000001ULL)));        // IPv6 multicast
    CHECK(mac_excluded(mac(0x00005e000101ULL)));        // VRRP IPv4
    CHECK(mac_excluded(mac(0x00005e0002ffULL)));        // VRRP IPv6
    CHECK(mac_excluded(mac(0x00000c07ac0aULL)));        // HSRP
    CHECK(!mac_excluded(mac(0x00005e005301ULL)));       // documentation range, used by tests
    CHECK(!mac_excluded(mac(0x00005e000301ULL)));
    CHECK(!mac_excluded(mac(0x020000000001ULL)));
    CHECK(!mac_excluded(mac(0x00000c07ab01ULL)));

    CHECK(mac_is_local(mac(0x020000000001ULL)));
    CHECK(mac_is_local(mac(0x060000000001ULL)));
    CHECK(!mac_is_local(mac(0x00005e005301ULL)));
}

static void test_confidence() {
    CHECK(kind_of(client_ev) == wifi_kind::client);
    CHECK(confidence_of(client_ev) == base_client);
    CHECK(confidence_of(client_ev | ev::local_mac) == base_client_local);
    CHECK(confidence_of(client_ev | ev::ip_match) == base_client + bonus_ip_match);

    // Probe-only and other management-only clients are possible links, not linked ones
    CHECK(kind_of(ev::radio_client) == wifi_kind::client_mgmt);
    CHECK(confidence_of(ev::radio_client) == base_client_mgmt);
    CHECK(confidence_of(ev::radio_client) < default_min_confidence);
    CHECK(kind_of(ev::associated) == wifi_kind::inferred);

    // ... even with the IPv4 bonus, and so is every inferred record: every combination of bits
    CHECK(confidence_of(ev::radio_client | ev::ip_match) < default_min_confidence);
    CHECK(confidence_of(ev::radio_client | ev::ip_match | ev::local_mac) == base_client_mgmt + bonus_ip_match);
    for (unsigned e = 0; e < (1u << 8); e++) {
        const auto k = kind_of(static_cast<uint16_t>(e));
        if (k == wifi_kind::client_mgmt || k == wifi_kind::inferred)
            CHECK(confidence_of(static_cast<uint16_t>(e)) < default_min_confidence);
        else
            CHECK(confidence_of(static_cast<uint16_t>(e)) >= default_min_confidence);
    }
    CHECK(params{}.min_confidence == default_min_confidence);

    CHECK(kind_of(ev::bridged_from_ds) == wifi_kind::bridged);
    CHECK(kind_of(ev::bridged_4addr) == wifi_kind::bridged);
    CHECK(confidence_of(ev::bridged_from_ds) == base_bridged);
    CHECK(confidence_of(ev::bridged_4addr | ev::bridged_from_ds | ev::local_mac) == base_bridged);
    CHECK(confidence_of(ev::bridged_from_ds | ev::ip_match) == base_bridged + bonus_ip_match);
    CHECK(relationship_of(wifi_kind::bridged) == relationship::wired_bridged);

    // A bridged link is weaker than a radio client's (the plan's first table had them inverted)
    CHECK(base_bridged < base_client);
    CHECK(base_bridged >= 60);

    CHECK(kind_of(ev::radio_ap) == wifi_kind::ap);
    CHECK(kind_of(ev::wds_radio) == wifi_kind::ap);
    CHECK(kind_of(ev::radio_ap | client_ev) == wifi_kind::ap);
    CHECK(kind_of(client_ev | ev::bridged_from_ds) == wifi_kind::client);
    CHECK(confidence_of(ev::radio_ap) == base_ap);
    CHECK(relationship_of(wifi_kind::ap) == relationship::wired_same_mac);
    CHECK(relationship_of(wifi_kind::client) == relationship::wired_same_mac);

    CHECK(kind_of(0) == wifi_kind::inferred);
    CHECK(confidence_of(0) == base_inferred);

    // Every bit at once still stays under the cap
    for (unsigned e = 0; e < (1u << 8); e++)
        CHECK(confidence_of(static_cast<uint16_t>(e)) <= max_confidence);

    // The best score is reachable, and the threshold option is clamped to it
    CHECK(ev::all == 0xff);
    CHECK(max_reachable_confidence == 90);
    CHECK(confidence_of(client_ev | ev::ip_match) == max_reachable_confidence);
    unsigned best = 0;
    for (unsigned e = 0; e < (1u << 8); e++)
        best = std::max<unsigned>(best, confidence_of(static_cast<uint16_t>(e)));
    CHECK(best == max_reachable_confidence);

    auto names = evidence_names(client_ev | ev::ip_match);
    CHECK(names.size() == 3);
    CHECK(names.size() == 3 && names[0] == "radio_client" && names[1] == "associated" && names[2] == "ip_match");
    CHECK(evidence_names(0).empty());

    std::array<uint64_t, max_via> via{mac(0x02000000aa01ULL), mac(0x02000000aa02ULL)};
    auto i = evaluate(ev::bridged_from_ds, via, 200);
    CHECK(i.n_via == max_via);
    CHECK(i.via[0] == via[0] && i.via[1] == via[1]);
    CHECK(i.rel == relationship::wired_bridged && i.kind == wifi_kind::bridged);

    CHECK(relationship_name(relationship::wired_same_mac) == "wired_same_mac");
    CHECK(relationship_name(relationship::wired_bridged) == "wired_bridged");
    CHECK(wifi_kind_name(wifi_kind::client_mgmt) == "client_mgmt");
}

// As a dot11 client's ipdata holds it: the first octet in the top byte, on any host
static uint32_t s_addr_of(std::array<uint8_t, 4> b) {
    return (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
        (static_cast<uint32_t>(b[2]) << 8) | b[3];
}

static void test_ip() {
    const std::array<uint8_t, 4> a{192, 0, 2, 10}, b{192, 0, 2, 11}, zero{0, 0, 0, 0}, bc{255, 255, 255, 255};

    CHECK(ipv4_match({s_addr_of(a)}, {b, a}));
    CHECK(ipv4_match({s_addr_of(b), s_addr_of(a)}, {a}));
    CHECK(!ipv4_match({s_addr_of(a)}, {b}));
    // Byte order matters: 10.2.0.192 isn't 192.0.2.10
    CHECK(!ipv4_match({s_addr_of({10, 2, 0, 192})}, {a}));
    // 192.0.2.10 as phy_80211 stores it, the value seen in a live record
    CHECK(ipv4_match({3221225994U}, {a}));
    CHECK(!ipv4_match({0}, {zero}));
    CHECK(!ipv4_match({s_addr_of(bc)}, {bc}));
    CHECK(!ipv4_match({}, {a}));
    CHECK(!ipv4_match({s_addr_of(a)}, {}));
}

static bool dirty_has(const std::vector<std::pair<node, uint64_t>>& d, const node& n, uint64_t iid) {
    for (const auto& [dn, di] : d)
        if (dn == n && di == iid)
            return true;
    return false;
}

static void test_link() {
    graph g(params{}, 1);
    std::vector<std::pair<node, uint64_t>> d;
    const uint64_t m = mac(0x020000000001ULL);

    CHECK(g.upsert(wifi(m), 10, wire(m), 20, m, info_of(client_ev), 100) == graph::upsert_result::added);
    CHECK_GRAPH(g);
    CHECK(g.entity_of(wifi(m)) != 0);
    CHECK(g.entity_of(wifi(m)) == g.entity_of(wire(m)));

    auto mw = g.desired(wifi(m));
    CHECK(mw.entity_id == g.entity_of(wifi(m)));
    CHECK(mw.linked.size() == 1 && mw.linked[0].first == relationship::wired_same_mac && mw.linked[0].second == wire(m));
    auto me = g.desired(wire(m));
    CHECK(me.linked.size() == 1 && me.linked[0].second == wifi(m));

    g.take_dirty(d);
    CHECK(d.size() == 2 && dirty_has(d, wifi(m), 10) && dirty_has(d, wire(m), 20));
    g.take_dirty(d);
    CHECK(d.empty());

    // The same evidence again changes nothing and dirties nothing
    CHECK(g.upsert(wifi(m), 10, wire(m), 20, m, info_of(client_ev), 200) == graph::upsert_result::unchanged);
    g.take_dirty(d);
    CHECK(d.empty());

    std::vector<edge> es;
    g.edges_of(wifi(m), es);
    CHECK(es.size() == 1 && es[0].first_time == 100 && es[0].last_time == 200 && es[0].linked);
    // last_time only moves forward
    g.upsert(wifi(m), 10, wire(m), 20, m, info_of(client_ev), 150);
    g.edges_of(wifi(m), es);
    CHECK(es.size() == 1 && es[0].last_time == 200);

    // Bridged becomes a radio client: same link, new relationship on both records
    const uint64_t m2 = mac(0x020000000002ULL);
    g.upsert(wifi(m2), 11, wire(m2), 21, m2, info_of(ev::bridged_from_ds), 100);
    CHECK(g.desired(wifi(m2)).linked.size() == 1 &&
            g.desired(wifi(m2)).linked[0].first == relationship::wired_bridged);
    g.take_dirty(d);
    CHECK(g.upsert(wifi(m2), 11, wire(m2), 21, m2, info_of(client_ev | ev::bridged_from_ds), 101) ==
            graph::upsert_result::updated);
    CHECK(g.desired(wifi(m2)).linked.size() == 1 &&
            g.desired(wifi(m2)).linked[0].first == relationship::wired_same_mac);
    g.take_dirty(d);
    CHECK(dirty_has(d, wifi(m2), 11) && dirty_has(d, wire(m2), 21));
    CHECK_GRAPH(g);

    // Two pairs, two entities
    CHECK(g.get_stats().entities == 2);
    CHECK(g.entity_of(wifi(m)) != g.entity_of(wifi(m2)));
    CHECK(g.get_stats().linked == 2);
}

static void test_threshold() {
    graph g(params{}, 2);
    std::vector<std::pair<node, uint64_t>> d;
    const uint64_t m = mac(0x020000000003ULL);

    // A probe-only client is kept as a possible link: no entity, nothing mirrored
    g.upsert(wifi(m), 1, wire(m), 2, m, info_of(ev::radio_client), 10);
    CHECK_GRAPH(g);
    CHECK(g.entity_of(wifi(m)) == 0);
    CHECK(g.desired(wifi(m)).linked.empty());
    CHECK(g.get_stats().edges == 1 && g.get_stats().linked == 0);

    // It associates: linked
    g.upsert(wifi(m), 1, wire(m), 2, m, info_of(client_ev), 11);
    CHECK(g.entity_of(wifi(m)) != 0);
    CHECK_GRAPH(g);

    // Evidence lost again: unlinked, ids cleared, both records told
    g.take_dirty(d);
    g.upsert(wifi(m), 1, wire(m), 2, m, info_of(ev::radio_client), 12);
    CHECK(g.entity_of(wifi(m)) == 0 && g.entity_of(wire(m)) == 0);
    CHECK(g.desired(wire(m)).linked.empty());
    g.take_dirty(d);
    CHECK(dirty_has(d, wifi(m), 1) && dirty_has(d, wire(m), 2));
    CHECK_GRAPH(g);

    // A conflicted edge is never linked, whatever its confidence
    auto ci = info_of(client_ev | ev::ip_match);
    ci.conflicted = true;
    g.upsert(wifi(m), 1, wire(m), 2, m, ci, 13);
    CHECK(g.entity_of(wifi(m)) == 0);
    CHECK_GRAPH(g);

    // The threshold is the parameter's
    params p;
    p.min_confidence = 85;
    graph g2(p, 3);
    g2.upsert(wifi(m), 1, wire(m), 2, m, info_of(client_ev), 10);
    CHECK(g2.entity_of(wifi(m)) == 0);
    g2.upsert(wifi(m), 1, wire(m), 2, m, info_of(client_ev | ev::ip_match), 10);
    CHECK(g2.entity_of(wifi(m)) != 0);

    // Exactly at the threshold links; one under doesn't
    for (const auto& [thr, linked] : {std::make_pair(base_ap, true), std::make_pair(uint8_t(base_ap + 1), false)}) {
        params pt;
        pt.min_confidence = thr;
        graph gt(pt, 4);
        gt.upsert(wifi(m), 1, wire(m), 2, m, info_of(ev::radio_ap), 10);
        CHECK((gt.entity_of(wifi(m)) != 0) == linked);
        CHECK_GRAPH(gt);
    }

    // A management-only client with the IPv4 bonus stays a possible link at the default
    graph g3(params{}, 5);
    g3.upsert(wifi(m), 1, wire(m), 2, m, info_of(ev::radio_client | ev::ip_match | ev::local_mac), 10);
    CHECK(g3.entity_of(wifi(m)) == 0 && g3.get_stats().linked == 0 && g3.get_stats().edges == 1);
}

static void test_quiet_updates() {
    graph g(params{}, 13);
    std::vector<std::pair<node, uint64_t>> d;
    const uint64_t m = mac(0x020000000005ULL);
    const uint64_t b1 = mac(0x02000000aa01ULL), b2 = mac(0x02000000aa02ULL), b3 = mac(0x02000000aa03ULL);

    g.upsert(wifi(m), 1, wire(m), 2, m, evaluate(client_ev, {b1, b2}, 2), 10);
    g.take_dirty(d);

    // The BSSIDs in a newer order: the same link, nothing rewritten, the new order kept
    CHECK(g.upsert(wifi(m), 1, wire(m), 2, m, evaluate(client_ev, {b2, b1}, 2), 11) == graph::upsert_result::unchanged);
    g.take_dirty(d);
    CHECK(d.empty());
    std::vector<edge> es;
    g.edges_of(wifi(m), es);
    CHECK(es.size() == 1 && es[0].info.via[0] == b2 && es[0].info.via[1] == b1);

    // A different set is an update
    CHECK(g.upsert(wifi(m), 1, wire(m), 2, m, evaluate(client_ev, {b1, b3}, 2), 12) == graph::upsert_result::updated);
    CHECK(evaluate(client_ev, {b1, b1}, 2) != evaluate(client_ev, {b1, b2}, 2));
    CHECK(evaluate(client_ev, {b1, b2}, 1) != evaluate(client_ev, {b1, b2}, 2));

    // New evidence that keeps the relationship changes nothing the records show
    g.take_dirty(d);
    CHECK(g.upsert(wifi(m), 1, wire(m), 2, m, evaluate(client_ev | ev::ip_match, {b1, b3}, 2), 13) ==
            graph::upsert_result::updated);
    g.take_dirty(d);
    CHECK(d.empty());
    CHECK_GRAPH(g);
}

static void test_recreate_and_remove() {
    graph g(params{}, 4);
    std::vector<std::pair<node, uint64_t>> d;
    const uint64_t m = mac(0x020000000004ULL);

    g.upsert(wifi(m), 1, wire(m), 2, m, info_of(client_ev), 10);
    const uint64_t first_id = g.entity_of(wifi(m));
    g.take_dirty(d);

    // The Wi-Fi record was forgotten and made again under the same key: a new record, a new edge
    CHECK(g.upsert(wifi(m), 7, wire(m), 2, m, info_of(client_ev), 20) == graph::upsert_result::added);
    CHECK(g.node_iid(wifi(m)) == 7);
    CHECK(g.entity_of(wifi(m)) != 0 && g.entity_of(wifi(m)) == g.entity_of(wire(m)));
    CHECK(g.entity_of(wifi(m)) != first_id);
    std::vector<edge> es;
    g.edges_of(wire(m), es);
    CHECK(es.size() == 1 && es[0].first_time == 20 && (es[0].a_iid == 7 || es[0].b_iid == 7));
    g.take_dirty(d);
    CHECK(dirty_has(d, wifi(m), 7) && dirty_has(d, wire(m), 2));
    CHECK_GRAPH(g);

    // The wired record goes: the Wi-Fi record is told, and nothing is left
    CHECK(g.remove_node(wire(m)) == 1);
    CHECK(!g.has_node(wire(m)) && !g.has_node(wifi(m)));
    CHECK(g.desired(wifi(m)).entity_id == 0 && g.desired(wifi(m)).linked.empty());
    g.take_dirty(d);
    CHECK(dirty_has(d, wifi(m), 7) && dirty_has(d, wire(m), 2));
    CHECK(g.get_stats().edges == 0 && g.get_stats().nodes == 0 && g.get_stats().entities == 0);
    CHECK_GRAPH(g);

    CHECK(g.remove_node(wire(m)) == 0);
    CHECK(!g.remove_edge(wifi(m), wire(m)));
    CHECK(g.upsert(wifi(m), 1, wifi(m), 1, m, info_of(client_ev), 1) == graph::upsert_result::invalid);
}

static void test_caps() {
    params p;
    p.max_edges = 3;
    p.max_edges_per_node = 2;
    p.max_component = 3;
    graph g(p, 5);

    const node a{1, 1}, b{1, 2}, c{1, 3}, dd{1, 4}, e{1, 5};
    const auto li = info_of(client_ev);

    CHECK(g.upsert(a, 1, b, 2, 0, li, 1) == graph::upsert_result::added);
    CHECK(g.upsert(b, 2, c, 3, 0, li, 1) == graph::upsert_result::added);
    CHECK(g.upsert(b, 2, dd, 4, 0, li, 1) == graph::upsert_result::refused_node_cap);
    CHECK_GRAPH(g);
    CHECK(g.entity_of(a) == g.entity_of(c) && g.entity_of(a) != 0);

    // A fourth record would put the component over its cap: kept, not linked
    CHECK(g.upsert(c, 3, dd, 4, 0, li, 1) == graph::upsert_result::added);
    std::vector<edge> es;
    g.edges_of(dd, es);
    CHECK(es.size() == 1 && !es[0].linked);
    CHECK(g.entity_of(dd) == 0);
    CHECK(g.get_stats().component_capped == 1);
    CHECK_GRAPH(g);

    CHECK(g.upsert(dd, 4, e, 5, 0, li, 1) == graph::upsert_result::refused_cap);
    CHECK(g.get_stats().refused_cap == 1 && g.get_stats().refused_node_cap == 1);

    // Room again: the capped edge links on its next update
    g.remove_edge(a, b);
    CHECK_GRAPH(g);
    g.upsert(c, 3, dd, 4, 0, li, 2);
    CHECK(g.entity_of(dd) != 0 && g.entity_of(dd) == g.entity_of(b));
    CHECK_GRAPH(g);

    params z;
    z.max_edges = 0;
    graph gz(z, 6);
    CHECK(gz.upsert(a, 1, b, 2, 0, li, 1) == graph::upsert_result::refused_cap);
}

static void test_ids() {
    graph g(params{}, 7);
    const auto li = info_of(client_ev);
    const node a{1, 1}, b{1, 2}, c{2, 1}, d{2, 2}, e{2, 3};

    g.upsert(a, 1, b, 2, 0, li, 1);
    const uint64_t x = g.entity_of(a);
    g.upsert(c, 3, d, 4, 0, li, 1);
    g.upsert(d, 4, e, 5, 0, li, 1);
    const uint64_t y = g.entity_of(c);
    CHECK(x != 0 && y != 0 && x != y);
    CHECK(g.entity_of(e) == y);

    // Merging: the larger group's id wins
    g.upsert(b, 2, c, 3, 0, li, 1);
    for (const auto& n : {a, b, c, d, e})
        CHECK(g.entity_of(n) == y);
    CHECK(g.get_stats().entities == 1);
    CHECK_GRAPH(g);

    // Splitting again: the larger part keeps it, the other gets a new one
    g.remove_edge(b, c);
    CHECK(g.entity_of(c) == y && g.entity_of(e) == y);
    CHECK(g.entity_of(a) != 0 && g.entity_of(a) != y && g.entity_of(a) != x);
    CHECK(g.entity_of(a) == g.entity_of(b));
    CHECK_GRAPH(g);

    // Equal sizes: the older id wins
    graph h(params{}, 8);
    h.upsert(a, 1, b, 2, 0, li, 1);
    h.upsert(c, 3, d, 4, 0, li, 1);
    const uint64_t older = h.entity_of(a);
    h.upsert(b, 2, c, 3, 0, li, 1);
    CHECK(h.entity_of(d) == older);

    // A record linked two ways stays in its group when one link goes
    h.upsert(a, 1, d, 4, 0, li, 1);
    h.remove_edge(b, c);
    CHECK(h.entity_of(a) == older && h.entity_of(c) == older && h.entity_of(b) == older);
    CHECK_GRAPH(h);

    // A middle record removed splits the chain
    h.remove_node(a);
    CHECK(h.entity_of(b) == 0 || !h.has_node(b));
    CHECK(h.entity_of(c) == h.entity_of(d) && h.entity_of(c) != 0);
    CHECK_GRAPH(h);
}

static void test_sweep_page() {
    graph g(params{}, 9);
    for (uint64_t i = 1; i <= 10; i++) {
        const uint64_t m = mac(0x020000000100ULL + i);
        g.upsert(wifi(m), i, wire(m), 100 + i, m,
                info_of(i <= 4 ? ev::radio_client : client_ev), 1);
    }

    std::vector<edge> out;
    std::set<uint64_t> seen;
    for (int round = 0; round < 4; round++) {
        g.sweep(3, out);
        CHECK(out.size() == 3);
        for (const auto& e : out)
            seen.insert(e.mac);
    }
    CHECK(seen.size() == 10);

    size_t total = 0;
    g.page(0, 100, 0, out, total);
    CHECK(total == 10 && out.size() == 10);
    g.page(0, 100, 60, out, total);
    CHECK(total == 6 && out.size() == 6);
    g.page(4, 100, 60, out, total);
    CHECK(total == 6 && out.size() == 2);
    g.page(2, 3, 0, out, total);
    CHECK(total == 10 && out.size() == 3);
    g.page(50, 3, 0, out, total);
    CHECK(total == 10 && out.empty());

    graph empty(params{}, 10);
    empty.sweep(5, out);
    CHECK(out.empty());
    empty.page(0, 10, 0, out, total);
    CHECK(total == 0 && out.empty());

    // Every page matches a brute-force filter of all edges, in table order
    std::vector<edge> all;
    g.sweep(g.get_stats().edges, all);
    for (uint8_t mc : {0, 50, 60, 80, 81, 96}) {
        size_t want = 0;
        for (const auto& e : all)
            if (e.info.confidence >= mc)
                want++;

        std::vector<uint64_t> paged;
        for (size_t s = 0; s < 12; s += 3) {
            g.page(s, 3, mc, out, total);
            CHECK(total == want);
            CHECK(out.size() == (s < want ? std::min<size_t>(3, want - s) : 0));
            for (const auto& e : out) {
                CHECK(e.info.confidence >= mc);
                paged.push_back(e.mac);
            }
        }
        CHECK(paged.size() == want);
        CHECK(std::set<uint64_t>(paged.begin(), paged.end()).size() == want);
    }

    // Removing edges and changing confidence keep the totals
    g.upsert(wifi(mac(0x020000000101ULL)), 1, wire(mac(0x020000000101ULL)), 101, mac(0x020000000101ULL),
            info_of(client_ev | ev::ip_match), 2);
    g.remove_edge(wifi(mac(0x020000000102ULL)), wire(mac(0x020000000102ULL)));
    g.page(0, 100, 81, out, total);
    CHECK(total == 1 && out.size() == 1);
    g.page(0, 100, 0, out, total);
    CHECK(total == 9 && out.size() == 9);
    CHECK_GRAPH(g);
}

static void test_index() {
    mac_index x(3, 11);
    std::vector<uint64_t> out;
    const uint64_t a = mac(0x020000000201ULL), b = mac(0x020000000202ULL), c = mac(0x020000000203ULL),
          d = mac(0x020000000204ULL);

    CHECK(x.add(a) == mac_index::add_result::added);
    CHECK(x.add(a) == mac_index::add_result::present);
    CHECK(x.add(mac(0x00005e000101ULL)) == mac_index::add_result::excluded);
    CHECK(x.add(0) == mac_index::add_result::excluded);
    CHECK(x.add(b) == mac_index::add_result::added);
    CHECK(x.add(c) == mac_index::add_result::added);
    CHECK(x.add(d) == mac_index::add_result::full);
    CHECK(x.refused() == 1 && x.size() == 3);

    // Queued once each, however often they're touched
    for (int i = 0; i < 100; i++)
        x.touch(a);
    CHECK(x.queued() == 3);
    CHECK(!x.touch(d));
    CHECK(x.contains(a) && !x.contains(d));

    x.take(2, out);
    CHECK(out.size() == 2 && out[0] == a && out[1] == b);
    CHECK(x.queued() == 1);

    // Taken and not queued again: can go.  Queued again before the erase: stays.
    x.touch(b);
    CHECK(!x.erase_if_idle(b));
    CHECK(x.erase_if_idle(a));
    CHECK(!x.contains(a));
    CHECK(!x.erase_if_idle(a));

    x.take(10, out);
    CHECK(out.size() == 2 && out[0] == c && out[1] == b);
    CHECK(x.queued() == 0);
    CHECK(x.add(d) == mac_index::add_result::added);

    mac_index z(0, 12);
    CHECK(z.add(a) == mac_index::add_result::full);

    std::string why;
    CHECK(x.check(why));
}

// A MAC refused while the index was full is found again by a rescan once there's room
static void test_index_rescan() {
    mac_index x(2, 14);
    std::vector<uint64_t> out;
    std::string why;
    const uint64_t a = mac(0x020000000301ULL), b = mac(0x020000000302ULL), c = mac(0x020000000303ULL);

    CHECK(!x.rescan_due());
    x.add(a);
    x.add(b);
    CHECK(x.add(c) == mac_index::add_result::full);
    // Full: nothing to rescan into yet
    CHECK(!x.rescan_due());

    x.take(10, out);
    CHECK(x.erase_if_idle(a));
    CHECK(x.rescan_due());

    // The rescan: c goes in and is queued; b, already indexed and idle, isn't queued again
    x.rescan_started();
    CHECK(!x.rescan_due());
    CHECK(x.add_missing(b) == mac_index::add_result::present);
    CHECK(x.add_missing(c) == mac_index::add_result::added);
    x.take(10, out);
    CHECK(out.size() == 1 && out[0] == c);
    CHECK(x.contains(c));

    // Refused again during the rescan: due again once there's room
    CHECK(x.add_missing(a) == mac_index::add_result::full);
    CHECK(!x.rescan_due());
    CHECK(x.erase_if_idle(b));
    CHECK(x.rescan_due());
    CHECK(x.check(why));

    // An excluded MAC never makes a rescan due
    mac_index y(1, 15);
    y.add(a);
    CHECK(y.add(mac(0x00005e000101ULL)) == mac_index::add_result::excluded);
    y.take(1, out);
    y.erase_if_idle(a);
    CHECK(!y.rescan_due());

    // A batch that read no view never finishes the walk (no phy views and no view of every
    // device), whatever else it says; one stopped by a full index is due again
    for (const bool more : {false, true})
        for (const bool full : {false, true})
            CHECK(rescan_after(false, more, full) == rescan_state::unfinished);
    CHECK(rescan_after(true, false, true) == rescan_state::unfinished);
    CHECK(rescan_after(true, true, true) == rescan_state::unfinished);
    CHECK(rescan_after(true, true, false) == rescan_state::more);
    CHECK(rescan_after(true, false, false) == rescan_state::finished);
}

static void test_index_defer() {
    mac_index x(8, 16);
    std::vector<uint64_t> out;
    std::string why;
    const uint64_t a = mac(0x020000000401ULL), b = mac(0x020000000402ULL), c = mac(0x020000000403ULL);

    for (auto m : {a, b, c})
        x.add(m);
    x.take(10, out);

    CHECK(!x.defer(mac(0x020000000499ULL)));    // not indexed
    CHECK(x.defer(a));
    CHECK(!x.defer(a));
    CHECK(x.defer(b));
    CHECK(x.deferred() == 2 && x.queued() == 0);
    CHECK(x.check(why));

    // Released oldest first, and queued for the next pass
    CHECK(x.requeue_deferred(1) == 1);
    x.take(10, out);
    CHECK(out.size() == 1 && out[0] == a);
    CHECK(x.deferred() == 1);

    // Forgotten while held: gone from the held set, and its stale entry is skipped
    CHECK(x.erase_if_idle(b));
    CHECK(x.deferred() == 0);
    CHECK(x.requeue_deferred(10) == 0);
    CHECK(x.check(why));

    // Held, forgotten, indexed and held again: released once
    x.defer(c);
    x.erase_if_idle(c);
    x.add(c);
    x.take(10, out);
    CHECK(x.defer(c));
    CHECK(x.requeue_deferred(10) == 1);
    x.take(10, out);
    CHECK(out.size() == 1 && out[0] == c);
    CHECK(x.check(why));

    // Churn of held MACs forgotten keeps the queue compacted
    mac_index y(4096, 17);
    for (uint64_t i = 0; i < 2000; i++) {
        const uint64_t m = mac(0x020000010000ULL + i);
        y.add(m);
        y.take(10, out);
        y.defer(m);
        y.erase_if_idle(m);
    }
    CHECK(y.deferred() == 0 && y.size() == 0);
    CHECK(y.check(why));
}

// The tracker's loop over a graph and index: a link refused at entity_max_edges is retried
// after an edge is removed, and made
static void test_retry_after_cap() {
    params p;
    p.max_edges = 2;
    graph g(p, 18);
    mac_index x(16, 19);
    std::vector<uint64_t> out;
    const uint64_t m[3] = {mac(0x020000000501ULL), mac(0x020000000502ULL), mac(0x020000000503ULL)};
    uint64_t seen_removals = g.removals();

    auto pass = [&]() {
        if (g.removals() != seen_removals) {
            seen_removals = g.removals();
            x.requeue_deferred(100);
        }
        x.take(100, out);
        for (const auto mm : out) {
            const auto r = g.upsert(wifi(mm), mm, wire(mm), mm + 1, mm, info_of(client_ev), 1);
            if (r == graph::upsert_result::refused_cap || r == graph::upsert_result::refused_node_cap)
                x.defer(mm);
        }
    };

    for (const auto mm : m)
        x.add(mm);
    pass();
    CHECK(g.get_stats().edges == 2 && g.get_stats().refused_cap == 1);
    CHECK(x.deferred() == 1);
    CHECK(g.entity_of(wifi(m[2])) == 0);

    // Nothing removed: passes don't retry it
    pass();
    pass();
    CHECK(g.get_stats().refused_cap == 1);

    g.remove_node(wire(m[0]));
    CHECK(g.removals() == 1);
    pass();
    CHECK(g.entity_of(wifi(m[2])) != 0 && g.get_stats().edges == 2);
    CHECK(x.deferred() == 0);
    CHECK_GRAPH(g);

    // The per-record cap the same way
    params q;
    q.max_edges_per_node = 1;
    graph h(q, 20);
    const node r{9, 9};
    CHECK(h.upsert(wifi(m[0]), 1, r, 9, 0, info_of(client_ev), 1) == graph::upsert_result::added);
    CHECK(h.upsert(wire(m[0]), 2, r, 9, 0, info_of(client_ev), 1) == graph::upsert_result::refused_node_cap);
    const auto before = h.removals();
    h.remove_edge(wifi(m[0]), r);
    CHECK(h.removals() == before + 1);
    CHECK(h.upsert(wire(m[0]), 2, r, 9, 0, info_of(client_ev), 1) == graph::upsert_result::added);
    CHECK_GRAPH(h);
}

// A held MAC read again for another reason and linked once room came is held no longer
static void test_index_release() {
    mac_index x(8, 21);
    std::vector<uint64_t> out;
    std::string why;
    const uint64_t a = mac(0x020000000601ULL), b = mac(0x020000000602ULL);

    x.add(a);
    x.add(b);
    x.take(10, out);
    CHECK(x.defer(a) && x.defer(b));
    CHECK(x.deferred() == 2);

    CHECK(x.release(a));
    CHECK(!x.release(a));
    CHECK(!x.release(mac(0x020000000699ULL)));
    CHECK(x.deferred() == 1);
    CHECK(x.check(why));

    // Its stale queue entry isn't released again; b still is
    CHECK(x.requeue_deferred(10) == 1);
    x.take(10, out);
    CHECK(out.size() == 1 && out[0] == b);
    CHECK(x.check(why));

    // Churn of releases keeps the queue compacted
    mac_index y(4096, 22);
    for (uint64_t i = 0; i < 2000; i++) {
        const uint64_t m = mac(0x020000020000ULL + i);
        y.add(m);
        y.take(10, out);
        y.defer(m);
        y.release(m);
    }
    CHECK(y.deferred() == 0 && y.size() == 2000);
    CHECK(y.check(why));
}

// A pass that fails after taking MACs and dirty records puts them back: the next pass reads
// the MACs and writes every record the failed one didn't
static void test_failed_pass() {
    graph g(params{}, 23);
    mac_index x(16, 24);
    std::vector<uint64_t> out;
    std::vector<std::pair<node, uint64_t>> dirty;
    std::string why;
    const uint64_t a = mac(0x020000000701ULL), b = mac(0x020000000702ULL);

    x.add(a);
    x.add(b);

    // The pass takes both MACs, links a, takes the dirty records, then fails before writing
    x.take(10, out);
    CHECK(out.size() == 2 && x.queued() == 0);
    g.upsert(wifi(a), 1, wire(a), 2, a, info_of(client_ev), 1);
    g.take_dirty(dirty);
    CHECK(dirty.size() == 2);

    x.requeue(out);
    g.restore_dirty(dirty);

    CHECK(x.queued() == 2);
    std::vector<uint64_t> again;
    x.take(10, again);
    CHECK(again == out);

    std::vector<std::pair<node, uint64_t>> written;
    g.take_dirty(written);
    CHECK(written.size() == 2 && dirty_has(written, wifi(a), 1) && dirty_has(written, wire(a), 2));

    // A MAC forgotten meanwhile isn't indexed again; one already queued again stays queued once
    x.touch(a);
    CHECK(x.erase_if_idle(b));
    x.requeue({a, b});
    CHECK(x.queued() == 1 && !x.contains(b));
    CHECK(x.check(why));

    // A record marked dirty again since the failed pass keeps its newer record id
    g.upsert(wifi(b), 5, wire(b), 6, b, info_of(client_ev), 1);
    g.take_dirty(dirty);
    g.upsert(wifi(b), 7, wire(b), 6, b, info_of(client_ev), 2);
    g.restore_dirty(dirty);
    g.take_dirty(written);
    CHECK(dirty_has(written, wifi(b), 7) && !dirty_has(written, wifi(b), 5));
    CHECK_GRAPH(g);
}

// Expose the hashers to test their seeding
struct graph_hashes : graph {
    using graph::seeded_node_hash;
};

struct index_hashes : mac_index {
    using mac_index::seeded_mac_hash;
};

static void test_seeded_hashes() {
    // Keys that all land in one of 1024 buckets under one seed spread out under another
    const graph_hashes::seeded_node_hash h1{0x1234}, h2{0x9876543210ULL};
    std::vector<node> colliding;
    for (uint64_t i = 0; colliding.size() < 256 && i < 50000000; i++) {
        const node n{0x1111, mac(0x020000000000ULL + i)};
        if ((h1(n) & 1023) == 0)
            colliding.push_back(n);
    }
    CHECK(colliding.size() == 256);

    std::vector<int> buckets(1024, 0);
    int worst = 0;
    for (const auto& n : colliding)
        worst = std::max(worst, ++buckets[h2(n) & 1023]);
    CHECK(worst <= 4);

    const index_hashes::seeded_mac_hash m1{1}, m2{2};
    std::vector<uint64_t> cm;
    for (uint64_t i = 0; cm.size() < 256 && i < 50000000; i++)
        if ((m1(mac(0x020000000000ULL + i)) & 1023) == 0)
            cm.push_back(mac(0x020000000000ULL + i));
    CHECK(cm.size() == 256);
    std::fill(buckets.begin(), buckets.end(), 0);
    worst = 0;
    for (auto m : cm)
        worst = std::max(worst, ++buckets[m2(m) & 1023]);
    CHECK(worst <= 4);

    // The seed reaches the hash of every key, not just a few bits of it
    CHECK(h1(node{0, 0}) != h2(node{0, 0}));
    CHECK(m1(0) != m2(0));
}

int main() {
    test_macs();
    test_confidence();
    test_ip();
    test_link();
    test_threshold();
    test_quiet_updates();
    test_recreate_and_remove();
    test_caps();
    test_ids();
    test_sweep_page();
    test_index();
    test_index_rescan();
    test_index_defer();
    test_retry_after_cap();
    test_index_release();
    test_failed_pass();
    test_seeded_hashes();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("all entity graph tests passed\n");
    return 0;
}
