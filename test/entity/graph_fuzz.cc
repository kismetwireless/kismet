/* libFuzzer harness for entity_graph: a stream of upserts, removals, re-created records,
 * sweeps and pages over ten records and a small graph.  After every step the graph's
 * invariants hold (graph::check), and writing only the dirty records' desired state, the way
 * entity_tracker does, leaves every record showing exactly what the graph says it should.
 *
 * Built without KIS_UNIT_FUZZ it runs seeded random streams instead, for the normal, asan
 * and ubsan flavors.
 */

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "entity_graph.h"

using namespace entity;

namespace {

constexpr size_t n_nodes = 10;

struct record_view {
    uint64_t entity_id = 0;
    std::vector<std::pair<relationship, node>> linked;
};

node node_of(size_t i) {
    // Two "phys", so pairs cross them like real links
    return node{i & 1 ? 0x2222u : 0x1111u, i};
}

void fail(const char *what) {
    fprintf(stderr, "graph_fuzz: %s\n", what);
    abort();
}

void sorted(std::vector<std::pair<relationship, node>>& v) {
    std::sort(v.begin(), v.end(), [](const auto& x, const auto& y) {
            return x.second != y.second ? x.second < y.second : x.first < y.first;
        });
}

void run(const uint8_t *data, size_t size) {
    params p;
    p.max_edges = 12;
    p.max_edges_per_node = 3;
    p.max_component = 4;
    p.min_confidence = 60;
    graph g(p, 0x5eed);

    std::vector<uint64_t> iid(n_nodes);
    std::vector<record_view> view(n_nodes);
    for (size_t i = 0; i < n_nodes; i++)
        iid[i] = i + 1;
    uint64_t next_iid = n_nodes + 1;
    time_t now = 0;

    std::vector<std::pair<node, uint64_t>> dirty;
    std::vector<edge> out;
    size_t n_pages = 0;

    for (size_t off = 0; off + 4 <= size; off += 4) {
        const uint8_t *r = data + off;
        const size_t x = r[1] % n_nodes;
        const size_t y = r[2] % n_nodes;
        now += r[3] & 3;

        switch (r[0] % 6) {
            case 0: {
                const auto li = evaluate(static_cast<uint16_t>(r[3]), {}, 0);
                g.upsert(node_of(x), iid[x], node_of(y), iid[y], x, li, now);
                break;
            }
            case 1:
                g.remove_edge(node_of(x), node_of(y));
                break;
            case 2:
                g.remove_node(node_of(x));
                break;
            case 3:
                // The device tracker forgot the record and made it again under the same key
                iid[x] = next_iid++;
                view[x] = record_view{};
                break;
            case 4: {
                g.sweep(r[2] % 8, out);
                if (out.size() > g.get_stats().edges)
                    fail("sweep returned more edges than exist");
                size_t total = 0;
                const size_t start = r[1] % 16, length = (r[2] % 8) + 1;
                const uint8_t mc = r[3] % 100;
                g.page(start, length, mc, out, total);
                if (total > g.get_stats().edges || out.size() > length)
                    fail("page out of bounds");
                for (const auto& e : out)
                    if (e.info.confidence < mc)
                        fail("page ignored min_confidence");

                // The same page from a brute-force filter of every edge, now and then: it's
                // the slowest step
                if (n_pages++ % 4 != 0)
                    break;
                std::vector<edge> all;
                g.sweep(g.get_stats().edges, all);
                size_t want = 0;
                for (const auto& e : all)
                    if (e.info.confidence >= mc)
                        want++;
                if (total != want)
                    fail("page total differs from the edges");
                if (out.size() != (start < want ? std::min(length, want - start) : 0))
                    fail("page length differs from the edges");
                break;
            }
            case 5:
                // A pass failed after taking the dirty records: they're written next time
                g.take_dirty(dirty);
                g.restore_dirty(dirty);
                break;
            default:
                break;
        }

        std::string why;
        if (!g.check(why))
            fail(why.c_str());

        // Write the desired state of each dirty record, only to the record it was made for
        g.take_dirty(dirty);
        for (const auto& [n, n_iid] : dirty) {
            const size_t i = n.dkey;
            if (i >= n_nodes || n != node_of(i))
                fail("dirty record outside the set");
            if (iid[i] != n_iid)
                continue;
            auto m = g.desired(n);
            view[i].entity_id = m.entity_id;
            view[i].linked = m.linked;
        }

        for (size_t i = 0; i < n_nodes; i++) {
            const node n = node_of(i);
            auto want = record_view{};
            if (g.has_node(n) && g.node_iid(n) == iid[i]) {
                auto m = g.desired(n);
                want.entity_id = m.entity_id;
                want.linked = m.linked;
            }
            auto have = view[i].linked;
            sorted(have);
            sorted(want.linked);
            if (view[i].entity_id != want.entity_id || have != want.linked)
                fail("a record shows a stale entity id or link");
        }

        const auto st = g.get_stats();
        if (st.edges > p.max_edges || st.linked > st.edges)
            fail("stats out of bounds");
    }
}

// The wired MAC index against a model: which MACs are indexed, queued and held, and in what
// order held MACs come back.  A MAC refused while full must leave a rescan due once there's
// room.
void run_index(const uint8_t *data, size_t size) {
    constexpr size_t cap = 6;
    constexpr size_t n_macs = 12;
    mac_index x(cap, 0x5eed);

    std::map<uint64_t, bool> indexed;       // MAC -> queued
    std::map<uint64_t, bool> held;
    std::deque<uint64_t> held_order;
    bool refused_since_rescan = false;
    std::vector<uint64_t> out;

    auto mac_of = [](size_t i) -> uint64_t { return (0x020000000000ULL + i) << 16; };

    // As mac_index compacts its held queue, at the same steps: the first entry of each MAC
    // still held stays, which decides the order a MAC held, let go and held again comes back
    auto compact = [&]() {
        if (held_order.size() <= 2 * held.size() + 64)
            return;
        std::deque<uint64_t> q;
        std::map<uint64_t, bool> kept;
        for (const auto h : held_order)
            if (held.count(h) && kept.emplace(h, true).second)
                q.push_back(h);
        held_order.swap(q);
    };

    for (size_t off = 0; off + 2 <= size; off += 2) {
        const uint8_t *r = data + off;
        const uint64_t m = mac_of(r[1] % n_macs);

        switch (r[0] % 8) {
            case 0:
            case 1: {
                const bool missing = r[0] % 8 == 1;
                const auto res = missing ? x.add_missing(m) : x.add(m);
                if (indexed.count(m)) {
                    if (res != mac_index::add_result::present)
                        fail("indexed MAC not present");
                    if (!missing)
                        indexed[m] = true;
                } else if (indexed.size() >= cap) {
                    if (res != mac_index::add_result::full)
                        fail("full index took a MAC");
                    refused_since_rescan = true;
                } else {
                    if (res != mac_index::add_result::added)
                        fail("index refused a MAC with room");
                    indexed[m] = true;
                }
                break;
            }
            case 2:
                if (x.touch(m) != (indexed.count(m) != 0))
                    fail("touch disagrees with the index");
                if (indexed.count(m))
                    indexed[m] = true;
                break;
            case 3:
                x.take(r[1] % 4, out);
                for (const auto t : out) {
                    if (!indexed.count(t) || !indexed[t])
                        fail("took a MAC that wasn't queued");
                    indexed[t] = false;
                }
                break;
            case 4: {
                const bool idle = indexed.count(m) && !indexed[m];
                if (x.erase_if_idle(m) != idle)
                    fail("erase_if_idle disagrees with the model");
                if (idle) {
                    indexed.erase(m);
                    if (held.erase(m) != 0)
                        compact();
                }
                break;
            }
            case 5: {
                const bool can = indexed.count(m) && !held.count(m);
                if (x.defer(m) != can)
                    fail("defer disagrees with the model");
                if (can) {
                    held[m] = true;
                    held_order.push_back(m);
                }
                break;
            }
            case 6: {
                // Oldest held first; an order entry for a MAC no longer held is skipped
                const size_t n = r[1] % 4;
                size_t want = 0;
                while (want < n && !held_order.empty()) {
                    const uint64_t h = held_order.front();
                    held_order.pop_front();
                    if (held.erase(h) == 0)
                        continue;
                    want++;
                    indexed[h] = true;
                }
                if (x.requeue_deferred(n) != want)
                    fail("requeue_deferred released the wrong count");
                compact();
                break;
            }
            case 7: {
                const bool was_held = held.erase(m) != 0;
                if (x.release(m) != was_held)
                    fail("release disagrees with the model");
                if (was_held)
                    compact();
                break;
            }
            default:
                break;
        }

        if (x.size() != indexed.size() || x.size() > cap)
            fail("index size differs from the model");
        if (x.deferred() != held.size())
            fail("held count differs from the model");

        if (refused_since_rescan && x.size() < cap) {
            if (!x.rescan_due())
                fail("a refused MAC with room left no rescan due");
            x.rescan_started();
            refused_since_rescan = false;
        }

        std::string why;
        if (!x.check(why))
            fail(why.c_str());
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    run(data, size);
    run_index(data, size);
    return 0;
}

#ifndef KIS_UNIT_FUZZ
int main(int argc, char **argv) {
    const unsigned runs = argc > 1 ? static_cast<unsigned>(atoi(argv[1])) : 20000;
    std::mt19937 rng(42);
    std::vector<uint8_t> buf;

    for (unsigned i = 0; i < runs; i++) {
        buf.resize(4 * (1 + rng() % 200));
        for (auto& b : buf)
            b = static_cast<uint8_t>(rng());
        run(buf.data(), buf.size());
        run_index(buf.data(), buf.size());
    }

    printf("graph_fuzz: %u random streams passed\n", runs);
    return 0;
}
#endif
