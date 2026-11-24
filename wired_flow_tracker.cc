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

#include "wired_flow_tracker.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <random>
#include <tuple>

namespace {

// splitmix64 finalizer
constexpr uint64_t avalanche(uint64_t h) {
    h ^= h >> 30;
    h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27;
    h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;
    return h;
}

uint64_t load64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

// What a pending slot holds for hash h; never 0, which marks an empty slot.  Bit 0 is part of
// the shard index, so it's the same for every hash in one shard and setting it loses nothing.
constexpr uint64_t pending_tag(uint64_t h) {
    return h | 1;
}

static_assert(wired_flow_tracker::n_shards % 2 == 0, "pending_tag needs bit 0 in the shard index");

uint64_t random_seed() {
    std::random_device rd;
    return (static_cast<uint64_t>(rd()) << 32) ^ rd();
}

constexpr uint8_t tcp_fin = 0x01;
constexpr uint8_t tcp_rst = 0x04;

}

wired_flow_tracker::key_hash::key_hash(uint64_t seed) {
    for (auto& k : keys) {
        seed += 0x9e3779b97f4a7c15ULL;
        k = avalanche(seed);
    }
}

uint64_t wired_flow_tracker::key_hash::operator()(const key& k) const noexcept {
    // NH (as in UMAC) over the six key words: the sum of (w0 + k0) * (w1 + k1) in 128 bits is
    // the same for two keys with chance 2^-64 unless the attacker knows the keys
    uint64_t lo = 0, hi = 0;
    const auto nh = [&lo, &hi](uint64_t a, uint64_t b) {
        ankerl::unordered_dense::detail::wyhash::mum(&a, &b);
        lo += a;
        hi += b + (lo < a);
    };

    nh(((static_cast<uint64_t>(k.family) << 56) | (static_cast<uint64_t>(k.proto) << 48) |
                (static_cast<uint64_t>(k.port_a) << 16) | k.port_b) + keys[0],
            k.vlan + keys[1]);
    nh(load64(k.addr_a.data()) + keys[2], load64(k.addr_a.data() + 8) + keys[3]);
    nh(load64(k.addr_b.data()) + keys[4], load64(k.addr_b.data() + 8) + keys[5]);

    return avalanche(lo ^ hi ^ keys[6]);
}

wired_flow_tracker::wired_flow_tracker(const params& in_p) :
    wired_flow_tracker(in_p, random_seed()) { }

wired_flow_tracker::wired_flow_tracker(const params& in_p, uint64_t hash_seed) :
    p{in_p},
    hasher{hash_seed},
    shards{std::make_unique<shard[]>(n_shards)} {

    for (size_t i = 0; i < n_shards; i++)
        shards[i].flows = decltype(shard::flows)(0, hasher);

    if (p.admit_pct > 100)
        p.admit_pct = 100;

    admit_threshold = p.max_flows / 100 * p.admit_pct + (p.max_flows % 100) * p.admit_pct / 100;
}

time_t wired_flow_tracker::idle_for(uint8_t proto, const flow_state& f) const {
    if (proto == 6)
        return f.closed ? p.tcp_closed_idle : p.tcp_idle;
    if (proto == 17)
        return p.udp_idle;
    return p.other_idle;
}

wired_flow_tracker::result wired_flow_tracker::add(const observation& o) {
    if (p.max_flows == 0 || !o.src.set() || o.src.family != o.dst.family)
        return result::ignored;

    key k;
    k.family = o.src.family;
    k.proto = o.proto;
    k.vlan = o.vlan;

    // Both directions of a flow share one key: side a is the lower (address, port)
    const bool src_is_a = o.src.a < o.dst.a || (o.src.a == o.dst.a && o.sport <= o.dport);

    if (src_is_a) {
        k.addr_a = o.src.a;
        k.addr_b = o.dst.a;
        k.port_a = o.sport;
        k.port_b = o.dport;
    } else {
        k.addr_a = o.dst.a;
        k.addr_b = o.src.a;
        k.port_a = o.dport;
        k.port_b = o.sport;
    }

    const auto h = hasher(k);
    auto& s = shards[h % n_shards];

    std::lock_guard<std::mutex> lk(s.mutex);

    auto fi = s.flows.find(k);
    bool created = false;

    if (fi == s.flows.end()) {
        auto n = n_flows.load(std::memory_order_relaxed);

        if (n >= admit_threshold && n < p.max_flows) {
            auto& slot = s.pending[(h / n_shards) % pending_slots];
            const auto tag = pending_tag(h);
            if (slot != tag) {
                slot = tag;
                n_deferred.fetch_add(1, std::memory_order_relaxed);
                return result::deferred;
            }
            slot = 0;
        }

        // Reserve the slot first; other shards add flows at the same time
        do {
            if (n >= p.max_flows) {
                n_dropped_full.fetch_add(1, std::memory_order_relaxed);
                return result::dropped;
            }
        } while (!n_flows.compare_exchange_weak(n, n + 1, std::memory_order_relaxed));

        created = true;

        flow_state f;
        f.initiator_a = src_is_a;
        f.first_time = o.ts;
        f.last_time = o.ts;
        fi = s.flows.emplace(k, f).first;
        n_created.fetch_add(1, std::memory_order_relaxed);
    }

    auto& f = fi->second;

    if (src_is_a) {
        f.bytes_ab += o.bytes;
        f.packets_ab++;
        f.flags_ab |= o.tcp_flags;
        if (o.src_mac != 0)
            f.mac_a = o.src_mac;
        if (o.dst_mac != 0)
            f.mac_b = o.dst_mac;
    } else {
        f.bytes_ba += o.bytes;
        f.packets_ba++;
        f.flags_ba |= o.tcp_flags;
        if (o.src_mac != 0)
            f.mac_b = o.src_mac;
        if (o.dst_mac != 0)
            f.mac_a = o.dst_mac;
    }

    if (k.proto == 6 && (o.tcp_flags & (tcp_fin | tcp_rst)))
        f.closed = true;

    // Packets from several sources arrive out of order
    if (o.ts < f.first_time)
        f.first_time = o.ts;
    if (o.ts > f.last_time)
        f.last_time = o.ts;
    if (o.seen > f.seen)
        f.seen = o.seen;

    return created ? result::created : result::updated;
}

size_t wired_flow_tracker::expire(time_t now) {
    size_t removed = 0;

    for (size_t i = 0; i < n_shards; i++) {
        auto& s = shards[i];
        std::lock_guard<std::mutex> lk(s.mutex);

        for (auto fi = s.flows.begin(); fi != s.flows.end(); ) {
            if (now - fi->second.seen > idle_for(fi->first.proto, fi->second)) {
                // erase moves the last entry into this slot, so don't advance
                fi = s.flows.erase(fi);
                removed++;
            } else {
                ++fi;
            }
        }
    }

    n_flows.fetch_sub(removed, std::memory_order_relaxed);
    n_expired.fetch_add(removed, std::memory_order_relaxed);
    return removed;
}

void wired_flow_tracker::snapshot(const filter& f, size_t start, size_t length,
        std::vector<flow>& out, size_t& total_matched) const {
    // Most recent packet first; ties broken by key so pages don't shift between calls
    const auto newer = [](const flow& a, const flow& b) {
        if (a.last_time != b.last_time)
            return a.last_time > b.last_time;
        return std::tie(a.k.family, a.k.addr_a, a.k.addr_b, a.k.port_a, a.k.port_b, a.k.proto, a.k.vlan) <
            std::tie(b.k.family, b.k.addr_a, b.k.addr_b, b.k.port_a, b.k.port_b, b.k.proto, b.k.vlan);
    };

    // Keep only the newest start + length matches, in a heap whose front is the oldest kept
    const size_t keep = length == 0 ? SIZE_MAX : start + length;

    out.clear();
    out.reserve(std::min({keep, n_flows.load(std::memory_order_relaxed), p.max_flows}));
    total_matched = 0;

    for (size_t i = 0; i < n_shards; i++) {
        const auto& s = shards[i];
        std::lock_guard<std::mutex> lk(s.mutex);

        for (const auto& [k, fl] : s.flows) {
            if (f.mac != 0 && fl.mac_a != f.mac && fl.mac_b != f.mac)
                continue;

            if (f.ip.set() && (f.ip.family != k.family || (f.ip.a != k.addr_a && f.ip.a != k.addr_b)))
                continue;

            if (f.vlan >= 0) {
                const auto tags = k.vlan >> 32;
                const auto outer = static_cast<int>((k.vlan >> 12) & 0xfff);
                const auto inner = static_cast<int>(k.vlan & 0xfff);
                if (tags == 0 || (outer != f.vlan && (tags < 2 || inner != f.vlan)))
                    continue;
            }

            total_matched++;

            if (out.size() == keep) {
                // Older than everything kept: not on the page
                if (fl.last_time < out.front().last_time)
                    continue;

                flow cand;
                static_cast<flow_state&>(cand) = fl;
                cand.k = k;

                if (!newer(cand, out.front()))
                    continue;

                std::pop_heap(out.begin(), out.end(), newer);
                out.back() = cand;
                std::push_heap(out.begin(), out.end(), newer);
                continue;
            }

            out.emplace_back();
            static_cast<flow_state&>(out.back()) = fl;
            out.back().k = k;
            std::push_heap(out.begin(), out.end(), newer);
        }
    }

    std::sort_heap(out.begin(), out.end(), newer);

    if (start >= out.size()) {
        out.clear();
        return;
    }

    out.erase(out.begin(), out.begin() + start);
}

wired_flow_tracker::stats wired_flow_tracker::get_stats() const {
    stats st;
    st.flows = n_flows.load(std::memory_order_relaxed);
    st.created = n_created.load(std::memory_order_relaxed);
    st.expired = n_expired.load(std::memory_order_relaxed);
    st.dropped_full = n_dropped_full.load(std::memory_order_relaxed);
    st.deferred = n_deferred.load(std::memory_order_relaxed);
    return st;
}
