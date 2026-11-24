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
#include <cstddef>
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

// Pool use, in percent, at which the expiry pass takes histories back from idle flows
constexpr size_t history_release_pct = 90;

// Key text: hex digits per field
constexpr size_t family_digits = 2, proto_digits = 2, port_digits = 4, vlan_digits = 10, serial_digits = 16;
constexpr size_t fixed_digits = family_digits + proto_digits + 2 * port_digits + vlan_digits;
constexpr char key_serial_sep = '-';

static_assert(fixed_digits + 2 * 4 * 2 + 1 + serial_digits == wired_flow_tracker::key_text_len_v4);
static_assert(fixed_digits + 2 * 16 * 2 + 1 + serial_digits == wired_flow_tracker::key_text_len_v6);

// The bits vlan_key() can set: the tag count and two 12-bit IDs, all in vlan_digits
constexpr uint64_t vlan_key_mask = (0xffULL << 32) | 0xffffffULL;
static_assert(wired_flow_tracker::vlan_key(0xff, 0xfff, 0xfff) == vlan_key_mask);
static_assert(vlan_key_mask >> (vlan_digits * 4) == 0);

void put_hex(std::string& out, uint64_t v, size_t digits) {
    constexpr char hex[] = "0123456789abcdef";
    for (size_t i = digits; i > 0; i--)
        out.push_back(hex[(v >> ((i - 1) * 4)) & 0xf]);
}

// digits lowercase hex characters at pos, which moves past them; false on anything else
bool get_hex(std::string_view s, size_t& pos, size_t digits, uint64_t& out) {
    if (digits > 16 || pos > s.size() || s.size() - pos < digits)
        return false;

    uint64_t v = 0;
    for (size_t i = 0; i < digits; i++) {
        const char c = s[pos + i];
        unsigned int d;
        if (c >= '0' && c <= '9')
            d = static_cast<unsigned int>(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = static_cast<unsigned int>(c - 'a') + 10;
        else
            return false;
        v = (v << 4) | d;
    }

    pos += digits;
    out = v;
    return true;
}

bool get_addr(std::string_view s, size_t& pos, size_t len, std::array<uint8_t, 16>& out) {
    for (size_t i = 0; i < len; i++) {
        uint64_t b;
        if (!get_hex(s, pos, 2, b))
            return false;
        out[i] = static_cast<uint8_t>(b);
    }
    return true;
}

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

    p.max_histories = std::min(p.max_histories, p.max_flows);
    p.history_min_packets = std::max<uint64_t>(p.history_min_packets, 1);
    release_threshold = p.max_histories / 100 * history_release_pct +
        (p.max_histories % 100) * history_release_pct / 100;
}

wired_flow_tracker::~wired_flow_tracker() {
    shards.reset();
}

void wired_flow_tracker::history_release::operator()(flow_history* h) const noexcept {
    auto pool = h->pool;
    delete h;
    if (pool != nullptr)
        pool->fetch_sub(1, std::memory_order_relaxed);
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
        const bool evict = p.on_full == full_policy::evict;
        auto n = n_flows.load(std::memory_order_relaxed);

        // Under evict a full table still waits for the second packet, so single packets
        // can't replace anything
        if (n >= admit_threshold && (n < p.max_flows || evict)) {
            auto& slot = s.pending[(h / n_shards) % pending_slots];
            const auto tag = pending_tag(h);
            if (slot != tag) {
                slot = tag;
                s.counts.refused++;
                n_deferred.fetch_add(1, std::memory_order_relaxed);
                return result::deferred;
            }
            slot = 0;
        }

        // Reserve the slot first; other shards add flows at the same time.  With the table
        // full, an evicted flow in this shard hands over its slot and the count stays put.
        bool reserved = false;
        while (n < p.max_flows) {
            if (n_flows.compare_exchange_weak(n, n + 1, std::memory_order_relaxed)) {
                reserved = true;
                break;
            }
        }

        if (!reserved && !(evict && evict_one(s, o.seen))) {
            s.counts.refused++;
            n_dropped_full.fetch_add(1, std::memory_order_relaxed);
            return result::dropped;
        }

        created = true;
        s.counts.created++;

        flow_entry f;
        f.initiator_a = src_is_a;
        f.first_time = o.ts;
        f.last_time = o.ts;
        fi = s.flows.emplace(k, std::move(f)).first;
        fi->second.serial = n_created.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    auto& f = fi->second;

    s.counts.bytes += o.bytes;
    s.counts.packets++;

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

    if (f.history == nullptr && p.max_histories != 0 && f.packets_ab + f.packets_ba >= p.history_min_packets)
        admit_history(f, o.seen);
    if (f.history != nullptr)
        f.history->record(o.seen, src_is_a, o.bytes);

    return created ? result::created : result::updated;
}

void wired_flow_tracker::admit_history(flow_entry& f, time_t now) {
    auto n = n_histories.load(std::memory_order_relaxed);

    if (n < p.max_histories) {
        // Allocated before the slot is reserved, so a failed allocation can't leak a slot
        std::unique_ptr<flow_history, history_release> h{new flow_history(now)};

        while (n < p.max_histories) {
            if (n_histories.compare_exchange_weak(n, n + 1, std::memory_order_relaxed)) {
                h->pool = &n_histories;
                f.history = std::move(h);
                return;
            }
        }
    }

    // Counted once, on the packet that qualifies the flow; later ones only retry
    if (f.packets_ab + f.packets_ba == p.history_min_packets)
        n_histories_denied.fetch_add(1, std::memory_order_relaxed);
}

bool wired_flow_tracker::evict_one(shard& s, time_t now) {
    const auto& v = s.flows.values();
    const size_t n = v.size();

    if (n == 0)
        return false;

    const size_t n_samples = std::min(n, evict_samples);
    size_t best = n;

    for (size_t i = 0; i < n_samples; i++) {
        const size_t idx = (s.evict_cursor + i) % n;
        const auto& f = v[idx].second;

        // Negative when another thread stamped a later second; that's recent too
        if (now - f.seen < (f.closed ? p.evict_closed_idle : p.evict_idle))
            continue;

        if (best == n) {
            best = idx;
            continue;
        }

        // Closed TCP first, then flows without history, then the longest idle
        const auto& b = v[best].second;
        const bool f_hist = f.history != nullptr, b_hist = b.history != nullptr;
        if (f.closed != b.closed) {
            if (f.closed)
                best = idx;
        } else if (f_hist != b_hist) {
            if (!f_hist)
                best = idx;
        } else if (f.seen < b.seen) {
            best = idx;
        }
    }

    s.evict_cursor = (s.evict_cursor + n_samples) % n;

    if (best == n)
        return false;

    s.flows.erase(s.flows.begin() + static_cast<std::ptrdiff_t>(best));
    n_evicted.fetch_add(1, std::memory_order_relaxed);
    return true;
}

size_t wired_flow_tracker::expire(time_t now) {
    size_t removed = 0;
    uint64_t released = 0;

    for (size_t i = 0; i < n_shards; i++) {
        auto& s = shards[i];
        std::lock_guard<std::mutex> lk(s.mutex);

        for (auto fi = s.flows.begin(); fi != s.flows.end(); ) {
            auto& f = fi->second;

            if (now - f.seen > idle_for(fi->first.proto, f)) {
                // erase moves the last entry into this slot, so don't advance
                fi = s.flows.erase(fi);
                removed++;
                continue;
            }

            // Freeing one lowers n_histories, so this stops once the pool is below the mark
            if (f.history != nullptr && now - f.seen >= p.history_idle &&
                    n_histories.load(std::memory_order_relaxed) >= release_threshold) {
                f.history.reset();
                released++;
            }

            ++fi;
        }
    }

    n_flows.fetch_sub(removed, std::memory_order_relaxed);
    n_expired.fetch_add(removed, std::memory_order_relaxed);
    n_histories_released.fetch_add(released, std::memory_order_relaxed);
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
                to_flow(k, fl, cand);

                if (!newer(cand, out.front()))
                    continue;

                std::pop_heap(out.begin(), out.end(), newer);
                out.back() = cand;
                std::push_heap(out.begin(), out.end(), newer);
                continue;
            }

            out.emplace_back();
            to_flow(k, fl, out.back());
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

void wired_flow_tracker::to_flow(const key& k, const flow_entry& e, flow& out) {
    static_cast<flow_state&>(out) = e;
    out.k = k;
    out.serial = e.serial;
    out.history_time = e.history != nullptr ? e.history->start_time() : 0;
}

bool wired_flow_tracker::lookup(const key& k, uint64_t serial, time_t now, flow& out,
        flow_history* hist_out) const {
    if (p.max_flows == 0)
        return false;

    const auto& s = shards[hasher(k) % n_shards];
    bool copied = false;

    {
        std::lock_guard<std::mutex> lk(s.mutex);

        const auto fi = s.flows.find(k);
        if (fi == s.flows.end() || fi->second.serial != serial)
            return false;

        to_flow(k, fi->second, out);
        if (hist_out != nullptr && fi->second.history != nullptr) {
            *hist_out = *fi->second.history;
            copied = true;
        }
    }

    if (copied) {
        hist_out->pool = nullptr;
        hist_out->advance_to(now);
    }

    return true;
}

std::string wired_flow_tracker::format_key(const key& k, uint64_t serial) {
    const size_t addr_len = k.family == 4 ? 4 : 16;

    std::string out;
    out.reserve(addr_len == 4 ? key_text_len_v4 : key_text_len_v6);

    put_hex(out, k.family, family_digits);
    put_hex(out, k.proto, proto_digits);
    put_hex(out, k.port_a, port_digits);
    put_hex(out, k.port_b, port_digits);
    put_hex(out, k.vlan & vlan_key_mask, vlan_digits);
    for (size_t i = 0; i < addr_len; i++)
        put_hex(out, k.addr_a[i], 2);
    for (size_t i = 0; i < addr_len; i++)
        put_hex(out, k.addr_b[i], 2);
    out.push_back(key_serial_sep);
    put_hex(out, serial, serial_digits);

    return out;
}

bool wired_flow_tracker::parse_key(std::string_view text, key& k, uint64_t& serial) {
    // Length first, so nothing longer is ever read
    if (text.size() != key_text_len_v4 && text.size() != key_text_len_v6)
        return false;

    size_t pos = 0;
    uint64_t family, proto, port_a, port_b, vlan, ser;

    if (!get_hex(text, pos, family_digits, family) || !get_hex(text, pos, proto_digits, proto) ||
            !get_hex(text, pos, port_digits, port_a) || !get_hex(text, pos, port_digits, port_b) ||
            !get_hex(text, pos, vlan_digits, vlan))
        return false;

    if (!((family == 4 && text.size() == key_text_len_v4) || (family == 6 && text.size() == key_text_len_v6)))
        return false;

    if ((vlan & ~vlan_key_mask) != 0)
        return false;

    key out;
    out.family = static_cast<uint8_t>(family);
    out.proto = static_cast<uint8_t>(proto);
    out.port_a = static_cast<uint16_t>(port_a);
    out.port_b = static_cast<uint16_t>(port_b);
    out.vlan = vlan;

    const size_t addr_len = family == 4 ? 4 : 16;
    if (!get_addr(text, pos, addr_len, out.addr_a) || !get_addr(text, pos, addr_len, out.addr_b))
        return false;

    // Side a is the lower address and port, as add() keys every flow
    if (out.addr_a > out.addr_b || (out.addr_a == out.addr_b && out.port_a > out.port_b))
        return false;

    if (pos >= text.size() || text[pos] != key_serial_sep)
        return false;
    pos++;

    if (!get_hex(text, pos, serial_digits, ser) || ser == 0 || pos != text.size())
        return false;

    k = out;
    serial = ser;
    return true;
}

wired_flow_tracker::stats wired_flow_tracker::get_stats() const {
    stats st;
    st.flows = n_flows.load(std::memory_order_relaxed);
    st.created = n_created.load(std::memory_order_relaxed);
    st.expired = n_expired.load(std::memory_order_relaxed);
    st.dropped_full = n_dropped_full.load(std::memory_order_relaxed);
    st.deferred = n_deferred.load(std::memory_order_relaxed);
    st.evicted = n_evicted.load(std::memory_order_relaxed);
    st.histories = n_histories.load(std::memory_order_relaxed);
    st.histories_denied = n_histories_denied.load(std::memory_order_relaxed);
    st.histories_released = n_histories_released.load(std::memory_order_relaxed);
    return st;
}

wired_flow_tracker::totals wired_flow_tracker::get_totals() const {
    totals t;

    for (size_t i = 0; i < n_shards; i++) {
        const auto& s = shards[i];
        std::lock_guard<std::mutex> lk(s.mutex);
        t.bytes += s.counts.bytes;
        t.packets += s.counts.packets;
        t.created += s.counts.created;
        t.refused += s.counts.refused;
        t.flows += s.flows.size();
    }

    return t;
}

wired_flow_rates::feed wired_flow_rates::next(time_t now, const wired_flow_tracker::totals& t) {
    // Unsigned differences stay right across a wrap
    std::array<uint64_t, n_series> d{
        t.bytes - prev.bytes, t.packets - prev.packets, t.created - prev.created, t.refused - prev.refused,
    };
    for (auto& v : d)
        v = std::min(v, max_count);
    prev = t;

    feed f;
    f.flows = t.flows;

    const auto one = [&f, &d](time_t at) {
        f.n_samples = 1;
        f.samples[0].t = at;
        f.samples[0].v = d;
        f.gauge_time = at;
    };

    if (!started) {
        started = true;
        last = now;
        one(now);
        return f;
    }

    // Both are server seconds, far from overflowing a time_t
    const time_t gap = now - last;

    if (gap < -max_backstep_s) {
        f.restart = true;
        last = now;
        one(now);
    } else if (gap <= 0) {
        one(last);
    } else if (gap <= max_spread_s) {
        const auto n = static_cast<uint64_t>(gap);
        f.n_samples = static_cast<size_t>(gap);
        for (size_t i = 0; i < f.n_samples; i++) {
            auto& s = f.samples[i];
            s.t = last + 1 + static_cast<time_t>(i);
            for (size_t k = 0; k < n_series; k++)
                s.v[k] = d[k] / n;
        }
        // The remainder goes in the newest second, so the sum is exact
        for (size_t k = 0; k < n_series; k++)
            f.samples[f.n_samples - 1].v[k] += d[k] % n;
        f.gauge_time = now;
        last = now;
    } else {
        last = now;
        one(now);
    }

    return f;
}
