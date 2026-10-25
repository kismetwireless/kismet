// SPDX-License-Identifier: GPL-2.0-or-later
// LTE serving-cell config cache from 0xB197 -- see lte_cell_config.h.

#include "lte_cell_config.h"

namespace lte_cell_config {

namespace {

void note(Decline* why, Decline d) {
    if (why != nullptr)
        *why = d;
}

// parse_0xb197's per-version layouts: v0x02 is 36 B with a u32 EARFCN @4 and
// pci @8; the MDM9625 v0x01 is 32 B with a u16 EARFCN @4, pci @6 and every
// later field 4 B earlier. Any other (version, size) is rejected.
struct Layout {
    unsigned version;
    size_t size;
    size_t earfcn_width;
    size_t pci_off;
    size_t ports_off;
};
const Layout kLayouts[] = {
    {0x01, 32, 2, 6, 30},
    {0x02, 36, 4, 8, 34},
};
const uint32_t kLow16 = 0xFFFF;

unsigned byte_at(const std::string& s, size_t off) {
    return static_cast<unsigned char>(s[off]);
}

bool valid_rb(unsigned rb) {
    return rb == 6 || rb == 15 || rb == 25 || rb == 50 || rb == 75 || rb == 100;
}

bool valid_ports(unsigned n) {
    return n == 1 || n == 2 || n == 4;   // 3 is the no-measurement sentinel
}

}  // namespace

bool learn(State& state, const std::string& payload, Decline* why) {
    note(why, Decline::kNone);
    if (payload.empty()) {
        note(why, Decline::kRefused);    // parse_0xb197 -> None
        return false;
    }
    const Layout* lay = nullptr;
    for (const Layout& l : kLayouts)
        if (byte_at(payload, 0) == l.version && payload.size() == l.size)
            lay = &l;
    if (lay == nullptr) {
        note(why, Decline::kRefused);    // unknown version or size -> None
        return false;
    }

    const unsigned bw = byte_at(payload, 1);
    uint32_t earfcn = 0;
    for (size_t i = 0; i < lay->earfcn_width; ++i)
        earfcn |= static_cast<uint32_t>(byte_at(payload, 4 + i)) << (8 * i);
    const int32_t pci = static_cast<int32_t>(
        (byte_at(payload, lay->pci_off) | (byte_at(payload, lay->pci_off + 1) << 8)) & 0x1FF);
    const unsigned ports = byte_at(payload, lay->ports_off);

    // earfcn == 0 has no groundable cell identity (the 0xB17F rule): skipped
    // BEFORE the entry is created (no cache entry for it at all).
    if (earfcn == 0)
        return false;

    // setdefault: the entry exists from here on even when neither field binds,
    // but an empty Config reads as absent in attach(), as `not cfg` does.
    Config& cfg = state.cfg[std::make_pair(pci, earfcn & kLow16)];
    if (valid_rb(bw) && !cfg.has_bandwidth_rb) {
        cfg.has_bandwidth_rb = true;
        cfg.bandwidth_rb = static_cast<int>(bw);
    }
    if (valid_ports(ports) && !cfg.has_tx_antennas) {
        cfg.has_tx_antennas = true;
        cfg.tx_antennas = static_cast<int>(ports);
    }
    return true;
}

Config attach(State& state, int32_t pci, int64_t earfcn) {
    const std::pair<int32_t, uint32_t> key(
        pci, static_cast<uint32_t>(earfcn) & kLow16);
    auto it = state.cfg.find(key);
    if (it == state.cfg.end() ||
            (!it->second.has_bandwidth_rb && !it->second.has_tx_antennas))
        return Config();                 // `if not cfg: return` -- seen untouched

    std::set<int64_t>& seen = state.seen[key];
    seen.insert(earfcn);
    if (seen.size() > 1)
        return Config();                 // aliased: two cells share the key
    return it->second;
}

int rb_to_mhz(int rb) {
    switch (rb) {
    case 15:  return 3;
    case 25:  return 5;
    case 50:  return 10;
    case 75:  return 15;
    case 100: return 20;
    default:  return 0;
    }
}

bool is_refusal(Decline d) {
    return d == Decline::kRefused;
}

}  // namespace lte_cell_config
