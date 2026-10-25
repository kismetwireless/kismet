// SPDX-License-Identifier: GPL-2.0-or-later
// LTE serving-cell config cache from 0xB197 -- learns each cell's config and
// attaches it to later LTE observations.
//
// 0xB197 (LTE ML1 Serving Cell Information) carries the cell's DL bandwidth (RB
// count) and Tx antenna port count. Both are per-cell CONFIGURATION constants,
// so a cached value is attached to later LTE observations of the same cell --
// the cache is keyed ("lte_cfg", pci, earfcn & 0xFFFF).
//
// It is STATEFUL in two places, and both are part of the output contract:
//   * learn() caches first-wins per field, and only fields the parser bound.
//   * attach() records every full EARFCN seen under a truncated key, and once two
//     DIFFERENT full EARFCNs have shared one, the config is attached to neither
//     (0xB197 truncates its EARFCN to 16 bits, so B66 66786 and B3 1250
//     alias). attach() therefore MUTATES the state, and must be called on every
//     LTE observation in emit order, not only on the ones that render.
#ifndef DIAGSPEC_LTE_CELL_CONFIG_H
#define DIAGSPEC_LTE_CELL_CONFIG_H

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>

namespace lte_cell_config {

struct Config {
    bool has_bandwidth_rb = false;
    int bandwidth_rb = 0;          // RB count: one of 6/15/25/50/75/100
    bool has_tx_antennas = false;
    int tx_antennas = 0;           // CRS antenna ports: 1/2/4
};

struct State {
    // ("lte_cfg", pci, low16) -> config, first write wins per field.
    std::map<std::pair<int32_t, uint32_t>, Config> cfg;
    // ("lte_cfg_full", pci, low16) -> every full EARFCN attach() saw under it.
    std::map<std::pair<int32_t, uint32_t>, std::set<int64_t>> seen;
};

// Why learn() returned what it did. kRefused is exactly a record the
// parser refuses: the census counts it DROPPED. kNone is a
// completed parse, whatever its row count, and is counted decoded. The out-param
// is additive: `observations(payload)` behaves byte-for-byte as before.
enum class Decline {
    kNone = 0,
    kRefused,
};
bool is_refusal(Decline d);

// One 0xB197 payload -> the cache (parse, then cache the cell's config).
// Returns true when the record was a decodable 0xB197 with a nonzero EARFCN.
// A false return is a refusal only when *why == kRefused: an EARFCN-0 record
// parses and is skipped, which the census counts decoded.
bool learn(State& state, const std::string& payload, Decline* why = nullptr);

// Attach the cached config to one LTE observation. Returns the config to render;
// an empty Config (no has_*) means "attach nothing".
Config attach(State& state, int32_t pci, int64_t earfcn);

// RB count -> the integer-MHz `bandwidth`, or 0 when the RB count has none
// (6 RB is 1.4 MHz, which the integer key cannot carry -- bandwidth_rb only).
int rb_to_mhz(int rb);

}  // namespace lte_cell_config

#endif  // DIAGSPEC_LTE_CELL_CONFIG_H
