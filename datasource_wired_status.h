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

#ifndef __DATASOURCE_WIRED_STATUS_H__
#define __DATASOURCE_WIRED_STATUS_H__

// The wiredstatus record kismet_cap_wired sends every few seconds.  A remote
// helper can send anything, so every key is optional and type checked, and only
// known offload names are kept.  Standalone so the tests link it without the server.

#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include "nlohmann/json.hpp"

namespace wired_status {

constexpr std::string_view json_type = "wiredstatus";

// The helper's names, the kernel's ETH_SS_FEATURES strings
constexpr std::array<std::string_view, 7> offload_names = {
    "rx-gro", "rx-gro-hw", "rx-lro", "rx-vlan-filter",
    "tx-tcp-segmentation", "tx-tcp6-segmentation", "tx-generic-segmentation",
};

struct report {
    std::optional<uint64_t> kernel_received;
    std::optional<uint64_t> kernel_drops;
    std::optional<uint64_t> if_drops;
    std::optional<uint64_t> frames;
    std::optional<uint64_t> forwarded;
    std::optional<uint32_t> sample;
    std::optional<uint32_t> snaplen;
    std::optional<uint32_t> buffer_mb;
    std::optional<bool> promisc;
    std::optional<bool> remote_excluded;
    std::optional<bool> carrier;
    // Known names only, comma separated, in offload_names order
    std::optional<std::string> offloads;
};

inline std::optional<uint64_t> get_u64(const nlohmann::json& j, const char *key) {
    auto i = j.find(key);

    if (i == j.end() || !i->is_number_unsigned())
        return std::nullopt;

    return i->get<uint64_t>();
}

inline std::optional<uint32_t> get_u32(const nlohmann::json& j, const char *key) {
    auto v = get_u64(j, key);

    if (!v || *v > std::numeric_limits<uint32_t>::max())
        return std::nullopt;

    return static_cast<uint32_t>(*v);
}

inline std::optional<bool> get_bool(const nlohmann::json& j, const char *key) {
    auto i = j.find(key);

    if (i == j.end() || !i->is_boolean())
        return std::nullopt;

    return i->get<bool>();
}

inline std::optional<std::string> get_offloads(const nlohmann::json& j) {
    auto i = j.find("offloads");

    if (i == j.end() || !i->is_array())
        return std::nullopt;

    uint32_t seen = 0;

    for (const auto& e : *i) {
        if (!e.is_string())
            continue;

        const auto& s = e.get_ref<const std::string&>();

        for (size_t n = 0; n < offload_names.size(); n++) {
            if (s == offload_names[n])
                seen |= 1U << n;
        }
    }

    std::string ret;

    for (size_t n = 0; n < offload_names.size(); n++) {
        if (!(seen & (1U << n)))
            continue;

        if (!ret.empty())
            ret += ",";

        ret += offload_names[n];
    }

    return ret;
}

// The helper's record is under 512 bytes
constexpr size_t max_json_len = 4096;

// False for anything which isn't a JSON object of a sane size
inline bool parse(std::string_view json, report& out) {
    if (json.size() > max_json_len)
        return false;

    auto j = nlohmann::json::parse(json.begin(), json.end(), nullptr, false);

    if (j.is_discarded() || !j.is_object())
        return false;

    out.kernel_received = get_u64(j, "kernel_received");
    out.kernel_drops = get_u64(j, "kernel_drops");
    out.if_drops = get_u64(j, "if_drops");
    out.frames = get_u64(j, "frames");
    out.forwarded = get_u64(j, "forwarded");
    out.sample = get_u32(j, "sample");
    out.snaplen = get_u32(j, "snaplen");
    out.buffer_mb = get_u32(j, "buffer_mb");
    out.promisc = get_bool(j, "promisc");
    out.remote_excluded = get_bool(j, "remote_excluded");
    out.carrier = get_bool(j, "carrier");
    out.offloads = get_offloads(j);

    return true;
}

// True for a name in a comma-separated list
inline bool list_has(std::string_view list, std::string_view name) {
    while (!list.empty()) {
        auto c = list.find(',');

        if (list.substr(0, c) == name)
            return true;

        if (c == std::string_view::npos)
            break;

        list.remove_prefix(c + 1);
    }

    return false;
}

// Offloads which hide traffic from the capture, not only change how it's counted.
// GRO and LRO (rx-gro-hw too) merge a TCP stream's segments: flows, devices and
// every protocol Kismet dissects stay right, only packet counts run low.  TSO and
// GSO only change what this host sends itself.  rx-vlan-filter drops frames of
// VLANs the host isn't a member of, so whole devices and flows go missing, but
// most drivers stop filtering in promiscuous mode
inline bool offload_hides_traffic(std::string_view name, bool promisc) {
    return name == "rx-vlan-filter" && !promisc;
}

// The source's standing warning for what the report shows, "" for none
inline std::string warning(const std::string& offloads, std::optional<bool> carrier, bool promisc) {
    std::string w;

    if (carrier.has_value() && !*carrier)
        w = "No link on the interface. ";

    for (const auto& n : offload_names) {
        if (offload_hides_traffic(n, promisc) && list_has(offloads, n))
            w += std::string(n) + " is on outside promiscuous mode, so frames of VLANs this host "
                "isn't a member of are dropped; turn it off with ethtool -K <interface> " +
                std::string(n) + " off. ";
    }

    while (!w.empty() && w.back() == ' ')
        w.pop_back();

    return w;
}

// True when the status may replace or clear the source's warning: there is none, or
// it's the one the status set itself (mine)
inline bool warning_is_ours(const std::string& current, const std::string& mine) {
    return current.empty() || current == mine;
}

// Whether the source's warning, now current, becomes want.  mine is the status's
// last one: want when it's taken, "" while a warning set elsewhere stands, so the
// status's shows again once that one is cleared
inline bool take_warning(const std::string& current, std::string& mine, const std::string& want) {
    if (!warning_is_ours(current, mine)) {
        mine.clear();
        return false;
    }

    mine = want;
    return current != want;
}

// The source closed or failed: whether its warning, now current, is the status's
// own and goes with it.  mine is forgotten either way; the next open's status sets
// its warning again
inline bool release_warning(const std::string& current, std::string& mine) {
    const bool ours = !mine.empty() && current == mine;

    mine.clear();
    return ours;
}

}

#endif
