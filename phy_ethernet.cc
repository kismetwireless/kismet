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

#include "config.h"

#include <arpa/inet.h>

#include <algorithm>
#include <random>

#include "censor.h"
#include "configfile.h"
#include "kis_net_beast_httpd.h"
#include "messagebus.h"
#include "phy_ethernet.h"
#include "timetracker.h"
#include "util.h"

namespace {

// How much an address source is worth; a stronger one may replace a weaker one in a full list
constexpr uint8_t rank_data = 1;
constexpr uint8_t rank_arp = 2;
constexpr uint8_t rank_dhcp = 3;

constexpr uint64_t vlan_inv_key(uint8_t tags, uint16_t vid, uint16_t inner) {
    return (static_cast<uint64_t>(tags) << 32) | (static_cast<uint64_t>(vid) << 16) | inner;
}

mac_addr mac_of(const std::array<uint8_t, 6>& a) {
    return mac_addr(a.data(), 6);
}

std::string hex_of(std::string_view s) {
    static constexpr char hx[] = "0123456789abcdef";
    std::string r;
    r.reserve(s.length() * 2);
    for (auto c : s) {
        auto u = static_cast<unsigned char>(c);
        r.push_back(hx[u >> 4]);
        r.push_back(hx[u & 0xf]);
    }
    return r;
}

// Printable, bounded copy of a string from the wire: munge_to_printable escapes controls and
// anything not well-formed, escape_hidden what can still hide or reorder text on screen
std::string clean(std::string_view s) {
    return kis_l3::escape_hidden(munge_to_printable(s.data(), s.length()));
}

// pcap stores 32-bit seconds which libpcap sign-extends; a date past 2038 arrives negative
int64_t packet_seconds(const struct timeval& tv) {
    int64_t s = tv.tv_sec;
    if (s < 0 && s >= -(INT64_C(1) << 31))
        s += INT64_C(1) << 32;
    return s;
}

// RFC 1918, CGNAT (RFC 6598), IPv4 link-local, IPv6 ULA and link-local
bool private_ip(const kis_l3::ip_addr& a) {
    if (a.family == 4) {
        return a.a[0] == 10 || (a.a[0] == 172 && (a.a[1] & 0xf0) == 16) ||
            (a.a[0] == 192 && a.a[1] == 168) || (a.a[0] == 100 && (a.a[1] & 0xc0) == 64) ||
            (a.a[0] == 169 && a.a[1] == 254);
    }

    if (a.family == 6)
        return (a.a[0] & 0xfe) == 0xfc || (a.a[0] == 0xfe && (a.a[1] & 0xc0) == 0x80);

    return false;
}

bool in_prefix(const kis_l3::ip_addr& a, const kis_l3::ip_addr& net, uint8_t prefix) {
    if (a.family != net.family)
        return false;

    const size_t full = prefix / 8;
    for (size_t i = 0; i < full; i++)
        if (a.a[i] != net.a[i])
            return false;

    if (prefix % 8 == 0)
        return true;

    const uint8_t mask = static_cast<uint8_t>(0xff << (8 - prefix % 8));
    return (a.a[full] & mask) == (net.a[full] & mask);
}

// Prefix length of a contiguous IPv4 netmask, or -1
int mask_prefix(const kis_l3::ip_addr& m) {
    if (m.family != 4)
        return -1;

    const uint32_t v = (static_cast<uint32_t>(m.a[0]) << 24) | (m.a[1] << 16) | (m.a[2] << 8) | m.a[3];
    const uint32_t inv = ~v;
    if ((inv & (inv + 1)) != 0)
        return -1;

    int n = 0;
    for (uint32_t b = v; b & 0x80000000U; b <<= 1)
        n++;
    return n;
}

kis_l3::ip_addr masked(const kis_l3::ip_addr& a, uint8_t prefix) {
    kis_l3::ip_addr r;
    r.family = a.family;
    const size_t len = a.family == 4 ? 4 : 16;
    for (size_t i = 0; i < len; i++) {
        const int bits = std::clamp(static_cast<int>(prefix) - static_cast<int>(i) * 8, 0, 8);
        r.a[i] = a.a[i] & static_cast<uint8_t>(0xff << (8 - bits));
    }
    return r;
}

// A source address a host could really own
bool usable_ip(const kis_l3::ip_addr& a) {
    if (a.family == 4) {
        if (a.a[0] == 0 || a.a[0] >= 224 || a.a[0] == 127)
            return false;
        return true;
    }

    if (a.family == 6) {
        // unspecified, loopback, multicast
        if (a.a[0] == 0xff)
            return false;
        bool zero = true;
        for (size_t i = 0; i < 15; i++)
            if (a.a[i] != 0)
                zero = false;
        if (zero && (a.a[15] == 0 || a.a[15] == 1))
            return false;
        return true;
    }

    return false;
}

// The MAC in a modified EUI-64 interface ID, if there is one
bool eui64_mac(const kis_l3::ip_addr& a, mac_addr& out) {
    if (a.family != 6 || a.a[11] != 0xff || a.a[12] != 0xfe)
        return false;

    std::array<uint8_t, 6> m{static_cast<uint8_t>(a.a[8] ^ 0x02), a.a[9], a.a[10], a.a[13], a.a[14], a.a[15]};
    out = mac_addr(m.data(), 6);
    return true;
}

}

std::string ethernet_ip_string(const kis_l3::ip_addr& a) {
    char buf[INET6_ADDRSTRLEN];

    if (a.family == 4) {
        if (inet_ntop(AF_INET, a.a.data(), buf, sizeof(buf)) != nullptr)
            return buf;
    } else if (a.family == 6) {
        if (inet_ntop(AF_INET6, a.a.data(), buf, sizeof(buf)) != nullptr)
            return buf;
    }

    return "";
}

bool ethernet_parse_ip(const std::string& s, kis_l3::ip_addr& out) {
    out = kis_l3::ip_addr{};

    if (s.empty() || s.length() >= INET6_ADDRSTRLEN)
        return false;

    if (inet_pton(AF_INET, s.c_str(), out.a.data()) == 1) {
        out.family = 4;
        return true;
    }

    out.a = {};
    if (inet_pton(AF_INET6, s.c_str(), out.a.data()) == 1) {
        out.family = 6;
        return true;
    }

    out.a = {};
    return false;
}

kis_ethernet_phy::kis_ethernet_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("IEEE802.3");

    packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

    type_device = devicetracker->get_cached_display_type("Ethernet Device", "Ethernet");
    type_router = devicetracker->get_cached_display_type("Ethernet Router", "Ethernet");
    type_server = devicetracker->get_cached_display_type("Ethernet Server", "Ethernet");

    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_decap = packetchain->register_packet_component("DECAP");
    pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");
    pack_comp_ethernet = packetchain->register_packet_component("ETHERNET");

    ethernet_device_id =
        entrytracker->register_field("ethernet.device",
                tracker_element_factory<ethernet_tracked_device>(), "Ethernet device");
    vlan_entry_id =
        entrytracker->register_field("ethernet.device.vlan",
                tracker_element_factory<ethernet_tracked_vlan>(), "VLAN a device sent on");
    ip_entry_id =
        entrytracker->register_field("ethernet.device.ip",
                tracker_element_factory<ethernet_tracked_ip>(), "address of a device");
    name_entry_id =
        entrytracker->register_field("ethernet.device.name",
                tracker_element_factory<ethernet_tracked_name>(), "name of a device");

    auto conf = Globalreg::globalreg->kismet_config;

    max_devices = conf->fetch_opt_uint("wired_max_devices", 16384);
    new_device_rate = conf->fetch_opt_uint("wired_new_device_rate", 200);
    learn_remote_ips = conf->fetch_opt_bool("wired_learn_remote_ips", false);

    std::random_device rd;
    const auto random_seed = [&rd]() { return (static_cast<uint64_t>(rd()) << 32) ^ rd(); };
    refused_seed = random_seed();
    ip_table = decltype(ip_table)(0, kis_l3::ip_addr_hash{random_seed()});
    vlan_inventory = decltype(vlan_inventory)(0, kis_l3::seeded_u64_hash{random_seed()});

    wired_flow_tracker::params fp;
    fp.max_flows = conf->fetch_opt_uint("wired_max_flows", 16384);
    fp.tcp_idle = std::clamp(conf->fetch_opt_uint("wired_flow_tcp_timeout", 300), 1U, 86400U);
    fp.tcp_closed_idle = std::clamp(conf->fetch_opt_uint("wired_flow_tcp_closed_timeout", 10), 1U, 86400U);
    fp.udp_idle = std::clamp(conf->fetch_opt_uint("wired_flow_udp_timeout", 60), 1U, 86400U);
    fp.other_idle = fp.udp_idle;

    const auto on_full = str_lower(conf->fetch_opt_dfl("wired_flow_full", "evict"));
    if (on_full == "drop")
        fp.on_full = wired_flow_tracker::full_policy::drop;
    else if (on_full != "evict")
        _MSG_ERROR("wired_flow_full must be evict or drop; using evict");

    if (fp.max_flows > 1048576) {
        _MSG_ERROR("wired_max_flows={} is too large; using 1048576", fp.max_flows);
        fp.max_flows = 1048576;
    }

    // Each history is about 3.2 KB; more than wired_max_flows is never used
    constexpr unsigned int max_flow_histories = 65536;
    fp.max_histories = conf->fetch_opt_uint("wired_flow_history_max", 4096);
    if (fp.max_histories > max_flow_histories) {
        _MSG_ERROR("wired_flow_history_max={} is too large; using {}", fp.max_histories, max_flow_histories);
        fp.max_histories = max_flow_histories;
    }
    fp.max_histories = std::min(fp.max_histories, fp.max_flows);

    const auto hist_min = conf->fetch_opt_uint("wired_flow_history_min_packets", 8);
    fp.history_min_packets = std::clamp(hist_min, 1U, 1000000U);
    if (fp.history_min_packets != hist_min)
        _MSG_ERROR("wired_flow_history_min_packets must be 1 to 1000000; using {}", fp.history_min_packets);

    const auto hist_idle = conf->fetch_opt_uint("wired_flow_history_idle", 60);
    fp.history_idle = std::clamp(hist_idle, 10U, 86400U);
    if (fp.history_idle != static_cast<time_t>(hist_idle))
        _MSG_ERROR("wired_flow_history_idle must be 10 to 86400; using {}", fp.history_idle);

    if (fp.max_flows != 0)
        flows = std::make_unique<wired_flow_tracker>(fp);

    packetchain->register_handler(&dissector, this, CHAINPOS_LLCDISSECT, -50);
    packetchain->register_handler(&common_classifier, this, CHAINPOS_CLASSIFIER, -50);

    auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();
    expire_timer_id =
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, nullptr, 1, [this](int) -> int {
                const time_t now = Globalreg::globalreg->last_tv_sec;
                if (flows != nullptr)
                    flows->expire(now);
                prune_ip_table(now);
                prune_services(now);
                return 1;
            });

    auto reg_u64 = [this](const char *name, const char *desc) {
        return entrytracker->register_field(name, tracker_element_factory<tracker_element_uint64>(), desc);
    };
    auto reg_str = [this](const char *name, const char *desc) {
        return entrytracker->register_field(name, tracker_element_factory<tracker_element_string>(), desc);
    };

    flow_fields[0] = reg_u64("ethernet.flow.family", "address family, 4 or 6");
    flow_fields[1] = reg_u64("ethernet.flow.proto", "IP protocol");
    flow_fields[2] = reg_str("ethernet.flow.addr_a", "address of side a");
    flow_fields[3] = reg_u64("ethernet.flow.port_a", "port of side a");
    flow_fields[4] = reg_str("ethernet.flow.addr_b", "address of side b");
    flow_fields[5] = reg_u64("ethernet.flow.port_b", "port of side b");
    flow_fields[6] = entrytracker->register_field("ethernet.flow.mac_a",
            tracker_element_factory<tracker_element_mac_addr>(), "last MAC seen for side a");
    flow_fields[7] = entrytracker->register_field("ethernet.flow.mac_b",
            tracker_element_factory<tracker_element_mac_addr>(), "last MAC seen for side b");
    flow_fields[8] = reg_u64("ethernet.flow.vlan_tags", "VLAN tags, 0 untagged");
    flow_fields[9] = reg_u64("ethernet.flow.vid", "outer VLAN ID");
    flow_fields[10] = reg_u64("ethernet.flow.inner_vid", "second VLAN ID");
    flow_fields[11] = reg_str("ethernet.flow.initiator", "side which sent the first packet seen, a or b");
    flow_fields[12] = reg_u64("ethernet.flow.bytes_ab", "bytes from a to b");
    flow_fields[13] = reg_u64("ethernet.flow.bytes_ba", "bytes from b to a");
    flow_fields[14] = reg_u64("ethernet.flow.packets_ab", "packets from a to b");
    flow_fields[15] = reg_u64("ethernet.flow.packets_ba", "packets from b to a");
    flow_fields[16] = reg_u64("ethernet.flow.first_time", "first packet time");
    flow_fields[17] = reg_u64("ethernet.flow.last_time", "last packet time");
    flow_fields[18] = reg_u64("ethernet.flow.tcp_flags_ab", "TCP flags seen from a, ORed");
    flow_fields[19] = reg_u64("ethernet.flow.tcp_flags_ba", "TCP flags seen from b, ORed");
    flow_fields[20] = reg_u64("ethernet.flows.total", "flows matching the request");
    flow_fields[21] = reg_u64("ethernet.flows.start", "index of the first flow returned");
    flow_fields[22] = entrytracker->register_field("ethernet.flows.flows",
            tracker_element_factory<tracker_element_vector>(), "flows, most recently seen first");
    flow_fields[23] = reg_str("ethernet.flow.key", "flow id for /phy/ethernet/flows/by-key/");
    flow_fields[24] = reg_u64("ethernet.flow.id", "serial number of the flow, never reused while the server runs");
    flow_fields[25] = reg_u64("ethernet.flow.history_time", "server time the traffic history began, 0 for none");

    // In flow_history::series order
    const char *rrd_names[][2] = {
        { "ethernet.flow.bytes_ab.rrd", "bytes from a to b, history" },
        { "ethernet.flow.bytes_ba.rrd", "bytes from b to a, history" },
        { "ethernet.flow.packets_ab.rrd", "packets from a to b, history" },
        { "ethernet.flow.packets_ba.rrd", "packets from b to a, history" },
    };
    static_assert(sizeof(rrd_names) / sizeof(rrd_names[0]) == flow_history::n_series);
    static_assert(flow_rrd_field + flow_history::n_series == sizeof(flow_fields) / sizeof(flow_fields[0]));
    for (size_t i = 0; i < flow_history::n_series; i++)
        flow_fields[flow_rrd_field + i] = entrytracker->register_field(rrd_names[i][0],
                tracker_element_factory<tracker_element_map>(), rrd_names[i][1]);

    // In wired_flow_rates::series order
    const char *rate_names[][2] = {
        { "ethernet.flows.bytes.rrd", "bytes in flows per second, history" },
        { "ethernet.flows.packets.rrd", "packets in flows per second, history" },
        { "ethernet.flows.created.rrd", "flows created per second, history" },
        { "ethernet.flows.refused.rrd", "new flows dropped or deferred per second, history" },
    };
    static_assert(sizeof(rate_names) / sizeof(rate_names[0]) == wired_flow_rates::n_series);
    for (size_t i = 0; i < wired_flow_rates::n_series; i++)
        rate_fields[i] = entrytracker->register_field(rate_names[i][0],
                tracker_element_factory<kis_tracked_rrd<>>(), rate_names[i][1]);
    rate_fields[wired_flow_rates::n_series] = entrytracker->register_field("ethernet.flows.active.rrd",
            tracker_element_factory<flow_gauge_rrd>(), "flows in the table, history");

    rate_rrds = make_rate_rrds();

    vlan_fields[0] = reg_u64("ethernet.vlan.tags", "VLAN tags, 0 untagged");
    vlan_fields[1] = reg_u64("ethernet.vlan.vid", "outer VLAN ID");
    vlan_fields[2] = reg_u64("ethernet.vlan.inner_vid", "second VLAN ID");
    vlan_fields[3] = reg_u64("ethernet.vlan.first_time", "first frame time");
    vlan_fields[4] = reg_u64("ethernet.vlan.last_time", "last frame time");
    vlan_fields[5] = reg_u64("ethernet.vlan.packets", "frames");
    vlan_fields[6] = reg_u64("ethernet.vlan.bytes", "bytes, as on the wire");
    vlan_fields[7] = reg_u64("ethernet.vlan.devices", "devices that sent on the VLAN");

    status_fields[0] = reg_u64("ethernet.status.frames", "Ethernet frames processed");
    status_fields[1] = reg_u64("ethernet.status.malformed", "malformed frames");
    status_fields[2] = reg_u64("ethernet.status.devices", "Ethernet devices tracked");
    status_fields[3] = reg_u64("ethernet.status.max_devices", "wired_max_devices, 0 for no limit");
    status_fields[4] = reg_u64("ethernet.status.devices_capped",
            "new source MACs not tracked because wired_max_devices was reached");
    status_fields[5] = reg_u64("ethernet.status.new_device_rate", "wired_new_device_rate, 0 for no limit");
    status_fields[6] = reg_u64("ethernet.status.devices_rate_limited",
            "new source MACs not tracked because of wired_new_device_rate");
    status_fields[7] = reg_u64("ethernet.status.flows", "flows tracked");
    status_fields[8] = reg_u64("ethernet.status.max_flows", "wired_max_flows, 0 when flows are off");
    status_fields[9] = reg_u64("ethernet.status.flows_created", "flows created");
    status_fields[10] = reg_u64("ethernet.status.flows_expired", "flows expired");
    status_fields[11] = reg_u64("ethernet.status.flows_dropped",
            "new flows dropped with the table full and no idle flow to replace");
    status_fields[12] = reg_u64("ethernet.status.flows_deferred",
            "new flows held for a second packet with the table nearly full");
    status_fields[13] = reg_u64("ethernet.status.ip_bindings", "IP to MAC bindings");
    status_fields[14] = reg_u64("ethernet.status.ip_bindings_dropped", "bindings dropped with the table full");
    status_fields[15] = reg_u64("ethernet.status.vlans_dropped",
            "VLANs not added to the inventory because it was full");
    status_fields[16] = reg_u64("ethernet.status.devices_evicted",
            "devices which sent only a frame or two, forgotten at wired_max_devices to make room "
            "for a new source MAC which kept sending");
    status_fields[17] = reg_u64("ethernet.status.future_timestamps",
            "frames dated more than a minute past the server clock");
    status_fields[18] = reg_u64("ethernet.status.flows_evicted",
            "idle flows forgotten with the table full to make room for a new flow");
    status_fields[19] = reg_u64("ethernet.status.flow_histories", "flows keeping a traffic history");
    status_fields[20] = reg_u64("ethernet.status.max_flow_histories",
            "wired_flow_history_max, 0 when flow history is off");
    status_fields[21] = reg_u64("ethernet.status.flow_history_min_packets",
            "packets a flow needs before it gets a traffic history");
    status_fields[22] = reg_u64("ethernet.status.flow_histories_denied",
            "flows which qualified for a traffic history while all were in use");
    status_fields[23] = reg_u64("ethernet.status.flow_histories_released",
            "traffic histories taken back from idle flows with nearly all in use");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/phy/ethernet/flows/flows", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return flows_endpoint(con);
                }));

    httpd->register_route("/phy/ethernet/flows/by-key/:key/flow", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return flow_by_key_endpoint(con);
                }));

    httpd->register_route("/phy/ethernet/flows/history", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection>) {
                    return flow_history_endpoint();
                }));

    httpd->register_route("/phy/ethernet/vlans/vlans", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection>) {
                    return vlans_endpoint();
                }));

    httpd->register_route("/phy/ethernet/by-ip/:ip/devices", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return by_ip_endpoint(con);
                }));

    httpd->register_route("/phy/ethernet/status/status", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection>) {
                    return status_endpoint();
                }));

    if (flows != nullptr)
        rates_timer_id = timetracker->register_timer(SERVER_TIMESLICES_SEC, nullptr, 1, [this](int) -> int {
                sample_flow_rates();
                return 1;
            });

    _MSG_INFO("Tracking Ethernet devices from DLT_EN10MB and Linux cooked captures (at most {} devices, "
            "{} new per second, {} flows{})", max_devices, new_device_rate, fp.max_flows,
            learn_remote_ips ? ", listing remote addresses" : "");
}

kis_ethernet_phy::~kis_ethernet_phy() {
    // remove_timer waits out a running callback, so neither timer outlives the flows or RRDs
    auto timetracker = Globalreg::fetch_global_as<time_tracker>();
    if (timetracker != nullptr && rates_timer_id >= 0)
        timetracker->remove_timer(rates_timer_id);
    if (timetracker != nullptr && expire_timer_id >= 0)
        timetracker->remove_timer(expire_timer_id);

    packetchain->remove_handler(&common_classifier, CHAINPOS_CLASSIFIER);
    packetchain->remove_handler(&dissector, CHAINPOS_LLCDISSECT);
}

bool kis_ethernet_phy::device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) {
    return dev->get_sub_as<ethernet_tracked_device>(ethernet_device_id) != nullptr;
}

void kis_ethernet_phy::load_phy_storage(shared_tracker_element in_storage,
        shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);
    auto ei = storage->find(ethernet_device_id);

    if (ei != storage->end() && ei->second != nullptr &&
            ei->second->get_type() == tracker_type::tracker_map) {
        auto ed = std::make_shared<ethernet_tracked_device>(ethernet_device_id,
                std::static_pointer_cast<tracker_element_map>(ei->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(ed);
    }
}

uint64_t kis_ethernet_phy::refused_hash(uint64_t mac) const {
    // splitmix64 over the seeded MAC
    uint64_t h = mac + refused_seed;
    h ^= h >> 30;
    h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27;
    h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;
    return h;
}

bool kis_ethernet_phy::refused_before(uint64_t mac) {
    if (refused == nullptr)
        return false;

    const auto& set = refused[refused_hash(mac) % refused_sets];
    return set[0] == mac || set[1] == mac;
}

void kis_ethernet_phy::remember_refused(uint64_t mac) {
    if (refused == nullptr)
        refused = std::make_unique<std::array<uint64_t, 2>[]>(refused_sets);

    const auto h = refused_hash(mac);
    auto& set = refused[h % refused_sets];

    if (set[0] == mac || set[1] == mac)
        return;

    // An empty way, else one picked by a hash bit the sender can't predict
    if (set[0] == 0)
        set[0] = mac;
    else if (set[1] == 0)
        set[1] = mac;
    else
        set[(h >> 63) & 1] = mac;
}

void kis_ethernet_phy::forget_refused(uint64_t mac) {
    if (refused == nullptr)
        return;

    auto& set = refused[refused_hash(mac) % refused_sets];
    for (auto& w : set)
        if (w == mac)
            w = 0;
}

bool kis_ethernet_phy::evict_one() {
    const time_t now = Globalreg::globalreg->last_tv_sec;

    if (now != evict_second) {
        evict_second = now;
        evict_count = 0;
    }

    if (evict_count >= max_evict_per_sec)
        return false;

    // Oldest first.  A device that sent more than a couple of frames is a real host and is
    // never a candidate again; one already gone is skipped.
    for (unsigned int scanned = 0; scanned < max_evict_scan && !admit_order.empty(); scanned++) {
        const auto k = admit_order.front();
        admit_order.pop_front();

        if (devicetracker->expire_device(k, [](kis_tracked_device_base& d) {
                    return d.get_packets() <= max_evict_packets;
                })) {
            evict_count++;
            n_evicted.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
    }

    return false;
}

bool kis_ethernet_phy::admit_new_device(const std::shared_ptr<kis_packet>& in_pack, const mac_addr& mac,
        bool& report_cap) {
    const bool retry = refused_before(mac.longmac);

    // Budgeted per capture second: a replay at any speed gets the same number of new devices
    // each second.  Which MACs of an over-budget second get in depends on worker order.
    if (new_device_rate != 0) {
        const int64_t sec = packet_seconds(in_pack->ts);
        const int64_t wall = Globalreg::globalreg->last_tv_sec;
        rate_slot *slot;
        int64_t key;

        if (sec > wall + max_future_skew) {
            // A forged far-future date shares one bucket per server second and moves nothing
            slot = &rate_future;
            key = wall;
        } else {
            slot = &rate_ring[static_cast<uint64_t>(sec) % rate_slots];
            key = sec;

            // A slot only moves forward to a newer second.  One already holding a newer
            // second means this second aged out of the ring, perhaps after spending its
            // budget, so it goes to the stale bucket; unless it's hours older, which is
            // another capture appended, and then the slot is reopened, a bounded number of
            // times a server second so alternating dates can't keep reopening it.
            if (slot->second > sec) {
                const auto behind = static_cast<uint64_t>(slot->second) - static_cast<uint64_t>(sec);

                if (wall != rate_reopen_wall) {
                    rate_reopen_wall = wall;
                    rate_reopens = 0;
                }

                if (behind > rate_epoch_jump && rate_reopens < max_rate_reopens) {
                    rate_reopens++;
                    slot->second = INT64_MIN;
                } else {
                    slot = &rate_stale;
                    key = wall;
                }
            }
        }

        if (slot->second != key) {
            slot->second = key;
            slot->count = 0;
            slot->retry = 0;
        }

        // A second older than the ring may already have spent its own budget there, so it
        // only gets the retry budget: no more new devices than rate times the seconds seen
        if (slot != &rate_stale && slot->count < new_device_rate) {
            slot->count++;
        } else if (retry && slot->retry < new_device_rate) {
            slot->retry++;
        } else {
            n_rate_limited.fetch_add(1, std::memory_order_relaxed);
            remember_refused(mac.longmac);
            return false;
        }
    }

    if (max_devices != 0 && devicetracker->count_phy_devices(phyid) >= max_devices) {
        // Only a MAC seen again makes room, so single-frame floods don't churn the devices
        if (!retry || !evict_one()) {
            n_capped.fetch_add(1, std::memory_order_relaxed);
            report_cap = !cap_reported.exchange(true);
            remember_refused(mac.longmac);
            return false;
        }
    }

    return true;
}

void kis_ethernet_phy::admitted(const mac_addr& mac) {
    forget_refused(mac.longmac);

    if (max_devices == 0)
        return;

    // Entries for devices that expired some other way are skipped by evict_one; this keeps
    // the queue bounded when nothing evicts
    admit_order.push_back(device_key(fetch_phyname_hash(), mac));
    while (admit_order.size() > max_devices * 2)
        admit_order.pop_front();
}

std::shared_ptr<ethernet_tracked_device>
    kis_ethernet_phy::fetch_ethernet(const std::shared_ptr<kis_tracked_device_base>& dev) {
    auto ed = dev->get_sub_as<ethernet_tracked_device>(ethernet_device_id);

    if (ed == nullptr) {
        ed = entrytracker->get_shared_instance_as<ethernet_tracked_device>(ethernet_device_id);
        dev->insert(ed);
    }

    return ed;
}

bool kis_ethernet_phy::add_vlan(ethernet_tracked_device& ed, const kis_l3::frame& f, time_t ts) {
    const uint8_t tags = f.n_tags;
    const uint16_t vid = tags > 0 ? f.tags[0].vid() : 0;
    const uint16_t inner = tags > 1 ? f.tags[1].vid() : 0;

    auto vec = ed.get_vlans();

    for (const auto& e : *vec) {
        auto v = static_cast<ethernet_tracked_vlan *>(e.get());
        if (v->matches(tags, vid, inner)) {
            v->inc_packets();
            if (ts > v->get_last_time())
                v->set_last_time(ts);
            if (ts < v->get_first_time())
                v->set_first_time(ts);
            return false;
        }
    }

    if (vec->size() >= max_vlans) {
        ed.set_list_full(ed.get_list_full() + 1);
        return false;
    }

    auto v = entrytracker->get_shared_instance_as<ethernet_tracked_vlan>(vlan_entry_id);
    v->set_tags(tags);
    v->set_vid(vid);
    v->set_inner_vid(inner);
    v->set_first_time(ts);
    v->set_last_time(ts);
    v->set_packets(1);
    vec->push_back(v);
    return true;
}

bool kis_ethernet_phy::add_ip(kis_tracked_device_base& dev, ethernet_tracked_device& ed,
        const kis_l3::ip_addr& ip, uint8_t rank, const char *source, time_t ts) {
    if (!usable_ip(ip))
        return false;

    auto vec = ip.family == 4 ? ed.get_ipv4() : ed.get_ipv6();
    const time_t minute = Globalreg::globalreg->last_tv_sec / 60;

    for (const auto& e : *vec) {
        auto a = static_cast<ethernet_tracked_ip *>(e.get());
        if (a->raw != ip)
            continue;

        if (ts > a->get_last_time())
            a->set_last_time(ts);
        if (ts < a->get_first_time())
            a->set_first_time(ts);

        if (rank > a->rank) {
            a->rank = rank;
            a->set_source(source);
        }

        // Refresh the IP table once a minute per address
        if (minute != a->table_minute) {
            a->table_minute = minute;
            return true;
        }

        return false;
    }

    size_t slot = vec->size();

    if (slot >= max_addrs) {
        // A full list keeps its first addresses, unless a stronger source names a new one;
        // then the weakest, oldest data address makes room
        slot = max_addrs;
        time_t oldest = 0;

        for (size_t i = 0; i < vec->size(); i++) {
            auto a = static_cast<ethernet_tracked_ip *>((*vec)[i].get());
            if (a->rank < rank && a->rank == rank_data && (slot == max_addrs || a->get_last_time() < oldest)) {
                slot = i;
                oldest = a->get_last_time();
            }
        }

        if (slot == max_addrs) {
            ed.set_list_full(ed.get_list_full() + 1);
            return false;
        }
    }

    auto a = entrytracker->get_shared_instance_as<ethernet_tracked_ip>(ip_entry_id);
    a->raw = ip;
    a->rank = rank;
    a->table_minute = minute;
    a->set_address(ethernet_ip_string(ip));
    a->set_source(source);
    a->set_first_time(ts);
    a->set_last_time(ts);

    mac_addr em;
    if (eui64_mac(ip, em) && em != dev.get_macaddr())
        a->set_eui64_mac(em);

    if (slot < vec->size())
        (*vec)[slot] = a;
    else
        vec->push_back(a);

    return true;
}

void kis_ethernet_phy::add_name(ethernet_tracked_device& ed, const std::string& name,
        const char *source, time_t ts) {
    if (name.empty())
        return;

    auto vec = ed.get_names();
    size_t from_source = 0;

    for (const auto& e : *vec) {
        auto n = static_cast<ethernet_tracked_name *>(e.get());

        if (n->get_source() != source)
            continue;

        if (n->get_host_name() == name) {
            if (ts > n->get_last_time())
                n->set_last_time(ts);
            if (ts < n->get_first_time())
                n->set_first_time(ts);
            return;
        }

        from_source++;
    }

    if (from_source >= max_names_per_source) {
        ed.set_list_full(ed.get_list_full() + 1);
        return;
    }

    auto n = entrytracker->get_shared_instance_as<ethernet_tracked_name>(name_entry_id);
    n->set_host_name(name);
    n->set_source(source);
    n->set_first_time(ts);
    n->set_last_time(ts);
    vec->push_back(n);
}

void kis_ethernet_phy::set_display_from_roles(kis_tracked_device_base& dev, uint32_t roles) {
    using r = ethernet_tracked_device;

    if (roles & r::role_gateway)
        dev.set_display_type(type_router);
    else if (roles & (r::role_dhcp_server | r::role_dhcpv6_server | r::role_dns_server))
        dev.set_display_type(type_server);
}

uint32_t kis_ethernet_phy::service_roles(const kis_l3::ip_addr& ip) {
    if (n_service_ips.load(std::memory_order_relaxed) == 0)
        return 0;

    kis_lock_guard<kis_mutex> lk(service_mutex, "ethernet service_roles");
    uint32_t r = 0;
    const auto is = [&ip](const service_ip& s) { return s.ip == ip; };

    if (std::any_of(gateway_ips.begin(), gateway_ips.end(), is))
        r |= ethernet_tracked_device::role_gateway;
    if (std::any_of(dns_ips.begin(), dns_ips.end(), is))
        r |= ethernet_tracked_device::role_dns_server;

    return r;
}

void kis_ethernet_phy::learn_service(std::vector<service_ip>& list, const kis_l3::ip_addr& ip, time_t now,
        std::vector<kis_l3::ip_addr>& added) {
    if (!usable_ip(ip))
        return;

    kis_lock_guard<kis_mutex> lk(service_mutex, "ethernet learn_service");

    for (auto& s : list) {
        if (s.ip == ip) {
            s.seen = now;
            return;
        }
    }

    // Spoofed DHCP replies can name any address: a full list replaces its stalest entry
    if (list.size() >= max_service_ips) {
        auto oldest = std::min_element(list.begin(), list.end(),
                [](const service_ip& a, const service_ip& b) { return a.seen < b.seen; });
        *oldest = service_ip{ip, now};
    } else {
        list.push_back(service_ip{ip, now});
        n_service_ips.fetch_add(1, std::memory_order_relaxed);
    }

    added.push_back(ip);
}

void kis_ethernet_phy::learn_subnet(const kis_l3::ip_addr& ip, uint8_t prefix, time_t now) {
    if (!usable_ip(ip))
        return;

    const auto net = masked(ip, prefix);

    kis_lock_guard<kis_mutex> lk(service_mutex, "ethernet learn_subnet");

    for (auto& s : subnets) {
        if (s.prefix == prefix && s.net == net) {
            s.seen = now;
            return;
        }
    }

    if (subnets.size() >= max_subnets) {
        auto oldest = std::min_element(subnets.begin(), subnets.end(),
                [](const subnet& a, const subnet& b) { return a.seen < b.seen; });
        *oldest = subnet{net, prefix, now};
    } else {
        subnets.push_back(subnet{net, prefix, now});
        n_subnets.fetch_add(1, std::memory_order_relaxed);
    }
}

void kis_ethernet_phy::prune_services(time_t now) {
    kis_lock_guard<kis_mutex> lk(service_mutex, "ethernet prune_services");

    const auto stale_ip = [now](const service_ip& s) { return now - s.seen > service_idle; };
    const auto stale_net = [now](const subnet& s) { return now - s.seen > service_idle; };

    gateway_ips.erase(std::remove_if(gateway_ips.begin(), gateway_ips.end(), stale_ip), gateway_ips.end());
    dns_ips.erase(std::remove_if(dns_ips.begin(), dns_ips.end(), stale_ip), dns_ips.end());
    subnets.erase(std::remove_if(subnets.begin(), subnets.end(), stale_net), subnets.end());

    n_service_ips.store(gateway_ips.size() + dns_ips.size(), std::memory_order_relaxed);
    n_subnets.store(subnets.size(), std::memory_order_relaxed);
}

bool kis_ethernet_phy::local_ip(const kis_l3::ip_addr& ip) {
    if (learn_remote_ips || private_ip(ip))
        return true;

    if (n_subnets.load(std::memory_order_relaxed) == 0)
        return false;

    kis_lock_guard<kis_mutex> lk(service_mutex, "ethernet local_ip");

    return std::any_of(subnets.begin(), subnets.end(),
            [&ip](const subnet& s) { return in_prefix(ip, s.net, s.prefix); });
}

void kis_ethernet_phy::bind_ip(const kis_l3::ip_addr& ip, const mac_addr& mac, time_t now) {
    if (!usable_ip(ip))
        return;

    kis_lock_guard<kis_mutex> lk(ip_mutex, "ethernet bind_ip");

    auto bi = ip_table.find(ip);

    if (bi == ip_table.end()) {
        if (ip_table.size() >= max_ip_table) {
            ip_table_full++;
            return;
        }

        bi = ip_table.emplace(ip, ip_binding{}).first;
    }

    auto& b = bi->second;
    size_t slot = max_macs_per_ip;

    for (size_t i = 0; i < max_macs_per_ip; i++) {
        if (b.macs[i] == mac.longmac) {
            slot = i;
            break;
        }
    }

    if (slot == max_macs_per_ip) {
        // An empty slot, or the one heard from longest ago
        slot = 0;
        for (size_t i = 0; i < max_macs_per_ip; i++) {
            if (b.macs[i] == 0) {
                slot = i;
                break;
            }
            if (b.seen[i] < b.seen[slot])
                slot = i;
        }
        b.macs[slot] = mac.longmac;
        b.seen[slot] = now;
    } else if (now > b.seen[slot]) {
        b.seen[slot] = now;
    }
}

std::vector<mac_addr> kis_ethernet_phy::lookup_ip(const kis_l3::ip_addr& ip) {
    std::vector<mac_addr> r;

    kis_lock_guard<kis_mutex> lk(ip_mutex, "ethernet lookup_ip");

    auto bi = ip_table.find(ip);
    if (bi == ip_table.end())
        return r;

    for (auto m : bi->second.macs)
        if (m != 0)
            r.push_back(mac_from_u64(m));

    return r;
}

void kis_ethernet_phy::prune_ip_table(time_t now) {
    // Bindings nobody has refreshed for an hour of server time; devices refresh theirs once a
    // minute
    constexpr time_t idle = 3600;

    kis_lock_guard<kis_mutex> lk(ip_mutex, "ethernet prune_ip_table");

    for (auto bi = ip_table.begin(); bi != ip_table.end(); ) {
        bool live = false;
        for (size_t i = 0; i < max_macs_per_ip; i++) {
            if (bi->second.macs[i] != 0 && now - bi->second.seen[i] > idle)
                bi->second.macs[i] = 0;
            if (bi->second.macs[i] != 0)
                live = true;
        }

        if (!live)
            bi = ip_table.erase(bi);
        else
            ++bi;
    }
}

void kis_ethernet_phy::count_vlan(const kis_l3::frame& f, uint64_t bytes, time_t ts, bool new_for_device) {
    const uint8_t tags = f.n_tags;
    const uint16_t vid = tags > 0 ? f.tags[0].vid() : 0;
    const uint16_t inner = tags > 1 ? f.tags[1].vid() : 0;
    const auto k = vlan_inv_key(tags, vid, inner);

    kis_lock_guard<kis_mutex> lk(vlan_mutex, "ethernet count_vlan");

    auto vi = vlan_inventory.find(k);

    if (vi == vlan_inventory.end()) {
        if (vlan_inventory.size() >= max_vlan_inventory) {
            vlan_inventory_full++;
            return;
        }

        vi = vlan_inventory.emplace(k, vlan_inv{tags, vid, inner, ts, ts, 0, 0, 0}).first;
    }

    auto& v = vi->second;
    v.packets++;
    v.bytes += bytes;
    if (ts > v.last_time)
        v.last_time = ts;
    if (ts < v.first_time)
        v.first_time = ts;
    if (new_for_device)
        v.devices++;
}

void kis_ethernet_phy::update_other(const mac_addr& mac, const std::shared_ptr<kis_packet>& in_pack,
        const std::function<void (kis_tracked_device_base&, ethernet_tracked_device&)>& fn,
        unsigned int flags) {
    kis_device_lock dlk;

    auto dev = devicetracker->update_common_device(mac, this, in_pack, flags | UCD_UPDATE_EXISTING_ONLY,
            "Ethernet Device", dlk);

    if (dev == nullptr)
        return;

    auto ed = fetch_ethernet(dev);

    if (fn != nullptr)
        fn(*dev, *ed);
}

void kis_ethernet_phy::change_other(const mac_addr& mac,
        const std::function<void (kis_tracked_device_base&, ethernet_tracked_device&)>& fn) {
    auto dev = devicetracker->fetch_device(device_key(fetch_phyname_hash(), mac));

    if (dev == nullptr)
        return;

    kis_device_lock dlk(dev, false);

    // Forgotten between the lookup and the lock
    if (dev->get_removed())
        return;

    auto ed = dev->get_sub_as<ethernet_tracked_device>(ethernet_device_id);

    if (ed == nullptr)
        return;

    fn(*dev, *ed);

    // Modified at server time, so the database and modified-since listings see it; last
    // seen stays as it was
    dev->update_modtime();
}

int kis_ethernet_phy::dissector(CHAINCALL_PARMS) {
    auto ephy = static_cast<kis_ethernet_phy *>(auxdata);

    auto chunk = in_pack->fetch<kis_datachunk>(ephy->pack_comp_decap, ephy->pack_comp_linkframe);

    if (chunk == nullptr)
        return 0;

    if (chunk->dlt != kis_l3::dlt_en10mb && chunk->dlt != kis_l3::dlt_linux_sll &&
            chunk->dlt != kis_l3::dlt_linux_sll2)
        return 0;

    // Undo libpcap's sign extension before the device times and logs use it, for every
    // frame of these link types: malformed, duplicate and filtered ones are logged too
    if (in_pack->ts.tv_sec < 0)
        in_pack->ts.tv_sec = static_cast<decltype(in_pack->ts.tv_sec)>(packet_seconds(in_pack->ts));

    if (in_pack->duplicate || in_pack->filtered)
        return 1;

    if (in_pack->common_info.common_info_ok)
        return 0;

    auto pi = ephy->packetchain->new_packet_component<ethernet_packinfo>();

    if (!kis_l3::parse_frame(chunk->dlt, reinterpret_cast<const uint8_t *>(chunk->data()),
                chunk->length(), pi->f)) {
        // A cooked frame of a non-Ethernet interface isn't an error
        if (pi->f.errors != 0)
            ephy->n_malformed.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }

    pi->parsed = true;
    in_pack->insert(ephy->pack_comp_ethernet, pi);

    const auto& f = pi->f;

    in_pack->common_info.common_info_ok = true;
    in_pack->common_info.phyid = ephy->fetch_phy_id();
    in_pack->common_info.type =
        (f.l3 == kis_l3::l3_type::ipv4 || f.l3 == kis_l3::l3_type::ipv6) ? packet_basic_data : packet_basic_mgmt;
    in_pack->common_info.source = mac_of(f.src);
    in_pack->common_info.transmitter = in_pack->common_info.source;
    if (f.has_dst)
        in_pack->common_info.dest = mac_of(f.dst);
    in_pack->common_info.datasize = in_pack->original_len > chunk->length() ?
        in_pack->original_len : chunk->length();
    in_pack->common_info.error = f.errors != 0;

    return 1;
}

int kis_ethernet_phy::common_classifier(CHAINCALL_PARMS) {
    auto ephy = static_cast<kis_ethernet_phy *>(auxdata);

    if (in_pack->filtered)
        return 1;

    // Another source heard the same frame; the original made or updated the devices, this
    // only adds that this source saw the sender too
    if (in_pack->duplicate) {
        if (in_pack->original == nullptr)
            return 1;

        auto opi = in_pack->original->fetch<ethernet_packinfo>(ephy->pack_comp_ethernet);
        if (opi == nullptr || !opi->parsed)
            return 1;

        in_pack->common_info = in_pack->original->common_info;
        ephy->devicetracker->update_common_device(mac_of(opi->f.src), ephy, in_pack,
                UCD_UPDATE_SEENBY | UCD_UPDATE_EXISTING_ONLY, "Ethernet Device");
        return 1;
    }

    auto pi = in_pack->fetch<ethernet_packinfo>(ephy->pack_comp_ethernet);
    if (pi == nullptr || !pi->parsed)
        return 0;

    const auto& f = pi->f;
    // Packet time is only shown; anything that expires runs on server time
    const time_t ts = in_pack->ts.tv_sec;
    const time_t now = Globalreg::globalreg->last_tv_sec;
    const uint64_t wire_len = in_pack->common_info.datasize;

    ephy->n_frames.fetch_add(1, std::memory_order_relaxed);
    if (f.errors != 0)
        ephy->n_malformed.fetch_add(1, std::memory_order_relaxed);
    if (ts > now + max_future_skew)
        ephy->n_future.fetch_add(1, std::memory_order_relaxed);

    const auto src = mac_of(f.src);

    // A group or all-zero source address isn't a station
    if ((f.src[0] & 0x01) || src.longmac == 0)
        return 1;

    const bool is_ip = f.l3 == kis_l3::l3_type::ipv4 || f.l3 == kis_l3::l3_type::ipv6;

    if (ephy->flows != nullptr && is_ip) {
        wired_flow_tracker::observation o;
        o.src = f.ip_src;
        o.dst = f.ip_dst;
        o.proto = f.ip_proto;
        if (f.l4_ok && (f.ip_proto == 6 || f.ip_proto == 17)) {
            o.sport = f.sport;
            o.dport = f.dport;
            o.tcp_flags = f.ip_proto == 6 ? f.tcp_flags : 0;
        }
        o.vlan = wired_flow_tracker::vlan_key(f.n_tags, f.n_tags > 0 ? f.tags[0].vid() : 0,
                f.n_tags > 1 ? f.tags[1].vid() : 0);
        o.src_mac = src.longmac;
        o.dst_mac = f.has_dst && f.dclass == kis_l3::dst_class::unicast ? mac_of(f.dst).longmac : 0;
        o.bytes = wire_len;
        o.ts = ts;
        o.seen = now;
        ephy->flows->add(o);
    }

    constexpr unsigned int src_flags = UCD_UPDATE_PACKETS | UCD_UPDATE_SEENBY;

    kis_device_lock dlk;
    auto dev = ephy->devicetracker->update_common_device(src, ephy, in_pack,
            src_flags | UCD_UPDATE_EXISTING_ONLY, "Ethernet Device", dlk);

    if (dev == nullptr) {
        bool report_cap = false;

        {
            kis_lock_guard<kis_mutex> alk(ephy->admit_mutex, "ethernet admit");

            // Another thread may have just made it
            dev = ephy->devicetracker->update_common_device(src, ephy, in_pack,
                    src_flags | UCD_UPDATE_EXISTING_ONLY, "Ethernet Device", dlk);

            if (dev == nullptr && ephy->admit_new_device(in_pack, src, report_cap)) {
                dev = ephy->devicetracker->update_common_device(src, ephy, in_pack, src_flags,
                        "Ethernet Device", dlk);
                if (dev != nullptr)
                    ephy->admitted(src);
            }
        }

        if (report_cap)
            _MSG_ERROR("Reached wired_max_devices ({}) Ethernet devices; new source MACs are counted "
                    "but not tracked.  A MAC flood looks like this; raise wired_max_devices in "
                    "kismet_wired.conf for a larger network.", ephy->max_devices);

        if (dev == nullptr)
            return 1;
    }

    using ed_t = ethernet_tracked_device;

    // Work for after the device is unlocked: IP bindings, and the other devices this frame
    // names, which can't be locked while this one is
    std::array<std::pair<kis_l3::ip_addr, mac_addr>, 4> binds;
    size_t n_binds = 0;
    auto bind_later = [&](const kis_l3::ip_addr& ip, const mac_addr& m) {
        if (n_binds < binds.size())
            binds[n_binds++] = {ip, m};
    };

    std::vector<kis_l3::ip_addr> new_gateways, new_dns;
    mac_addr client_mac;
    std::array<kis_l3::ip_addr, kis_l3::max_ia_addrs> client_ips;
    size_t n_client_ips = 0;
    const char *client_source = nullptr;
    const bool deep_tags = (f.errors & kis_l3::err_tags_deep) != 0;
    bool vlan_new;

    {
        auto ed = ephy->fetch_ethernet(dev);

        ed->inc_tx_bytes(wire_len);

        switch (f.dclass) {
            case kis_l3::dst_class::broadcast:
                ed->inc_tx_broadcast();
                break;
            case kis_l3::dst_class::multicast:
                ed->inc_tx_multicast();
                break;
            case kis_l3::dst_class::unicast:
                ed->inc_tx_unicast();
                break;
            default:
                break;
        }

        if (f.errors != 0)
            ed->set_malformed(ed->get_malformed() + 1);

        uint32_t proto = 0;
        if (f.n_tags == 1)
            proto |= ed_t::proto_vlan;
        else if (f.n_tags > 1)
            proto |= ed_t::proto_vlan | ed_t::proto_qinq;
        if (f.llc)
            proto |= ed_t::proto_llc;

        switch (f.l3) {
            case kis_l3::l3_type::arp:
                proto |= ed_t::proto_arp;
                break;
            case kis_l3::l3_type::ipv4:
                proto |= ed_t::proto_ipv4;
                break;
            case kis_l3::l3_type::ipv6:
                proto |= ed_t::proto_ipv6;
                break;
            case kis_l3::l3_type::other:
                proto |= ed_t::proto_other;
                break;
            default:
                break;
        }

        if (f.l4_ok) {
            if (f.ip_proto == 6)
                proto |= ed_t::proto_tcp;
            else if (f.ip_proto == 17)
                proto |= ed_t::proto_udp;
            else if (f.ip_proto == 1)
                proto |= ed_t::proto_icmp;
            else if (f.ip_proto == 58)
                proto |= ed_t::proto_icmpv6;
        }

        if (f.dhcp4.valid)
            proto |= ed_t::proto_dhcp;
        if (f.dhcp6.valid)
            proto |= ed_t::proto_dhcpv6;

        if ((ed->get_protocols() & proto) != proto)
            ed->set_protocols(ed->get_protocols() | proto);

        // More than 4 tags is malformed, and isn't a VLAN worth listing
        vlan_new = !deep_tags && ephy->add_vlan(*ed, f, ts);

        uint32_t roles = ed->get_roles();
        const uint32_t old_roles = roles;

        auto learn = [&](const kis_l3::ip_addr& ip, uint8_t rank, const char *source) {
            if (ephy->add_ip(*dev, *ed, ip, rank, source, ts)) {
                bind_later(ip, src);
                roles |= ephy->service_roles(ip);
            }
        };

        // A router forwards traffic from every remote address; those only clutter its list
        if (is_ip && ephy->local_ip(f.ip_src))
            learn(f.ip_src, rank_data, "traffic");

        if (f.l3 == kis_l3::l3_type::arp && f.arp_spa.set() && mac_of(f.arp_sha) == src)
            learn(f.arp_spa, rank_arp, "arp");

        const auto& d4 = f.dhcp4;

        if (d4.valid && d4.op == 1 && d4.chaddr_eth && mac_of(d4.chaddr) == src) {
            if (d4.ciaddr.set())
                learn(d4.ciaddr, rank_dhcp, "dhcp");

            if (!d4.hostname.empty())
                ephy->add_name(*ed, clean(d4.hostname.view()), "dhcp_hostname", ts);
            if (d4.has_fqdn && !d4.fqdn.empty())
                ephy->add_name(*ed, clean(d4.fqdn.view()), "dhcp_fqdn", ts);

            if (!d4.prl.empty()) {
                std::string prl;
                for (auto c : d4.prl.view()) {
                    if (!prl.empty())
                        prl.push_back(',');
                    prl += std::to_string(static_cast<unsigned char>(c));
                }
                if (ed->get_dhcp_prl() != prl)
                    ed->set_dhcp_prl(prl);
            }

            if (!d4.vendor.empty()) {
                auto v = clean(d4.vendor.view());
                if (ed->get_dhcp_vendor() != v)
                    ed->set_dhcp_vendor(v);
            }

            if (!d4.client_id.empty()) {
                auto c = hex_of(d4.client_id.view());
                if (ed->get_dhcp_client_id() != c)
                    ed->set_dhcp_client_id(c);
            }
        } else if (d4.valid && d4.op == 2 && (d4.msgtype == 2 || d4.msgtype == 5)) {
            roles |= ed_t::role_dhcp_server;

            ephy->learn_service(ephy->gateway_ips, d4.router, now, new_gateways);
            for (size_t i = 0; i < d4.n_dns; i++)
                ephy->learn_service(ephy->dns_ips, d4.dns[i], now, new_dns);

            // An ACK assigns the address to the client named in chaddr
            if (d4.msgtype == 5 && d4.chaddr_eth && d4.yiaddr.set() && usable_ip(d4.yiaddr)) {
                client_mac = mac_of(d4.chaddr);
                client_ips[n_client_ips++] = d4.yiaddr;
                client_source = "dhcp";

                // The lease's subnet is local.  Anyone can send an ACK, so a public subnet must
                // be /16 or narrower; private ranges are local already.
                const int plen = ephy->learn_remote_ips ? -1 : mask_prefix(d4.subnet_mask);
                if (plen >= 16 && plen <= 32 && !private_ip(d4.yiaddr))
                    ephy->learn_subnet(d4.yiaddr, static_cast<uint8_t>(plen), now);
            }
        }

        const auto& d6 = f.dhcp6;

        if (d6.valid) {
            switch (d6.msgtype) {
                case 2:     // advertise
                case 7:     // reply
                    roles |= ed_t::role_dhcpv6_server;

                    // A reply to a unicast client hands it its addresses
                    if (d6.msgtype == 7 && f.has_dst && f.dclass == kis_l3::dst_class::unicast &&
                            d6.n_ia_addrs > 0) {
                        client_mac = mac_of(f.dst);
                        for (size_t i = 0; i < d6.n_ia_addrs && n_client_ips < client_ips.size(); i++) {
                            client_ips[n_client_ips++] = d6.ia_addrs[i];
                            // The /64 of a global unicast lease (2000::/3); ULA and
                            // link-local are local already, anything else isn't a lease
                            if (!ephy->learn_remote_ips && (d6.ia_addrs[i].a[0] & 0xe0) == 0x20)
                                ephy->learn_subnet(d6.ia_addrs[i], 64, now);
                        }
                        client_source = "dhcpv6";
                    }
                    break;
                case 1: case 3: case 4: case 5: case 6: case 8: case 9: case 11:
                    if (!d6.client_duid.empty()) {
                        auto du = hex_of(d6.client_duid.view());
                        if (ed->get_dhcpv6_duid() != du)
                            ed->set_dhcpv6_duid(du);
                    }
                    if (d6.has_fqdn && !d6.fqdn.empty())
                        ephy->add_name(*ed, clean(d6.fqdn.view()), "dhcpv6_fqdn", ts);
                    if (!d6.vendor.empty()) {
                        auto v = clean(d6.vendor.view());
                        if (ed->get_dhcpv6_vendor() != v)
                            ed->set_dhcpv6_vendor(v);
                    }
                    if (d6.n_oro > 0) {
                        std::string oro;
                        for (size_t i = 0; i < d6.n_oro; i++) {
                            if (!oro.empty())
                                oro.push_back(',');
                            oro += std::to_string(d6.oro[i]);
                        }
                        if (ed->get_dhcpv6_oro() != oro)
                            ed->set_dhcpv6_oro(oro);
                    }
                    break;
                default:
                    break;
            }
        }

        if (roles != old_roles) {
            ed->set_roles(roles);
            ephy->set_display_from_roles(*dev, roles);
        }
    }

    dlk.unlock();

    if (!deep_tags)
        ephy->count_vlan(f, wire_len, ts, vlan_new);

    for (size_t i = 0; i < n_binds; i++)
        ephy->bind_ip(binds[i].first, binds[i].second, now);

    // The client of a DHCP ACK or DHCPv6 reply
    auto apply_client = [&](kis_tracked_device_base& cdev, ethernet_tracked_device& ced) {
        uint32_t roles = ced.get_roles();
        const uint32_t old = roles;

        for (size_t i = 0; i < n_client_ips; i++) {
            if (ephy->add_ip(cdev, ced, client_ips[i], rank_dhcp, client_source, ts))
                roles |= ephy->service_roles(client_ips[i]);
        }

        if (roles != old) {
            ced.set_roles(roles);
            ephy->set_display_from_roles(cdev, roles);
        }
    };

    const bool have_client = n_client_ips > 0 && client_mac.longmac != 0 && client_mac != src;

    if (f.has_dst && f.dclass == kis_l3::dst_class::unicast) {
        const auto dst = mac_of(f.dst);

        if (dst != src) {
            const bool dst_is_client = have_client && dst == client_mac;

            ephy->update_other(dst, in_pack,
                    [&](kis_tracked_device_base& ddev, ethernet_tracked_device& ded) {
                        ded.inc_rx_bytes(wire_len);
                        if (dst_is_client)
                            apply_client(ddev, ded);
                    }, UCD_UPDATE_PACKETS);

            if (dst_is_client) {
                for (size_t i = 0; i < n_client_ips; i++)
                    ephy->bind_ip(client_ips[i], client_mac, now);
            }
        }
    }

    // A broadcast ACK: the client didn't send this frame, so it isn't seen by it
    if (have_client && !(f.has_dst && f.dclass == kis_l3::dst_class::unicast && mac_of(f.dst) == client_mac)) {
        ephy->change_other(client_mac, apply_client);
        for (size_t i = 0; i < n_client_ips; i++)
            ephy->bind_ip(client_ips[i], client_mac, now);
    }

    // Newly named gateways and DNS servers: mark the devices already using those addresses
    auto mark = [&](const std::vector<kis_l3::ip_addr>& ips, uint32_t role) {
        for (const auto& ip : ips) {
            for (const auto& m : ephy->lookup_ip(ip)) {
                ephy->change_other(m, [&](kis_tracked_device_base& rdev, ethernet_tracked_device& red) {
                            if ((red.get_roles() & role) == 0) {
                                red.set_roles(red.get_roles() | role);
                                ephy->set_display_from_roles(rdev, red.get_roles());
                            }
                        });
            }
        }
    };

    mark(new_gateways, ed_t::role_gateway);
    mark(new_dns, ed_t::role_dns_server);

    return 1;
}

std::shared_ptr<tracker_element>
    kis_ethernet_phy::flows_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    auto ret = std::make_shared<tracker_element_map>();
    auto vec = std::make_shared<tracker_element_vector>();

    wired_flow_tracker::filter flt;
    size_t start = 0, length = 100;

    // GET variables or a POST json body; anything malformed is an error, not a default
    auto param = [&con](const char *name, std::string& out) -> bool {
        auto v = con->http_variables().find(name);
        if (v != con->http_variables().end()) {
            out = v->second;
            return true;
        }

        const auto& j = con->json();
        if (j.is_object() && j.contains(name)) {
            const auto& jv = j[name];
            if (jv.is_string())
                out = jv.get<std::string>();
            else if (jv.is_number_unsigned())
                out = std::to_string(jv.get<uint64_t>());
            else
                throw std::runtime_error("invalid parameter type");
            return true;
        }

        return false;
    };

    std::string s;

    if (param("mac", s)) {
        if (s.length() > 17)
            throw std::runtime_error("invalid mac");
        mac_addr m(s);
        if (m.error() || m.length() != 6)
            throw std::runtime_error("invalid mac");
        flt.mac = m.longmac;
    }

    if (param("ip", s) && !ethernet_parse_ip(s, flt.ip))
        throw std::runtime_error("invalid ip");

    if (param("vlan", s)) {
        auto v = string_to_n<unsigned int>(s);
        if (v > 4095)
            throw std::runtime_error("invalid vlan");
        flt.vlan = static_cast<int>(v);
    }

    if (param("start", s)) {
        start = string_to_n<unsigned int>(s);
        if (start > 1048576)
            throw std::runtime_error("invalid start");
    }

    if (param("length", s)) {
        length = string_to_n<unsigned int>(s);
        if (length == 0 || length > 1000)
            throw std::runtime_error("invalid length; 1 to 1000");
    }

    size_t total = 0;
    std::vector<wired_flow_tracker::flow> out;

    if (flows != nullptr)
        flows->snapshot(flt, start, length, out, total);

    for (const auto& fl : out)
        vec->push_back(flow_row(fl));

    vec->set_id(flow_fields[22]);
    ret->insert(vec);
    ret->insert(std::make_shared<tracker_element_uint64>(flow_fields[20], total));
    ret->insert(std::make_shared<tracker_element_uint64>(flow_fields[21], start));

    return ret;
}

std::shared_ptr<tracker_element_map> kis_ethernet_phy::flow_row(const wired_flow_tracker::flow& fl) {
    auto m = std::make_shared<tracker_element_map>();
    kis_l3::ip_addr a, b;
    a.family = b.family = fl.k.family;
    a.a = fl.k.addr_a;
    b.a = fl.k.addr_b;

    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[0], fl.k.family));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[1], fl.k.proto));
    m->insert(std::make_shared<tracker_element_string>(flow_fields[2], ethernet_ip_string(a)));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[3], fl.k.port_a));
    m->insert(std::make_shared<tracker_element_string>(flow_fields[4], ethernet_ip_string(b)));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[5], fl.k.port_b));
    m->insert(std::make_shared<tracker_element_mac_addr>(flow_fields[6], mac_from_u64(fl.mac_a)));
    m->insert(std::make_shared<tracker_element_mac_addr>(flow_fields[7], mac_from_u64(fl.mac_b)));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[8], fl.k.vlan >> 32));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[9], (fl.k.vlan >> 12) & 0xfff));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[10], fl.k.vlan & 0xfff));
    m->insert(std::make_shared<tracker_element_string>(flow_fields[11], fl.initiator_a ? "a" : "b"));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[12], fl.bytes_ab));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[13], fl.bytes_ba));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[14], fl.packets_ab));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[15], fl.packets_ba));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[16], fl.first_time));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[17], fl.last_time));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[18], fl.flags_ab));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[19], fl.flags_ba));
    m->insert(std::make_shared<tracker_element_string>(flow_fields[23],
                wired_flow_tracker::format_key(fl.k, fl.serial)));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[24], fl.serial));
    m->insert(std::make_shared<tracker_element_uint64>(flow_fields[25], fl.history_time));

    return m;
}

std::shared_ptr<tracker_element>
    kis_ethernet_phy::flow_by_key_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    // A key is only lowercase hex and '-', so a URL-encoded one is malformed and isn't decoded;
    // nothing of it is echoed back
    wired_flow_tracker::key k;
    uint64_t serial = 0;

    if (!wired_flow_tracker::parse_key(con->uri_params()[":key"], k, serial)) {
        con->set_status(400);
        return std::make_shared<tracker_element_map>();
    }

    wired_flow_tracker::flow fl;
    flow_history hist{0};
    const time_t now = Globalreg::globalreg->last_tv_sec;

    // Gone, or the same addresses and ports are now a later flow
    if (flows == nullptr || !flows->lookup(k, serial, now, fl, &hist)) {
        con->set_status(404);
        return std::make_shared<tracker_element_map>();
    }

    auto m = flow_row(fl);

    if (fl.history_time != 0) {
        for (size_t i = 0; i < flow_history::n_series; i++)
            m->insert(flow_rrd.build(flow_fields[flow_rrd_field + i],
                        hist.vectors(static_cast<flow_history::series>(i)), now));
    }

    return m;
}

std::shared_ptr<kis_ethernet_phy::flow_rate_rrds> kis_ethernet_phy::make_rate_rrds() const {
    auto r = std::make_shared<flow_rate_rrds>();

    // The timer keeps them current, so serializing doesn't add a blank second; that would
    // leave the gauge's last value blank
    for (size_t i = 0; i < wired_flow_rates::n_series; i++) {
        r->counts[i] = std::make_shared<kis_tracked_rrd<>>(rate_fields[i]);
        r->counts[i]->update_before_serialize(false);
    }
    r->active = std::make_shared<flow_gauge_rrd>(rate_fields[wired_flow_rates::n_series]);
    r->active->update_before_serialize(false);

    return r;
}

void kis_ethernet_phy::sample_flow_rates() {
    const time_t now = Globalreg::globalreg->last_tv_sec;
    // Takes and releases each shard lock before any RRD lock
    const auto f = rates.next(now, flows->get_totals());

    std::shared_ptr<flow_rate_rrds> r = f.restart ? make_rate_rrds() : nullptr;
    // The replaced set is freed after the lock, once no request still holds it
    std::shared_ptr<flow_rate_rrds> old;

    {
        kis_lock_guard<kis_mutex> lk(rates_mutex, "ethernet sample_flow_rates");
        if (r != nullptr) {
            old = std::move(rate_rrds);
            rate_rrds = r;
        } else {
            r = rate_rrds;
        }
    }

    for (size_t s = 0; s < f.n_samples; s++) {
        const auto& smp = f.samples[s];
        for (size_t i = 0; i < wired_flow_rates::n_series; i++)
            r->counts[i]->add_sample(static_cast<double>(smp.v[i]), smp.t);
    }

    // The gauge keeps the last value in a second, so a second read twice isn't counted twice
    r->active->add_sample(static_cast<double>(f.flows), f.gauge_time);
}

std::shared_ptr<tracker_element> kis_ethernet_phy::flow_history_endpoint() {
    std::shared_ptr<flow_rate_rrds> r;

    {
        kis_lock_guard<kis_mutex> lk(rates_mutex, "ethernet flow_history_endpoint");
        r = rate_rrds;
    }

    auto m = std::make_shared<tracker_element_map>();
    for (const auto& c : r->counts)
        m->insert(c);
    m->insert(r->active);

    return m;
}

std::shared_ptr<tracker_element> kis_ethernet_phy::vlans_endpoint() {
    auto vec = std::make_shared<tracker_element_vector>();

    std::vector<vlan_inv> copy;

    {
        kis_lock_guard<kis_mutex> lk(vlan_mutex, "ethernet vlans_endpoint");
        copy.reserve(vlan_inventory.size());
        for (const auto& [k, v] : vlan_inventory)
            copy.push_back(v);
    }

    std::sort(copy.begin(), copy.end(), [](const vlan_inv& a, const vlan_inv& b) {
            return vlan_inv_key(a.tags, a.vid, a.inner_vid) < vlan_inv_key(b.tags, b.vid, b.inner_vid);
        });

    for (const auto& v : copy) {
        auto m = std::make_shared<tracker_element_map>();
        m->insert(std::make_shared<tracker_element_uint64>(vlan_fields[0], v.tags));
        m->insert(std::make_shared<tracker_element_uint64>(vlan_fields[1], v.vid));
        m->insert(std::make_shared<tracker_element_uint64>(vlan_fields[2], v.inner_vid));
        m->insert(std::make_shared<tracker_element_uint64>(vlan_fields[3], v.first_time));
        m->insert(std::make_shared<tracker_element_uint64>(vlan_fields[4], v.last_time));
        m->insert(std::make_shared<tracker_element_uint64>(vlan_fields[5], v.packets));
        m->insert(std::make_shared<tracker_element_uint64>(vlan_fields[6], v.bytes));
        m->insert(std::make_shared<tracker_element_uint64>(vlan_fields[7], v.devices));
        vec->push_back(m);
    }

    return vec;
}

std::shared_ptr<tracker_element>
    kis_ethernet_phy::by_ip_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    auto vec = std::make_shared<tracker_element_vector>();

    // Path parameters arrive still URL-encoded (an IPv6 address as 2001%3Adb8%3A%3A1)
    auto raw = con->uri_params()[":ip"];
    if (raw.length() > 128)
        throw std::runtime_error("invalid ip");

    kis_l3::ip_addr ip;
    if (!ethernet_parse_ip(kis_net_beast_httpd::decode_uri(raw, false), ip))
        throw std::runtime_error("invalid ip");

    for (const auto& m : lookup_ip(ip)) {
        auto dev = devicetracker->fetch_device(device_key(fetch_phyname_hash(), m));
        if (dev != nullptr)
            vec->push_back(dev);
    }

    return vec;
}

std::shared_ptr<tracker_element> kis_ethernet_phy::status_endpoint() {
    auto m = std::make_shared<tracker_element_map>();

    wired_flow_tracker::stats fs;
    if (flows != nullptr)
        fs = flows->get_stats();

    size_t n_ip, n_ip_full, n_vlan_full;
    {
        kis_lock_guard<kis_mutex> lk(ip_mutex, "ethernet status_endpoint");
        n_ip = ip_table.size();
        n_ip_full = ip_table_full;
    }
    {
        kis_lock_guard<kis_mutex> lk(vlan_mutex, "ethernet status_endpoint");
        n_vlan_full = vlan_inventory_full;
    }

    const uint64_t v[n_status_fields] = {
        n_frames.load(), n_malformed.load(), devicetracker->count_phy_devices(phyid), max_devices,
        n_capped.load(), new_device_rate, n_rate_limited.load(), fs.flows,
        flows != nullptr ? flows->get_params().max_flows : 0, fs.created, fs.expired, fs.dropped_full,
        fs.deferred, n_ip, n_ip_full, n_vlan_full, n_evicted.load(), n_future.load(), fs.evicted,
        fs.histories, flows != nullptr ? flows->get_params().max_histories : 0,
        flows != nullptr ? flows->get_params().history_min_packets : 0, fs.histories_denied,
        fs.histories_released,
    };

    for (size_t i = 0; i < n_status_fields; i++)
        m->insert(std::make_shared<tracker_element_uint64>(status_fields[i], v[i]));

    return m;
}
