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

#ifndef __PHY_ETHERNET_H__
#define __PHY_ETHERNET_H__

// IEEE802.3 (Ethernet) phy: frames of DLT_EN10MB, and Linux cooked SLL / SLL2 from "any"
// captures.  Devices are keyed by MAC; VLANs are a set on the device.  Only source MACs make
// devices, and a MAC flood is held back by wired_max_devices and wired_new_device_rate.
// Never inserts DATAPAYLOAD, so the 802.11 IP dissector never sees Ethernet frames.

#include "config.h"

#include <array>
#include <atomic>
#include <climits>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "devicetracker.h"
#include "devicetracker_component.h"
#include "globalregistry.h"
#include "kis_l3_parse.h"
#include "kis_mutex.h"
#include "packet.h"
#include "packetchain.h"
#include "unordered_dense.h"
#include "wired_flow_tracker.h"

class kis_net_beast_httpd_connection;

// A 6 byte MAC from mac_addr::longmac, as flows and the link graph keep them
inline mac_addr mac_from_u64(uint64_t v) {
    std::array<uint8_t, 6> b;
    for (size_t i = 0; i < b.size(); i++)
        b[i] = static_cast<uint8_t>(v >> ((8 - i - 1) * 8));
    return mac_addr(b.data(), 6);
}

// A VLAN (or tag stack) a device was seen sending on
class ethernet_tracked_vlan : public tracker_component {
public:
    ethernet_tracked_vlan() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    ethernet_tracked_vlan(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    ethernet_tracked_vlan(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("ethernet_tracked_vlan");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(tags, uint8_t, uint8_t, uint8_t, tags);
    __Proxy(vid, uint16_t, uint16_t, uint16_t, vid);
    __Proxy(inner_vid, uint16_t, uint16_t, uint16_t, inner_vid);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __Proxy(packets, uint64_t, uint64_t, uint64_t, packets);
    __ProxyIncDec(packets, uint64_t, uint64_t, packets);

    bool matches(uint8_t t, uint16_t v, uint16_t iv) const {
        return get_tags() == t && get_vid() == v && get_inner_vid() == iv;
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("ethernet.device.vlan.tags",
                "VLAN tags on the frame: 1 for 802.1Q (VLAN 0 is priority tagged), 2 or more for QinQ",
                &tags);
        register_field("ethernet.device.vlan.vid", "VLAN ID of the outer tag", &vid);
        register_field("ethernet.device.vlan.inner_vid", "VLAN ID of the second tag, 0 with one tag",
                &inner_vid);
        register_field("ethernet.device.vlan.first_time", "first time seen on this VLAN", &first_time);
        register_field("ethernet.device.vlan.last_time", "last time seen on this VLAN", &last_time);
        register_field("ethernet.device.vlan.packets", "frames sent on this VLAN", &packets);
    }

    std::shared_ptr<tracker_element_uint8> tags;
    std::shared_ptr<tracker_element_uint16> vid;
    std::shared_ptr<tracker_element_uint16> inner_vid;
    std::shared_ptr<tracker_element_uint64> first_time;
    std::shared_ptr<tracker_element_uint64> last_time;
    std::shared_ptr<tracker_element_uint64> packets;
};

// An IPv4 or IPv6 address a device used or was given
class ethernet_tracked_ip : public tracker_component {
public:
    ethernet_tracked_ip() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    ethernet_tracked_ip(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    ethernet_tracked_ip(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("ethernet_tracked_ip");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(address, std::string, std::string, std::string, address);
    __Proxy(source, std::string, std::string, std::string, source);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __ProxyDynamic(eui64_mac, mac_addr, mac_addr, mac_addr, eui64_mac, eui64_mac_id);

    // Not exported: the address for quick compares, how strong its source is, and the server
    // minute the IP table last heard about it
    kis_l3::ip_addr raw;
    uint8_t rank = 0;
    time_t table_minute = 0;

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("ethernet.device.ip.address", "IP address", &address);
        register_field("ethernet.device.ip.source",
                "where the address was learned: arp, dhcp, dhcpv6, or traffic (the source address "
                "of IP packets the device sent; only local addresses unless wired_learn_remote_ips "
                "is set)", &source);
        register_field("ethernet.device.ip.first_time", "first time seen", &first_time);
        register_field("ethernet.device.ip.last_time", "last time seen", &last_time);
        eui64_mac_id =
            register_dynamic_field("ethernet.device.ip.eui64_mac",
                    "MAC address in an EUI-64 IPv6 interface ID, when it isn't this device's",
                    &eui64_mac);
    }

    std::shared_ptr<tracker_element_string> address;
    std::shared_ptr<tracker_element_string> source;
    std::shared_ptr<tracker_element_uint64> first_time;
    std::shared_ptr<tracker_element_uint64> last_time;
    std::shared_ptr<tracker_element_mac_addr> eui64_mac;
    uint16_t eui64_mac_id;
};

// A name a device announced for itself
class ethernet_tracked_name : public tracker_component {
public:
    ethernet_tracked_name() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    ethernet_tracked_name(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    ethernet_tracked_name(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("ethernet_tracked_name");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    // Not get_name/set_name, which would override tracker_component::get_name
    __Proxy(host_name, std::string, std::string, std::string, name);
    __Proxy(source, std::string, std::string, std::string, source);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("ethernet.device.name.name", "name, with unprintable bytes escaped", &name);
        register_field("ethernet.device.name.source",
                "where the name came from (dhcp_hostname, dhcp_fqdn, dhcpv6_fqdn)", &source);
        register_field("ethernet.device.name.first_time", "first time seen", &first_time);
        register_field("ethernet.device.name.last_time", "last time seen", &last_time);
    }

    std::shared_ptr<tracker_element_string> name;
    std::shared_ptr<tracker_element_string> source;
    std::shared_ptr<tracker_element_uint64> first_time;
    std::shared_ptr<tracker_element_uint64> last_time;
};

class ethernet_tracked_device : public tracker_component {
public:
    ethernet_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    ethernet_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    ethernet_tracked_device(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("ethernet_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    // ethernet.device.protocols bits
    static constexpr uint32_t proto_arp = 1 << 0;
    static constexpr uint32_t proto_ipv4 = 1 << 1;
    static constexpr uint32_t proto_ipv6 = 1 << 2;
    static constexpr uint32_t proto_tcp = 1 << 3;
    static constexpr uint32_t proto_udp = 1 << 4;
    static constexpr uint32_t proto_icmp = 1 << 5;
    static constexpr uint32_t proto_icmpv6 = 1 << 6;
    static constexpr uint32_t proto_dhcp = 1 << 7;
    static constexpr uint32_t proto_dhcpv6 = 1 << 8;
    static constexpr uint32_t proto_llc = 1 << 9;
    static constexpr uint32_t proto_vlan = 1 << 10;
    static constexpr uint32_t proto_qinq = 1 << 11;
    static constexpr uint32_t proto_other = 1 << 12;

    // ethernet.device.roles bits
    static constexpr uint32_t role_dhcp_server = 1 << 0;
    static constexpr uint32_t role_dhcpv6_server = 1 << 1;
    static constexpr uint32_t role_gateway = 1 << 2;
    static constexpr uint32_t role_dns_server = 1 << 3;

    __Proxy(tx_bytes, uint64_t, uint64_t, uint64_t, tx_bytes);
    __ProxyIncDec(tx_bytes, uint64_t, uint64_t, tx_bytes);
    __Proxy(rx_bytes, uint64_t, uint64_t, uint64_t, rx_bytes);
    __ProxyIncDec(rx_bytes, uint64_t, uint64_t, rx_bytes);
    __Proxy(tx_unicast, uint64_t, uint64_t, uint64_t, tx_unicast);
    __ProxyIncDec(tx_unicast, uint64_t, uint64_t, tx_unicast);
    __Proxy(tx_multicast, uint64_t, uint64_t, uint64_t, tx_multicast);
    __ProxyIncDec(tx_multicast, uint64_t, uint64_t, tx_multicast);
    __Proxy(tx_broadcast, uint64_t, uint64_t, uint64_t, tx_broadcast);
    __ProxyIncDec(tx_broadcast, uint64_t, uint64_t, tx_broadcast);
    __Proxy(protocols, uint32_t, uint32_t, uint32_t, protocols);
    __Proxy(roles, uint32_t, uint32_t, uint32_t, roles);

    __ProxyDynamic(malformed, uint64_t, uint64_t, uint64_t, malformed, malformed_id);
    __ProxyDynamic(list_full, uint64_t, uint64_t, uint64_t, list_full, list_full_id);

    __ProxyDynamicTrackable(vlans, tracker_element_vector, vlans, vlans_id);
    __ProxyDynamicTrackable(ipv4, tracker_element_vector, ipv4, ipv4_id);
    __ProxyDynamicTrackable(ipv6, tracker_element_vector, ipv6, ipv6_id);
    __ProxyDynamicTrackable(names, tracker_element_vector, names, names_id);

    __ProxyDynamic(dhcp_prl, std::string, std::string, std::string, dhcp_prl, dhcp_prl_id);
    __ProxyDynamic(dhcp_vendor, std::string, std::string, std::string, dhcp_vendor, dhcp_vendor_id);
    __ProxyDynamic(dhcp_client_id, std::string, std::string, std::string, dhcp_client_id, dhcp_client_id_id);
    __ProxyDynamic(dhcpv6_duid, std::string, std::string, std::string, dhcpv6_duid, dhcpv6_duid_id);
    __ProxyDynamic(dhcpv6_vendor, std::string, std::string, std::string, dhcpv6_vendor, dhcpv6_vendor_id);
    __ProxyDynamic(dhcpv6_oro, std::string, std::string, std::string, dhcpv6_oro, dhcpv6_oro_id);

    // A record rebuilt from storage holds plain maps in its lists; the phy casts list entries
    // to their types, so make them those types (and drop anything that isn't a map)
    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        if (e == nullptr)
            return;

        retype<ethernet_tracked_vlan>(vlans);
        retype<ethernet_tracked_ip>(ipv4);
        retype<ethernet_tracked_ip>(ipv6);
        retype<ethernet_tracked_name>(names);
    }

protected:
    template<typename T>
    static void retype(const std::shared_ptr<tracker_element_vector>& vec) {
        if (vec == nullptr)
            return;

        std::vector<std::shared_ptr<tracker_element>> keep;
        for (const auto& i : *vec) {
            if (i != nullptr && i->get_type() == tracker_type::tracker_map)
                keep.push_back(std::make_shared<T>(i->get_id(), std::static_pointer_cast<tracker_element_map>(i)));
        }

        vec->clear();
        for (auto& k : keep)
            vec->push_back(k);
    }

    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("ethernet.device.tx_bytes", "bytes sent, as on the wire", &tx_bytes);
        register_field("ethernet.device.rx_bytes", "bytes received as a unicast destination",
                &rx_bytes);
        register_field("ethernet.device.tx_unicast", "unicast frames sent", &tx_unicast);
        register_field("ethernet.device.tx_multicast", "multicast frames sent", &tx_multicast);
        register_field("ethernet.device.tx_broadcast", "broadcast frames sent", &tx_broadcast);
        register_field("ethernet.device.protocols",
                "protocols sent, bitfield: 1 ARP, 2 IPv4, 4 IPv6, 8 TCP, 16 UDP, 32 ICMP, 64 ICMPv6, "
                "128 DHCP, 256 DHCPv6, 512 LLC, 1024 VLAN tagged, 2048 QinQ, 4096 other", &protocols);
        register_field("ethernet.device.roles",
                "roles seen, bitfield: 1 DHCP server, 2 DHCPv6 server, 4 gateway (a DHCP router "
                "option), 8 DNS server (a DHCP DNS option)", &roles);

        malformed_id =
            register_dynamic_field("ethernet.device.malformed", "malformed frames sent", &malformed);
        list_full_id =
            register_dynamic_field("ethernet.device.list_full",
                    "VLANs, addresses or names not kept because the device's list was full",
                    &list_full);

        vlans_id =
            register_dynamic_field("ethernet.device.vlans", "VLANs the device sent on", &vlans);
        ipv4_id =
            register_dynamic_field("ethernet.device.ipv4", "IPv4 addresses", &ipv4);
        ipv6_id =
            register_dynamic_field("ethernet.device.ipv6", "IPv6 addresses", &ipv6);
        names_id =
            register_dynamic_field("ethernet.device.names", "names the device announced", &names);

        dhcp_prl_id =
            register_dynamic_field("ethernet.device.dhcp_prl",
                    "DHCP parameter request list (option 55), comma separated", &dhcp_prl);
        dhcp_vendor_id =
            register_dynamic_field("ethernet.device.dhcp_vendor", "DHCP vendor class (option 60)",
                    &dhcp_vendor);
        dhcp_client_id_id =
            register_dynamic_field("ethernet.device.dhcp_client_id", "DHCP client ID (option 61), hex",
                    &dhcp_client_id);
        dhcpv6_duid_id =
            register_dynamic_field("ethernet.device.dhcpv6_duid", "DHCPv6 client DUID, hex",
                    &dhcpv6_duid);
        dhcpv6_vendor_id =
            register_dynamic_field("ethernet.device.dhcpv6_vendor", "DHCPv6 vendor class data",
                    &dhcpv6_vendor);
        dhcpv6_oro_id =
            register_dynamic_field("ethernet.device.dhcpv6_oro",
                    "DHCPv6 option request list, comma separated", &dhcpv6_oro);
    }

    std::shared_ptr<tracker_element_uint64> tx_bytes;
    std::shared_ptr<tracker_element_uint64> rx_bytes;
    std::shared_ptr<tracker_element_uint64> tx_unicast;
    std::shared_ptr<tracker_element_uint64> tx_multicast;
    std::shared_ptr<tracker_element_uint64> tx_broadcast;
    std::shared_ptr<tracker_element_uint32> protocols;
    std::shared_ptr<tracker_element_uint32> roles;

    std::shared_ptr<tracker_element_uint64> malformed;
    uint16_t malformed_id;
    std::shared_ptr<tracker_element_uint64> list_full;
    uint16_t list_full_id;

    std::shared_ptr<tracker_element_vector> vlans;
    uint16_t vlans_id;
    std::shared_ptr<tracker_element_vector> ipv4;
    uint16_t ipv4_id;
    std::shared_ptr<tracker_element_vector> ipv6;
    uint16_t ipv6_id;
    std::shared_ptr<tracker_element_vector> names;
    uint16_t names_id;

    std::shared_ptr<tracker_element_string> dhcp_prl;
    uint16_t dhcp_prl_id;
    std::shared_ptr<tracker_element_string> dhcp_vendor;
    uint16_t dhcp_vendor_id;
    std::shared_ptr<tracker_element_string> dhcp_client_id;
    uint16_t dhcp_client_id_id;
    std::shared_ptr<tracker_element_string> dhcpv6_duid;
    uint16_t dhcpv6_duid_id;
    std::shared_ptr<tracker_element_string> dhcpv6_vendor;
    uint16_t dhcpv6_vendor_id;
    std::shared_ptr<tracker_element_string> dhcpv6_oro;
    uint16_t dhcpv6_oro_id;
};

// The decoded frame, carried from the dissector to the classifier
class ethernet_packinfo : public packet_component {
public:
    ethernet_packinfo() { }

    void reset() {
        parsed = false;
    }

    bool parsed = false;
    kis_l3::frame f;
};

class kis_ethernet_phy : public kis_phy_handler {
public:
    kis_ethernet_phy() :
        kis_phy_handler() { }

    kis_ethernet_phy(int in_phyid);

    virtual ~kis_ethernet_phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_ethernet_phy(in_phyid);
    }

    static int dissector(CHAINCALL_PARMS);
    static int common_classifier(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device) override;

    virtual bool device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) override;

    virtual bool uses_device_locking() const override {
        return true;
    }

    // Per-device list caps
    static constexpr size_t max_vlans = 16;
    static constexpr size_t max_addrs = 8;
    static constexpr size_t max_names_per_source = 4;
    // Global table caps
    static constexpr size_t max_ip_table = 65536;
    static constexpr size_t max_macs_per_ip = 4;
    static constexpr size_t max_vlan_inventory = 4096;
    static constexpr size_t max_service_ips = 64;

    // wired_max_devices, fixed at startup; 0 for no limit
    size_t get_max_devices() const {
        return max_devices;
    }

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int pack_comp_linkframe, pack_comp_decap, pack_comp_ethernet, pack_comp_datasrc;
    int ethernet_device_id, vlan_entry_id, ip_entry_id, name_entry_id;

    device_display_type type_device, type_router, type_server;

    // wired_max_devices / wired_new_device_rate / wired_learn_remote_ips
    size_t max_devices;
    unsigned int new_device_rate;
    bool learn_remote_ips;

    // Held across admitting and creating a new device, so concurrent new MACs can't pass
    // the cap together; taken before the device list lock
    kis_mutex admit_mutex{"ethernet admit"};

    // New devices admitted per capture second, a slot per second mod rate_slots; a reordered
    // second keeps its own budget instead of sharing the newest one, and a slot never goes
    // back to an older second.  retry is a second budget for MACs refused before, so a host
    // that keeps sending gets in while single-frame MACs flood the first.
    struct rate_slot {
        int64_t second = INT64_MIN;
        unsigned int count = 0;
        unsigned int retry = 0;
    };
    static constexpr size_t rate_slots = 16;
    std::array<rate_slot, rate_slots> rate_ring{};
    // Frames dated past max_future_skew, and frames whose slot holds a newer second: one
    // bucket each per server second; the stale one only has its retry budget
    rate_slot rate_future, rate_stale;
    // A slot newer than a frame by more than rate_epoch_jump seconds may be reopened for it,
    // max_rate_reopens times a server second
    static constexpr uint64_t rate_epoch_jump = 3600;
    static constexpr unsigned int max_rate_reopens = 32;
    int64_t rate_reopen_wall = 0;
    unsigned int rate_reopens = 0;
    static constexpr time_t max_future_skew = 60;

    // MACs refused by the rate or the cap, in 2-way sets under a hash seeded at startup, so
    // a flood overwrites unpredictable entries and nobody can aim at one host's entry;
    // allocated on the first refusal
    static constexpr size_t refused_sets = 32768;
    std::unique_ptr<std::array<uint64_t, 2>[]> refused;
    uint64_t refused_seed;
    uint64_t refused_hash(uint64_t mac) const;
    bool refused_before(uint64_t mac);
    void remember_refused(uint64_t mac);
    void forget_refused(uint64_t mac);

    // At the cap, a MAC refused before may evict the oldest device which sent only a frame or
    // two; at most max_evict_per_sec a second, scanning at most max_evict_scan candidates
    static constexpr unsigned int max_evict_per_sec = 100;
    static constexpr unsigned int max_evict_scan = 32;
    static constexpr uint64_t max_evict_packets = 2;
    std::deque<device_key> admit_order;
    time_t evict_second = 0;
    unsigned int evict_count = 0;
    bool evict_one();

    std::atomic<uint64_t> n_capped{0}, n_rate_limited{0}, n_frames{0}, n_malformed{0};
    std::atomic<uint64_t> n_evicted{0}, n_future{0};
    std::atomic<bool> cap_reported{false};

    // Call with admit_mutex held; report_cap is set the first time the cap refuses one
    bool admit_new_device(const std::shared_ptr<kis_packet>& in_pack, const mac_addr& mac, bool& report_cap);
    void admitted(const mac_addr& mac);

    std::unique_ptr<wired_flow_tracker> flows;
    int expire_timer_id = -1;

    // IP to MAC bindings, from ARP, DHCP and the addresses devices use; seen is server time
    struct ip_binding {
        std::array<uint64_t, max_macs_per_ip> macs{};
        std::array<time_t, max_macs_per_ip> seen{};
    };
    kis_mutex ip_mutex{"ethernet ip table"};
    // Built in the constructor with a hasher seeded at startup, as is vlan_inventory
    ankerl::unordered_dense::map<kis_l3::ip_addr, ip_binding, kis_l3::ip_addr_hash> ip_table;
    uint64_t ip_table_full = 0;
    void bind_ip(const kis_l3::ip_addr& ip, const mac_addr& mac, time_t now);
    std::vector<mac_addr> lookup_ip(const kis_l3::ip_addr& ip);
    void prune_ip_table(time_t now);

    // Gateways, DNS servers and subnets named by DHCP, expired by server time.  Devices using
    // a gateway or DNS address get the role; addresses in a subnet count as local.
    struct service_ip {
        kis_l3::ip_addr ip;
        time_t seen;
    };
    struct subnet {
        kis_l3::ip_addr net;
        uint8_t prefix;
        time_t seen;
    };
    static constexpr size_t max_subnets = 32;
    static constexpr time_t service_idle = 86400;
    kis_mutex service_mutex{"ethernet services"};
    std::vector<service_ip> gateway_ips, dns_ips;
    std::vector<subnet> subnets;
    std::atomic<size_t> n_service_ips{0}, n_subnets{0};
    uint32_t service_roles(const kis_l3::ip_addr& ip);
    void learn_service(std::vector<service_ip>& list, const kis_l3::ip_addr& ip, time_t now,
            std::vector<kis_l3::ip_addr>& added);
    void learn_subnet(const kis_l3::ip_addr& ip, uint8_t prefix, time_t now);
    void prune_services(time_t now);

    // Whether a source address of traffic is worth listing on the device: local addresses,
    // or any of them with wired_learn_remote_ips
    bool local_ip(const kis_l3::ip_addr& ip);

    // VLAN inventory
    struct vlan_inv {
        uint8_t tags;
        uint16_t vid, inner_vid;
        time_t first_time, last_time;
        uint64_t packets, bytes, devices;
    };
    kis_mutex vlan_mutex{"ethernet vlans"};
    ankerl::unordered_dense::map<uint64_t, vlan_inv, kis_l3::seeded_u64_hash> vlan_inventory;
    uint64_t vlan_inventory_full = 0;
    void count_vlan(const kis_l3::frame& f, uint64_t bytes, time_t ts, bool new_for_device);

    // Device updates, with the device locked
    std::shared_ptr<ethernet_tracked_device> fetch_ethernet(const std::shared_ptr<kis_tracked_device_base>& dev);
    bool add_vlan(ethernet_tracked_device& ed, const kis_l3::frame& f, time_t ts);
    bool add_ip(kis_tracked_device_base& dev, ethernet_tracked_device& ed, const kis_l3::ip_addr& ip,
            uint8_t rank, const char *source, time_t ts);
    void add_name(ethernet_tracked_device& ed, const std::string& name, const char *source, time_t ts);
    void set_display_from_roles(kis_tracked_device_base& dev, uint32_t roles);

    // The destination of the frame: count the packet on it if it already exists
    void update_other(const mac_addr& mac, const std::shared_ptr<kis_packet>& in_pack,
            const std::function<void (kis_tracked_device_base&, ethernet_tracked_device&)>& fn,
            unsigned int flags);

    // A device this frame says something about (a DHCP client, a gateway) without the device
    // sending it: change it if it exists and mark it modified, leaving its last seen time
    // and packet counts alone
    void change_other(const mac_addr& mac,
            const std::function<void (kis_tracked_device_base&, ethernet_tracked_device&)>& fn);

    std::shared_ptr<tracker_element> flows_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);
    std::shared_ptr<tracker_element> vlans_endpoint();
    std::shared_ptr<tracker_element> by_ip_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);
    std::shared_ptr<tracker_element> status_endpoint();

    int flow_fields[23];
    int vlan_fields[8];
    static constexpr size_t n_status_fields = 19;
    int status_fields[n_status_fields];
};

std::string ethernet_ip_string(const kis_l3::ip_addr& a);
bool ethernet_parse_ip(const std::string& s, kis_l3::ip_addr& out);

#endif
