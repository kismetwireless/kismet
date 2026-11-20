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

#include <cstring>

#include "globalregistry.h"
#include "util.h"
#include "endian_magic.h"
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"
#include "alertracker.h"

#include "kis_dissector_ipdata.h"
#include "kis_l3_parse.h"

namespace {

// LLC/SNAP: DSAP, SSAP, UI control, OUI, then a protocol id
constexpr size_t snap_len = 8;

// Cisco OUI and the CDP protocol id
constexpr uint8_t cdp_snap[snap_len] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00};
constexpr size_t cdp_tlv_hdr = 4;

constexpr uint16_t be16(const uint8_t *p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// The byte order the device ipdata records have always used
uint32_t ipdata_addr(const kis_l3::ip_addr& a) {
    uint32_t addr;
    memcpy(&addr, a.a.data(), 4);
    return kis_hton32(addr);
}

// A host address a lease can hand out: not 0/8, loopback, multicast or above
constexpr bool usable_v4(const kis_l3::ip_addr& a) {
    return a.family == 4 && a.a[0] != 0 && a.a[0] != 127 && a.a[0] < 224;
}

std::string clean(std::string_view s) {
    return kis_l3::escape_hidden(munge_to_printable(s.data(), s.length()));
}

}

int ipdata_packethook(CHAINCALL_PARMS) {
	return ((kis_dissector_ip_data *) auxdata)->handle_packet(in_pack);
}

kis_dissector_ip_data::kis_dissector_ip_data() {
    auto packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();

    packetchain->register_handler(&ipdata_packethook, this,
            CHAINPOS_DATADISSECT, -100);

	pack_comp_basicdata =
		packetchain->register_packet_component("BASICDATA");

	pack_comp_datapayload =
		packetchain->register_packet_component("DATAPAYLOAD");

    auto alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();

	alert_dhcpclient_ref =
		alertracker->activate_configured_alert("DHCPCLIENTID",
                "SPOOF", kis_alert_severity::low,
                "A DHCP client sending a DHCP Discovery packet should "
                "provide a Client-ID tag (Tag 61) which matches the source "
                "MAC of the packet.  A client which fails to do so may "
                "be attempting to exhaust the DHCP pool with spoofed requests.");

}

kis_dissector_ip_data::~kis_dissector_ip_data() {
    Globalreg::globalreg->remove_global(global_name());

    auto packetchain =
        Globalreg::fetch_global_as<packet_chain>();

    if (packetchain != nullptr)
        packetchain->remove_handler(&ipdata_packethook, CHAINPOS_DATADISSECT);
}

// CDP over LLC/SNAP: device and port id
int kis_dissector_ip_data::handle_cdp(const std::shared_ptr<kis_packet>& in_pack,
        const uint8_t *data, size_t len) {
    // The TLVs start after the version, TTL and checksum; frames that aren't version 2 have
    // always been read from 15, which is kept
    size_t offset = data[snap_len] == 2 ? snap_len + 4 : 15;

    std::string dev_id, port_id;

    while (offset < len && len - offset >= cdp_tlv_hdr) {
        const uint16_t elemtype = be16(data + offset);
        const size_t elemlen = be16(data + offset + 2);

        if (elemlen == 0 || elemlen > len - offset)
            break;

        if (elemtype == 0x01 || elemtype == 0x03) {
            if (elemlen < cdp_tlv_hdr) {
                _MSG_ERROR("Corrupt CDP frame (possibly an exploit attempt), discarded");
                return 0;
            }

            auto v = clean(std::string_view(reinterpret_cast<const char *>(data + offset + cdp_tlv_hdr),
                        elemlen - cdp_tlv_hdr));

            if (elemtype == 0x01)
                dev_id = std::move(v);
            else
                port_id = std::move(v);
        }

        offset += elemlen;
    }

    if (dev_id.empty() && port_id.empty())
        return 1;

    auto datainfo = std::make_shared<kis_data_packinfo>();
    datainfo->proto = proto_cdp;
    datainfo->cdp_dev_id = std::move(dev_id);
    datainfo->cdp_port_id = std::move(port_id);
    in_pack->insert(pack_comp_basicdata, datainfo);

    return 1;
}

int kis_dissector_ip_data::handle_packet(std::shared_ptr<kis_packet> in_pack) {
	if (in_pack->error)
		return 0;

    // Only 802.11 inserts the data payload; it starts at the LLC header
	auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_datapayload);

	if (chunk == nullptr)
		return 0;

	if (chunk->length() == 0)
		return 0;

    if (!in_pack->common_info.common_info_ok) {
        return 0;
    }

    const auto *data = reinterpret_cast<const uint8_t *>(chunk->data());
    const size_t len = chunk->length();

    // +1 for the CDP version byte
    if (len > snap_len + 1 && memcmp(data, cdp_snap, snap_len) == 0)
        return handle_cdp(in_pack, data, len);

    // RFC 1042 SNAP, or 802.1H for the protocols bridged that way
    if (len < snap_len || data[0] != 0xaa || data[1] != 0xaa || data[2] != 0x03 ||
            data[3] != 0 || data[4] != 0 || (data[5] != 0 && data[5] != 0xf8))
        return 1;

    uint16_t ethertype = be16(data + 6);
    size_t offset = snap_len;

    if (ethertype == 0x8100) {
        if (len - offset < 4)
            return 1;
        ethertype = be16(data + offset + 2);
        offset += 4;
    }

    if (ethertype != 0x0800 && ethertype != 0x0806)
        return 1;

    // Reused per thread; reset() clears the strings by length, not by zeroing them
    thread_local kis_l3::frame f;
    f.reset();

    kis_l3::parse_l3(ethertype, data + offset, len - offset, f);

    if (f.l3 == kis_l3::l3_type::arp) {
        if (!f.arp_spa.set())
            return 1;

        auto datainfo = std::make_shared<kis_data_packinfo>();
        datainfo->proto = proto_arp;
        datainfo->ip_source_addr.s_addr = ipdata_addr(f.arp_spa);
        in_pack->insert(pack_comp_basicdata, datainfo);
        return 1;
    }

    // Addresses are set once the 20 byte IPv4 header was captured; the ports need the
    // transport header too
    if (f.l3 != kis_l3::l3_type::ipv4 || !f.ip_src.set() ||
            (f.ip_proto != 6 && f.ip_proto != 17))
        return 1;

    auto datainfo = std::make_shared<kis_data_packinfo>();

    datainfo->proto = f.ip_proto == 17 ? proto_udp : proto_tcp;
    datainfo->ip_source_addr.s_addr = ipdata_addr(f.ip_src);
    datainfo->ip_dest_addr.s_addr = ipdata_addr(f.ip_dst);

    if (f.l4_ok) {
        datainfo->ip_source_port = f.sport;
        datainfo->ip_dest_port = f.dport;
    }

    const auto& dhcp = f.dhcp4;

    if (f.ip_proto == 17 && f.l4_ok && dhcp.valid) {
        if (f.sport == 67 && f.dport == 68 && (dhcp.msgtype == 2 || dhcp.msgtype == 5) &&
                usable_v4(dhcp.yiaddr)) {
            // Broadcast or unicast; phy80211 matches the client by chaddr
            datainfo->proto = dhcp.msgtype == 5 ? proto_dhcp_ack : proto_dhcp_offer;
            datainfo->ip_dest_addr.s_addr = ipdata_addr(dhcp.yiaddr);

            if (dhcp.chaddr_eth)
                datainfo->dhcp_chaddr = mac_addr(dhcp.chaddr.data(), 6);

            if (dhcp.subnet_mask.set())
                datainfo->ip_netmask_addr.s_addr = ipdata_addr(dhcp.subnet_mask);

            if (dhcp.router.set())
                datainfo->ip_gateway_addr.s_addr = ipdata_addr(dhcp.router);
        } else if (in_pack->common_info.dest == Globalreg::globalreg->broadcast_mac &&
                f.sport == 68 && f.dport == 67 && dhcp.msgtype == 1) {
            datainfo->proto = proto_dhcp_discover;

            if (!dhcp.hostname.empty())
                datainfo->discover_host = clean(dhcp.hostname.view());

            if (!dhcp.vendor.empty())
                datainfo->discover_vendor = clean(dhcp.vendor.view());

            // Client id is a type byte and a 6 byte MAC
            if (dhcp.client_id.len == 7) {
                mac_addr clmac(reinterpret_cast<const uint8_t *>(dhcp.client_id.buf.data()) + 1, 6);

                if (clmac != in_pack->common_info.source) {
                    _COMMONALERT(alert_dhcpclient_ref, in_pack,
                            in_pack->common_info.network,
                            censor::format("DHCP request from {} doesn't match DHCP "
                                "DISCOVER client id {} which can indicate a DHCP "
                                "spoofing attack", in_pack->common_info.source, clmac));
                }
            }
        }
    }

    in_pack->insert(pack_comp_basicdata, datainfo);
    return 1;
}
