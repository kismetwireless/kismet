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

#include "globalregistry.h"
#include "util.h"
#include "endian_magic.h"
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"
#include "alertracker.h"

#include "kis_dissector_ipdata.h"
#include "phy_80211_packetsignatures.h"

int get_length_tag_offsets(unsigned int init_offset, 
        std::shared_ptr<kis_datachunk> in_chunk, std::map<int, std::vector<int> > *tag_cache_map) {
    int cur_tag = 0;
    // Initial offset is 36, that's the first tag
    unsigned int cur_offset = (unsigned int) init_offset;
    uint8_t len;

    // Bail on invalid incoming offsets
    if (init_offset >= in_chunk->length()) {
        return -1;
	}
    
    // If we haven't parsed the tags for this frame before, parse them all now.
    // Return an error code if one of them is malformed.
    if (tag_cache_map->size() == 0) {
        while (1) {
            // Are we over the packet length?
            if (cur_offset + 2 >= in_chunk->length()) {
                break;
            }

            // Read the tag we're on and bail out if we're done
            cur_tag = (int) in_chunk->data()[cur_offset];

            // Move ahead one byte and read the length.
            len = (in_chunk->data()[cur_offset+1] & 0xFF);

            // If this is longer than we have...
            if ((cur_offset + len + 2) > in_chunk->length()) {
                return -1;
            }

            // (*tag_cache_map)[cur_tag] = cur_offset + 1;
			
            (*tag_cache_map)[cur_tag].push_back(cur_offset + 1);

            // Jump the length+length byte, this should put us at the next tag
            // number.
            cur_offset += len+2;
        }
    }
    
    return 0;
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

	pack_comp_common = 
		packetchain->register_packet_component("COMMON");

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

#define MDNS_PTR_MASK		0xC0
#define MDNS_PTR_ADDRESS	0x3FFF

// Fetch a name; if it's a pointer, follow that reference and get the value
// Cache offsets we've looked at in the map so we don't follow them repeatedly
// Bytelen indicates how many bytes to advance the stream; negative indicates
// error
std::string MDNS_Fetchname(std::shared_ptr<kis_datachunk> chunk, unsigned int baseofft, 
					  unsigned int startofft, std::map<unsigned int, std::string> *name_cache,
					  int *bytelen) {
	// If we're fed a bad offset just throw it back
	if (startofft > chunk->length()) {
		*bytelen = -1;
		return "";
	}

	std::string dns_str;

	unsigned int offt = startofft;

	while (offt < chunk->length()) {
		// Find a starting at this position
		uint8_t len = chunk->data()[offt];

		// If we hit a 0x00 we're at the end of the string
		if (len == 0) {
			offt += 1;
			break;
		}

		// Pointer to another value
		if ((len & MDNS_PTR_MASK) == MDNS_PTR_MASK) {
			// Catch wonky records
			if (offt + 1 >= chunk->length()) {
				*bytelen = -1;
				return dns_str;
			}

			// Derive the new start address
			uint16_t ptr = 
				kis_ntoh16(kis_extract16(&(chunk->data()[offt])));

			ptr &= MDNS_PTR_ADDRESS;

			// Get the cached value if we can, instead of following the pointer
			std::map<unsigned int, std::string>::iterator nci = name_cache->find(ptr);
			if (nci != name_cache->end()) {
				if (dns_str == "")
					dns_str = nci->second;
				else
					dns_str += "." + nci->second;
			} else {
				// Set our current location in the map to empty so we won't loop 
				// on a malicious packet with self-referencing compression
				// pointers
				(*name_cache)[offt - baseofft] = "";

				int junklen;
				std::string ret = MDNS_Fetchname(chunk, baseofft, baseofft + ptr, name_cache, 
											&junklen);

				(*name_cache)[offt - baseofft] = ret;

				if (dns_str == "")
					dns_str = ret;
				else
					dns_str += "." + ret;

				// All address pointers are len2 in the buffer
				offt += 2;
			}

			// Pointer record indicates end of string
			break;
		}

		// Skip the length byte
		offt += 1;

		if (offt + len >= chunk->length()) {
			*bytelen = -1;
			return dns_str;
		}

		std::string ret = 
			munge_to_printable(std::string((char *) &(chunk->data()[offt]), len));

		offt += len;

		if (dns_str == "")
			dns_str = ret;
		else
			dns_str += "." + ret;
	}

	*bytelen = (offt - startofft);

	return dns_str;
}

int kis_dissector_ip_data::handle_packet(std::shared_ptr<kis_packet> in_pack) {
    std::shared_ptr<kis_data_packinfo> datainfo;
	uint32_t addr;

	if (in_pack->error)
		return 0;

	auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_datapayload);

	if (chunk == nullptr)
		return 0;

	if (chunk->length() == 0)
		return 0;

	auto common = in_pack->fetch<kis_common_info>(pack_comp_common);

	if (common == nullptr)
		return 0;

	datainfo = std::make_shared<kis_data_packinfo>();

	// CDP cisco discovery frames, good for finding unauthorized APs
	// +1 for the version frame we compare first
	if ((LLC_UI_OFFSET + 1 + sizeof(CISCO_SIGNATURE)) < chunk->length() &&
		memcmp(&(chunk->data()[LLC_UI_OFFSET]), CISCO_SIGNATURE,
			   sizeof(CISCO_SIGNATURE)) == 0) {
		unsigned int offset = 0;

		// Look for frames the old way, maybe v1 used it?  Compare the versions.
		// I don't remember why the code worked this way.
		if (chunk->data()[LLC_UI_OFFSET + sizeof(CISCO_SIGNATURE)] == 2)
			offset = LLC_UI_OFFSET + sizeof(CISCO_SIGNATURE) + 4;
		else
			offset = LLC_UI_OFFSET + 12;

		// Did we get useful info?
		int gotinfo = 0;

		while (offset + CDP_ELEMENT_LEN < chunk->length()) {
		// uint16_t dot1x_length = kis_extract16(&(chunk->data[offset + 2]));
			uint16_t elemtype = kis_ntoh16(kis_extract16(&(chunk->data()[offset + 0])));
			uint16_t elemlen = kis_ntoh16(kis_extract16(&(chunk->data()[offset + 2])));

			if (elemlen == 0)
				break;

			if (offset + elemlen >= chunk->length())
				break;

			if (elemtype == 0x01) {
				// Device id, we care about this
				if (elemlen < 4) {
					_MSG_ERROR("Corrupt CDP frame (possibly an exploit attempt), discarded");
					return 0;
				}

				datainfo->cdp_dev_id = 
					munge_to_printable(std::string((char *) &(chunk->data()[offset + 4]), elemlen - 4));
				gotinfo = 1;
			} else if (elemtype == 0x03) {
				if (elemlen < 4) {
					_MSG_ERROR("Corrupt CDP frame (possibly an exploit attempt), discarded");
					return 0;
				}

				datainfo->cdp_port_id = 
					munge_to_printable(std::string((char *) &(chunk->data()[offset + 4]), elemlen - 4));
				gotinfo = 1;
			}

			offset += elemlen;
		}

		if (gotinfo) {
			datainfo->proto = proto_cdp;
			in_pack->insert(pack_comp_basicdata, datainfo);
			return 1;
		}

	}

	if (kismax(20, ARP_OFFSET + ARP_PACKET_SIZE) < chunk->length() && 
		ARP_OFFSET + sizeof(ARP_SIGNATURE) < chunk->length() &&
		memcmp(&(chunk->data()[ARP_OFFSET]), ARP_SIGNATURE, sizeof(ARP_SIGNATURE)) == 0) {
		// If we look like a ARP frame and we're big enough to be an arp 
		// frame...
		
		datainfo->proto = proto_arp;
		memcpy(&addr, &(chunk->data()[ARP_OFFSET + 16]), 4);
		datainfo->ip_source_addr.s_addr = kis_hton32(addr);
		in_pack->insert(pack_comp_basicdata, datainfo);
		return 1;
	}

	if (kismax(UDP_OFFSET + 4, IP_OFFSET + 11) < chunk->length() && 
		IP_OFFSET + sizeof(TCP_SIGNATURE) < chunk->length() &&
		memcmp(&(chunk->data()[IP_OFFSET]), UDP_SIGNATURE, sizeof(UDP_SIGNATURE)) == 0) {

		// UDP frame...
		datainfo->proto = proto_udp;
		datainfo->ip_source_port = 
			kis_ntoh16(kis_extract16(&(chunk->data()[UDP_OFFSET])));
		datainfo->ip_dest_port = 
			kis_ntoh16(kis_extract16(&(chunk->data()[UDP_OFFSET + 2])));

		memcpy(&addr, &(chunk->data()[IP_OFFSET + 3]), 4);
		datainfo->ip_source_addr.s_addr = kis_hton32(addr);
		memcpy(&addr, &(chunk->data()[IP_OFFSET + 7]), 4);
		datainfo->ip_dest_addr.s_addr = kis_hton32(addr);

		/* DHCP Offer */
		if (common->dest == Globalreg::globalreg->broadcast_mac &&
			datainfo->ip_source_port == 67 &&
			datainfo->ip_dest_port == 68) {

			// Extract the DHCP tags the same way we get IEEE 80211 tags,
			// in fact we can re-use the code
			std::map<int, std::vector<int> > dhcp_tag_map;

			// This is convenient since it won't return anything that is outside
			// the context of the packet, we can feed it the length w/out checking 
			// and we can trust the tags
			get_length_tag_offsets(DHCPD_OFFSET + 252, chunk, &dhcp_tag_map);

			if (dhcp_tag_map.find(53) != dhcp_tag_map.end() &&
				dhcp_tag_map[53].size() != 0 &&
				chunk->data()[dhcp_tag_map[53][0] + 1] == 0x02) {

				// We're a DHCP offer...
				datainfo->proto = proto_dhcp_offer;

				// This should never be possible, but let's check
				if ((DHCPD_OFFSET + 32) >= chunk->length()) {
					return 0;
				}

				memcpy(&addr, &(chunk->data()[DHCPD_OFFSET + 28]), 4);
				datainfo->ip_dest_addr.s_addr = kis_hton32(addr);

				if (dhcp_tag_map.find(1) != dhcp_tag_map.end() &&
					dhcp_tag_map[1].size() != 0) {

					memcpy(&addr, &(chunk->data()[dhcp_tag_map[1][0] + 1]), 4);
					datainfo->ip_netmask_addr.s_addr = kis_hton32(addr);
				}

				if (dhcp_tag_map.find(3) != dhcp_tag_map.end() &&
					dhcp_tag_map[3].size() != 0) {

					memcpy(&addr, &(chunk->data()[dhcp_tag_map[3][0] + 1]), 4);
					datainfo->ip_gateway_addr.s_addr = kis_hton32(addr);
				}
			}
		}

		/* DHCP Discover */
		if (common->dest == Globalreg::globalreg->broadcast_mac &&
			datainfo->ip_source_port == 68 &&
			datainfo->ip_dest_port == 67) {

			// Extract the DHCP tags the same way we get IEEE 80211 tags,
			// in fact we can re-use the code
			std::map<int, std::vector<int> > dhcp_tag_map;

			// This is convenient since it won't return anything that is outside
			// the context of the packet, we can feed it the length w/out checking 
			// and we can trust the tags
			get_length_tag_offsets(DHCPD_OFFSET + 252, chunk, &dhcp_tag_map);

			if (dhcp_tag_map.find(53) != dhcp_tag_map.end() &&
				dhcp_tag_map[53].size() != 0 &&
				chunk->data()[dhcp_tag_map[53][0] + 1] == 0x01) {

				// We're definitely a dhcp discover
				datainfo->proto = proto_dhcp_discover;

				if (dhcp_tag_map.find(12) != dhcp_tag_map.end() &&
					dhcp_tag_map[12].size() != 0) {

					datainfo->discover_host = 
						std::string((char *) &(chunk->data()[dhcp_tag_map[12][0] + 1]), 
							   chunk->data()[dhcp_tag_map[12][0]]);

					datainfo->discover_host = munge_to_printable(datainfo->discover_host);
				}

				if (dhcp_tag_map.find(60) != dhcp_tag_map.end() &&
					dhcp_tag_map[60].size() != 0) {

					datainfo->discover_vendor = 
						std::string((char *) &(chunk->data()[dhcp_tag_map[60][0] + 1]), 
							   chunk->data()[dhcp_tag_map[60][0]]);
					datainfo->discover_vendor = 
						munge_to_printable(datainfo->discover_vendor);
				}

				if (dhcp_tag_map.find(61) != dhcp_tag_map.end() &&
					dhcp_tag_map[61].size() == 7) {
					mac_addr clmac = mac_addr(&(chunk->data()[dhcp_tag_map[61][0] + 2]), 6);

					if (clmac != common->source) {
                        _COMMONALERT(alert_dhcpclient_ref, in_pack, common, 
                                common->network,
                                std::string("DHCP request from ") +
                                common->source.mac_to_string() + 
                                std::string(" doesn't match DHCP DISCOVER client id ") +
                                clmac.mac_to_string() + std::string(" which can indicate "
                                    "a DHCP spoofing attack"));
					}
				}
			}
		}

		// MDNS extractor
		if (datainfo->ip_source_port == 5353 &&
			datainfo->ip_dest_port == 5353) {
			uint16_t mdns_flag_response = (1 << 15);

			uint16_t mdns_flags;
			uint16_t answer_rr = 0, auth_rr = 0, additional_rr = 0;

			// mdns name
			std::string mdns_name;
			std::string mdns_ptr;

			// Skip UDP headers
			unsigned int mdns_start = UDP_OFFSET + 8;
			unsigned int offt = UDP_OFFSET + 8;

			std::map<unsigned int, std::string> mdns_cache;

			// Skip transaction ID, we don't care
			offt += 2;

			if (offt + 2 >= chunk->length())
				goto mdns_end;

			mdns_flags = 
				kis_ntoh16(kis_extract16(&(chunk->data()[offt])));

			// Only care about responses right now
			if ((mdns_flags & mdns_flag_response) == 0) {
				// printf("debug - mdns doesn't look like response, flags %x\n", mdns_flags);
				goto mdns_end;
			}

			// Skip past flags
			offt += 2;

			// Skip Q
			offt += 2;

			if (offt + 8 >= chunk->length())
				goto mdns_end;

			answer_rr = 
				kis_ntoh16(kis_extract16(&(chunk->data()[offt])));
			auth_rr = 
				kis_ntoh16(kis_extract16(&(chunk->data()[offt+2])));
			additional_rr = 
				kis_ntoh16(kis_extract16(&(chunk->data()[offt+4])));

			// answer, auth, additional
			offt += 6;

			if (offt >= chunk->length())
				goto mdns_end;

			// printf("debug - mdns - looking at %u answers\n", answer_rr + auth_rr + additional_rr);
			for (uint32_t a = 0; a < (uint32_t) (answer_rr + auth_rr + additional_rr); a++) {
				int retbytes;

				mdns_name = MDNS_Fetchname(chunk, mdns_start, offt, &mdns_cache, &retbytes);

				if (retbytes <= 0)
					goto mdns_end;

				offt += retbytes;

				// printf("debug - mdns record name: %s\n", mdns_name.c_str());

				if (offt + 2 >= chunk->length()) {
					goto mdns_end;
				}

				uint16_t rec_type;

				rec_type = 
					kis_ntoh16(kis_extract16(&(chunk->data()[offt])));

				// printf("debug - rectype %x\n", rec_type);

				offt += 8;

				if (offt + 2 >= chunk->length()) {
					goto mdns_end;
				}

				uint16_t rec_len;

				rec_len =
					kis_ntoh16(kis_extract16(&(chunk->data()[offt])));

				offt += 2;

				// printf("debug - mdns - record length %u\n", rec_len);

				if (offt + rec_len >= chunk->length())
					goto mdns_end;

				// printf("debug - mdns - rectype %x reclen %u\n", rec_type, rec_len);

				// Only care about PTR records for now
				if (rec_type != 0xC) {
					offt += rec_len;
					continue;
				}

				std::string mdns_rec;

				mdns_rec = MDNS_Fetchname(chunk, mdns_start, offt, &mdns_cache, &retbytes);

				if (retbytes <= 0)
					goto mdns_end;

				offt += retbytes;

				// printf("debug - mdns ptr %s\n", mdns_rec.c_str());
			}

mdns_end:
			;

		}

		in_pack->insert(pack_comp_basicdata, datainfo);
		return 1;

	} // UDP frame

	if (kismax(TCP_OFFSET + 4, IP_OFFSET + TCP_HEADER_SIZE) < chunk->length() && 
		IP_OFFSET + sizeof(TCP_SIGNATURE) < chunk->length() &&
		memcmp(&(chunk->data()[IP_OFFSET]),
			   TCP_SIGNATURE, sizeof(TCP_SIGNATURE)) == 0) {

		// TCP frame...
		datainfo->ip_source_port = 
			kis_ntoh16(kis_extract16(&(chunk->data()[TCP_OFFSET])));
		datainfo->ip_dest_port = 
			kis_ntoh16(kis_extract16(&(chunk->data()[TCP_OFFSET + 2])));

		memcpy(&addr, &(chunk->data()[IP_OFFSET + 3]), 4);
		datainfo->ip_source_addr.s_addr = kis_hton32(addr);
		memcpy(&addr, &(chunk->data()[IP_OFFSET + 7]), 4);
		datainfo->ip_dest_addr.s_addr = kis_hton32(addr);

		datainfo->proto = proto_tcp;

		in_pack->insert(pack_comp_basicdata, datainfo);
		return 1;
	} // TCP frame

	return 1;
}
