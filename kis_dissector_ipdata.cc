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
#include "packetsource.h"
#include "alertracker.h"

#include "kis_dissector_ipdata.h"
#include "packetsignatures.h"

int ipdata_packethook(CHAINCALL_PARMS) {
	return ((Kis_Dissector_IPdata *) auxdata)->HandlePacket(in_pack);
}

Kis_Dissector_IPdata::Kis_Dissector_IPdata(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	globalreg->InsertGlobal("DISSECTOR_IPDATA", this);

	globalreg->packetchain->RegisterHandler(&ipdata_packethook, this,
		 									CHAINPOS_DATADISSECT, -100);

	pack_comp_basicdata = 
		globalreg->packetchain->RegisterPacketComponent("BASICDATA");

	pack_comp_datapayload =
		globalreg->packetchain->RegisterPacketComponent("DATAPAYLOAD");

	pack_comp_common = 
		globalreg->packetchain->RegisterPacketComponent("COMMON");

	alert_dhcpclient_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DHCPCLIENTID");

}

Kis_Dissector_IPdata::~Kis_Dissector_IPdata() {
	globalreg->InsertGlobal("DISSECTOR_IPDATA", NULL);

	globalreg->packetchain->RemoveHandler(&ipdata_packethook, CHAINPOS_DATADISSECT);
}

int Kis_Dissector_IPdata::HandlePacket(kis_packet *in_pack) {
	kis_data_packinfo *datainfo = NULL;

	if (in_pack->error)
		return 0;

	kis_datachunk *chunk =
		(kis_datachunk *) in_pack->fetch(pack_comp_datapayload);

	if (chunk == NULL)
		return 0;

	if (chunk->length == 0)
		return 0;

	kis_common_info *common = 
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	if (common == NULL)
		return 0;

	datainfo = new kis_data_packinfo;

	// CDP cisco discovery frames, good for finding unauthorized APs
	// +1 for the version frame we compare first
	if ((LLC_UI_OFFSET + 1 + sizeof(CISCO_SIGNATURE)) < chunk->length &&
		memcmp(&(chunk->data[LLC_UI_OFFSET]), CISCO_SIGNATURE,
			   sizeof(CISCO_SIGNATURE)) == 0) {
		unsigned int offset = 0;

		// Look for frames the old way, maybe v1 used it?  Compare the versions.
		// I don't remember why the code worked this way.
		if (chunk->data[LLC_UI_OFFSET + sizeof(CISCO_SIGNATURE)] == 2)
			offset = LLC_UI_OFFSET + sizeof(CISCO_SIGNATURE) + 4;
		else
			offset = LLC_UI_OFFSET + 12;

		// Did we get useful info?
		int gotinfo = 0;

		while (offset + CDP_ELEMENT_LEN < chunk->length) {
		// uint16_t dot1x_length = kis_extract16(&(chunk->data[offset + 2]));
			uint16_t elemtype = kis_ntoh16(kis_extract16(&(chunk->data[offset + 0])));
			uint16_t elemlen = kis_ntoh16(kis_extract16(&(chunk->data[offset + 2])));

			if (elemlen == 0)
				break;

			if (offset + elemlen >= chunk->length)
				break;

			if (elemtype == 0x01) {
				// Device id, we care about this
				if (elemlen < 4) {
					_MSG("Corrupt CDP frame (possibly an exploit attempt), discarded",
						 MSGFLAG_ERROR);
					delete(datainfo);
					return 0;
				}

				datainfo->cdp_dev_id = 
					MungeToPrintable((char *) &(chunk->data[offset + 4]), 
									 elemlen - 4, 0);
				gotinfo = 1;
			} else if (elemtype == 0x03) {
				if (elemlen < 4) {
					_MSG("Corrupt CDP frame (possibly an exploit attempt), discarded",
						 MSGFLAG_ERROR);
					delete(datainfo);
					return 0;
				}

				datainfo->cdp_port_id = 
					MungeToPrintable((char *) &(chunk->data[offset + 4]), 
									 elemlen - 4, 0);
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

	if (kismax(20, ARP_OFFSET + ARP_PACKET_SIZE) < chunk->length && 
		ARP_OFFSET + sizeof(ARP_SIGNATURE) < chunk->length &&
		memcmp(&(chunk->data[ARP_OFFSET]),
			   ARP_SIGNATURE, sizeof(ARP_SIGNATURE)) == 0) {
		// If we look like a ARP frame and we're big enough to be an arp 
		// frame...
		
		datainfo->proto = proto_arp;
		memcpy(&(datainfo->ip_source_addr.s_addr),
			   &(chunk->data[ARP_OFFSET + 16]), 4);
		in_pack->insert(pack_comp_basicdata, datainfo);
		return 1;
	}

	if (kismax(UDP_OFFSET + 4, IP_OFFSET + 11) < chunk->length && 
		IP_OFFSET + sizeof(TCP_SIGNATURE) < chunk->length &&
		memcmp(&(chunk->data[IP_OFFSET]),
			   UDP_SIGNATURE, sizeof(UDP_SIGNATURE)) == 0) {

		// UDP frame...
		datainfo->ip_source_port = 
			kis_ntoh16(kis_extract16(&(chunk->data[UDP_OFFSET])));
		datainfo->ip_dest_port = 
			kis_ntoh16(kis_extract16(&(chunk->data[UDP_OFFSET + 2])));

		memcpy(&(datainfo->ip_source_addr.s_addr),
			   &(chunk->data[IP_OFFSET + 3]), 4);
		memcpy(&(datainfo->ip_dest_addr.s_addr),
			   &(chunk->data[IP_OFFSET + 7]), 4);

#if 0
		if (datainfo->ip_source_port == IAPP_PORT &&
			datainfo->ip_dest_port == IAPP_PORT &&
			(IAPP_OFFSET + IAPP_HEADER_SIZE) < chunk->length) {

			uint8_t iapp_version = 
				chunk->data[IAPP_OFFSET];
			uint8_t iapp_type =
				chunk->data[IAPP_OFFSET + 1];

			// If we can't understand the iapp version, bail and return the
			// UDP frame we DID decode
			if (iapp_version != 1) {
				in_pack->insert(pack_comp_basicdata, datainfo);
				return 1;
			}

			// Same again -- bail on UDP if we can't make sense of this
			switch (iapp_type) {
				case iapp_announce_request:
				case iapp_announce_response:
				case iapp_handover_request:
				case iapp_handover_response:
					break;
				default:
					in_pack->insert(pack_comp_basicdata, datainfo);
					return 1;
					break;
			}

			unsigned int pdu_offset = IAPP_OFFSET + IAPP_HEADER_SIZE;

			while (pdu_offset + IAPP_PDUHEADER_SIZE < chunk->length) {
				uint8_t *pdu = &(chunk->data[pdu_offset]);
				uint8_t pdu_type = pdu[0];
				uint8_t pdu_len = pdu[1];

				// If we have a short/malformed PDU frame, bail
				if ((pdu_offset + 3 + pdu_len) >= chunk->length) {
					delete datainfo;
					return 0;
				}

				switch (pdu_type) {
					case iapp_pdu_ssid:
						if (pdu_len > SSID_SIZE)
							break;

						packinfo->ssid = 
							MungeToPrintable((char *) &(pdu[3]), pdu_len, 0);
						break;
					case iapp_pdu_bssid:
						if (pdu_len != PHY80211_MAC_LEN)
							break;

						packinfo->bssid_mac = mac_addr(&(pdu[3]), PHY80211_MAC_LEN);
						break;
					case iapp_pdu_capability:
						if (pdu_len != 1)
							break;
						if ((pdu[3] & iapp_cap_wep))
							packinfo->cryptset |= crypt_wep;
						break;
					case iapp_pdu_channel:
						if (pdu_len != 1)
							break;
						packinfo->channel = (int) pdu[3];
						break;
					case iapp_pdu_beaconint:
						if (pdu_len != 2)
							break;
						packinfo->beacon_interval = (int) ((pdu[3] << 8) | pdu[4]);
						break;
					case iapp_pdu_oldbssid:
					case iapp_pdu_msaddr:
					case iapp_pdu_announceint:
					case iapp_pdu_hotimeout:
					case iapp_pdu_messageid:
					case iapp_pdu_phytype:
					case iapp_pdu_regdomain:
					case iapp_pdu_ouiident:
					case iapp_pdu_authinfo:
					default:
						break;
				}
				pdu_offset += pdu_len + 3;
			}

			datainfo->proto = proto_iapp;
			in_pack->insert(pack_comp_basicdata, datainfo);
			return 1;
		} // IAPP port

		if ((datainfo->ip_source_port == ISAKMP_PORT ||
			 datainfo->ip_dest_port == ISAKMP_PORT) &&
			(ISAKMP_OFFSET + ISAKMP_PACKET_SIZE) < chunk->length) {
			
			datainfo->proto = proto_isakmp;
			datainfo->field1 = 
				chunk->data[ISAKMP_OFFSET + 4];

			packinfo->cryptset |= crypt_isakmp;
			
			in_pack->insert(pack_comp_basicdata, datainfo);
			return 1;

		}
#endif

		/* DHCP Offer */
		if (common->dest == globalreg->broadcast_mac &&
			datainfo->ip_source_port == 67 &&
			datainfo->ip_dest_port == 68) {

			// Extract the DHCP tags the same way we get IEEE 80211 tags,
			// infact we can re-use the code
			map<int, vector<int> > dhcp_tag_map;

			// This is convenient since it won't return anything that is outside
			// the context of the packet, we can feed it the length w/out checking 
			// and we can trust the tags
			GetLengthTagOffsets(DHCPD_OFFSET + 252, chunk, &dhcp_tag_map);

			if (dhcp_tag_map.find(53) != dhcp_tag_map.end() &&
				dhcp_tag_map[53].size() != 0 &&
				chunk->data[dhcp_tag_map[53][0] + 1] == 0x02) {

				// We're a DHCP offer...
				datainfo->proto = proto_dhcp_offer;

				// This should never be possible, but let's check
				if ((DHCPD_OFFSET + 32) >= chunk->length) {
					delete datainfo;
					return 0;
				}

				memcpy(&(datainfo->ip_dest_addr.s_addr), 
					   &(chunk->data[DHCPD_OFFSET + 28]), 4);

				if (dhcp_tag_map.find(1) != dhcp_tag_map.end() &&
					dhcp_tag_map[1].size() != 0) {

					memcpy(&(datainfo->ip_netmask_addr.s_addr), 
						   &(chunk->data[dhcp_tag_map[1][0] + 1]), 4);
				}

				if (dhcp_tag_map.find(3) != dhcp_tag_map.end() &&
					dhcp_tag_map[3].size() != 0) {

					memcpy(&(datainfo->ip_gateway_addr.s_addr), 
						   &(chunk->data[dhcp_tag_map[3][0] + 1]), 4);
				}
			}
		}

		/* DHCP Discover */
		if (common->dest == globalreg->broadcast_mac &&
			datainfo->ip_source_port == 68 &&
			datainfo->ip_dest_port == 67) {

			// Extract the DHCP tags the same way we get IEEE 80211 tags,
			// infact we can re-use the code
			map<int, vector<int> > dhcp_tag_map;

			// This is convenient since it won't return anything that is outside
			// the context of the packet, we can feed it the length w/out checking 
			// and we can trust the tags
			GetLengthTagOffsets(DHCPD_OFFSET + 252, chunk, &dhcp_tag_map);

			if (dhcp_tag_map.find(53) != dhcp_tag_map.end() &&
				dhcp_tag_map[53].size() != 0 &&
				chunk->data[dhcp_tag_map[53][0] + 1] == 0x01) {

				// We're definitely a dhcp discover
				datainfo->proto = proto_dhcp_discover;

				if (dhcp_tag_map.find(12) != dhcp_tag_map.end() &&
					dhcp_tag_map[12].size() != 0) {

					datainfo->discover_host = 
						string((char *) &(chunk->data[dhcp_tag_map[12][0] + 1]), 
							   chunk->data[dhcp_tag_map[12][0]]);

					datainfo->discover_host = MungeToPrintable(datainfo->discover_host);
				}

				if (dhcp_tag_map.find(60) != dhcp_tag_map.end() &&
					dhcp_tag_map[60].size() != 0) {

					datainfo->discover_vendor = 
						string((char *) &(chunk->data[dhcp_tag_map[60][0] + 1]), 
							   chunk->data[dhcp_tag_map[60][0]]);
					datainfo->discover_vendor = 
						MungeToPrintable(datainfo->discover_vendor);
				}

				if (dhcp_tag_map.find(61) != dhcp_tag_map.end() &&
					dhcp_tag_map[61].size() == 7) {
					mac_addr clmac = mac_addr(&(chunk->data[dhcp_tag_map[61][0] + 2]),
											  MAC_STD_LEN);

					if (clmac != common->source) {
						_COMMONALERT(alert_dhcpclient_ref, in_pack, common, 
							 string("DHCP request from ") +
							 common->source.Mac2String() + 
							 string(" doesn't match DHCP DISCOVER client id ") +
							 clmac.Mac2String() + string(" which can indicate "
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
			string mdns_name;
			string mdns_ptr;

			// Skip UDP headers
			unsigned int offt = UDP_OFFSET + 8;

			// Skip transaction ID, we don't care
			offt += 2;

			if (offt + 2 >= chunk->length)
				goto mdns_end;

			mdns_flags = 
				kis_ntoh16(kis_extract16(&(chunk->data[offt])));

			// Only care about responses right now
			if ((mdns_flags & mdns_flag_response) == 0) {
				// printf("debug - mdns doesn't look like response, flags %x\n", mdns_flags);
				goto mdns_end;
			}

			// Skip past flags
			offt += 2;

			// Skip Q
			offt += 2;

			if (offt + 8 >= chunk->length)
				goto mdns_end;

			answer_rr = 
				kis_ntoh16(kis_extract16(&(chunk->data[offt])));
			auth_rr = 
				kis_ntoh16(kis_extract16(&(chunk->data[offt+2])));
			additional_rr = 
				kis_ntoh16(kis_extract16(&(chunk->data[offt+4])));

			// answer, auth, additional
			offt += 6;

			if (offt >= chunk->length)
				goto mdns_end;

			// printf("debug - mdns - looking at %u answers\n", answer_rr + auth_rr + additional_rr);
			for (unsigned int a = 0; a < (answer_rr + auth_rr + additional_rr); a++) {
				// printf("debug - mdns - looking at answer %u\n", a);

				for (unsigned int s = offt; s < chunk->length; ) {
					uint8_t len = chunk->data[s];

					if (len == 0) {
						offt = s + 1;
						break;
					}

					// Skip pointers to other names
					if (len == 0xC0) {
						offt = s + 2;
						break;
					}

					// printf("debug - mdns string fragment %u\n", len);

					// Length byte
					s += 1;

					if (s + len >= chunk->length)
						goto mdns_end;

					// printf("debug - mdns string %s\n", MungeToPrintable((char *) &(chunk->data[s]), len, 0).c_str());

					mdns_name += MungeToPrintable((char *) &(chunk->data[s]), len, 0) + ".";

					s += len;

				}

				// printf("debug - mdns name: %s\n", mdns_name.c_str());

				if (offt + 2 >= chunk->length)
					goto mdns_end;

				// printf("debug - mdns debug %02x %02x %02x %02x\n", chunk->data[offt], chunk->data[offt+1], chunk->data[offt+2], chunk->data[offt+3]);

				uint16_t rec_type;

				rec_type = 
					kis_ntoh16(kis_extract16(&(chunk->data[offt])));

				offt += 8;

				if (offt + 2 >= chunk->length)
					goto mdns_end;

				uint16_t rec_len;

				rec_len =
					kis_ntoh16(kis_extract16(&(chunk->data[offt])));

				offt += 2;

				// printf("debug - mdns - record length %u\n", rec_len);

				if (offt + rec_len >= chunk->length)
					goto mdns_end;

				// Only care about PTR records for now
				if (rec_type != 0xC) {
					// printf("debug - mdns - not a PTR record, skipping\n");
					offt += rec_len;
					continue;
				}

				// Skip non-explicit records
				if (rec_len <= 2) {
					offt += rec_len;
					continue;
				}


				string mdns_rec;

				for (unsigned int s = offt; s < chunk->length; ) {
					uint8_t len = chunk->data[s];

					if (len == 0) {
						break;
					}

					if (len == 0xC0) {
						s += 2;
						continue;
					}

					// Length byte
					s += 1;

					if (s + len >= chunk->length) {
						// printf("debug - mdns - bogus record length %u\n", len);
						goto mdns_end;
					}

					mdns_rec += MungeToPrintable((char *) &(chunk->data[s]), len, 0) + ".";

					s += len;
				}

				// printf("debug - mdns ptr %s\n", mdns_rec.c_str());

				offt += rec_len;
			}

mdns_end:
			;

		}

		in_pack->insert(pack_comp_basicdata, datainfo);
		return 1;

	} // UDP frame

	if (kismax(TCP_OFFSET + 4, IP_OFFSET + TCP_HEADER_SIZE) < chunk->length && 
		IP_OFFSET + sizeof(TCP_SIGNATURE) < chunk->length &&
		memcmp(&(chunk->data[IP_OFFSET]),
			   TCP_SIGNATURE, sizeof(TCP_SIGNATURE)) == 0) {

		// TCP frame...
		datainfo->ip_source_port = 
			kis_ntoh16(kis_extract16(&(chunk->data[TCP_OFFSET])));
		datainfo->ip_dest_port = 
			kis_ntoh16(kis_extract16(&(chunk->data[TCP_OFFSET + 2])));

		memcpy(&(datainfo->ip_source_addr.s_addr),
			   &(chunk->data[IP_OFFSET + 3]), 4);
		memcpy(&(datainfo->ip_dest_addr.s_addr),
			   &(chunk->data[IP_OFFSET + 7]), 4);

		datainfo->proto = proto_tcp;

		/*
		if (datainfo->ip_source_port == PPTP_PORT || 
			datainfo->ip_dest_port == PPTP_PORT) {
			datainfo->proto = proto_pptp;
			packinfo->cryptset |= crypt_pptp;
		}
		*/

		in_pack->insert(pack_comp_basicdata, datainfo);
		return 1;
	} // TCP frame

	// Trash the data if we didn't fill it in
	delete(datainfo);

	return 1;
}
