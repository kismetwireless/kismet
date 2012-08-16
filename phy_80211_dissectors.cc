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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <map>
#include <iomanip>
#include <sstream>

#include "endian_magic.h"
#include "phy_80211.h"
#include "packetsignatures.h"
#include "packetchain.h"
#include "alertracker.h"
#include "configfile.h"
#include "packetsource.h"

// Handly little global so that it only has to do the ascii->mac_addr transform once
mac_addr broadcast_mac = "FF:FF:FF:FF:FF:FF";

// CRC32 index for verifying WEP - cribbed from ethereal
static const uint32_t dot11_wep_crc32_table[256] = {
    0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
    0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
    0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
    0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
    0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
    0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
    0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
    0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
    0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
    0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
    0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
    0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
    0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
    0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
    0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
    0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
    0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
    0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
    0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
    0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
    0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
    0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
    0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
    0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
    0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
    0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
    0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
    0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
    0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
    0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
    0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
    0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
    0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
    0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
    0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
    0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
    0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
    0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
    0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
    0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
    0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
    0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
    0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
    0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
    0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
    0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
    0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
    0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
    0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
    0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
    0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
    0x2d02ef8dL
};

// Convert WPA cipher elements into crypt_set stuff
int Kis_80211_Phy::WPACipherConv(uint8_t cipher_index) {
	int ret = crypt_wpa;

	switch (cipher_index) {
		case 1:
			ret |= crypt_wep40;
			break;
		case 2:
			ret |= crypt_tkip;
			break;
		case 3:
			ret |= crypt_aes_ocb;
			break;
		case 4:
			ret |= crypt_aes_ccm;
			break;
		case 5:
			ret |= crypt_wep104;
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
}

// Convert WPA key management elements into crypt_set stuff
int Kis_80211_Phy::WPAKeyMgtConv(uint8_t mgt_index) {
	int ret = crypt_wpa;

	switch (mgt_index) {
		case 1:
			ret |= crypt_wpa;
			break;
		case 2:
			ret |= crypt_psk;
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
}

// This needs to be optimized and it needs to not use casting to do its magic
int Kis_80211_Phy::PacketDot11dissector(kis_packet *in_pack) {
	static int debugpcknum = 0;

	if (in_pack->error) {
		return 0;
	}

	debugpcknum++;
	// printf("debug - packet %d\n", debugpcknum);

    // Extract data, bail if it doesn't exist, make a local copy of what we're
    // inserting into the frame.
    dot11_packinfo *packinfo;
	kis_datachunk *chunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_decap);

	// If we can't grab an 802.11 chunk, grab the raw link frame
	if (chunk == NULL) {
		chunk = (kis_datachunk *) in_pack->fetch(pack_comp_linkframe);
		if (chunk == NULL) {
			return 0;
		}
	}

	// If we don't have a dot11 frame, throw it away
	if (chunk->dlt != KDLT_IEEE802_11)
		return 0;

	kis_ref_capsource *capsrc =
		(kis_ref_capsource *) in_pack->fetch(_PCM(PACK_COMP_KISCAPSRC));
	packet_parm srcparms;
	if (capsrc != NULL)
		srcparms = capsrc->ref_source->FetchGenericParms();

	// Flat-out dump if it's not big enough to be 80211, don't even bother making a
	// packinfo record for it because we're completely broken
    if (chunk->length < 10) {
        return 0;
	}

	kis_common_info *common = 
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	if (common == NULL) {
		common = new kis_common_info;
		in_pack->insert(pack_comp_common, common);
	}

	common->phyid = phyid;

    packinfo = new dot11_packinfo;

    frame_control *fc = (frame_control *) chunk->data;

	// Inherit the FC privacy flag
	if (fc->wep)
		packinfo->cryptset |= crypt_wep;

    uint16_t duration = 0;

    // 18 bytes of normal address ranges
    uint8_t *addr0 = NULL;
    uint8_t *addr1 = NULL;
    uint8_t *addr2 = NULL;
    // And an optional 6 bytes of address range for ds=0x03 packets
    uint8_t *addr3 = NULL;

    // We'll fill these in as we go
    packinfo->type = packet_unknown;
    packinfo->subtype = packet_sub_unknown;
    packinfo->distrib = distrib_unknown;

    // Endian swap the duration  ** Optimize this in the future **
    memcpy(&duration, &(chunk->data[2]), 2);
    duration = kis_ntoh16(duration);

    // 2 bytes of sequence and fragment counts
    wireless_fragseq *sequence;

	// We always have addr0 even on phy
    addr0 = &(chunk->data[4]);
	// We may have addr2
	if (chunk->length >= 16)
		addr1 = &(chunk->data[10]);

	if (fc->more_fragments)
		packinfo->fragmented = 1;

	if (fc->retry)
		packinfo->retry = 1;

    // Assign the distribution direction this packet is traveling
    if (fc->to_ds == 0 && fc->from_ds == 0)
        packinfo->distrib = distrib_adhoc; 
    else if (fc->to_ds == 0 && fc->from_ds == 1)
        packinfo->distrib = distrib_from;
    else if (fc->to_ds == 1 && fc->from_ds == 0)
        packinfo->distrib = distrib_to;
    else if (fc->to_ds == 1 && fc->from_ds == 1)
        packinfo->distrib = distrib_inter;

	// Shortcut PHYs here because they're shorter than normal packets
    if (fc->type == packet_phy) {
        packinfo->type = packet_phy;

		common->type = packet_basic_phy;

        // Throw away large phy packets just like we throw away large management.
        // Phy stuff is all really small, so we set the limit smaller.
        if (chunk->length > 128) {
            packinfo->corrupt = 1;
			in_pack->insert(pack_comp_80211, packinfo);
            return 0;
        }

		if (fc->subtype == 10) {
			packinfo->subtype = packet_sub_pspoll;

			if (addr0 == NULL) {
				packinfo->corrupt = 1;
				packinfo->corrupt = 1;
				in_pack->insert(pack_comp_80211, packinfo);
				return 0;
			}

            packinfo->source_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr0, PHY80211_MAC_LEN);

		} else if (fc->subtype == 11) {
            packinfo->subtype = packet_sub_rts;

			if (addr0 == NULL || addr1 == NULL) {
				packinfo->corrupt = 1;
				packinfo->corrupt = 1;
				in_pack->insert(pack_comp_80211, packinfo);
				return 0;
			}

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);

        } else if (fc->subtype == 12) {
            packinfo->subtype = packet_sub_cts;

			if (addr0 == NULL) {
				packinfo->corrupt = 1;
				packinfo->corrupt = 1;
				in_pack->insert(pack_comp_80211, packinfo);
				return 0;
			}

			packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);

        } else if (fc->subtype == 13) {
            packinfo->subtype = packet_sub_ack;

			if (addr0 == NULL) {
				packinfo->corrupt = 1;
				packinfo->corrupt = 1;
				in_pack->insert(pack_comp_80211, packinfo);
				return 0;
			}

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);

        } else if (fc->subtype == 14) {
            packinfo->subtype = packet_sub_cf_end;

        } else if (fc->subtype == 15) {
            packinfo->subtype = packet_sub_cf_end_ack;

        } else {
            packinfo->subtype = packet_sub_unknown;
        }

		// Nothing more to do if we get a phy
		in_pack->insert(pack_comp_80211, packinfo);
		return 1;
	}

	// Anything from this point on can't be less than 24 bytes since we need
	// a full 802.11 header, so throw it out
	// Flat-out dump if it's not big enough to be 80211.
    if (chunk->length < 24) {
		packinfo->corrupt = 1;
		in_pack->insert(pack_comp_80211, packinfo);
        return 0;
	}

    addr1 = &(chunk->data[10]);
    addr2 = &(chunk->data[16]);
    sequence = (wireless_fragseq *) &(chunk->data[22]);
    addr3 = &(chunk->data[24]);

    packinfo->sequence_number = sequence->sequence;
    packinfo->frag_number = sequence->frag;

    unsigned int tag_offset = 0;
	unsigned int taglen = 0;

    // Rip apart management frames
    if (fc->type == packet_management) {
        packinfo->type = packet_management;

        packinfo->distrib = distrib_unknown;

        // Throw away large management frames that don't make any sense.  512b is 
        // an arbitrary number to pick, but this should keep some drivers from messing
        // with us
		// TODO: Make this a driver option
        if (chunk->length > 512) {
            packinfo->corrupt = 1;
            in_pack->insert(pack_comp_80211, packinfo);
            return 0;
        }

        fixed_parameters *fixparm = NULL;

        if (fc->subtype == 0) {
            packinfo->subtype = packet_sub_association_req;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

        } else if (fc->subtype == 1) {
            packinfo->subtype = packet_sub_association_resp;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

        } else if (fc->subtype == 2) {
            packinfo->subtype = packet_sub_reassociation_req;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

        } else if (fc->subtype == 3) {
            packinfo->subtype = packet_sub_reassociation_resp;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

        } else if (fc->subtype == 4) {
            packinfo->subtype = packet_sub_probe_req;

            packinfo->distrib = distrib_to;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);
            
        } else if (fc->subtype == 5) {
            packinfo->subtype = packet_sub_probe_resp;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);
        } else if (fc->subtype == 8) {
            packinfo->subtype = packet_sub_beacon;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            // If beacons aren't do a broadcast destination, consider them corrupt.
            if (packinfo->dest_mac != broadcast_mac) 
                packinfo->corrupt = 1;
            
        } else if (fc->subtype == 9) {
            // I'm not positive this is the right handling of atim packets.  
			// Do something smarter in the future
            packinfo->subtype = packet_sub_atim;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            packinfo->distrib = distrib_unknown;

        } else if (fc->subtype == 10) {
            packinfo->subtype = packet_sub_disassociation;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            uint16_t rcode;
            memcpy(&rcode, (const char *) &(chunk->data[24]), 2);

            packinfo->mgt_reason_code = rcode;

        } else if (fc->subtype == 11) {
            packinfo->subtype = packet_sub_authentication;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            uint16_t rcode;
            memcpy(&rcode, (const char *) &(chunk->data[24]), 2);

            packinfo->mgt_reason_code = rcode;

        } else if (fc->subtype == 12) {
            packinfo->subtype = packet_sub_deauthentication;

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            uint16_t rcode;
            memcpy(&rcode, (const char *) &(chunk->data[24]), 2);

            packinfo->mgt_reason_code = rcode;
        } else {
            packinfo->subtype = packet_sub_unknown;
        }

		// add management addr packet
		common->source = packinfo->source_mac;
		common->dest = packinfo->dest_mac;
		common->device = packinfo->bssid_mac;
		common->type = packet_basic_mgmt;

        if (fc->subtype == packet_sub_probe_req || 
			fc->subtype == packet_sub_disassociation || 
			fc->subtype == packet_sub_authentication || 
			fc->subtype == packet_sub_deauthentication) {
			// Shortcut handling of probe req, disassoc, auth, deauth since they're
			// not normal management frames
            packinfo->header_offset = 24;
            fixparm = NULL;
        } else {
			// If we're not long enough to have the fixparm and look like a normal
			// mgt header, bail.
			if (chunk->length < 36) {
				packinfo->corrupt = 1;
				in_pack->insert(pack_comp_80211, packinfo);
				return 0;
			}
            packinfo->header_offset = 36;
            fixparm = (fixed_parameters *) &(chunk->data[24]);
			if (fixparm->wep) {
				packinfo->cryptset |= crypt_wep;
			}

			// Set the transmitter info
			packinfo->ess = fixparm->ess;
			packinfo->ibss = fixparm->ibss;

            // Pull the fixparm ibss info
            if (fixparm->ess == 0 && fixparm->ibss == 1) {
                packinfo->distrib = distrib_adhoc;
            }

            // Pull the fixparm timestamp
            uint64_t temp_ts;
            memcpy(&temp_ts, fixparm->timestamp, 8);
#ifdef WORDS_BIGENDIAN
            packinfo->timestamp = kis_swap64(temp_ts);
#else
            packinfo->timestamp = temp_ts;
#endif
        }

		// Look for MSF opcode beacons before tag decode
		if (fc->subtype == packet_sub_beacon &&
			packinfo->source_mac == msfopcode_mac) {

			_ALERT(alert_msfbcomssid_ref, in_pack, packinfo,
				   "MSF-style poisoned beacon packet for Broadcom drivers detected");
		}

		if (fc->subtype == packet_sub_beacon &&
			chunk->length >= 1184) {
			if (memcmp(&(chunk->data[1180]), "\x6a\x39\x58\x01", 4) == 0)
				_ALERT(alert_msfnetgearbeacon_ref, in_pack, packinfo,
					   "MSF-style poisoned options in over-sized beacon for Netgear "
					   "driver attack");
		}

        map<int, vector<int> > tag_cache_map;
        map<int, vector<int> >::iterator tcitr;

        // Extract various tags from the packet
        int found_ssid_tag = 0;
        int found_rate_tag = 0;
        int found_channel_tag = 0;

        if (fc->subtype == packet_sub_beacon || 
			fc->subtype == packet_sub_probe_req || 
			fc->subtype == packet_sub_probe_resp) {

			if (fc->subtype == packet_sub_beacon)
				packinfo->beacon_interval = kis_letoh16(fixparm->beacon);

			packinfo->ietag_csum = 
				Adler32Checksum((const char *) (chunk->data + packinfo->header_offset),
								chunk->length - packinfo->header_offset);

            // This is guaranteed to only give us tags that fit within the packets,
            // so we don't have to do more error checking
            if (GetLengthTagOffsets(packinfo->header_offset, chunk, 
									&tag_cache_map) < 0) {
				if (srcparms.weak_dissect == 0) {
					// The frame is corrupt, bail
					packinfo->corrupt = 1;
					in_pack->insert(pack_comp_80211, packinfo);
					return 0;
				}
            }
     
            if ((tcitr = tag_cache_map.find(0)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];

                found_ssid_tag = 1;
                taglen = (chunk->data[tag_offset] & 0xFF);
                packinfo->ssid_len = taglen;

                // Protect against malicious packets
                if (taglen == 0) {
                    // do nothing for 0-length ssid's
                } else if (taglen <= DOT11_PROTO_SSID_LEN) {
					// Test the SSID for cloaked len!=0 data==0 situation,
					// then munge it to something printable if it makes sense
					// to do so

					int zeroed = 1;
					for (unsigned int sp = 0; sp < taglen; sp++) {
						if (chunk->data[tag_offset+sp+1] != 0) {
							zeroed = 0;
							break;
						}
					}

					if (zeroed == 0) {
						packinfo->ssid = 
							MungeToPrintable((char *) 
											 &(chunk->data[tag_offset+1]), taglen, 0);
					} else {
						packinfo->ssid_blank = 1;
					}
                } else { 
					_ALERT(alert_longssid_ref, in_pack, packinfo,
						   "Illegal SSID (greater than 32 bytes) detected, this "
						   "likely indicates an exploit attempt against a client");
                    // Otherwise we're corrupt, set it and stop processing
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
                }
            } else {
                packinfo->ssid_len = 0;
            }

            // Probe req's with no SSID are bad
			if (fc->subtype == packet_sub_probe_resp) {
				if (found_ssid_tag == 0) {
					packinfo->corrupt = 1;
					in_pack->insert(pack_comp_80211, packinfo);
					return 0;
				}
			}

            // Extract the CISCO beacon info
            if ((tcitr = tag_cache_map.find(133)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];
                taglen = (chunk->data[tag_offset] & 0xFF);

				// Copy and munge the beacon info if it falls w/in our
				// boundaries
				if ((tag_offset + 11) < chunk->length && taglen >= 11) {
					packinfo->beacon_info = 
						MungeToPrintable((char *) &(chunk->data[tag_offset+11]), 
										 taglen - 11, 1);
                }

				// Other conditions on beacon info non-fatal
            }

            // Extract the supported rates
            if ((tcitr = tag_cache_map.find(1)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];
                taglen = (chunk->data[tag_offset] & 0xFF);

				if (tag_offset + taglen > chunk->length) {
                    // Otherwise we're corrupt, set it and stop processing
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
				}

				for (unsigned int t = 0; t < tcitr->second.size(); t++) {
					int moffset = tcitr->second[t];

					if ((chunk->data[moffset] & 0xFF) == 75 &&
						memcmp(&(chunk->data[moffset + 1]), "\xEB\x49", 2) == 0) {

						_ALERT(alert_msfdlinkrate_ref, in_pack, packinfo,
							   "MSF-style poisoned rate field in beacon for network " +
							   packinfo->bssid_mac.Mac2String() + ", exploit attempt "
							   "against D-Link drivers");

						packinfo->corrupt = 1;
						in_pack->insert(pack_comp_80211, packinfo);
						return 0;
					}
				}

                found_rate_tag = 1;
                for (unsigned int x = 0; x < taglen; x++) {
                    if (packinfo->maxrate < 
						(chunk->data[tag_offset+1+x] & 0x7F) * 0.5)
                        packinfo->maxrate = 
							(chunk->data[tag_offset+1+x] & 0x7F) * 0.5;
                }
            }

			// And the extended supported rates
            if ((tcitr = tag_cache_map.find(50)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];
                taglen = (chunk->data[tag_offset] & 0xFF);

				if (tag_offset + taglen > chunk->length) {
                    // Otherwise we're corrupt, set it and stop processing
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
				}

                found_rate_tag = 1;
                for (unsigned int x = 0; x < taglen; x++) {
                    if (packinfo->maxrate < 
						(chunk->data[tag_offset+1+x] & 0x7F) * 0.5)
                        packinfo->maxrate = 
							(chunk->data[tag_offset+1+x] & 0x7F) * 0.5;
                }
            }

            // If beacons don't have a SSID and a basicrate then we consider them
            // corrupt
            if (found_ssid_tag == 0 || found_rate_tag == 0) {
                packinfo->corrupt = 1;
			}

            // Find the offset of flag 3 and get the channel.   802.11a doesn't have 
            // this tag so we use the hardware channel, assigned at the beginning of 
            // GetPacketInfo
            if ((tcitr = tag_cache_map.find(3)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];
                found_channel_tag = 1;
                // Extract the channel from the next byte (GetTagOffset returns
                // us on the size byte)
                taglen = (chunk->data[tag_offset] & 0xFF);

				if (tag_offset + taglen > chunk->length) {
                    // Otherwise we're corrupt, set it and stop processing
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
				}
				
                packinfo->channel = (int) (chunk->data[tag_offset+1]);
            }

            if ((tcitr = tag_cache_map.find(7)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];

                taglen = (chunk->data[tag_offset] & 0xFF);

				tag_offset++;

				if (tag_offset + taglen > chunk->length) {
					packinfo->corrupt = 1;
					in_pack->insert(pack_comp_80211, packinfo);
					return 0;
				}
			
				// country tags only valid if 6 bytes or more, ubnt throws
				// broken ones on some APs
				if (taglen > 6) {
					packinfo->dot11d_country =
						MungeToPrintable(string((const char *) 
												&(chunk->data[tag_offset]), 
												0, 3));

					// We don't have to check taglen since we check that above
					for (unsigned int p = 3; p + 3 <= taglen; p += 3) {
						dot11_11d_range_info ri;

						ri.startchan = chunk->data[tag_offset + p];
						ri.numchan = chunk->data[tag_offset + p + 1];
						ri.txpower = chunk->data[tag_offset + p + 2];

						packinfo->dot11d_vec.push_back(ri);
					}
				}
			}

			// WPA frame matching if we have the privacy bit set
			if ((packinfo->cryptset & crypt_wep)) {
				// Liberally borrowed from Ethereal
				if ((tcitr = tag_cache_map.find(221)) != tag_cache_map.end()) {
					for (unsigned int tagct = 0; tagct < tcitr->second.size(); 
						 tagct++) {
						tag_offset = tcitr->second[tagct];
						unsigned int tag_orig = tag_offset + 1;
						unsigned int taglen = (chunk->data[tag_offset] & 0xFF);
						unsigned int offt = 0;

						if (tag_orig + taglen > chunk->length) {
							packinfo->corrupt = 1;
							in_pack->insert(pack_comp_80211, packinfo);
							return 0;
						}

						// Match 221 tag header for WPA
						if (taglen < 6)
							continue;

						if (memcmp(&(chunk->data[tag_orig + offt]), 
								   WPA_OUI, sizeof(WPA_OUI)))
							continue;

						offt += 6;

						// Match WPA multicast suite
						if (offt + 4 > taglen)
							continue;
						
						if (memcmp(&(chunk->data[tag_orig + offt]), WPA_OUI,
								   sizeof(WPA_OUI)))
							continue;

						packinfo->cryptset |= 
							WPACipherConv(chunk->data[tag_orig + offt + 3]);

						// We don't care about parsing the number of ciphers,
						// we'll just iterate, so skip the cipher number
						offt += 6;

						// Match WPA unicast components
						while (offt + 4 <= taglen) {
							if (memcmp(&(chunk->data[tag_orig + offt]), 
									  WPA_OUI, sizeof(WPA_OUI)) == 0) {
								packinfo->cryptset |= 
									WPACipherConv(chunk->data[tag_orig + offt + 3]);
								offt += 4;
							} else {
								break;
							}
						}

						// WPA Migration Mode
						if ((packinfo->cryptset & crypt_tkip) && 
							((packinfo->cryptset & crypt_wep40) || 
							 (packinfo->cryptset & crypt_wep104)) )
							packinfo->cryptset |= crypt_wpa_migmode;

						// Match auth key components
						offt += 2;
						while (offt + 4 <= taglen) {
							if (memcmp(&(chunk->data[tag_orig + offt]), 
									  WPA_OUI, sizeof(WPA_OUI)) == 0) {
								packinfo->cryptset |= 
									WPAKeyMgtConv(chunk->data[tag_orig + offt + 3]);
								offt += 4;
							} else {
								break;
							}
						}
					}
				} /* 221 */

				// Match tag 48 RSN WPA2
				if ((tcitr = tag_cache_map.find(48)) != tag_cache_map.end()) {
					for (unsigned int tagct = 0; tagct < tcitr->second.size(); 
						 tagct++) {
						tag_offset = tcitr->second[tagct];
						unsigned int tag_orig = tag_offset + 1;
						unsigned int taglen = (chunk->data[tag_offset] & 0xFF);
						unsigned int offt = 0;

						if (tag_orig + taglen > chunk->length || taglen < 6) {
							packinfo->corrupt = 1;
							in_pack->insert(pack_comp_80211, packinfo);
							return 0;
						}

						// Skip version
						offt += 2;

						// Match multicast
						if (offt + 3 > taglen ||
							memcmp(&(chunk->data[tag_orig + offt]), RSN_OUI,
								   sizeof(RSN_OUI))) {
							packinfo->corrupt = 1;
							in_pack->insert(pack_comp_80211, packinfo);
							return 0;
						}

						packinfo->cryptset |= 
							WPACipherConv(chunk->data[tag_orig + offt + 3]);
						offt += 4;

						// We don't care about unicast number
						offt += 2;

						while (offt + 4 <= taglen) {
							if (memcmp(&(chunk->data[tag_orig + offt]), 
									  RSN_OUI, sizeof(RSN_OUI)) == 0) {
								packinfo->cryptset |= 
									WPACipherConv(chunk->data[tag_orig + offt + 3]);
								offt += 4;
							} else {
								break;
							}
						}

						// We don't care about authkey number
						offt += 2;

						while (offt + 4 <= taglen) {
							if (memcmp(&(chunk->data[tag_orig + offt]), 
									  RSN_OUI, sizeof(RSN_OUI)) == 0) {
								packinfo->cryptset |= 
									WPAKeyMgtConv(chunk->data[tag_orig + offt + 3]);
								offt += 4;
							} else {
								break;
							}
						}
					}
				} /* 48 */
			} /* protected frame */

			/* Look for WPS */
			if ((tcitr = tag_cache_map.find(221)) != tag_cache_map.end()) {
				for (unsigned int tagct = 0; tagct < tcitr->second.size(); 
					 tagct++) {

					tag_offset = tcitr->second[tagct];
					unsigned int tag_orig = tag_offset + 1;
					unsigned int taglen = (chunk->data[tag_offset] & 0xFF);
					unsigned int offt = 0;

					// Corrupt tag
					if (tag_orig + taglen > chunk->length) {
						packinfo->corrupt = 1;
						in_pack->insert(pack_comp_80211, packinfo);
						return 0;
					}

					if (offt + sizeof(MSF_OUI) > taglen)
						continue;

					// WPS is always under MSF
					if (memcmp(&(chunk->data[tag_orig + offt]), 
							   MSF_OUI, sizeof(MSF_OUI)))
						continue;

					// OUI + 1 - random byte after OUI in tags
					offt += sizeof(MSF_OUI) + 1;

					if (offt + sizeof(WPS_VERSION) > taglen)
						continue;

					if (memcmp(&(chunk->data[tag_orig + offt]),
							   WPS_VERSION, sizeof(WPS_VERSION)))
						continue;

					offt += sizeof(WPS_VERSION);

					if (offt + sizeof(WPS_CONFIGURED) > taglen)
						continue;

					if (memcmp(&(chunk->data[tag_orig + offt]),
							   WPS_CONFIGURED, sizeof(WPS_CONFIGURED)))
						continue;

					// printf("debug - got WPS network!\n");
					packinfo->cryptset |= crypt_wps;

				} /* tagfor */
			} /* 221/WPS */

        } else if (fc->subtype == packet_sub_deauthentication) {
			if ((packinfo->mgt_reason_code >= 25 && packinfo->mgt_reason_code <= 31) ||
				packinfo->mgt_reason_code > 45) {

				_ALERT(alert_deauthinvalid_ref, in_pack, packinfo,
					   "Unknown deauthentication code " +
					   HexIntToString(packinfo->mgt_reason_code) + 
					   " from network " + packinfo->bssid_mac.Mac2String());
			}
        } else if (fc->subtype == packet_sub_disassociation) {
			if ((packinfo->mgt_reason_code >= 25 && packinfo->mgt_reason_code <= 31) ||
				packinfo->mgt_reason_code > 45) {

				_ALERT(alert_disconinvalid_ref, in_pack, packinfo,
					   "Unknown disassociation code " +
					   HexIntToString(packinfo->mgt_reason_code) + 
					   " from network " + packinfo->bssid_mac.Mac2String());
			}
		}

    } else if (fc->type == 2) {
        packinfo->type = packet_data;

        // Collect the subtypes - we probably want to do something better with thse
        // in the future
        if (fc->subtype == 0) {
            packinfo->subtype = packet_sub_data;

        } else if (fc->subtype == 1) {
            packinfo->subtype = packet_sub_data_cf_ack;

        } else if (fc->subtype == 2) {
            packinfo->subtype = packet_sub_data_cf_poll;

        } else if (fc->subtype == 3) {
            packinfo->subtype = packet_sub_data_cf_ack_poll;

        } else if (fc->subtype == 4) {
            packinfo->subtype = packet_sub_data_null;

        } else if (fc->subtype == 5) {
            packinfo->subtype = packet_sub_cf_ack;

        } else if (fc->subtype == 6) {
            packinfo->subtype = packet_sub_cf_ack_poll;
		} else if (fc->subtype == 8) {
			// Ugly hack, do this better
			packinfo->subtype = packet_sub_data_qos_data;
			// printf("debug - qos data, offset +2, %u to %u\n", packinfo->header_offset, packinfo->header_offset + 2);
			packinfo->header_offset += 2;
		} else if (fc->subtype == 9) {
			// Ugly hack, do this better
			packinfo->subtype = packet_sub_data_qos_data_cf_ack;
			packinfo->header_offset += 2;
		} else if (fc->subtype == 10) {
			// Ugly hack, do this better
			packinfo->subtype = packet_sub_data_qos_data_cf_poll;
			packinfo->header_offset += 2;
		} else if (fc->subtype == 11) {
			// Ugly hack, do this better
			packinfo->subtype = packet_sub_data_qos_data_cf_ack_poll;
			packinfo->header_offset += 2;
		} else if (fc->subtype == 12) {
			// Ugly hack, do this better
			packinfo->subtype = packet_sub_data_qos_null;
			packinfo->header_offset += 2;
		} else if (fc->subtype == 14) {
			// Ugly hack, do this better
			packinfo->subtype = packet_sub_data_qos_cf_poll_nod;
			packinfo->header_offset += 2;
		} else if (fc->subtype == 15) {
			// Ugly hack, do this better
			packinfo->subtype = packet_sub_data_qos_cf_ack_poll;
			packinfo->header_offset += 2;
        } else {
            packinfo->corrupt = 1;
            packinfo->subtype = packet_sub_unknown;
			in_pack->insert(pack_comp_80211, packinfo);
            return 0;
        }

        // Extract ID's
        switch (packinfo->distrib) {
        case distrib_adhoc:

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            if (packinfo->bssid_mac.longmac == 0)
                packinfo->bssid_mac = packinfo->source_mac;

            packinfo->header_offset += 24;
            break;
        case distrib_from:
            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            packinfo->header_offset += 24;
            break;
        case distrib_to:
            packinfo->bssid_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->dest_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            packinfo->header_offset += 24;
            break;
        case distrib_unknown:
            // If we aren't long enough to hold a intra-ds packet, bail
            if (chunk->length < 30) {
                packinfo->corrupt = 1;
				in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->bssid_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr3, PHY80211_MAC_LEN);
            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);

            packinfo->distrib = distrib_inter;

            // First byte of offsets
            packinfo->header_offset += 30;
            break;
        default:
            packinfo->corrupt = 1;
			in_pack->insert(pack_comp_80211, packinfo);
            return 0;
            break;
        }

		// add data addr packet
		common->source = packinfo->source_mac;
		common->dest = packinfo->dest_mac;
		common->device = packinfo->bssid_mac;
		common->type = packet_basic_data;


		// WEP/Protected on data frames means encrypted, not WEP, sometimes
		if (fc->wep) {
			bool alt_crypt = false;
			// Either way to be useful it has to be 2+ bytes, so check tkip
			// and ccmp at the same time
			if (packinfo->header_offset + 2 < chunk->length) {
				if (chunk->data[packinfo->header_offset + 2] == 0) {
					packinfo->cryptset |= crypt_aes_ccm;
					alt_crypt = true;
				}  else if (chunk->data[packinfo->header_offset + 1] & 0x20) {
					packinfo->cryptset |= crypt_tkip;
					alt_crypt = true;
				}
			}  
		
			if (!alt_crypt)
				packinfo->cryptset |= crypt_wep;
		}

        int datasize = chunk->length - packinfo->header_offset;
        if (datasize > 0) {
            packinfo->datasize = datasize;
			common->datasize = datasize;
		}

		if (packinfo->cryptset == 0 && dissect_data) {
			// Keep whatever datachunk we already found
			kis_datachunk *datachunk = 
				(kis_datachunk *) in_pack->fetch(pack_comp_datapayload);

			if (datachunk == NULL) {
				// Don't set a DLT on the data payload, since we don't know what it is
				// but it's not 802.11.
				datachunk = new kis_datachunk;
				datachunk->set_data(chunk->data + packinfo->header_offset,
									chunk->length - packinfo->header_offset, false);
				in_pack->insert(pack_comp_datapayload, datachunk);
			}

			if (datachunk->length > LLC_UI_OFFSET + sizeof(PROBE_LLC_SIGNATURE) && 
				memcmp(&(datachunk->data[0]), LLC_UI_SIGNATURE,
					   sizeof(LLC_UI_SIGNATURE)) == 0) {
				// Handle the batch of frames that fall under the LLC UI 0x3 frame
				if (memcmp(&(datachunk->data[LLC_UI_OFFSET]),
						   PROBE_LLC_SIGNATURE, sizeof(PROBE_LLC_SIGNATURE)) == 0) {

					// Packets that look like netstumber probes...
					if (NETSTUMBLER_OFFSET + sizeof(NETSTUMBLER_322_SIGNATURE) < 
						datachunk->length && 
						memcmp(&(datachunk->data[NETSTUMBLER_OFFSET]),
							   NETSTUMBLER_322_SIGNATURE, 
							   sizeof(NETSTUMBLER_322_SIGNATURE)) == 0) {
						_ALERT(alert_netstumbler_ref, in_pack, packinfo,
							   "Detected Netstumbler 3.22 probe");
					}

					if (NETSTUMBLER_OFFSET + sizeof(NETSTUMBLER_323_SIGNATURE) < 
						datachunk->length && 
						memcmp(&(datachunk->data[NETSTUMBLER_OFFSET]),
							   NETSTUMBLER_323_SIGNATURE, 
							   sizeof(NETSTUMBLER_323_SIGNATURE)) == 0) {
						_ALERT(alert_netstumbler_ref, in_pack, packinfo,
							   "Detected Netstumbler 3.23 probe");
					}

					if (NETSTUMBLER_OFFSET + sizeof(NETSTUMBLER_330_SIGNATURE) < 
						datachunk->length && 
						memcmp(&(datachunk->data[NETSTUMBLER_OFFSET]),
							   NETSTUMBLER_330_SIGNATURE, 
							   sizeof(NETSTUMBLER_330_SIGNATURE)) == 0) {
						_ALERT(alert_netstumbler_ref, in_pack, packinfo,
							   "Detected Netstumbler 3.30 probe");
					}

					if (LUCENT_OFFSET + sizeof(LUCENT_TEST_SIGNATURE) < 
						datachunk->length && 
						memcmp(&(datachunk->data[LUCENT_OFFSET]),
							   LUCENT_TEST_SIGNATURE, 
							   sizeof(LUCENT_TEST_SIGNATURE)) == 0) {
						_ALERT(alert_lucenttest_ref, in_pack, packinfo,
							   "Detected Lucent probe/link test");
					}

					_ALERT(alert_netstumbler_ref, in_pack, packinfo,
						   "Detected what looks like a Netstumber probe but didn't "
						   "match known version fingerprint");
				} // LLC_SIGNATURE
			} // LLC_UI

			// Fortress LLC
			if ((LLC_UI_OFFSET + 1 + sizeof(FORTRESS_SIGNATURE)) < 
				datachunk->length && memcmp(&(datachunk->data[LLC_UI_OFFSET]), 
											FORTRESS_SIGNATURE,
					   sizeof(FORTRESS_SIGNATURE)) == 0) {
				packinfo->cryptset |= crypt_fortress;
			}

			// Dot1x frames
			// +1 for the version byte at header_offset + hot1x off
			// +3 for the offset past LLC_UI
			if ((LLC_UI_OFFSET + 4 + sizeof(DOT1X_PROTO)) < chunk->length && 
				memcmp(&(chunk->data[LLC_UI_OFFSET + 3]),
					   DOT1X_PROTO, sizeof(DOT1X_PROTO)) == 0) {

				kis_data_packinfo *datainfo = new kis_data_packinfo;

				datainfo->proto = proto_eap;

				// printf("debug - dot1x frame?\n");
				// It's dot1x, is it LEAP?
				//
				// Make sure its an EAP socket
				unsigned int offset = DOT1X_OFFSET;

				// Dot1x bits
				uint8_t dot1x_version = chunk->data[offset];
				uint8_t dot1x_type = chunk->data[offset + 1];
				// uint16_t dot1x_length = kis_extract16(&(chunk->data[offset + 2]));

				offset += EAP_OFFSET;

				if (dot1x_version != 1 || dot1x_type != 0 || 
					offset + EAP_PACKET_SIZE > chunk->length) {
					delete datainfo;
					goto eap_end;
				}

				// Eap bits
				uint8_t eap_code = chunk->data[offset];
				// uint8_t eap_id = chunk->data[offset + 1];
				uint16_t eap_length = kis_extractBE16(&(chunk->data[offset + 2]));
				uint8_t eap_type = chunk->data[offset + 4];

				unsigned int rawlen;
				char *rawid;

				if (offset + eap_length > chunk->length) {
					delete datainfo;
					goto eap_end;
				}

				packinfo->cryptset |= crypt_eap;
				switch (eap_type) {
					case EAP_TYPE_LEAP:
						datainfo->field1 = eap_code;
						packinfo->cryptset |= crypt_leap;
						break;
					case EAP_TYPE_TLS:
						datainfo->field1 = eap_code;
						packinfo->cryptset |= crypt_tls;
						break;
					case EAP_TYPE_TTLS:
						datainfo->field1 = eap_code;
						packinfo->cryptset |= crypt_ttls;
						break;
					case EAP_TYPE_PEAP:
						// printf("debug - peap!\n");
						datainfo->field1 = eap_code;
						packinfo->cryptset |= crypt_peap;
						break;
					case EAP_TYPE_IDENTITY:
						if (eap_code == EAP_CODE_RESPONSE) {

							rawlen = eap_length - 5;
							rawid = new char[rawlen + 1];
							memcpy(rawid, &(chunk->data[offset + 5]), rawlen);
							rawid[rawlen] = 0;

							datainfo->auxstring = MungeToPrintable(rawid, rawlen, 1);
							delete[] rawid;
						}

						break;
					default:
						break;
				}

				in_pack->insert(pack_comp_basicdata, datainfo);
			}

eap_end:
			;

		}
	}

	// Do a little sanity checking on the BSSID
	if (packinfo->bssid_mac.error == 1 ||
		packinfo->source_mac.error == 1 ||
		packinfo->dest_mac.error == 1) {
		packinfo->corrupt = 1;
	}

	in_pack->insert(pack_comp_80211, packinfo);

	return 1;
}

kis_datachunk *Kis_80211_Phy::DecryptWEP(dot11_packinfo *in_packinfo,
											   kis_datachunk *in_chunk,
											   unsigned char *in_key, int in_key_len,
											   unsigned char *in_id) {
	kis_datachunk *manglechunk = NULL;

	// printf("debug - decryptwep\n");
	if (in_packinfo->corrupt)
		return NULL;

	// printf("debug - decryptwep dlt %u want %u\n", in_chunk->dlt, KDLT_IEEE802_11);
	// If we don't have a dot11 frame, throw it away
	if (in_chunk->dlt != KDLT_IEEE802_11)
		return NULL;

	// printf("debug - decryptwep size len %u offt %u\n", in_chunk->length, in_packinfo->header_offset);
	// Bail on size check
	if (in_chunk->length < in_packinfo->header_offset ||
		in_chunk->length - in_packinfo->header_offset <= 8)
		return NULL;

	// printf("debug - decryptwep data header offt %u test head %02x %02x %02x %02x offt %02x %02x %02x %02x\n", in_packinfo->header_offset, in_chunk->data[0], in_chunk->data[1], in_chunk->data[2], in_chunk->data[3], in_chunk->data[in_packinfo->header_offset], in_chunk->data[in_packinfo->header_offset+1], in_chunk->data[in_packinfo->header_offset+2], in_chunk->data[in_packinfo->header_offset+3]);

	// printf("debug - password\n");
	// Password field
	char pwd[WEPKEY_MAX + 3];
	memset(pwd, 0, WEPKEY_MAX + 3);

	// Extract the IV and add it to the key
	pwd[0] = in_chunk->data[in_packinfo->header_offset + 0] & 0xFF;
	pwd[1] = in_chunk->data[in_packinfo->header_offset + 1] & 0xFF;
	pwd[2] = in_chunk->data[in_packinfo->header_offset + 2] & 0xFF;

	// Add the supplied password to the key
	memcpy(pwd + 3, in_key, WEPKEY_MAX);
	int pwdlen = 3 + in_key_len;

	// printf("debug - wep stuff\n");

	// Prepare the keyblock for the rc4 cipher
	unsigned char keyblock[256];
	memcpy(keyblock, in_id, 256);
	int kba = 0, kbb = 0;
	for (kba = 0; kba < 256; kba++) {
		kbb = (kbb + keyblock[kba] + pwd[kba % pwdlen]) & 0xFF;
		unsigned char oldkey = keyblock[kba];
		keyblock[kba] = keyblock[kbb];
		keyblock[kbb] = oldkey;
	}

	// Allocate the mangled chunk -- 4 byte IV/Key# gone, 4 byte ICV gone
	manglechunk = new kis_datachunk;
	manglechunk->dlt = KDLT_IEEE802_11;

#if 0
	manglechunk->length = in_chunk->length - 8;
	manglechunk->data = new uint8_t[manglechunk->length];

	// Copy the packet headers to the new chunk
	memcpy(manglechunk->data, in_chunk->data, in_packinfo->header_offset);
#endif
	
	// Copy because we're modifying
	manglechunk->set_data(in_chunk->data, in_chunk->length - 8, true);

	// Decrypt the data payload and check the CRC
	kba = kbb = 0;
	uint32_t crc = ~0;
	uint8_t c_crc[4];
	uint8_t icv[4];

	// Copy the ICV into the CRC buffer for checking
	memcpy(icv, &(in_chunk->data[in_chunk->length - 4]), 4);
	// printf("debug - icv %02x %02x %02x %02x\n", icv[0], icv[1], icv[2], icv[3]);

	for (unsigned int dpos = in_packinfo->header_offset + 4; 
		 dpos < in_chunk->length - 4; dpos++) {
		kba = (kba + 1) & 0xFF;
		kbb = (kbb + keyblock[kba]) & 0xFF;

		unsigned char oldkey = keyblock[kba];
		keyblock[kba] = keyblock[kbb];
		keyblock[kbb] = oldkey;

		// Decode the packet into the mangle chunk
		manglechunk->data[dpos - 4] = 
			in_chunk->data[dpos] ^ keyblock[(keyblock[kba] + keyblock[kbb]) & 0xFF];

		crc = dot11_wep_crc32_table[(crc ^ manglechunk->data[dpos - 4]) & 0xFF] ^ (crc >> 8);
	}

	// Check the CRC
	crc = ~crc;
	c_crc[0] = crc;
	c_crc[1] = crc >> 8;
	c_crc[2] = crc >> 16;
	c_crc[3] = crc >> 24;

	int crcfailure = 0;
	for (unsigned int crcpos = 0; crcpos < 4; crcpos++) {
		kba = (kba + 1) & 0xFF;
		kbb = (kbb + keyblock[kba]) & 0xFF;

		unsigned char oldkey = keyblock[kba];
		keyblock[kba] = keyblock[kbb];
		keyblock[kbb] = oldkey;

		if ((c_crc[crcpos] ^ keyblock[(keyblock[kba] + 
									   keyblock[kbb]) & 0xFF]) != icv[crcpos]) {
			crcfailure = 1;
			break;
		}
	}

	// If the CRC check failed, delete the moddata
	if (crcfailure) {
		delete manglechunk;
		return NULL;
	}

	// Remove the privacy flag in the mangled data
    frame_control *fc = (frame_control *) manglechunk->data;
	fc->wep = 0;

	return manglechunk;
}

int Kis_80211_Phy::PacketWepDecryptor(kis_packet *in_pack) {
	kis_datachunk *manglechunk = NULL;

	if (in_pack->error)
		return 0;

	// Grab the 80211 info, compare, bail
    dot11_packinfo *packinfo;
	if ((packinfo = 
		 (dot11_packinfo *) in_pack->fetch(_PCM(PACK_COMP_80211))) == NULL)
		return 0;
	if (packinfo->corrupt)
		return 0;
	if (packinfo->type != packet_data || 
		(packinfo->subtype != packet_sub_data &&
		 packinfo->subtype != packet_sub_data_qos_data))
		return 0;

	// No need to look at data thats already been decoded
	if (packinfo->cryptset == 0 || packinfo->decrypted == 1)
		return 0;

	// Grab the 80211 frame, if that doesn't exist, grab the link frame
	kis_datachunk *chunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_decap);

	if (chunk == NULL) {
		if ((chunk = 
			 (kis_datachunk *) in_pack->fetch(pack_comp_linkframe)) == NULL) {
			return 0;
		}
	}

	// If we don't have a dot11 frame, throw it away
	if (chunk->dlt != KDLT_IEEE802_11)
		return 0;

	// Bail if we can't find a key match
	macmap<dot11_wep_key *>::iterator bwmitr = wepkeys.find(packinfo->bssid_mac);
	if (bwmitr == wepkeys.end())
		return 0;

	manglechunk = DecryptWEP(packinfo, chunk, (*bwmitr->second)->key,
							 (*bwmitr->second)->len, wep_identity);

	if (manglechunk == NULL) {
		(*bwmitr->second)->failed++;
		return 0;
	}

	(*bwmitr->second)->decrypted++;
	// printf("debug - flagging packet as decrypted\n");
	packinfo->decrypted = 1;

	in_pack->insert(pack_comp_mangleframe, manglechunk);

	kis_datachunk *datachunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_datapayload);

	in_pack->insert(pack_comp_datapayload, NULL);

	if (datachunk != NULL)
		delete datachunk;

	if (manglechunk->length > packinfo->header_offset) {
		datachunk = new kis_datachunk;

		datachunk->set_data(manglechunk->data + packinfo->header_offset,
							manglechunk->length - packinfo->header_offset,
							false);
	}

	return 1;
}

#if 0
int Kis_80211_Phy::PacketDot11stringDissector(kis_packet *in_pack) {
	if (dissect_strings == 0)
		return 0;

	kis_string_info *stringinfo = NULL;
	vector<string> parsed_strings;

	if (in_pack->error)
		return 0;

	// Grab the 80211 info, compare, bail
    dot11_packinfo *packinfo;
	if ((packinfo = 
		 (dot11_packinfo *) in_pack->fetch(_PCM(PACK_COMP_80211))) == NULL)
		return 0;
	if (packinfo->corrupt)
		return 0;
	if (packinfo->type != packet_data || 
		(packinfo->subtype != packet_sub_data &&
		 packinfo->subtype != packet_sub_data_qos_data))
		return 0;

	// If it's encrypted and hasn't been decrypted, we can't do anything
	// smart with it, so toss.
	if (packinfo->cryptset != 0 && packinfo->decrypted == 0)
		return 0;

	if (dissect_all_strings == 0 && dissect_strings) {
		if (string_nets.find(packinfo->bssid_mac) == string_nets.end() &&
			string_nets.find(packinfo->source_mac) == string_nets.end() &&
			string_nets.find(packinfo->dest_mac) == string_nets.end()) {
			return 0;
		}
	}
	
	// Grab the mangled frame if we have it, then try to grab up the list of
	// data types and die if we can't get anything
	kis_datachunk *chunk = 
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_MANGLEFRAME));

	if (chunk == NULL) {
		if ((chunk = 
			 (kis_datachunk *) in_pack->fetch(pack_comp_decap)) == NULL) {
			if ((chunk = (kis_datachunk *) 
				 in_pack->fetch(pack_comp_linkframe)) == NULL) {
				return 0;
			}
		}
	}

	// If we don't have a dot11 frame, throw it away
	if (chunk->dlt != KDLT_IEEE802_11)
		return 0;

	// Blow up on no content
    if (packinfo->header_offset > chunk->length)
        return 0;

	string str;
	int pos = 0;
	int printable = 0;
	for (unsigned int x = packinfo->header_offset; x < chunk->length; x++) {
		if (printable && !isprint(chunk->data[x]) && pos != 0) {
			if (pos > 4 && 
				string_filter->RunFilter(packinfo->bssid_mac, packinfo->source_mac,
										 packinfo->dest_mac) == 0 &&
				string_filter->RunPcreFilter(str) == 0) {
				str = MungeToPrintable(str);

				// Cache it in the packet
				parsed_strings.push_back(str);
			}

			str = "";
			pos = 0;
			printable = 0;
		} else if (isprint(chunk->data[x])) {
			str += (char) chunk->data[x];
			pos++;
			printable = 1;
		}
	}

	if (parsed_strings.size() <= 0)
		return 0;

	stringinfo =
		(kis_string_info *) in_pack->fetch(_PCM(PACK_COMP_STRINGS));

	if (stringinfo == NULL) {
		stringinfo = new kis_string_info;
		in_pack->insert(_PCM(PACK_COMP_STRINGS), stringinfo);
	}

	stringinfo->extracted_strings = parsed_strings;

	return 1;
}
#endif

int Kis_80211_Phy::PacketDot11WPSM3(kis_packet *in_pack) {
	if (in_pack->error)
		return 0;

	// Grab the 80211 info, compare, bail
    dot11_packinfo *packinfo;
	if ((packinfo = 
		 (dot11_packinfo *) in_pack->fetch(_PCM(PACK_COMP_80211))) == NULL)
		return 0;
	if (packinfo->corrupt)
		return 0;
	if (packinfo->type != packet_data || 
		(packinfo->subtype != packet_sub_data &&
		 packinfo->subtype != packet_sub_data_qos_data))
		return 0;

	// If it's encrypted it's not eapol
	if (packinfo->cryptset)
		return 0;

	// Grab the 80211 frame, if that doesn't exist, grab the link frame
	kis_datachunk *chunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_decap);

	if (chunk == NULL) {
		if ((chunk = 
			 (kis_datachunk *) in_pack->fetch(pack_comp_linkframe)) == NULL) {
			return 0;
		}
	}

	// If we don't have a dot11 frame, throw it away
	if (chunk->dlt != KDLT_IEEE802_11)
		return 0;

    if (packinfo->header_offset >= chunk->length)
        return 0;

	unsigned int pos = packinfo->header_offset;

	uint8_t eapol_llc[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e };
	uint8_t dot1x_v1_hdr[] = { 0x01, 0x00 };
	uint8_t eapreq = 0x01;
	uint8_t eaptype_et = 0xfe;
	uint8_t wfawps[] = { 0x00, 0x37, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x04 };
	uint8_t wfa_msg[] = { 0x10, 0x22 };
	uint8_t wfa_m3 = 0x07;

	if (pos + sizeof(eapol_llc) >= chunk->length)
		return 0;

	if (memcmp(&(chunk->data[pos]), eapol_llc, sizeof(eapol_llc)))
		return 0;

	// printf("debug - potential eapol frame, matched llc\n");

	pos += sizeof(eapol_llc);

	if (pos + sizeof(dot1x_v1_hdr) >= chunk->length)
		return 0;

	if (memcmp(&(chunk->data[pos]), dot1x_v1_hdr, sizeof(dot1x_v1_hdr)))
		return 0;

	pos += sizeof(dot1x_v1_hdr);

	// 2 bytes of length, ignore, check before next compare
	pos += 2;

	// Check that it's a request
	if (pos + 1 >= chunk->length)
		return 0;

	// printf("debug - eapreq inspecting %x %x %x\n", chunk->data[pos - 1], chunk->data[pos], chunk->data[pos + 1]);

	if (chunk->data[pos] != eapreq)
		return 0;

	// printf("debug - eap request\n");

	// don't care for id or length
	pos += 4;

	if (pos + 1 >= chunk->length)
		return 0;

	// printf("debug - et %x\n", chunk->data[pos]);

	// Compare expanded type
	if (chunk->data[pos] != eaptype_et)
		return 0;

	pos += 1;

	// printf("debug - got past eaptype hdr\n");

	if (pos + sizeof(wfawps) >= chunk->length)
		return 0;

	if (memcmp(&(chunk->data[pos]), wfawps, sizeof(wfawps)))
		return 0;

	pos += sizeof(wfawps);

	// printf("debug - got wfawps eapol content\n");

	// Don't care about flags
	pos += 1;

	while (pos + 5 < chunk->length) {
		uint16_t tlen;
		memcpy(&tlen, &(chunk->data[pos + 2]), 2);
		tlen = kis_betoh16(tlen);

		if (memcmp(&(chunk->data[pos]), wfa_msg, sizeof(wfa_msg))) {
			// printf("debug - skipping tag %x%x %u long\n", chunk->data[pos], chunk->data[pos + 1], tlen);
			pos += 4 + tlen;
			continue;
		}

		if (tlen != 1) {
			// printf("debug - weird eapol wfa len?\n");
			pos += 4 + tlen;
		}

		pos += 4;

		if (chunk->data[pos] == wfa_m3) {
			// printf("debug - saw WPA M3 frame\n");
			return 1;
		}

		pos += tlen;
	}


	return 0;
}


#if 0
void KisBuiltinDissector::AddWepKey(mac_addr bssid, uint8_t *key, unsigned int len, 
									int temp) {
	if (len > WEPKEY_MAX)
		return;

    wep_key_info *winfo = new wep_key_info;

	winfo->decrypted = 0;
	winfo->failed = 0;
    winfo->bssid = bssid;
	winfo->fragile = temp;
    winfo->len = len;

    memcpy(winfo->key, key, len);

    // Replace exiting ones
	if (wepkeys.find(winfo->bssid) != wepkeys.end()) {
		delete wepkeys[winfo->bssid];
		wepkeys[winfo->bssid] = winfo;
		return;
	}

	wepkeys.insert(winfo->bssid, winfo);
}

int KisBuiltinDissector::cmd_listwepkeys(CLIENT_PARMS) {
    if (client_wepkey_allowed == 0) {
        snprintf(errstr, 1024, "Server does not allow clients to fetch keys");
        return -1;
    }

    if (wepkeys.size() == 0) {
        snprintf(errstr, 1024, "Server has no WEP keys");
        return -1;
    }

    if (_NPM(PROTO_REF_WEPKEY) < 0) {
        snprintf(errstr, 1024, "Unable to find WEPKEY protocol");
        return -1;
    }
    
    for (macmap<wep_key_info *>::iterator wkitr = wepkeys.begin(); 
		 wkitr != wepkeys.end(); wkitr++) {
        globalreg->kisnetserver->SendToClient(in_clid, _NPM(PROTO_REF_WEPKEY), 
											  (void *) wkitr->second, NULL);
    }

    return 1;
}

int KisBuiltinDissector::cmd_addwepkey(CLIENT_PARMS) {
    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal addwepkey request");
        return -1;
    }

    vector<string> keyvec = StrTokenize((*parsedcmdline)[1].word, ",");
    if (keyvec.size() != 2) {
        snprintf(errstr, 1024, "Illegal addwepkey request");
        return -1;
    }

	mac_addr bssid = keyvec[0].c_str();
	if (bssid.error) {
		snprintf(errstr, 1024, "Illegal BSSID for addwepkey");
		return -1;
	}

    unsigned char key[WEPKEY_MAX];
    int len = Hex2UChar((unsigned char *) keyvec[1].c_str(), key);

	AddWepKey(bssid, key, len, 1);

    snprintf(errstr, 1024, "Added key %s length %d for BSSID %s",
             (*parsedcmdline)[0].word.c_str(), len, 
			 bssid.Mac2String().c_str());

    _MSG(errstr, MSGFLAG_INFO);

    return 1;
}

int KisBuiltinDissector::cmd_delwepkey(CLIENT_PARMS) {
    if (client_wepkey_allowed == 0) {
        snprintf(errstr, 1024, "Server does not allow clients to modify keys");
        return -1;
    }

    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal delwepkey command");
        return -1;
    }

    mac_addr bssid_mac = (*parsedcmdline)[0].word.c_str();

    if (bssid_mac.error) {
        snprintf(errstr, 1024, "Illegal delwepkey bssid");
        return -1;
    }

    if (wepkeys.find(bssid_mac) == wepkeys.end()) {
        snprintf(errstr, 1024, "Unknown delwepkey bssid");
        return -1;
    }

    delete wepkeys[bssid_mac];
    wepkeys.erase(bssid_mac);

    snprintf(errstr, 1024, "Deleted key for BSSID %s", 
             bssid_mac.Mac2String().c_str());
    _MSG(errstr, MSGFLAG_INFO);

    return 1;
}

int KisBuiltinDissector::cmd_strings(CLIENT_PARMS) {
	// FIXME: write this
    if (parsedcmdline->size() < 1) {
        snprintf(errstr, 1024, "Illegal string request");
		_MSG(errstr, MSGFLAG_ERROR);
        return -1;
    }

    int req;
    if (sscanf(((*parsedcmdline)[0]).word.c_str(), "%d", &req) != 1) {
        snprintf(errstr, 1024, "Illegal string request");
		_MSG(errstr, MSGFLAG_ERROR);
        return -1;
    }

	if (dissect_strings == 2) {
		if (req == 0)
			_MSG("String dissection cannot be disabled because it is required "
				 "by another component", MSGFLAG_INFO);
		return 1;
	}

	if (parsedcmdline->size() > 1) {
		mac_addr ma = mac_addr((*parsedcmdline)[0].word.c_str());

		if (ma.error) {
			snprintf(errstr, 1024, "String dissection, got invalid MAC address");
			_MSG(errstr, MSGFLAG_ERROR);
			return -1;
		}

		if (req) {
			string_nets.insert(ma, 1);
			_MSG("String dissection turned on for " + ma.Mac2String(), MSGFLAG_INFO);
		} else {
			string_nets.erase(ma);
			_MSG("String dissection turned off for " + ma.Mac2String(), MSGFLAG_INFO);
		}

	} else {
		if (req) {
			_MSG("String dissection from data frames enabled", MSGFLAG_INFO);
			dissect_all_strings = 1;
		} else {
			_MSG("String dissection from data frames disabled", MSGFLAG_INFO);
			dissect_all_strings = 0;
		}
	}

	dissect_strings = req;
	
	return 1;
}

int KisBuiltinDissector::cmd_stringsfilter(CLIENT_PARMS) {
	if (parsedcmdline->size() != 1) {
		snprintf(errstr, 1024, "Illegal addstringsfilter request");
		_MSG(errstr, MSGFLAG_ERROR);
		return -1;
	}

	if (string_filter->AddFilterLine((*parsedcmdline)[0].word) < 0) {
		snprintf(errstr, 1024, "Failed to insert strings filter");
		_MSG(errstr, MSGFLAG_ERROR);
		return -1;
	}

	_MSG("Added string filter '" + (*parsedcmdline)[0].word + "'",
		 MSGFLAG_INFO);

	return 1;
}
#endif

