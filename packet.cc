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

#include <stdio.h>
#include <ctype.h>
#include "packet.h"
#include "packetsignatures.h"

// Handly little global so that it only has to do the ascii->mac_addr transform once
mac_addr broadcast_mac = "FF:FF:FF:FF:FF:FF";

// CRC32 index for verifying WEP - cribbed from ethereal
static const uint32_t wep_crc32_table[256] = {
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

// Munge text down to printable characters only
void MungeToPrintable(char *in_data, int max) {
    unsigned char *temp = new unsigned char[max];
    strncpy((char *) temp, in_data, max);
    // Make sure we terminate this just in case

    int i, j;

    for (i = 0, j = 0; i < max && j < max; i++) {
        if (temp[i] == 0 || temp[i] == '\n') {
            in_data[j++] = '\0';
            break;
        }

        if (temp[i] < 32) {
            if (temp[i] < 32) {
                if (j+2 < max) {
                    // Convert control chars to ^X and so on
                    in_data[j++] = '^';
                    in_data[j++] = temp[i] + 64;
                } else {
                    break;
                }
            }
        } else if (temp[i] > 126) {
            // Do nothing
        } else {
            in_data[j++] = temp[i];
        }
    }
    in_data[j] = '\0';

    delete[] temp;
}


// Returns a pointer in the data block to the size byte of the desired
// tag.
int GetTagOffsets(int init_offset, kis_packet *packet, 
				  map<int, vector<int> > *tag_cache_map) {
    int cur_tag = 0;
    // Initial offset is 36, that's the first tag
    int cur_offset = init_offset;
    uint8_t len;

    // Bail on invalid incoming offsets
    if (init_offset >= (uint8_t) packet->len)
        return -1;
    
    // If we haven't parsed the tags for this frame before, parse them all now.
    // Return an error code if one of them is malformed.
    if (tag_cache_map->size() == 0) {
        while (1) {
            // Are we over the packet length?
            if (cur_offset >= (uint8_t) packet->len) {
                break;
            }

            // Read the tag we're on and bail out if we're done
            cur_tag = (int) packet->data[cur_offset];

            // Move ahead one byte and read the length.
            len = (packet->data[cur_offset+1] & 0xFF);

            // If this is longer than we have...
            if ((unsigned int) (cur_offset + len + 2) > packet->len) {
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

// Get the info from a packet
static int dissect_packet_num = 0;
void GetPacketInfo(kis_packet *packet, packet_info *ret_packinfo,
                   macmap<wep_key_info *> *bssid_wep_map, unsigned char *identity) {

    dissect_packet_num++;

    //printf("debug - packet %d\n", packet_num);
    
    // Zero the entire struct
    memset(ret_packinfo, 0, sizeof(packet_info));

    // Screen capture-level errors as just pure noise
    if (packet->error == 1) {
        ret_packinfo->type = packet_noise;
        return;
    }

    // Copy the name into the packinfo
    memcpy(ret_packinfo->sourcename, packet->sourcename, 32);
    
    frame_control *fc = (frame_control *) packet->data;

    uint16_t duration = 0;

    // 18 bytes of normal address ranges
    uint8_t *addr0;
    uint8_t *addr1;
    uint8_t *addr2;

    // 2 bytes of sequence and fragment counts
    wireless_fragseq *sequence;

    // And an optional 6 bytes of address range for ds=0x3 packets
    uint8_t *addr3;

    // Copy the time with second precision
    ret_packinfo->ts.tv_sec = packet->ts.tv_sec;
    ret_packinfo->ts.tv_usec = packet->ts.tv_usec;
    // Copy the signal values
    ret_packinfo->quality = packet->quality;
    ret_packinfo->signal = packet->signal;
    ret_packinfo->noise = packet->noise;

    // Assign the carrier, encoding, and data rates
    ret_packinfo->carrier = packet->carrier;
    ret_packinfo->encoding = packet->encoding;
    ret_packinfo->datarate = packet->datarate;

    // Assign the location info
    ret_packinfo->gps_lat = packet->gps_lat;
    ret_packinfo->gps_lon = packet->gps_lon;
    ret_packinfo->gps_alt = packet->gps_alt;
    ret_packinfo->gps_spd = packet->gps_spd;
    ret_packinfo->gps_heading = packet->gps_heading;
    ret_packinfo->gps_fix = packet->gps_fix;

    // Assign a hardware channel if we're on an 802.11a carrier since the beacon doesn't
    // carry that tag
    if (packet->carrier == carrier_80211a)
        ret_packinfo->channel = packet->channel;

    // Temp pointer into the packet guts
    uint8_t temp;

    // We'll set these manually as we go
    ret_packinfo->type = packet_unknown;
    ret_packinfo->subtype = packet_sub_unknown;
    ret_packinfo->distrib = no_distribution;

    // If we don't have enough to make up an 802.11 frame and we're not a PHY layer frame,
    // count us as noise and bail.  We don't try to figure out what we are, we're just
    // broken
    if (packet->len < 24 && fc->type != 1) {
        ret_packinfo->type = packet_noise;
        return;
    }

    // Endian swap the 2 byte duration from a pointer
    memcpy(&duration, &packet->data[2], 2);
    duration = kis_ntoh16(duration);

    addr0 = &packet->data[4];
    addr1 = &packet->data[10];
    addr2 = &packet->data[16];
    sequence = (wireless_fragseq *) &packet->data[22];
    addr3 = &packet->data[24];

    // Fill in packet sequence and frag info... Neither takes a full byte so we don't
    // swap them
    ret_packinfo->sequence_number = sequence->sequence;
    ret_packinfo->frag_number = sequence->frag;

    int tag_offset = 0;

    // Assign the direction this packet is going in
    if (fc->to_ds == 0 && fc->from_ds == 0)
        ret_packinfo->distrib = adhoc_distribution;
    else if (fc->to_ds == 0 && fc->from_ds == 1)
        ret_packinfo->distrib = from_distribution;
    else if (fc->to_ds == 1 && fc->from_ds == 0)
        ret_packinfo->distrib = to_distribution;
    else if (fc->to_ds == 1 && fc->from_ds == 1)
        ret_packinfo->distrib = inter_distribution;

    if (fc->type == 0) {
        ret_packinfo->type = packet_management;

        ret_packinfo->distrib = no_distribution;

        // Throw away large management frames that don't make any sense.  512b is 
        // an arbitrary number to pick, but this should keep some drivers from messing
        // with us
        if (packet->caplen > 512) {
            ret_packinfo->corrupt = 1;
            return;
        }

        // Short handling of probe reqs since they don't have a fixed parameters
        // field
        fixed_parameters *fixparm;
        if (fc->subtype == 4) {
            ret_packinfo->header_offset = 24;
            fixparm = NULL;
        } else {
            ret_packinfo->header_offset = 36;
            fixparm = (fixed_parameters *) &packet->data[24];
			if (fixparm->wep)
				(int) ret_packinfo->crypt_set |= crypt_wep;

            // Pull the fixparm ibss info
            if (fixparm->ess == 0 && fixparm->ibss == 1) {
                ret_packinfo->distrib = adhoc_distribution;
            }

            // Pull the fixparm timestamp
            uint64_t temp_ts;
            memcpy(&temp_ts, fixparm->timestamp, 8);
            // ret_packinfo->timestamp = kis_hton64(temp_ts);
#ifdef WORDS_BIGENDIAN
            ret_packinfo->timestamp = kis_swap64(temp_ts);
#else
            ret_packinfo->timestamp = temp_ts;
#endif
        }

        map<int, vector<int> > tag_cache_map;
        map<int, vector<int> >::iterator tcitr;

        // Extract various tags from the packet
        int found_ssid_tag = 0;
        int found_rate_tag = 0;
        int found_channel_tag = 0;

        if (fc->subtype == 8 || fc->subtype == 4 || fc->subtype == 5) {
            // This is guaranteed to only give us tags that fit within the packets,
            // so we don't have to do more error checking
            if (GetTagOffsets(ret_packinfo->header_offset, packet, &tag_cache_map) < 0) {
                // The frame is corrupt, bail
                ret_packinfo->corrupt = 1;
                return;
            }
      
            if ((tcitr = tag_cache_map.find(0)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];

                found_ssid_tag = 1;
                temp = (packet->data[tag_offset] & 0xFF);
                ret_packinfo->ssid_len = temp;
                // Protect against malicious packets
                if (temp == 0) {
                    // do nothing for 0-length ssid's
                } else if (temp <= 32) {
                    memcpy(ret_packinfo->ssid, &packet->data[tag_offset+1], temp);
                    ret_packinfo->ssid[temp] = '\0';
                    // Munge it down to printable characters... SSID's can be anything
                    // but if we can't print them it's not going to be very useful
                    MungeToPrintable(ret_packinfo->ssid, temp);
                } else {
                    // Otherwise we're corrupt, set it and stop processing
                    ret_packinfo->corrupt = 1;
                    return;
                }
            } else {
                ret_packinfo->ssid_len = -1;
            }

            // Extract the supported rates
            if ((tcitr = tag_cache_map.find(1)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];

                found_rate_tag = 1;
                for (int x = 0; x < packet->data[tag_offset]; x++) {
                    if (ret_packinfo->maxrate < (packet->data[tag_offset+1+x] & 
                                                 0x7F) * 0.5)
                        ret_packinfo->maxrate = (packet->data[tag_offset+1+x] & 
                                                 0x7F) * 0.5;
                }
            }

            // Find the offset of flag 3 and get the channel.   802.11a doesn't have 
            // this tag so we use the hardware channel, assigned at the beginning of 
            // GetPacketInfo
            if ((tcitr = tag_cache_map.find(3)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];
                found_channel_tag = 1;
                // Extract the channel from the next byte (GetTagOffset returns
                // us on the size byte)
                temp = packet->data[tag_offset+1];
                ret_packinfo->channel = (int) temp;
            }
        }

        if (fc->subtype == 0) {
            ret_packinfo->subtype = packet_sub_association_req;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

        } else if (fc->subtype == 1) {
            ret_packinfo->subtype = packet_sub_association_resp;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

        } else if (fc->subtype == 2) {
            ret_packinfo->subtype = packet_sub_reassociation_req;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

        } else if (fc->subtype == 3) {
            ret_packinfo->subtype = packet_sub_reassociation_resp;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

        } else if (fc->subtype == 4) {
            ret_packinfo->subtype = packet_sub_probe_req;

            ret_packinfo->distrib = to_distribution;
            
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr1;
           
            // Probe req's with no SSID are bad
            if (found_ssid_tag == 0)
                ret_packinfo->corrupt = 1;

            // Catch wellenreiter probes
            if (!strncmp(ret_packinfo->ssid, "this_is_used_for_wellenreiter", 29)) {
                ret_packinfo->proto.type = proto_wellenreiter;
            }

        } else if (fc->subtype == 5) {
            ret_packinfo->subtype = packet_sub_probe_resp;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            /*
            if (ret_packinfo->ess == 0) {
                // A lot of cards seem to rotate through adhoc BSSID's, so we use the source
                // instead
                ret_packinfo->bssid_mac = ret_packinfo->source_mac;
                ret_packinfo->distrib = adhoc_distribution;
                }
                */

        } else if (fc->subtype == 8) {
            ret_packinfo->subtype = packet_sub_beacon;

            ret_packinfo->beacon = kis_ntoh16(fixparm->beacon);

            // Extract the CISC.O beacon info
            if ((tcitr = tag_cache_map.find(133)) != tag_cache_map.end()) {
                tag_offset = tcitr->second[0];

                if ((unsigned) tag_offset + 11 < packet->len) {
                    snprintf(ret_packinfo->beacon_info, BEACON_INFO_LEN, "%s", &packet->data[tag_offset+11]);
                    MungeToPrintable(ret_packinfo->beacon_info, BEACON_INFO_LEN);
                } else {
                    // Otherwise we're corrupt, bail
                    ret_packinfo->corrupt = 1;
                    return;
                }
            }

			// Extract WPA info -- we have to look at all the tags
			if ((tcitr = tag_cache_map.find(48)) != tag_cache_map.end() &&
				(ret_packinfo->crypt_set & crypt_wep)) {
				for (unsigned int tagct = 0; tagct < tcitr->second.size(); tagct++) {
					tag_offset = tcitr->second[tagct];
					temp = (packet->data[tag_offset] & 0xFF);

					if (temp > 6 && 
						memcmp(&(packet->data[tag_offset+1]), 
							   RSN_AES_TAGPARM_SIGNATURE,
							   sizeof(RSN_AES_TAGPARM_SIGNATURE)) == 0) {
						(int) ret_packinfo->crypt_set |= crypt_wpa2aes;
						break;
					}
				}
			}

			if ((tcitr = tag_cache_map.find(221)) != tag_cache_map.end() &&
				(ret_packinfo->crypt_set & crypt_wep)) {
				// Lets do a smarter test of WPA since APs like to send crap
				// tagged frames too
				// ret_packinfo->wpa = 1;
				for (unsigned int tagct = 0; tagct < tcitr->second.size(); tagct++) {
					tag_offset = tcitr->second[tagct];
					temp = (packet->data[tag_offset] & 0xFF);

					if (temp > 4 && 
						memcmp(&(packet->data[tag_offset+1]), WPA_TAGPARM_SIGNATURE,
							   sizeof(WPA_TAGPARM_SIGNATURE)) == 0) {
						(int) ret_packinfo->crypt_set |= crypt_wpa;
						break;
					}
				}
			}

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            // If beacons aren't do a broadcast destination, consider them corrupt.
            if (ret_packinfo->dest_mac != broadcast_mac) 
                ret_packinfo->corrupt = 1;
            
            // If beacons don't have a SSID and a basicrate then we consider them
            // corrupt
            if (found_ssid_tag == 0 || found_rate_tag == 0)
                ret_packinfo->corrupt = 1;

            /*
            if (ret_packinfo->ess == 0) {
                // Weird adhoc beacon where the BSSID isn't 'right' so we use the source instead.
                ret_packinfo->bssid_mac = ret_packinfo->source_mac;
                ret_packinfo->distrib = adhoc_distribution;
                }
                */
        } else if (fc->subtype == 9) {
            // I'm not positive this is the right handling of atim packets.  Do something
            // smarter in the future
            ret_packinfo->subtype = packet_sub_atim;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            ret_packinfo->distrib = no_distribution;

        } else if (fc->subtype == 10) {
            ret_packinfo->subtype = packet_sub_disassociation;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            uint16_t rcode;
            memcpy(&rcode, (const char *) &packet->data[24], 2);

            ret_packinfo->reason_code = rcode;

        } else if (fc->subtype == 11) {
            ret_packinfo->subtype = packet_sub_authentication;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            uint16_t rcode;
            memcpy(&rcode, (const char *) &packet->data[24], 2);

            ret_packinfo->reason_code = rcode;

        } else if (fc->subtype == 12) {
            ret_packinfo->subtype = packet_sub_deauthentication;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            uint16_t rcode;
            memcpy(&rcode, (const char *) &packet->data[24], 2);

            ret_packinfo->reason_code = rcode;
        } else {
            ret_packinfo->subtype = packet_sub_unknown;
        }

    } else if (fc->type == 1) {
        ret_packinfo->type = packet_phy;

        // Throw away large phy packets just like we throw away large management.
        // Phy stuff is all really small, so we set the limit smaller.
        if (packet->caplen > 128) {
            ret_packinfo->corrupt = 1;
            return;
        }

        ret_packinfo->distrib = no_distribution;

        if (fc->subtype == 11) {
            ret_packinfo->subtype = packet_sub_rts;

        } else if (fc->subtype == 12) {
            ret_packinfo->subtype = packet_sub_cts;

        } else if (fc->subtype == 13) {
            ret_packinfo->subtype = packet_sub_ack;

            ret_packinfo->dest_mac = addr0;

        } else if (fc->subtype == 14) {
            ret_packinfo->subtype = packet_sub_cf_end;

        } else if (fc->subtype == 15) {
            ret_packinfo->subtype = packet_sub_cf_end_ack;

        } else {
            ret_packinfo->subtype = packet_sub_unknown;
        }

    } else if (fc->type == 2) {
        ret_packinfo->type = packet_data;

        // Collect the subtypes - we probably want to do something better with thse
        // in the future
        if (fc->subtype == 0) {
            ret_packinfo->subtype = packet_sub_data;

        } else if (fc->subtype == 1) {
            ret_packinfo->subtype = packet_sub_data_cf_ack;

        } else if (fc->subtype == 2) {
            ret_packinfo->subtype = packet_sub_data_cf_poll;

        } else if (fc->subtype == 3) {
            ret_packinfo->subtype = packet_sub_data_cf_ack_poll;

        } else if (fc->subtype == 4) {
            ret_packinfo->subtype = packet_sub_data_null;

        } else if (fc->subtype == 5) {
            ret_packinfo->subtype = packet_sub_cf_ack;

        } else if (fc->subtype == 6) {
            ret_packinfo->subtype = packet_sub_cf_ack_poll;
        } else {
            ret_packinfo->corrupt = 1;
            ret_packinfo->subtype = packet_sub_unknown;
            return;
        }

        int datasize = packet->len - ret_packinfo->header_offset;
        if (datasize > 0)
            ret_packinfo->datasize = datasize;

        // Extract ID's
        switch (ret_packinfo->distrib) {
        case adhoc_distribution:
            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            if (ret_packinfo->bssid_mac.longmac == 0)
                ret_packinfo->bssid_mac = ret_packinfo->source_mac;

            ret_packinfo->header_offset = 24;
            break;
        case from_distribution:
            ret_packinfo->dest_mac = addr0;
            ret_packinfo->bssid_mac = addr1;
            ret_packinfo->source_mac = addr2;
            ret_packinfo->header_offset = 24;
            break;
        case to_distribution:
            ret_packinfo->bssid_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->dest_mac = addr2;
            ret_packinfo->header_offset = 24;
            break;
        case inter_distribution:
            // If we aren't long enough to hold a intra-ds packet, bail
            if (packet->len < 30) {
                ret_packinfo->corrupt = 1;
                return;
            }

            ret_packinfo->bssid_mac = addr1;
            ret_packinfo->source_mac = addr3;
            ret_packinfo->dest_mac = addr0;

            ret_packinfo->distrib = inter_distribution;

            // First byte of offsets
            ret_packinfo->header_offset = 30;
            break;
        default:
            ret_packinfo->corrupt = 1;
			ret_packinfo->header_offset = 0;
            return;
            break;
        }

		// If we're special data frame types bail now
		if (ret_packinfo->subtype != packet_sub_data) {
			ret_packinfo->datasize = 0;
			return;
		}

        // Detect encrypted frames
        if (fc->wep &&
			(*((unsigned short *) &packet->data[ret_packinfo->header_offset]) != 
			 0xAAAA || packet->data[ret_packinfo->header_offset + 1] & 0x40)) {
            ret_packinfo->encrypted = 1;
		}

		// If we're known encrypted or if we want to be fuzzycrypt detected, 
		// process the crypto info.  Otherwise we don't.  Cryptoinfo might
		// later be processed again if we're doing network-classification
		// wep detection
		if (ret_packinfo->encrypted || packet->parm.fuzzy_crypt)
			ProcessPacketCrypto(packet, ret_packinfo, bssid_wep_map, identity);

		// Extract the tcp layer info
        if (ret_packinfo->encrypted == 0 || ret_packinfo->decoded == 1)
            GetProtoInfo(packet, ret_packinfo);

    } else {
        // If we didn't figure out what it was yet, test it for cisco noise.  
		// If the first four bytes are 0xFF, bail
        uint32_t fox = ~0;
        if (memcmp(packet->data, &fox, 4) == 0) {
            ret_packinfo->type = packet_noise;
            return;
        }
    }

    // Do a little sanity checking on the BSSID
    if (ret_packinfo->bssid_mac.error == 1 ||
        ret_packinfo->source_mac.error == 1 ||
        ret_packinfo->dest_mac.error == 1) {
        ret_packinfo->corrupt = 1;
    }

}

// Handle detecting crypted packets and decoding them
void ProcessPacketCrypto(kis_packet *packet, packet_info *ret_packinfo,
						 macmap<wep_key_info *> *bssid_wep_map,
						 unsigned char *identity) {
	int datasize = ret_packinfo->datasize;

	if (ret_packinfo->encrypted == 0 && 
		(unsigned int) ret_packinfo->header_offset+9 < packet->len) {
		// Do a fuzzy data compare... if it's not:
		// 0xAA - IP LLC
		// 0x42 - I forgot.
		// 0xF0 - Netbios
		// 0xE0 - IPX
		if (packet->data[ret_packinfo->header_offset] != 0xAA && 
			packet->data[ret_packinfo->header_offset] != 0x42 &&
			packet->data[ret_packinfo->header_offset] != 0xF0 && 
			packet->data[ret_packinfo->header_offset] != 0xE0) {
			ret_packinfo->encrypted = 1;
			ret_packinfo->fuzzy = 1;
		}
	}

	if (ret_packinfo->encrypted) {
		// Match the range of cryptographically weak packets and let us
		// know.

		// New detection method from Airsnort 2.0, should be much better.
		unsigned int sum;
		if (packet->data[ret_packinfo->header_offset+1] == 255 && 
			packet->data[ret_packinfo->header_offset] > 2 &&
			packet->data[ret_packinfo->header_offset] < 16) {
			ret_packinfo->interesting = 1;
		} else {
			sum = packet->data[ret_packinfo->header_offset] + 
				packet->data[ret_packinfo->header_offset+1];
			if (sum == 1 && 
				(packet->data[ret_packinfo->header_offset + 2] <= 0x0A ||
				 packet->data[ret_packinfo->header_offset + 2] == 0xFF)) {
				ret_packinfo->interesting = 1;
			} else if (sum <= 0x0C && 
					   (packet->data[ret_packinfo->header_offset + 2] >= 0xF2 &&
						packet->data[ret_packinfo->header_offset + 2] <= 0xFE &&
						packet->data[ret_packinfo->header_offset + 2] != 0xFD))
				ret_packinfo->interesting = 1;
		}

		// Knock 8 bytes off the data size of encrypted packets for the
		// wep IV and check
		datasize = ret_packinfo->datasize - 8;
		if (datasize > 0)
			ret_packinfo->datasize = datasize;
		else
			ret_packinfo->datasize = 0;

		if (ret_packinfo->encrypted) {
			// De-wep if we have any keys
			if (bssid_wep_map->size() != 0)
				DecryptPacket(packet, ret_packinfo, bssid_wep_map, identity);

			// Record the IV in the info
			memcpy(&ret_packinfo->ivset, 
				   &packet->data[ret_packinfo->header_offset], 4);
		}

	}
}

void GetProtoInfo(kis_packet *packet, packet_info *in_info) {
    /* This buffering is an unpleasant slowdown, so lets trust our code to be correct
     * now. */
    /*
    u_char data[MAX_PACKET_LEN * 2];
    memset(data, 0, MAX_PACKET_LEN * 2);
    memcpy(data, in_data, header->len);
    */

    uint8_t *data;
    // Grab the modified data if there is any, and use the normal data otherwise.
    // This lets us handle dewepped data
    if (packet->modified != 0)
        data = packet->moddata;
    else
        data = packet->data;

    proto_info *ret_protoinfo = &(in_info->proto);

    // Zero the entire struct
    memset(ret_protoinfo, 0, sizeof(proto_info));

    ret_protoinfo->type = proto_unknown;

    if (memcmp(&data[in_info->header_offset], LLC_UI_SIGNATURE,
                      sizeof(LLC_UI_SIGNATURE)) == 0) {
        // Handle all the protocols which fall under the LLC UI 0x3 frame

        if (memcmp(&data[in_info->header_offset + LLC_UI_OFFSET], PROBE_LLC_SIGNATURE,
                   sizeof(PROBE_LLC_SIGNATURE)) == 0) {

            // If we have a LLC packet that looks like a netstumbler...
            if (memcmp(&data[in_info->header_offset + NETSTUMBLER_OFFSET], NETSTUMBLER_322_SIGNATURE,
                       sizeof(NETSTUMBLER_322_SIGNATURE)) == 0) {
                // Netstumbler 322 says Flurble gronk bloopit, bnip Frundletrune
                ret_protoinfo->type = proto_netstumbler;
                ret_protoinfo->prototype_extra = 22;
                return;
            } else if (memcmp(&data[in_info->header_offset + NETSTUMBLER_OFFSET], NETSTUMBLER_323_SIGNATURE,
                              sizeof(NETSTUMBLER_323_SIGNATURE)) == 0) {
                // Netstumbler 323 says All your 802.11b are belong to us
                ret_protoinfo->type = proto_netstumbler;
                ret_protoinfo->prototype_extra = 23;
                return;
            } else if (memcmp(&data[in_info->header_offset + NETSTUMBLER_OFFSET], NETSTUMBLER_330_SIGNATURE,
                              sizeof(NETSTUMBLER_330_SIGNATURE)) == 0) {
                // Netstumbler 330 says           Intentionally left blank
                ret_protoinfo->type = proto_netstumbler;
                ret_protoinfo->prototype_extra = 30;
                return;
            } else if (memcmp(&data[in_info->header_offset + LUCENT_OFFSET], LUCENT_TEST_SIGNATURE,
                              sizeof(LUCENT_TEST_SIGNATURE)) == 0) {
                ret_protoinfo->type = proto_lucenttest;
            }
        } else if (memcmp(&data[in_info->header_offset + LLC_UI_OFFSET], CISCO_SIGNATURE,
               sizeof(CISCO_SIGNATURE)) == 0) {
            // CDP

            unsigned int offset = in_info->header_offset + LLC_UI_OFFSET + 12;

            while (offset < packet->len) {
                // Make sure that whatever we do, we don't wander off the
                // edge of the proverbial world -- segfaulting due to crappy
                // packets is a really bad thing!

                cdp_element *elem = (cdp_element *) &data[offset];

                if (elem->length == 0)
                    break;

                if (elem->type == 0x01) {
                    // Device id
                    snprintf(ret_protoinfo->cdp.dev_id, elem->length-3, "%s", (char *) &elem->data);
                } else if (elem->type == 0x02) {
                    // IP range

                    cdp_proto_element *proto;
                    int8_t *datarr = (int8_t *) &elem->data;

                    // We only take the first addr (for now)... And only if
                    // it's an IP
                    proto = (cdp_proto_element *) &datarr[4];

                    if (proto->proto == 0xcc) {
                        memcpy(&ret_protoinfo->cdp.ip, &proto->addr, 4);
                    }
                    // }
                } else if (elem->type == 0x03) {
                    // port id
                    snprintf(ret_protoinfo->cdp.interface, elem->length-3, "%s", (char *) &elem->data);
                } else if (elem->type == 0x04) {
                    // capabilities
                    memcpy(&ret_protoinfo->cdp.cap, &elem->data, elem->length-4);
                } else if (elem->type == 0x05) {
                    // software version
                    snprintf(ret_protoinfo->cdp.software, elem->length-3, "%s", (char *) &elem->data);
                } else if (elem->type == 0x06) {
                    // Platform
                    snprintf(ret_protoinfo->cdp.platform, elem->length-3, "%s", (char *) &elem->data);
                }

                offset += elem->length;
            }

            ret_protoinfo->type = proto_cdp;
            return;

        } else if (memcmp(&data[in_info->header_offset + LLC_UI_OFFSET + 3], DOT1X_PROTO, 
            sizeof(DOT1X_PROTO)) == 0) {
                           
            // 802.1X frame - let's find out if it's LEAP

            // Make sure it's an EAP packet
            unsigned int offset = in_info->header_offset + DOT1X_OFFSET;
            struct dot1x_header *dot1x_ptr = (struct dot1x_header *)&data[offset];
            if (dot1x_ptr->version == 1 && dot1x_ptr->type == 0 &&
                (packet->len > (sizeof(dot1x_header) + offset))) {

                // Check out EAP characteristics
                offset = offset + EAP_OFFSET;
                struct eap_packet *eap_ptr = (struct eap_packet *)&data[offset];
                // code can be 1-4 for request, response, success or failure, respectively
                if ( (eap_ptr->code > 0 || eap_ptr->code < 5) && 
                    (packet->len > (sizeof(eap_packet) + offset)) ) {
                    switch(eap_ptr->type) {
                        case EAP_TYPE_LEAP:
                            ret_protoinfo->type = proto_leap;
                            ret_protoinfo->prototype_extra = eap_ptr->code;
                            return;
                            break;
                        case EAP_TYPE_TLS:
                            ret_protoinfo->type = proto_tls;
                            ret_protoinfo->prototype_extra = eap_ptr->code;
                            return;
                            break;
                        case EAP_TYPE_TTLS:
                            ret_protoinfo->type = proto_ttls;
                            ret_protoinfo->prototype_extra = eap_ptr->code;
                            return;
                            break;
                        case EAP_TYPE_PEAP:
                            ret_protoinfo->type = proto_peap;
                            ret_protoinfo->prototype_extra = eap_ptr->code;
                            return;
                            break;
                        default:
                            ret_protoinfo->type = proto_unknown;
                            return;
                            break;
                    }
                }
            }
        }


    }

    // This isn't an 'else' because we want to try to handle it if it looked like a netstumbler
    // but wasn't.
    if (in_info->dest_mac == LOR_MAC) {
        // First thing we do is see if the destination matches the multicast for
        // lucent outdoor routers, or if we're a multicast with no BSSID.  This should
        // be indicative of being a lucent outdoor router
        ret_protoinfo->type = proto_turbocell;

        // if it IS a turbocell packet, see if we can dissect it any...  Make sure its long
        // enough to have a SSID.
        if (in_info->encrypted == 0 && packet->len > (unsigned int) (in_info->header_offset + LLC_OFFSET + 7)) {
            // Get the modes from the LLC header
            uint8_t turbomode = data[in_info->header_offset + LLC_OFFSET + 6];
            switch (turbomode) {
            case 0xA0:
                in_info->turbocell_mode = turbocell_ispbase;
                break;
            case 0x80:
                in_info->turbocell_mode = turbocell_pollbase;
                break;
            case 0x40:
                in_info->turbocell_mode = turbocell_base;
                break;
            case 0x00:
                in_info->turbocell_mode = turbocell_nonpollbase;
                break;
            default:
                in_info->turbocell_mode = turbocell_unknown;
                break;
            }

            // Get the nwid and sat options
            uint8_t turbonwid = ((data[in_info->header_offset + LLC_OFFSET + 7] & 0xF0) >> 4);
            uint8_t turbosat = (data[in_info->header_offset + LLC_OFFSET + 7] & 0x0F);
            in_info->turbocell_nid = turbonwid;
            if (turbosat == 2)
                in_info->turbocell_sat = 1;
            else
                in_info->turbocell_sat = 0;

            // Get the SSID
            if (packet->len > (unsigned int) (in_info->header_offset + LLC_OFFSET + 26)) {
                u_char *turbossid = &data[in_info->header_offset + LLC_OFFSET + 26];
                if (isprint(turbossid[0])) {
                    // Make sure we get a terminator
                    int turbossidterm = 0;
                    unsigned int turbossidpos = 0;
                    while (in_info->header_offset + LLC_OFFSET + 26 + turbossidpos < packet->len) {
                        if (turbossid[turbossidpos] == '\0') {
                            turbossidterm = 1;
                            break;
                        }
                        turbossidpos++;
                    }

                    if (turbossidterm) {
                        snprintf(in_info->ssid, SSID_SIZE, "%s", turbossid);
                        MungeToPrintable(in_info->ssid, SSID_SIZE);
                    }
                }
            }
        }

	} else if (memcmp(&data[in_info->header_offset + ARP_OFFSET], ARP_SIGNATURE,
					  sizeof(ARP_SIGNATURE)) == 0) {
		// ARP
		// printf("debug - arp frame %d\n", dissect_packet_num);
		ret_protoinfo->type = proto_arp;

		memcpy(ret_protoinfo->source_ip, (const uint8_t *) 
			   &data[in_info->header_offset + ARP_OFFSET + 16], 4);
		memcpy(ret_protoinfo->misc_ip, (const uint8_t *) 
			   &data[in_info->header_offset + ARP_OFFSET + 26], 4);
    } else if (memcmp(&data[in_info->header_offset + LLC_OFFSET], NETBIOS_SIGNATURE,
                          sizeof(NETBIOS_SIGNATURE)) == 0) {
        ret_protoinfo->type = proto_netbios;

        uint8_t nb_command = data[in_info->header_offset + NETBIOS_OFFSET];
        if (nb_command == 0x01) {
            // Netbios browser announcement
            ret_protoinfo->nbtype = proto_netbios_host;
            snprintf(ret_protoinfo->netbios_source, 17, "%s",
                     &data[in_info->header_offset + NETBIOS_OFFSET + 6]);
        } else if (nb_command == 0x0F) {
            // Netbios srver announcement
            ret_protoinfo->nbtype = proto_netbios_master;
            snprintf(ret_protoinfo->netbios_source, 17, "%s",
                     &data[in_info->header_offset + NETBIOS_OFFSET + 6]);
        } else if (nb_command == 0x0C) {
            // Netbios domain announcement
            ret_protoinfo->nbtype = proto_netbios_domain;
        }
    } else if (memcmp(&data[in_info->header_offset + LLC_OFFSET], IPX_SIGNATURE,
                      sizeof(IPX_SIGNATURE)) == 0) {
        // IPX packet
		ret_protoinfo->type = proto_ipx_tcp;
	} else if (memcmp(&data[in_info->header_offset + IP_OFFSET], UDP_SIGNATURE,
					  sizeof(UDP_SIGNATURE)) == 0) {
		// UDP
		ret_protoinfo->type = proto_udp;
		// printf("debug - high-level UDP match packet %d\n", dissect_packet_num);

		uint16_t d, s;

		memcpy(&s, (uint16_t *) &data[in_info->header_offset + UDP_OFFSET], 2);
		memcpy(&d, (uint16_t *) &data[in_info->header_offset + UDP_OFFSET + 2], 2);

		ret_protoinfo->sport = ntohs((unsigned short int) s);
		ret_protoinfo->dport = ntohs((unsigned short int) d);

		memcpy(ret_protoinfo->source_ip, 
			   (const uint8_t *) &data[in_info->header_offset + IP_OFFSET + 3], 4);
		memcpy(ret_protoinfo->dest_ip, 
			   (const uint8_t *) &data[in_info->header_offset + IP_OFFSET + 7], 4);


		if (ret_protoinfo->sport == IAPP_PORT && ret_protoinfo->dport == IAPP_PORT) {
			iapp_header *ih = 
				(iapp_header *) &data[in_info->header_offset + IAPP_OFFSET];
			uint8_t *pdu = 
				&data[in_info->header_offset + IAPP_OFFSET + sizeof(iapp_header)];

			if (ih->iapp_version != 1)
				return;

			switch (ih->iapp_type) {
				case iapp_announce_request:
				case iapp_announce_response:
				case iapp_handover_request:
				case iapp_handover_response:
					break;
				default:
					return;
			}

			ret_protoinfo->type = proto_iapp;

			while (pdu < &data[packet->len - 1]) {
				iapp_pdu_header *ph = (iapp_pdu_header *) pdu;
				uint16_t pdu_len = ntohs(ph->pdu_len);

				switch (ph->pdu_type) {
					case iapp_pdu_ssid:
						if (pdu_len > SSID_SIZE)
							break;
						memcpy(in_info->ssid, &pdu[3], pdu_len);
						in_info->ssid[pdu_len] = '\0';
						break;
					case iapp_pdu_bssid:
						if (pdu_len != MAC_LEN)
							break;
						in_info->bssid_mac = mac_addr(&pdu[3]);
						break;
					case iapp_pdu_oldbssid:
						break;
					case iapp_pdu_msaddr:
						break;
					case iapp_pdu_capability:
						if (pdu_len != 1)
							break;
						if (!!(pdu[3] & iapp_cap_wep))
							(int) in_info->crypt_set |= crypt_wep;
						break;
					case iapp_pdu_announceint:
						break;
					case iapp_pdu_hotimeout:
						break;
					case iapp_pdu_messageid:
						break;
					case iapp_pdu_phytype:
						break;
					case iapp_pdu_regdomain:
						break;
					case iapp_pdu_channel:
						if (pdu_len != 1)
							break;
						in_info->channel = pdu[3];
						break;
					case iapp_pdu_beaconint:
						if (pdu_len != 2)
							break;
						in_info->beacon = (pdu[3] << 8) | pdu[4];
						break;
					case iapp_pdu_ouiident:
						break;
					case iapp_pdu_authinfo:
						break;
					default:
						break;
				}

				pdu += pdu_len + 3;
			}
		}

		else if (ret_protoinfo->sport == 138 && ret_protoinfo->dport == 138) {
			// netbios

			ret_protoinfo->type = proto_netbios_tcp;

			uint8_t nb_command = data[in_info->header_offset + NETBIOS_TCP_OFFSET];
			if (nb_command == 0x01) {
				// Netbios browser announcement
				ret_protoinfo->nbtype = proto_netbios_host;
				snprintf(ret_protoinfo->netbios_source, 17, "%s",
						 &data[in_info->header_offset + NETBIOS_TCP_OFFSET + 6]);
			} else if (nb_command == 0x0F) {
				// Netbios srver announcement
				ret_protoinfo->nbtype = proto_netbios_master;
				snprintf(ret_protoinfo->netbios_source, 17, "%s",
						 &data[in_info->header_offset + NETBIOS_TCP_OFFSET + 6]);
			} else if (nb_command == 0x0C) {
				// Netbios domain announcement
				ret_protoinfo->nbtype = proto_netbios_domain;
			}

		} else if (ret_protoinfo->sport == 137 && ret_protoinfo->dport == 137) {
			ret_protoinfo->type = proto_netbios_tcp;

			if (data[in_info->header_offset + UDP_OFFSET + 10] == 0x01 &&
				data[in_info->header_offset + UDP_OFFSET + 11] == 0x10) {
				ret_protoinfo->nbtype = proto_netbios_query;

				unsigned int offset = in_info->header_offset + UDP_OFFSET + 21;

				if (offset < packet->len && offset + 32 < packet->len) {
					ret_protoinfo->type = proto_netbios_tcp;
					for (unsigned int x = 0; x < 32; x += 2) {
						uint8_t fchr = data[offset+x];
						uint8_t schr = data[offset+x+1];

						if (fchr < 'A' || fchr > 'Z' ||
							schr < 'A' || schr > 'Z') {
							ret_protoinfo->type = proto_udp;
							ret_protoinfo->netbios_source[0] = '\0';
							break;
						}

						fchr -= 'A';
						ret_protoinfo->netbios_source[x/2] = fchr << 4;
						schr -= 'A';
						ret_protoinfo->netbios_source[x/2] |= schr;
					}

					ret_protoinfo->netbios_source[17] = '\0';
				}
			}

		} else if (memcmp(&data[in_info->header_offset + DHCPD_OFFSET], 
						  DHCPD_SIGNATURE, sizeof(DHCPD_SIGNATURE)) == 0) {

			// DHCP server responding
			ret_protoinfo->type = proto_dhcp_server;

			// Now we go through all the options until we find options 1, 3, and 53
			// netmask.
			unsigned int offset = in_info->header_offset + DHCPD_OFFSET + 252;


			while (offset < packet->len) {
				if (data[offset] == 0x01) {
					// netmask

					// Bail out of we're a "boring" dhcp ack
					if (data[offset+2] == 0x00) {
						ret_protoinfo->type = proto_udp;
						break;
					}

					memcpy(ret_protoinfo->mask, &data[offset+2], 4);
				} else if (data[offset] == 0x03) {
					// gateway

					// Bail out of we're a "boring" dhcp ack
					if (data[offset+2] == 0x00) {
						ret_protoinfo->type = proto_udp;
						break;
					}

					memcpy(ret_protoinfo->gate_ip, &data[offset+2], 4);
				} else if (data[offset] == 0x35) {
					// We're a DHCP ACK packet
					if (data[offset+2] != 0x05) {
						ret_protoinfo->type = proto_udp;
						break;
					} else {
						// Now rip straight to the heart of it and get the offered
						// IP from the BOOTP segment
						memcpy(ret_protoinfo->misc_ip, 
							   (const uint8_t *) &data[in_info->header_offset + 
							   DHCPD_OFFSET + 28], 4);
					}
				}
				offset += data[offset+1]+2;
			}

			// Check for ISAKMP traffic
        } else if (ret_protoinfo->type == proto_udp &&
				   (ret_protoinfo->sport == ISAKMP_PORT || 
					ret_protoinfo->dport == ISAKMP_PORT)) {

            unsigned int offset = in_info->header_offset + ISAKMP_OFFSET;
            // Don't read past the packet size
            if (packet->len >= (offset + sizeof(struct isakmp_packet))) {
                struct isakmp_packet *isakmp_ptr = 
					(struct isakmp_packet *)&data[offset];
                ret_protoinfo->type = proto_isakmp;
                ret_protoinfo->prototype_extra = isakmp_ptr->exchtype;
            }

        }

    } else if (memcmp(&data[in_info->header_offset + IP_OFFSET], TCP_SIGNATURE,
                      sizeof(TCP_SIGNATURE)) == 0) {
        // TCP
        ret_protoinfo->type = proto_misc_tcp;

        uint16_t d, s;

        memcpy(&s, (uint16_t *) &data[in_info->header_offset + TCP_OFFSET], 2);
        memcpy(&d, (uint16_t *) &data[in_info->header_offset + TCP_OFFSET + 2], 2);

        ret_protoinfo->sport = ntohs((unsigned short int) s);
        ret_protoinfo->dport = ntohs((unsigned short int) d);

        memcpy(ret_protoinfo->source_ip, 
			   (const uint8_t *) &data[in_info->header_offset + IP_OFFSET + 3], 4);
        memcpy(ret_protoinfo->dest_ip, 
			   (const uint8_t *) &data[in_info->header_offset + IP_OFFSET + 7], 4);

        // Check for PPTP traffic
        if (ret_protoinfo->type == proto_misc_tcp &&
        (ret_protoinfo->dport == PPTP_PORT || ret_protoinfo->sport == PPTP_PORT)) {
            ret_protoinfo->type = proto_pptp;
        }

    }


}

// Pull all the printable data out
vector<string> GetPacketStrings(const packet_info *in_info, const kis_packet *packet) {
    char str[MAX_PACKET_LEN];
    memset(str, 0, MAX_PACKET_LEN);
    vector<string> ret;

    // Get our modified data if we have it
    uint8_t *data;
    if (packet->modified != 0)
        data = packet->moddata;
    else
        data = packet->data;

    int pos = 0;
    int printable = 0;
    for (unsigned int x = in_info->header_offset; x < packet->len; x++) {
        if (printable && !isprint(data[x]) && pos != 0) {
            if (pos > 4)
                ret.push_back(str);

            memset(str, 0, pos+1);
            pos = 0;
        } else if (isprint(data[x])) {
            str[pos++] = data[x];
            printable = 1;
        }
    }

    return ret;
}

// Decode WEP for the given packet based on the keys in the bssid_wep_map.
// This is an amalgamation of ethereal, wlan-ng, and others
void DecryptPacket(kis_packet *packet, packet_info *in_info, 
                   macmap<wep_key_info *> *bssid_wep_map, unsigned char *identity) {

    // Bail if we don't have enough for the iv+any real data
    if ((int) packet->len - in_info->header_offset <= 8)
        return;

    // Bail if we don't have a match
    macmap<wep_key_info *>::iterator bwmitr = bssid_wep_map->find(in_info->bssid_mac);
    if (bwmitr == bssid_wep_map->end())
        return;

    // Our password field
    char pwd[WEPKEY_MAX + 3];
    memset(pwd, 0, WEPKEY_MAX + 3);

    // Add the WEP IV to the key
    pwd[0] = packet->data[in_info->header_offset] & 0xFF;
    pwd[1] = packet->data[in_info->header_offset + 1] & 0xFF;
    pwd[2] = packet->data[in_info->header_offset + 2] & 0xFF;

    // Add the supplied password to the key
    memcpy(pwd + 3, (*bwmitr->second)->key, WEPKEY_MAX);
    int pwdlen = 3 + (*bwmitr->second)->len;

    unsigned char keyblock[256];
    memcpy(keyblock, identity, 256);

    int kba = 0, kbb = 0;

    // Prepare the key block

    for (kba = 0; kba < 256; kba++) {
        kbb = (kbb + keyblock[kba] + pwd[kba % pwdlen]) & 0xff;

        unsigned char oldkey = keyblock[kba];
        keyblock[kba] = keyblock[kbb];
        keyblock[kbb] = oldkey;
    }

    // Copy the packet headers
    memcpy(packet->moddata, packet->data, in_info->header_offset + 4);

    // decrypt the data payload and check the crc
    kba = kbb = 0;
    uint32_t crc = ~0;
    uint8_t c_crc[4];
    uint8_t icv[4];

    // Copy out the icv for our crc check
    memcpy(icv, &packet->data[packet->len - 4], 4);

    for (unsigned int dpos = in_info->header_offset + 4; dpos < packet->len - 4; dpos++) {
        kba = (kba + 1) & 0xFF;
        kbb = (kbb + keyblock[kba]) & 0xFF;

        unsigned char oldkey = keyblock[kba];
        keyblock[kba] = keyblock[kbb];
        keyblock[kbb] = oldkey;

        packet->moddata[dpos] = packet->data[dpos] ^ keyblock[(keyblock[kba] + keyblock[kbb]) & 0xFF];

        crc = wep_crc32_table[(crc ^ packet->moddata[dpos]) & 0xff] ^ (crc >> 8);
    }

    // Check the CRC
    crc = ~crc;
    c_crc[0] = crc;
    c_crc[1] = crc >> 8;
    c_crc[2] = crc >> 16;
    c_crc[3] = crc >> 24;

    int crcfailure = 0;
    for (unsigned int crcpos = 0; crcpos < 4; crcpos++) {
        kba = (kba + 1) & 0xff;
        kbb = (kbb+keyblock[kba]) & 0xff;

        unsigned char oldkey = keyblock[kba];
        keyblock[kba] = keyblock[kbb];
        keyblock[kbb] = oldkey;

        if ((c_crc[crcpos] ^ keyblock[(keyblock[kba] + keyblock[kbb]) & 0xff]) != icv[crcpos]) {
            crcfailure = 1;
            break;
        }
    }

    // If the CRC check failed, delete the moddata, set it to null, and don't change the
    // length
    if (crcfailure == 1) {
        packet->modified = 0;
        (*bwmitr->second)->failed++;
    } else {
        packet->modified = 1;
        // Skip the IV and don't count the ICV
        in_info->header_offset += 4;
        packet->len -= 4;
        in_info->decoded = 1;
        (*bwmitr->second)->decrypted++;
    }
}

// Convert a crypted packet into an unencrypted packet with data and moddata fields
// set accordingly.
// Calling function is responsible for deleting the returned packet
// We turn the packet into an "un-modified" packet for logging
int MangleDeCryptPacket(const kis_packet *packet, const packet_info *in_info,
                        kis_packet *outpack, uint8_t *data, uint8_t *moddata) {
    if (in_info->decoded == 0 || packet->error != 0 || packet->modified == 0)
        return 0;

    // Remove the WEP header
    outpack->ts.tv_sec = packet->ts.tv_sec;
    outpack->ts.tv_usec = packet->ts.tv_usec;
    outpack->len = packet->len - 4;
    outpack->caplen = outpack->len;
    outpack->quality = packet->quality;
    outpack->signal = packet->signal;
    outpack->noise = packet->noise;
    outpack->error = 0;
    outpack->channel = packet->channel;
    outpack->carrier = packet->carrier;
    outpack->encoding = packet->encoding;
    outpack->datarate = packet->datarate;

    outpack->data = data;
    outpack->moddata = moddata;
    outpack->modified = 0;

    // Copy the decrypted data, skipping the wep header and dropping the crc32 off the end
    memcpy((void *) outpack->data, (void *) packet->moddata, in_info->header_offset - 4);
    memcpy((void *) &outpack->data[in_info->header_offset - 4],
           (void *) &packet->moddata[in_info->header_offset],
           outpack->len - (in_info->header_offset - 4));

    // Twiddle the frame control bit
    frame_control *fc = (frame_control *) outpack->data;
    fc->wep = 0;

    return outpack->len;
}

// Mangle a fuzzy packet into a "really encrypted" packet
int MangleFuzzyCryptPacket(const kis_packet *packet, const packet_info *in_info,
                           kis_packet *outpack, uint8_t *data, uint8_t *moddata) {
    if (in_info->fuzzy == 0 || packet->error != 0)
        return 0;

    // Remove the WEP header
    outpack->ts.tv_sec = packet->ts.tv_sec;
    outpack->ts.tv_usec = packet->ts.tv_usec;
    outpack->len = packet->len;
    outpack->caplen = packet->caplen;
    outpack->quality = packet->quality;
    outpack->signal = packet->signal;
    outpack->noise = packet->noise;
    outpack->error = 0;
    outpack->channel = packet->channel;
    outpack->carrier = packet->carrier;
    outpack->encoding = packet->encoding;
    outpack->datarate = packet->datarate;

    outpack->data = data;
    outpack->moddata = moddata;
    outpack->modified = packet->modified;

    // Copy the encrypted data
    memcpy((void *) outpack->data, (void *) packet->data, outpack->len);

    // Copy any decrypted data
    if (packet->modified != 0) {
        memcpy((void *) outpack->moddata, (void *) packet->moddata, outpack->len);
    }

    // Twiddle the frame control bit in the encrypted data to set us to be really encrypted
    frame_control *fc = (frame_control *) outpack->data;
    fc->wep = 1;

    return outpack->len;

}

