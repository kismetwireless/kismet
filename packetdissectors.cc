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

#include "packetdissectors.h"

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

// Returns a pointer in the data block to the size byte of the desired tag, with the 
// tag offsets cached
int GetTagOffsets(int init_offset, uint8_t *packet, map<int, int> *tag_cache_map) {
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

            (*tag_cache_map)[cur_tag] = cur_offset + 1;

            /*
               if (cur_tag == tagnum) {
               cur_offset++;
               break;
               } else if (cur_tag > tagnum) {
               return -1;
               }
               */

            // Jump the length+length byte, this should put us at the next tag
            // number.
            cur_offset += len+2;
        }
    }
    
    return 0;
}

// This needs to be optimized and it needs to not use casting to do its magic
int kis_80211_dissector(CHAINCALL_PARMS) {
    // Extract data, bail if it doesn't exist, make a local copy of what we're
    // inserting into the frame.
    kis_ieee_80211_packinfo *packinfo;
    kis_datachunk *chunk = in_pack->fetch(globalreg->pcr_80211frame_ref);

    // If we don't have enough data to figure out what we are, if we don't
    // have any packet data, or if we're known to be in error, bail out.
    if (chunk == NULL || in_pack->error)
        return 0;

    if (chunk->length < 24)
        return 0;

    packinfo = new kis_ieee_80211_packinfo;

    frame_control *fc = (frame control *) chunk->data;

    uint16_t duration = 0;

    // 18 bytes of normal address ranges
    uint8_t *addr0;
    uint8_t *addr1;
    uint8_t *addr2;
    // And an optional 6 bytes of address range for ds=0x03 packets
    uint8_t *addr3;

    // We'll fill these in as we go
    packinfo->type = packet_unknown;
    packinfo->subtype = packet_sub_unknown;
    packinfo->distrib = no_distribution;

    // Endian swap the duration  ** Optimize this in the future **
    memcpy(&duration, &(chunk->data[2]), 2);
    duration = kis_ntoh16(duration);

    // 2 bytes of sequence and fragment counts
    wireless_fragseq *sequence;

    addr0 = &(chunk->data[4]);
    addr1 = &(chunk->data[10]);
    addr2 = &(chunk->data[16]);
    sequence = (wireless_fragseq *) &(chunk->data[22]);
    addr3 = &(chunk->data[24]);

    packinfo->sequence_number = sequence->sequence;
    packinfo->frag_number = sequence->frag;

    int tag_offset = 0;

    // Assign the distribution direction this packet is traveling
    if (fc->to_ds == 0 && fc->from_ds == 0)
        packinfo->distrib = adhoc_distribution;
    else if (fc->to_ds == 0 && fc->from_ds == 1)
        packinfo->distrib = from_distribution;
    else if (fc->to_ds == 1 && fc->from_ds == 0)
        packinfo->distrib = to_distribution;
    else if (fc->to_ds == 1 && fc->from_ds == 1)
        packinfo->distrib = inter_distribution;

    // Rip apart management frames
    if (fc->type == 0) {
        packinfo->type = packet_management;

        packinfo->distrib = no_distribution;

        // Throw away large management frames that don't make any sense.  512b is 
        // an arbitrary number to pick, but this should keep some drivers from messing
        // with us
        if (chunk->length > 512) {
            packinfo->corrupt = 1;
            in_pack->insert(globalreg->pcr_80211_ref, packinfo);
            return 0;
        }

        // Short handling of probe reqs since they don't have a fixed parameters
        // field
        fixed_parameters *fixparm;
        if (fc->subtype == 4) {
            packinfo->header_offset = 24;
            fixparm = NULL;
        } else {
            packinfo->header_offset = 36;
            fixparm = (fixed_parameters *) &(chunk->data[24]);
            packinfo->wep = fixparm->wep;

            // Pull the fixparm ibss info
            if (fixparm->ess == 0 && fixparm->ibss == 1) {
                packinfo->distrib = adhoc_distribution;
            }

            // Pull the fixparm timestamp
            uint64_t temp_ts;
            memcpy(&temp_ts, fixparm->timestamp, 8);
#ifdef WORDS_BIGENDIAN
            packinfo = kis_swap64(temp_ts);
#else
            packinfo->timestamp = temp_ts;
#endif
        }

        map<int, int> tag_cache_map;
        map<int, int>::iterator tcitr;

        // Extract various tags from the packet
        int found_ssid_tag = 0;
        int found_rate_tag = 0;
        int found_channel_tag = 0;

        if (fc->subtype == 8 || fc->subtype == 4 || fc->subtype == 5) {
            // This is guaranteed to only give us tags that fit within the packets,
            // so we don't have to do more error checking
            if (GetTagOffsets(packinfo->header_offset, chunk->data, &tag_cache_map) < 0) {
                // The frame is corrupt, bail
                ret_packinfo->corrupt = 1;
                return;
            }
      
            if ((tcitr = tag_cache_map.find(0)) != tag_cache_map.end()) {
                tag_offset = tcitr->second;

                found_ssid_tag = 1;
                temp = (packet->data[tag_offset] & 0xFF);
                packinfo->ssid_len = temp;
                // Protect against malicious packets
                if (temp == 0) {
                    // do nothing for 0-length ssid's
                } else if (temp <= 32) {
                    memcpy(ret_packinfo->ssid, &packet->data[tag_offset+1], temp);
                    packinfo->ssid[temp] = '\0';
                    // Munge it down to printable characters... SSID's can be anything
                    // but if we can't print them it's not going to be very useful
                    // MungeToPrintable(ret_packinfo->ssid, temp);
                    // PRINTABLE MUNGING IS NOW THE RESPONSIBILITY OF OTHER CODE
                } else {
                    // Otherwise we're corrupt, set it and stop processing
                    packinfo->corrupt = 1;
                    in_pack->insert(globalreg->pcr_80211_ref, packinfo);
                    return 0;
                }
            } else {
                packinfo->ssid_len = -1;
            }

            // Extract the supported rates
            if ((tcitr = tag_cache_map.find(1)) != tag_cache_map.end()) {
                tag_offset = tcitr->second;

                found_rate_tag = 1;
                for (int x = 0; x < chunk->data[tag_offset]; x++) {
                    if (packinfo->maxrate < (chunk->data[tag_offset+1+x] & 
                                             0x7F) * 0.5)
                        packinfo->maxrate = (chunk->data[tag_offset+1+x] & 
                                             0x7F) * 0.5;
                }
            }

            // Find the offset of flag 3 and get the channel.   802.11a doesn't have 
            // this tag so we use the hardware channel, assigned at the beginning of 
            // GetPacketInfo
            if ((tcitr = tag_cache_map.find(3)) != tag_cache_map.end()) {
                tag_offset = tcitr->second;
                found_channel_tag = 1;
                // Extract the channel from the next byte (GetTagOffset returns
                // us on the size byte)
                temp = chunk->data[tag_offset+1];
                packinfo->channel = (int) temp;
            }
        }

        if (fc->subtype == 0) {
            packinfo->subtype = packet_sub_association_req;

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

        } else if (fc->subtype == 1) {
            packinfo->subtype = packet_sub_association_resp;

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

        } else if (fc->subtype == 2) {
            packinfo->subtype = packet_sub_reassociation_req;

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

        } else if (fc->subtype == 3) {
            packinfo->subtype = packet_sub_reassociation_resp;

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

        } else if (fc->subtype == 4) {
            packinfo->subtype = packet_sub_probe_req;

            packinfo->distrib = to_distribution;
            
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr1;
           
            // Probe req's with no SSID are bad
            if (found_ssid_tag == 0) {
                packinfo->corrupt = 1;
                in_pack->insert(globalreg->pcr_80211_ref, packinfo);
                return 0;
            }

        } else if (fc->subtype == 5) {
            packinfo->subtype = packet_sub_probe_resp;

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

            /*
            if (ret_packinfo->ess == 0) {
                // A lot of cards seem to rotate through adhoc BSSID's, so we use the source
                // instead
                ret_packinfo->bssid_mac = ret_packinfo->source_mac;
                ret_packinfo->distrib = adhoc_distribution;
                }
                */

        } else if (fc->subtype == 8) {
            packinfo->subtype = packet_sub_beacon;

            packinfo->beacon = kis_ntoh16(fixparm->beacon);

            // Extract the CISC.O beacon info
            if ((tcitr = tag_cache_map.find(133)) != tag_cache_map.end()) {
                tag_offset = tcitr->second;

                if ((unsigned) tag_offset + 11 < chunk->length) {
                    snprintf(packinfo->beacon_info, BEACON_INFO_LEN, "%s", &(chunk->data[tag_offset+11]));
                    // Munge this right here since it's just extra info
                    MungeToPrintable(packinfo->beacon_info, BEACON_INFO_LEN);
                } else {
                    // Otherwise we're corrupt, bail
                    packinfo->corrupt = 1;
                    in_pack->insert(globalreg->pcr_80211_ref, packinfo);
                    return 0;
                }
            }

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

            // If beacons aren't do a broadcast destination, consider them corrupt.
            if (packinfo->dest_mac != broadcast_mac) 
                packinfo->corrupt = 1;
            
            // If beacons don't have a SSID and a basicrate then we consider them
            // corrupt
            if (found_ssid_tag == 0 || found_rate_tag == 0)
                packinfo->corrupt = 1;

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
            packinfo->subtype = packet_sub_atim;

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

            packinfo->distrib = no_distribution;

        } else if (fc->subtype == 10) {
            packinfo->subtype = packet_sub_disassociation;

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

            uint16_t rcode;
            memcpy(&rcode, (const char *) &packet->data[24], 2);

            packinfo->reason_code = rcode;

        } else if (fc->subtype == 11) {
            packinfo->subtype = packet_sub_authentication;

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

            uint16_t rcode;
            memcpy(&rcode, (const char *) &(chunk->data[24]), 2);

            packinfo->reason_code = rcode;

        } else if (fc->subtype == 12) {
            packinfo->subtype = packet_sub_deauthentication;

            packinfo->dest_mac = addr0;
            packinfo->source_mac = addr1;
            packinfo->bssid_mac = addr2;

            uint16_t rcode;
            memcpy(&rcode, (const char *) &(chunk->data[24]), 2);

            packinfo->reason_code = rcode;
        } else {
            packinfo->subtype = packet_sub_unknown;
        }

}

