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

//#include "frontend.h"

// Munge text down to printable characters only
void MungeToPrintable(char *in_data, int max) {
    char *temp = new char[max];
    strncpy(temp, in_data, max);
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
int GetTagOffset(int init_offset, int tagnum, const pkthdr *header, const u_char *data) {
    int cur_tag = 0;
    // Initial offset is 36, that's the first tag
    int cur_offset = init_offset;
    uint8_t len;

    while (1) {
        // Are we over the packet length?
        if (cur_offset > (uint8_t) header->len) {
            return -1;
        }

        // Read the tag we're on and bail out if we're done
        cur_tag = (int) data[cur_offset];
        if (cur_tag == tagnum) {
            cur_offset++;
            break;
        } else if (cur_tag > tagnum) {
            return -1;
        }

        // Move ahead one byte and read the length.
        len = (data[cur_offset+1] & 0xFF);

        // Jump the length+length byte, this should put us at the next tag
        // number.
        cur_offset += len+2;
    }

    return cur_offset;
}

// Get the info from a packet
void GetPacketInfo(const pkthdr *header, const u_char *data,
                   packet_parm *parm, packet_info *ret_packinfo) {
    // packet_info ret;

    if (ret_packinfo == NULL)
        return;

    frame_control *fc = (frame_control *) data;

    uint16_t duration = 0;

    // 18 bytes of normal address ranges
    uint8_t *addr0;
    uint8_t *addr1;
    uint8_t *addr2;

    // 2 bytes of sequence and fragment counts
    wireless_fragseq *sequence;

    // And an optional 6 bytes of address range for ds=0x3 packets
    uint8_t *addr3;

    //numpack++;

    // Zero the entire struct
    memset(ret_packinfo, 0, sizeof(packet_info));

    // Copy the time with second precision
    ret_packinfo->time = header->ts.tv_sec;
    // Copy the signal values
    ret_packinfo->quality = header->quality;
    ret_packinfo->signal = header->signal;
    ret_packinfo->noise = header->noise;

    // Point to the packet data
    uint8_t *msgbuf = (uint8_t *) data;
    // Temp pointer into the packet guts
    uint8_t temp;

    ret_packinfo->type = packet_unknown;
    ret_packinfo->distrib = no_distribution;

    // Raw test to see if it's just noise
    if (msgbuf[0] == 0xff && msgbuf[1] == 0xff && msgbuf[2] == 0xff && msgbuf[3] == 0xff) {
        ret_packinfo->type = packet_noise;
        return;
    }

    // If we don't even have enough to make up an 802.11 frame, bail
    // as a garbage packet
    if (header->len < 24) {
        ret_packinfo->type = packet_noise;
        return;
    }

    // Endian swap the 2 byte duration from a pointer
    duration = kptoh16(&data[2]);

    addr0 = (uint8_t *) &data[4];
    addr1 = (uint8_t *) &data[10];
    addr2 = (uint8_t *) &data[16];
    sequence = (wireless_fragseq *) &data[22];
    addr3 = (uint8_t *) &data[24];

    // Fill in packet sequence and frag info... Neither takes a full byte so we don't
    // swap them
    ret_packinfo->sequence_number = sequence->sequence;
    ret_packinfo->frag_number = sequence->frag;

    int tag_offset = 0;

    if (fc->type == 0) {
        // First byte of offsets
        ret_packinfo->header_offset = 24;

        if (fc->subtype == 8) {
            // beacon frame

            // If we look like a beacon but we aren't long enough to hold
            // tags, then we probably aren't a beacon.  Throw us out.
            if (header->len < 36) {
                ret_packinfo->type = packet_noise;
                return;
            }

            fixed_parameters *fixparm = (fixed_parameters *) &msgbuf[24];

            //            ret.beacon = ntohl(fixparm->beacon);
            ret_packinfo->beacon = ktoh16(fixparm->beacon);

            ret_packinfo->wep = fixparm->wep;
            ret_packinfo->ap = fixparm->ess;

            // Find the offset of tag 0 and fill in the ssid if we got the
            // tag.
            if ((tag_offset = GetTagOffset(36, 0, header, data)) > 0) {
                temp = (msgbuf[tag_offset] & 0xFF) + 1;

                // Protect against malicious packets
                if (temp <= 32 && tag_offset + 1 + temp < (int) header->len) {
                    snprintf(ret_packinfo->ssid, temp, "%s", &msgbuf[tag_offset+1]);

                    // Munge it down to printable characters... SSID's can be anything
                    // but if we can't print them it's not going to be very useful
                    MungeToPrintable(ret_packinfo->ssid, temp);
                }

            }

            // Find the offset of flag 3 and get the channel
            if ((tag_offset = GetTagOffset(36, 3, header, data)) > 0) {
                // Extract the channel from the next byte (GetTagOffset returns
                // us on the size byte)
                temp = msgbuf[tag_offset+1];
                ret_packinfo->channel = (int) temp;
            }

            // Extract the CISCO beacon info
            if ((tag_offset = GetTagOffset(36, 133, header, data)) > 0) {
                if ((unsigned) tag_offset + 11 < header->len) {
                    snprintf(ret_packinfo->beacon_info, BEACON_INFO_LEN, "%s", &msgbuf[tag_offset+11]);
                    MungeToPrintable(ret_packinfo->beacon_info, BEACON_INFO_LEN);
                } else {
                    ret_packinfo->type = packet_noise;
                }
            }

            // Extract the supported rates
            if ((tag_offset = GetTagOffset(36, 1, header, data)) > 0) {
                for (int x = 0; x < msgbuf[tag_offset]; x++) {
                    if (ret_packinfo->maxrate < (msgbuf[tag_offset+1+x] & 0x7F) * 0.5)
                        ret_packinfo->maxrate = (msgbuf[tag_offset+1+x] & 0x7F) * 0.5;
                }
            }


            // Extract the MAC's
            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            ret_packinfo->type = packet_beacon;

            if (ret_packinfo->ap == 0) {
                // Weird adhoc beacon where the BSSID isn't 'right' so we use the source instead.
                ret_packinfo->bssid_mac = ret_packinfo->source_mac;
                ret_packinfo->type = packet_adhoc;
            }

        } else if (fc->subtype == 4) {
            // Probe req
            if ((tag_offset = GetTagOffset(24, 0, header, data)) > 0) {
                temp = (msgbuf[tag_offset] & 0xFF) + 1;

                if (temp <= 32 && tag_offset + 1 + temp < (int) header->len) {
                    snprintf(ret_packinfo->ssid, temp, "%s", &msgbuf[tag_offset+1]);
                    // Munge us to printable
                    MungeToPrintable(ret_packinfo->ssid, temp);
                } else {
                    ret_packinfo->type = packet_noise;
                }
            }

            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr1;

            ret_packinfo->type = packet_probe_req;

        } else if (fc->subtype == 5) {
            ret_packinfo->type = packet_probe_response;

            if ((tag_offset = GetTagOffset(36, 0, header, data)) > 0) {
                temp = (msgbuf[tag_offset] & 0xFF) + 1;

                if (temp <= 32 && tag_offset + 1 + temp < (int) header->len) {
                    snprintf(ret_packinfo->ssid, temp, "%s", &msgbuf[tag_offset+1]);
                    MungeToPrintable(ret_packinfo->ssid, temp);
                } else {
                    ret_packinfo->type = packet_noise;
                }
            }

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            // First byte of offsets
            ret_packinfo->header_offset = 24;
        } else if (fc->subtype == 3) {
            ret_packinfo->type = packet_reassociation;

            if ((tag_offset = GetTagOffset(36, 0, header, data)) > 0) {
                temp = (msgbuf[tag_offset] & 0xFF) + 1;

                if (temp <= 32 && tag_offset + 1 + temp < (int) header->len) {
                    snprintf(ret_packinfo->ssid, temp, "%s", &msgbuf[tag_offset+1]);
                    MungeToPrintable(ret_packinfo->ssid, temp);
                } else {
                    ret_packinfo->type = packet_noise;
                }
            }

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

        } else if (fc->subtype == 10) {
            // Disassociation
            ret_packinfo->type = packet_disassociation;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            uint16_t rcode;
            memcpy(&rcode, (const char *) &msgbuf[24], 2);

            ret_packinfo->reason_code = rcode;
        } else if (fc->subtype == 12) {
            // deauth
            ret_packinfo->type = packet_deauth;

            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr2;

            uint16_t rcode;
            memcpy(&rcode, (const char *) &msgbuf[24], 2);

            ret_packinfo->reason_code = rcode;
        }
    } else if (fc->type == 2) {
        // Data packets
        ret_packinfo->type = packet_data;

        // Extract ID's
        if (fc->to_ds == 0 && fc->from_ds == 0) {
            // Adhoc's get specially typed and their BSSID is set to
            // their source (I can't think of anything more reasonable
            // to do with them)
            ret_packinfo->dest_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->bssid_mac = addr1;

            // No distribution flags

            // First byte of offsets
            ret_packinfo->header_offset = 24;

            ret_packinfo->type = packet_adhoc_data;
        } else if (fc->to_ds == 0 && fc->from_ds == 1) {
            ret_packinfo->dest_mac = addr0;
            ret_packinfo->bssid_mac = addr1;
            ret_packinfo->source_mac = addr2;

            ret_packinfo->distrib = from_distribution;

            // First byte of offsets
            ret_packinfo->header_offset = 24;

        } else if (fc->to_ds == 1 && fc->from_ds == 0) {
            ret_packinfo->bssid_mac = addr0;
            ret_packinfo->source_mac = addr1;
            ret_packinfo->dest_mac = addr2;

            ret_packinfo->distrib = to_distribution;

            // First byte of offsets
            ret_packinfo->header_offset = 24;

        } else if (fc->to_ds == 1 && fc->from_ds == 1) {
            // AP->AP
            // Source is a special offset to the source
            // Dest is the reciever address

            // If we aren't long enough to hold a intra-ds packet, bail
            if (header->len < 30) {
                ret_packinfo->type = packet_noise;
                return;
            }

            ret_packinfo->bssid_mac = addr1;
            ret_packinfo->source_mac = addr3;
            ret_packinfo->dest_mac = addr0;

            ret_packinfo->distrib = inter_distribution;

            // First byte of offsets
            ret_packinfo->header_offset = 30;

            ret_packinfo->type = packet_ap_broadcast;
        }

        // Detect encrypted frames
        if (fc->wep) {
            ret_packinfo->encrypted = 1;

            // Match the range of cryptographically weak packets and let us
            // know.

            // New detection method from Airsnort 2.0, should be much better.
            unsigned int sum;
            if (data[ret_packinfo->header_offset+1] == 255 && data[ret_packinfo->header_offset] > 2 &&
                data[ret_packinfo->header_offset] < 16) {
                ret_packinfo->interesting = 1;
            } else {
                sum = data[ret_packinfo->header_offset] + data[ret_packinfo->header_offset+1];
                if (sum == 1 && (data[ret_packinfo->header_offset + 2] <= 0x0A ||
                                 data[ret_packinfo->header_offset + 2] == 0xFF)) {
                    ret_packinfo->interesting = 1;
                } else if (sum <= 0x0C && (data[ret_packinfo->header_offset + 2] >= 0xF2 &&
                                           data[ret_packinfo->header_offset + 2] <= 0xFE &&
                                           data[ret_packinfo->header_offset + 2] != 0xFD))
                    ret_packinfo->interesting = 1;
            }

        } else if (parm->fuzzy_crypt && (unsigned int) ret_packinfo->header_offset+9 < header->len) {
            // Do a fuzzy data compare... if it's not:
            // 0xAA - IP LLC
            // 0x42 - I forgot.
            // 0xF0 - Netbios
            // 0xE0 - IPX
            if (data[ret_packinfo->header_offset] != 0xAA && data[ret_packinfo->header_offset] != 0x42 &&
                data[ret_packinfo->header_offset] != 0xF0 && data[ret_packinfo->header_offset] != 0xE0)
                ret_packinfo->encrypted = 1;

            if (data[ret_packinfo->header_offset] >= 3 && data[ret_packinfo->header_offset] < 16 &&
                data[ret_packinfo->header_offset + 1] == 255) {
                ret_packinfo->interesting = 1;
                ret_packinfo->encrypted = 1;
            }
        }

        if (!ret_packinfo->encrypted && (ret_packinfo->type == packet_data || ret_packinfo->type == packet_adhoc_data ||
                               ret_packinfo->type == packet_ap_broadcast))
            GetProtoInfo(ret_packinfo, header, data, &ret_packinfo->proto);
    }

    // Do a little sanity checking on the BSSID
    for (int x = 0; x < MAC_LEN; x++) {
        if (ret_packinfo->bssid_mac[x] > 0xFF ||
            ret_packinfo->source_mac[x] > 0xFF ||
            ret_packinfo->dest_mac[x] > 0xFF) {

            //printf("noise packet, invalid mac\n");

            ret_packinfo->type = packet_noise;
            break;
        }
    }

}

void GetProtoInfo(const packet_info *in_info, const pkthdr *header,
                  const u_char *in_data, proto_info *ret_protoinfo) {
    // We cheat a little to protect ourselves.  We define a packet
    // that's double the maximum size, zero it out, and copy our data
    // packet into it.  This should give us a little leeway if a packet
    // is corrupt and we don't detect it -- it's better to read some
    // nulls than it is to fall into a segfault.
    u_char data[MAX_PACKET_LEN * 2];
    memset(data, 0, MAX_PACKET_LEN * 2);
    memcpy(data, in_data, header->len);

    //proto_info ret;

    // Zero the entire struct
    memset(ret_protoinfo, 0, sizeof(proto_info));

    // Point to the data packet
    uint8_t *msgbuf = (uint8_t *) data;

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

            while (offset < header->len) {
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
        }
    }

    // This isn't an 'else' because we want to try to handle it if it looked like a netstumbler
    // but wasn't.
    if (in_info->dest_mac == LOR_MAC) {
        /* This gets confused with STP, so we just rely on that one multicast now. ||
         (in_info->distrib == no_distribution && in_info->dest_mac[0] == 1)) {
         */
        // First thing we do is see if the destination matches the multicast for
        // lucent outdoor routers, or if we're a multicast with no BSSID.  This should
        // be indicative of being a lucent outdoor router
        ret_protoinfo->type = proto_lor;
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

        uint16_t d, s;

        memcpy(&s, (uint16_t *) &msgbuf[in_info->header_offset + UDP_OFFSET], 2);
        memcpy(&d, (uint16_t *) &msgbuf[in_info->header_offset + UDP_OFFSET + 2], 2);

        ret_protoinfo->sport = ntohs((unsigned short int) s);
        ret_protoinfo->dport = ntohs((unsigned short int) d);

        memcpy(ret_protoinfo->source_ip, (const uint8_t *) &msgbuf[in_info->header_offset + IP_OFFSET + 3], 4);
        memcpy(ret_protoinfo->dest_ip, (const uint8_t *) &msgbuf[in_info->header_offset + IP_OFFSET + 7], 4);

        if (ret_protoinfo->sport == 138 && ret_protoinfo->dport == 138) {
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

                if (offset < header->len && offset + 32 < header->len) {
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

        } else if (memcmp(&data[in_info->header_offset + DHCPD_OFFSET], DHCPD_SIGNATURE,
                          sizeof(DHCPD_SIGNATURE)) == 0) {

            // DHCP server responding
            ret_protoinfo->type = proto_dhcp_server;

            // Now we go through all the options until we find options 1, 3, and 53
            // netmask.
            unsigned int offset = in_info->header_offset + DHCPD_OFFSET + 252;


            while (offset < header->len) {
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
                        memcpy(ret_protoinfo->misc_ip, (const uint8_t *) &data[in_info->header_offset + DHCPD_OFFSET + 28], 4);
                    }
                }
                offset += data[offset+1]+2;
            }
        }
    } else if (memcmp(&data[in_info->header_offset + ARP_OFFSET], ARP_SIGNATURE,
               sizeof(ARP_SIGNATURE)) == 0) {
        // ARP
        ret_protoinfo->type = proto_arp;

        memcpy(ret_protoinfo->source_ip, (const uint8_t *) &data[in_info->header_offset + ARP_OFFSET + 16], 4);
        memcpy(ret_protoinfo->misc_ip, (const uint8_t *) &data[in_info->header_offset + ARP_OFFSET + 26], 4);
    } else if (memcmp(&data[in_info->header_offset + IP_OFFSET], TCP_SIGNATURE,
                      sizeof(TCP_SIGNATURE)) == 0) {
        // TCP
        ret_protoinfo->type = proto_misc_tcp;

        uint16_t d, s;

        memcpy(&s, (uint16_t *) &msgbuf[in_info->header_offset + TCP_OFFSET], 2);
        memcpy(&d, (uint16_t *) &msgbuf[in_info->header_offset + TCP_OFFSET + 2], 2);

        ret_protoinfo->sport = ntohs((unsigned short int) s);
        ret_protoinfo->dport = ntohs((unsigned short int) d);

        memcpy(ret_protoinfo->source_ip, (const uint8_t *) &msgbuf[in_info->header_offset + IP_OFFSET + 3], 4);
        memcpy(ret_protoinfo->dest_ip, (const uint8_t *) &msgbuf[in_info->header_offset + IP_OFFSET + 7], 4);

    }
}

// Pull all the printable data out
vector<string> GetPacketStrings(const packet_info *in_info, const pkthdr *header, const u_char *in_data) {
    char str[MAX_PACKET_LEN];
    memset(str, 0, MAX_PACKET_LEN);
    vector<string> ret;

    int pos = 0;
    int printable = 0;
    for (unsigned int x = in_info->header_offset; x < header->len; x++) {
        if (printable && !isprint(in_data[x]) && pos != 0) {
            if (pos > 4)
                ret.push_back(str);

            memset(str, 0, pos+1);
            pos = 0;
        } else if (isprint(in_data[x])) {
            str[pos++] = in_data[x];
            printable = 1;
        }
    }

    return ret;
}
