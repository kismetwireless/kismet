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

#ifndef __PACKET_H__
#define __PACKET_H__

#include "config.h"

#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <string>
#include <vector>
#include <map>

// These won't include right if they're not in the C namespace
extern "C" {
#ifdef HAVE_LIBPCAP
#ifndef HAVE_PCAPPCAP_H
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif
#endif

#ifdef HAVE_LIBWIRETAP
#include <wtap.h>
#endif
}

#define DEVNAME_LEN 16
#define MAX_PACKET_LEN 8192

#define SSID_SIZE 32

#define MAC_LEN 6
#define MAC_STR_LEN (MAC_LEN * 2) + 6

#define BEACON_INFO_LEN 128

// Cribbed from ethereal, pointer to host endian swap
#define kptoh16(p) (uint16_t) ((uint16_t) * ((uint8_t *)(p) + 0) << 8 | \
                               (uint16_t) * ((uint8_t *)(p) + 1) << 0)

#define kptoh24(p) (uint32_t) ((uint32_t) * ((uint8_t *)(p) + 0) << 16 | \
                               (uint32_t) * ((uint8_t *)(p) + 1) << 8 | \
                               (uint32_t) * ((uint8_t *)(p) + 2) << 0)

#define kptoh32(p) (uint32_t) ((uint32_t) * ((uint8_t *)(p) + 0) << 24 | \
                               (uint32_t) * ((uint8_t *)(p) + 1) << 16 | \
                               (uint32_t) * ((uint8_t *)(p) + 2) << 8 | \
                               (uint32_t) * ((uint8_t *)(p) + 3) << 0)

// Inline converters
#ifdef WORDS_BIGENDIAN
#define ktoh16(x) ((uint16_t) \
    ((uint16_t)((x) & 0x00FF) << 8 | \
    (uint16_t)((x) & 0xFF00) >> 8))

#define ktoh32(x) ((uint32_t) \
    ((uint32_t)((x) & 0x000000FF) << 24 | \
    (uint32_t)((x) & 0x0000FF00) << 8 | \
    (uint32_t)((x) & 0x00FF0000) >> 8 | \
    (uint32_t)((x) & 0xFF000000) >> 24)
#else
#define ktoh16(x) (x)
#define ktoh32(x) (x)
#endif


// Parmeters to the packet info
typedef struct packet_parm {
    int fuzzy_crypt;
};

// Very similar to pcap_pkthdr and wtap_pkthdr.  This is our
// common packet header that we convert everything to.
typedef struct {
    unsigned int len;		// The amount of data we've actually got
    unsigned int caplen;	// The amount of data originally captured
    struct timeval ts;
    int quality;
    int signal;
    int noise;
    int error;                  // Capture source told us this was a bad packet
} pkthdr;

#ifdef WORDS_BIGENDIAN
// Byte ordering for bigendian systems.  Bitwise strcts are so funky.
typedef struct {
    unsigned short subtype : 4 __attribute__ ((packed));
    unsigned short type : 2 __attribute__ ((packed));
    unsigned short version : 2 __attribute__ ((packed));

    unsigned short order : 1 __attribute__ ((packed));
    unsigned short wep : 1 __attribute__ ((packed));
    unsigned short more_data : 1 __attribute__ ((packed));
    unsigned short power_management : 1 __attribute__ ((packed));

    unsigned short retry : 1 __attribute__ ((packed));
    unsigned short more_fragments : 1 __attribute__ ((packed));
    unsigned short from_ds : 1 __attribute__ ((packed));
    unsigned short to_ds : 1 __attribute__ ((packed));
} frame_control;

typedef struct {
    unsigned short frag : 12 __attribute__ ((packed));
    unsigned short sequence : 4 __attribute__ ((packed));
} wireless_fragseq;

typedef struct {
    uint8_t timestamp[8];

    // This field must be converted to host-endian before being used
    unsigned int beacon : 16 __attribute__ ((packed));

    unsigned short agility : 1 __attribute__ ((packed));
    unsigned short pbcc : 1 __attribute__ ((packed));
    unsigned short short_preamble : 1 __attribute__ ((packed));
    unsigned short wep : 1 __attribute__ ((packed));

    unsigned short unused2 : 1 __attribute__ ((packed));
    unsigned short unused1 : 1 __attribute__ ((packed));
    unsigned short ibss : 1 __attribute__ ((packed));
    unsigned short ess : 1 __attribute__ ((packed));

    unsigned int coordinator : 8 __attribute__ ((packed));

} fixed_parameters;

#else
// And 802.11 packet frame header
typedef struct {
    unsigned short version : 2 __attribute__ ((packed));
    unsigned short type : 2 __attribute__ ((packed));
    unsigned short subtype : 4 __attribute__ ((packed));

    unsigned short to_ds : 1 __attribute__ ((packed));
    unsigned short from_ds : 1 __attribute__ ((packed));
    unsigned short more_fragments : 1 __attribute__ ((packed));
    unsigned short retry : 1 __attribute__ ((packed));

    unsigned short power_management : 1 __attribute__ ((packed));
    unsigned short more_data : 1 __attribute__ ((packed));
    unsigned short wep : 1 __attribute__ ((packed));
    unsigned short order : 1 __attribute__ ((packed));
} frame_control;

typedef struct {
    unsigned short frag : 4 __attribute__ ((packed));
    unsigned short sequence : 12 __attribute__ ((packed));
} wireless_fragseq;

typedef struct {
    uint8_t timestamp[8];

    // This field must be converted to host-endian before being used
    unsigned int beacon : 16 __attribute__ ((packed));

    unsigned short ess : 1 __attribute__ ((packed));
    unsigned short ibss : 1 __attribute__ ((packed));
    unsigned short unused1 : 1 __attribute__ ((packed));
    unsigned short unused2 : 1 __attribute__ ((packed));

    unsigned short wep : 1 __attribute__ ((packed));
    unsigned short short_preamble : 1 __attribute__ ((packed));
    unsigned short pbcc : 1 __attribute__ ((packed));
    unsigned short agility : 1 __attribute__ ((packed));

    unsigned int coordinator : 8 __attribute__ ((packed));
} fixed_parameters;


#endif

enum protocol_info_type {
    proto_unknown,
    proto_udp, proto_misc_tcp, proto_arp, proto_dhcp_server,
    proto_cdp,
    proto_netbios, proto_netbios_tcp,
    proto_ipx,
    proto_ipx_tcp,
    proto_lor,
    proto_netstumbler,
    proto_lucenttest,
    proto_wellenreiter,
    proto_gstsearch
};

enum protocol_netbios_type {
    proto_netbios_unknown,
    proto_netbios_host, proto_netbios_master,
    proto_netbios_domain, proto_netbios_query, proto_netbios_pdcquery
};

// CDP
// Cisco Discovery Protocol
// This spews a tremendous amount of revealing information about the
// internals of a network, if they have cisco equipment.
typedef struct {
    unsigned int : 8 __attribute__ ((packed));
    unsigned int : 8 __attribute__ ((packed));

    unsigned int : 8 __attribute__ ((packed));
    unsigned int : 1 __attribute__ ((packed));
    unsigned int level1 : 1 __attribute__ ((packed));
    unsigned int igmp_forward : 1 __attribute__ ((packed));
    unsigned int nlp : 1 __attribute__ ((packed));
    unsigned int level2_switching : 1 __attribute__ ((packed));
    unsigned int level2_sourceroute : 1 __attribute__ ((packed));
    unsigned int level2_transparent : 1 __attribute__ ((packed));
    unsigned int level3 : 1 __attribute__ ((packed));
} cdp_capabilities;

typedef struct {
    char dev_id[128];
    uint8_t ip[4];
    char interface[128];
    cdp_capabilities cap;
    char software[512];
    char platform[128];
} cdp_packet;

typedef struct {
    unsigned int : 8 __attribute__ ((packed));
    unsigned int type : 8 __attribute__ ((packed));
    unsigned int : 8 __attribute__ ((packed));
    unsigned int length : 8 __attribute__ ((packed));
    char data;
} cdp_element;

typedef struct {
    unsigned int type : 8 __attribute__ ((packed));
    unsigned int length : 8 __attribute__ ((packed));
    unsigned int proto : 8 __attribute__ ((packed));
    unsigned int : 8 __attribute__ ((packed));
    unsigned int proto_length : 8 __attribute__ ((packed));
    char addr;
} cdp_proto_element;

// Info about a protocol
typedef struct proto_info {
    protocol_info_type type;

    uint8_t source_ip[4];
    uint8_t dest_ip[4];

    uint8_t misc_ip[4];

    uint8_t mask[4];

    uint8_t gate_ip[4];

    uint16_t sport, dport;

    cdp_packet cdp;

    char netbios_source[17];

    protocol_netbios_type nbtype;

    // Extra versioning/details of the proto type
    int prototype_extra;

};


// ------------------------

// A packet MAC address
typedef struct mac_addr {
    uint8_t mac[MAC_LEN];
    uint64_t longmac;
    uint8_t mask;
    int error;

    void struc2long() {
        longmac = 0;
        error = 0;
        for (int x = 0; x < MAC_LEN; x++) {
            if (mac[x] > 0xFF) {
                longmac = 0;
                error = 1;
                break;
            }

            longmac |= (uint64_t) mac[x] << ((MAC_LEN - x - 1) * 8);
        }
    }

    mac_addr() {
        memset(mac, 0, MAC_LEN);
        longmac = 0;
        error = 0;
        mask = 0;
    }

    mac_addr(const uint8_t *in) {
        for (int x = 0; x < MAC_LEN; x++)
            mac[x] = in[x];
        mask = 0;
        error = 0;
        struc2long();
    }

    mac_addr(const char *in) {
        memset(mac, 0, MAC_LEN);

        short int bs_in[MAC_LEN];
        if (sscanf(in, "%hX:%hX:%hX:%hX:%hX:%hX",
                   &bs_in[0], &bs_in[1], &bs_in[2], &bs_in[3], &bs_in[4], &bs_in[5]) == 6) {
            for (int x = 0; x < MAC_LEN; x++)
                mac[x] = bs_in[x];
        } else {
            error = 1;
        }
        mask = 0;
        struc2long();
    }

    bool operator== (const mac_addr& op) const {
        return (longmac == op.longmac);
    }

    bool operator< (const mac_addr& op) const {
        return (longmac < op.longmac);
    }

    mac_addr& operator= (mac_addr op) {
        memcpy(mac, op.mac, MAC_LEN);
        longmac = op.longmac;
        return *this;
    }

    mac_addr& operator= (uint8_t *in) {
        for (int x = 0; x < MAC_LEN; x++)
            mac[x] = in[x];
        struc2long();
        return *this;
    }

    mac_addr& operator= (char *in) {
        memset(mac, 0, MAC_LEN);

        short int bs_in[MAC_LEN];
        if (sscanf(in, "%hX:%hX:%hX:%hX:%hX:%hX",
                   &bs_in[0], &bs_in[1], &bs_in[2], &bs_in[3], &bs_in[4], &bs_in[5]) == 6) {
            for (int x = 0; x < MAC_LEN; x++)
                mac[x] = bs_in[x];
        } else {
            error = 1;
        }
        struc2long();
        return *this;
    }

    const uint8_t& operator[] (const int& index) const {
        int mdex = index;
        if (index < 0 || index > MAC_LEN)
            mdex = 0;
        return mac[mdex];
    }

    string Mac2String() const {
        if (mask == 0) {
            char tempstr[MAC_STR_LEN];

            snprintf(tempstr, MAC_STR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return tempstr;
        }

        string ret;

        for (unsigned int macbit = 0; macbit < MAC_LEN; macbit++) {
            char adr[3];
            if (macbit < mask)
                snprintf(adr, 3, "%02X", mac[macbit]);
            else
                snprintf(adr, 3, "**");

            ret += adr;
            ret += ":";
        }

        return ret;
    }

};


// packet conversion and extraction utilities
// Packet types, these should correspond to the frame header types
enum packet_type {
    packet_noise = -2,  // We're too short or otherwise corrupted
    packet_unknown = -1, // What are we?
    packet_management = 0, // LLC management
    packet_phy = 1, // Physical layer packets, most drivers can't provide these
    packet_data = 2, // Data frames
};

// Subtypes are a little odd because we re-use values depending on the type
enum packet_sub_type {
    packet_sub_unknown = -1,
    // Management subtypes
    packet_sub_association_req = 0,
    packet_sub_association_resp = 1,
    packet_sub_reassociation_req = 2,
    packet_sub_reassociation_resp = 3,
    packet_sub_probe_req = 4,
    packet_sub_probe_resp = 5,
    packet_sub_beacon = 8,
    packet_sub_atim = 9,
    packet_sub_disassociation = 10,
    packet_sub_authentication = 11,
    packet_sub_deauthentication = 12,
    // Phy subtypes
    packet_sub_rts = 11,
    packet_sub_cts = 12,
    packet_sub_ack = 13,
    packet_sub_cf_end = 14,
    packet_sub_cf_end_ack = 15,
    // Data subtypes
    packet_sub_data = 0,
    packet_sub_data_cf_ack = 1,
    packet_sub_data_cf_poll = 2,
    packet_sub_data_cf_ack_poll = 3,
    packet_sub_data_null = 4,
    packet_sub_cf_ack = 5,
    packet_sub_cf_ack_poll = 6
};

/*
enum packet_info_type {
    packet_unknown, packet_beacon, packet_probe_req, packet_data, packet_ack,
    packet_ap_broadcast, packet_adhoc, packet_adhoc_data,
    packet_noise, packet_probe_response, packet_reassociation,
    packet_auth, packet_deauth, packet_disassociation, packet_association_req,
    packet_association_response
    };
    */

// distribution directions
enum distribution_type {
    no_distribution, from_distribution, to_distribution, inter_distribution, adhoc_distribution
};

// Info about a packet
typedef struct {
    // Packet info type
    packet_type type;
    packet_sub_type subtype;

    // reason code for some management protocols
    int reason_code;

    // Timestamp.  Second precision is fine.
    time_t time;

    // Connection info
    int quality;
    int signal;
    int noise;

    // SSID
    char ssid[SSID_SIZE+1];

    // Where did it come from?
    distribution_type distrib;
    // Is wep enabled?
    int wep;
    // Was it flagged as ess? (ap)
    int ess;
    // What channel?
    int channel;
    // Is this encrypted?
    int encrypted;
    // Is it weak crypto?
    int interesting;

    mac_addr source_mac;
    mac_addr dest_mac;
    mac_addr bssid_mac;

    // Beacon interval if this is a beacon packet, raw 16bit format
    int beacon;

    // Cisco tacks extra info into the beacon.  This is nice.
    char beacon_info[BEACON_INFO_LEN];

    // Offset of the header
    int header_offset;

    proto_info proto;

    double maxrate;

    int sequence_number;
    int frag_number;

    int duration;

} packet_info;

// ----------------------------------
// String munger
void MungeToPrintable(char *in_data, int max);

// Info extraction functions
int GetTagOffset(int init_offset, int tagnum, const pkthdr *header,
                 const u_char *data, map<int, int> *tag_cache_map);
void GetPacketInfo(const pkthdr *header, const u_char *data,
                   packet_parm *parm, packet_info *ret_packinfo);
void GetProtoInfo(const packet_info *in_info, const pkthdr *header,
                  const u_char *in_data, proto_info *ret_protoinfo);

vector<string> GetPacketStrings(const packet_info *in_info, const pkthdr *header, const u_char *in_data);

#endif

