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

#define BEACON_INFO_LEN 128

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
} pkthdr;

// And 802.11 packet frame header
typedef struct {
    unsigned short version : 2;
    unsigned short type : 2;
    unsigned short subtype : 4;
    unsigned short to_ds : 1;
    unsigned short from_ds : 1;
    unsigned short more_fragments : 1;
    unsigned short retry : 1;
    unsigned short power_management : 1;
    unsigned short more_data : 1;
    unsigned short wep : 1;
    unsigned short order : 1;
} frame_control;

typedef struct {
    uint8_t timestamp[8];
    unsigned int beacon : 16;
    unsigned short ess : 1;
    unsigned short ibss : 1;
    unsigned short unused1 : 1;
    unsigned short unused2 : 1;
    unsigned short wep : 1;
    unsigned short short_preamble : 1;
    unsigned short pbcc : 1;
    unsigned short agility : 1;
    unsigned int coordinator : 8;
} fixed_parameters;

enum protocol_info_type {
    proto_unknown,
    proto_udp, proto_misc_tcp, proto_arp, proto_dhcp_server,
    proto_cdp,
    proto_netbios, proto_netbios_tcp,
    proto_ipx,
    proto_ipx_tcp,
};

enum protocol_netbios_type {
    proto_netbios_unknown,
    proto_netbios_host, proto_netbios_master,
    proto_netbios_domain, proto_netbios_query, proto_netbios_pdcquery,
};

// CDP
// Cisco Discovery Protocol
// This spews a tremendous amount of revealing information about the
// internals of a network, if they have cisco equipment.
typedef struct {
    unsigned int : 8;
    unsigned int : 8;

    unsigned int : 8;
    unsigned int : 1;
    unsigned int level1 : 1;
    unsigned int igmp_forward : 1;
    unsigned int nlp : 1;
    unsigned int level2_switching : 1;
    unsigned int level2_sourceroute : 1;
    unsigned int level2_transparent : 1;
    unsigned int level3 : 1;
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
    unsigned int : 8;
    unsigned int type : 8;
    unsigned int : 8;
    unsigned int length : 8;
    char data;
} cdp_element;

typedef struct {
    unsigned int type : 8;
    unsigned int length : 8;
    unsigned int proto : 8;
    unsigned int : 8;
    unsigned int proto_length : 8;
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

};


// ------------------------


// packet conversion and extraction utilities
// Packet types
enum packet_info_type {
    packet_unknown, packet_beacon, packet_probe_req, packet_data,
    packet_ap_broadcast, packet_adhoc, packet_adhoc_data,
    packet_noise, packet_probe_response, packet_reassociation
};

// distribution directions
enum distribution_type {
    no_distribution, from_distribution, to_distribution, inter_distribution
};

// Info about a packet
typedef struct {
    // Packet info type
    packet_info_type type;

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
    // Is this an AP or a adhoc?
    int ap;
    // What channel?
    int channel;
    // Is this encrypted?
    int encrypted;
    // Is it weak crypto?
    int interesting;
    // MAC source of packet
    uint8_t source_mac[MAC_LEN];
    // MAC dest of packet
    uint8_t dest_mac[MAC_LEN];
    // BSSID MAC this packet belongs to
    uint8_t bssid_mac[MAC_LEN];

    // Beacon interval if this is a beacon packet, raw 16bit format
    int beacon;

    // Cisco tacks extra info into the beacon.  This is nice.
    char beacon_info[BEACON_INFO_LEN];

    // Offset of the header
    int header_offset;

    proto_info proto;

    double maxrate;

} packet_info;

// ----------------------------------
// String munger
void MungeToPrintable(char *in_data, int max);

// Info extraction functions
int GetTagOffset(int init_offset, int tagnum, const pkthdr *header, const u_char *data);
packet_info GetPacketInfo(const pkthdr *header, const u_char *data, packet_parm *parm);
proto_info GetProtoInfo(const packet_info *in_info, const pkthdr *header, const u_char *in_data);

vector<string> GetPacketStrings(const packet_info *in_info, const pkthdr *header, const u_char *in_data);

#endif

