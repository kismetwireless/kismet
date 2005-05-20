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
#include <algorithm>
#include <string>
#include <vector>
#include <map>

#include "macaddr.h"
#include "endian_magic.h"

#define DEVNAME_LEN 16
#define MAX_PACKET_LEN 10240

#define SSID_SIZE 32

#define MAC_LEN 6
#define MAC_STR_LEN ((MAC_LEN * 2) + 6)

#define BEACON_INFO_LEN 128

// Parmeters to the packet info
typedef struct packet_parm {
    int fuzzy_crypt;
};

// Signalling layer info - what protocol are we seeing data on?
// Not all of these types are currently supported, of course
enum carrier_type {
    carrier_unknown,
    carrier_80211b,
    carrier_80211bplus,
    carrier_80211a,
    carrier_80211g,
    carrier_80211fhss,
    carrier_80211dsss
};

// Packet encoding info - how are packets encoded?
enum encoding_type {
    encoding_unknown,
    encoding_cck,
    encoding_pbcc,
    encoding_ofdm
};

// Very similar to pcap_pkthdr and wtap_pkthdr.  This is our
// common packet header that we convert everything to.
typedef struct {
    unsigned int len;		// The amount of data we've actually got
    unsigned int caplen;	// The amount of data originally captured
    struct timeval ts;          // Capture timestamp
    int quality;                // Signal quality
    int signal;                 // Signal strength
    int noise;                  // Noise level
    int error;                  // Capture source told us this was a bad packet
    int channel;                // Hardware receive channel, if the drivers tell us
    int modified;               // Has moddata been populated?
    uint8_t *data;              // Raw packet data
    uint8_t *moddata;           // Modified packet data
    char sourcename[32];        // Name of the source that generated the data
    carrier_type carrier;       // Signal carrier
    encoding_type encoding;     // Signal encoding
    int datarate;               // Data rate in units of 100 kbps
    float gps_lat;              // GPS coordinates
    float gps_lon;
    float gps_alt;
    float gps_spd;
    float gps_heading;
    int gps_fix;
    packet_parm parm;           // Parameters from the packet source that trickle down
} kis_packet;

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
    proto_turbocell,
    proto_netstumbler,
    proto_lucenttest,
    proto_wellenreiter,
    proto_iapp,
    proto_leap,
    proto_ttls,
    proto_tls,
    proto_peap,
    proto_isakmp,
    proto_pptp,
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

// 802.1x Header
typedef struct dot1x_header {
    uint8_t    version;
    uint8_t    type;
    uint16_t   length;
} __attribute__ ((packed)) dot1x_header_t;

// EAP Packet header
typedef struct eap_packet {
    uint8_t    code; /* 1=request, 2=response, 3=success, 4=failure */
    uint8_t    identifier; /* Sequential counter, not sure what it's for */
    uint16_t   length; /* Length of the entire EAP message */
    uint8_t    type; /* 0x11 for LEAP */
    /* The fields that follow the type octet are variable, depending on the
       type and code values.  This information isn't important for us. */
} __attribute__ ((packed)) eap_packet_t;

// ISAKMP packet header
typedef struct isakmp_packet {
    uint8_t    init_cookie[8];
    uint8_t    resp_cookie[8];
    uint8_t    next_payload;
    uint8_t    version;
    uint8_t    exchtype;
    uint8_t    flags;
    uint32_t   messageid;
    uint32_t   length;
} __attribute__ ((packed)) isakmp_packet_t;

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

// packet conversion and extraction utilities
// Packet types, these should correspond to the frame header types
enum packet_type {
    packet_noise = -2,  // We're too short or otherwise corrupted
    packet_unknown = -1, // What are we?
    packet_management = 0, // LLC management
    packet_phy = 1, // Physical layer packets, most drivers can't provide these
    packet_data = 2 // Data frames
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

// distribution directions
enum distribution_type {
    no_distribution, from_distribution, to_distribution, inter_distribution, adhoc_distribution
};

// Turbocell modes
enum turbocell_type {
    turbocell_unknown,
    turbocell_ispbase, // 0xA0
    turbocell_pollbase, // 0x80
    turbocell_nonpollbase, // 0x00
    turbocell_base // 0x40
};

// IAPP stuff
enum iapp_type {
    iapp_announce_request = 0,
    iapp_announce_response = 1,
    iapp_handover_request = 2,
    iapp_handover_response = 3
};

enum iapp_pdu {
    iapp_pdu_ssid = 0x00,
    iapp_pdu_bssid = 0x01,
    iapp_pdu_oldbssid = 0x02,
    iapp_pdu_msaddr = 0x03,
    iapp_pdu_capability = 0x04,
    iapp_pdu_announceint = 0x05,
    iapp_pdu_hotimeout = 0x06,
    iapp_pdu_messageid = 0x07,
    iapp_pdu_phytype = 0x10,
    iapp_pdu_regdomain = 0x11,
    iapp_pdu_channel = 0x12,
    iapp_pdu_beaconint = 0x13,
    iapp_pdu_ouiident = 0x80,
    iapp_pdu_authinfo = 0x81
};

enum iapp_cap {
    iapp_cap_forwarding = 0x40,
    iapp_cap_wep = 0x20
};

enum iapp_phy {
    iapp_phy_prop = 0x00,
    iapp_phy_fhss = 0x01,
    iapp_phy_dsss = 0x02,
    iapp_phy_ir = 0x03,
    iapp_phy_ofdm = 0x04
};

enum iapp_dom {
    iapp_dom_fcc = 0x10,
    iapp_dom_ic = 0x20,
    iapp_dom_etsi = 0x30,
    iapp_dom_spain = 0x31,
    iapp_dom_france = 0x32,
    iapp_dom_mkk = 0x40
};

enum iapp_auth {
    iapp_auth_status = 0x01,
    iapp_auth_username = 0x02,
    iapp_auth_provname = 0x03,
    iapp_auth_rxpkts = 0x04,
    iapp_auth_txpkts = 0x05,
    iapp_auth_rxbytes = 0x06,
    iapp_auth_txbytes = 0x07,
    iapp_auth_logintime = 0x08,
    iapp_auth_timelimit = 0x09,
    iapp_auth_vollimit = 0x0a,
    iapp_auth_acccycle = 0x0b,
    iapp_auth_rxgwords = 0x0c,
    iapp_auth_txgwords = 0x0d,
    iapp_auth_ipaddr = 0x0e,
    iapp_auth_trailer = 0xff
};

typedef struct {
    unsigned iapp_version : 8 __attribute__ ((packed));
    unsigned iapp_type : 8 __attribute__ ((packed));
} iapp_header;

typedef struct {
    unsigned pdu_type : 8 __attribute__ ((packed));
    unsigned pdu_len : 16 __attribute__ ((packed));
} iapp_pdu_header;

// Info about a packet
typedef struct {
    // Packet info type
    packet_type type;
    packet_sub_type subtype;

    // Is it a corrupt packet?  We might want to know what type it is
    // even if it's corrupt
    int corrupt;

    // reason code for some management protocols
    int reason_code;

    // Timestamp.  Second precision is fine.
    struct timeval ts;

    // Connection info
    int quality;
    int signal;
    int noise;

    // SSID
    char ssid[SSID_SIZE+1];
    int ssid_len;

    // Source name
    char sourcename[32];

    // Where did it come from?
    distribution_type distrib;
    // Is wep enabled?
    int wep;
	// Is WPA enabled?
	int wpa;
    // Was the encryption detection fuzzy?
    int fuzzy;
    // Was it flagged as ess? (ap)
    int ess;
    // What channel?
    int channel;
    // Is this encrypted?
    int encrypted;
    // Did we decode it?
    int decoded;
    // Is it weak crypto?
    int interesting;
    // What carrier brought us this packet?
    carrier_type carrier;
    // What encoding?
    encoding_type encoding;
    // What data rate?
    int datarate;

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

    uint64_t timestamp;
    int sequence_number;
    int frag_number;

    int duration;

    int datasize;

    // Turbocell tracking info
    int turbocell_nid;
    turbocell_type turbocell_mode;
    int turbocell_sat;

    // Location info
    float gps_lat, gps_lon, gps_alt, gps_spd, gps_heading;
    int gps_fix;

    // ICV and key number
    uint32_t ivset;

} packet_info;

typedef struct {
    int fragile;
    mac_addr bssid;
    unsigned char key[WEPKEY_MAX];
    unsigned int len;
    unsigned int decrypted;
    unsigned int failed;
} wep_key_info;

// ----------------------------------
// String munger
void MungeToPrintable(char *in_data, int max);

// Info extraction functions
int GetTagOffset(int init_offset, int tagnum, kis_packet *packet,
                 map<int, vector<int> > *tag_cache_map);
void GetPacketInfo(kis_packet *packet, packet_info *ret_packinfo,
                   macmap<wep_key_info *> *bssid_wep_map, unsigned char *identity);
void GetProtoInfo(kis_packet *packet, packet_info *in_info);
void DecryptPacket(kis_packet *packet, packet_info *in_info, 
                   macmap<wep_key_info *> *bssid_wep_map, unsigned char *identity);
int MangleDeCryptPacket(const kis_packet *packet, const packet_info *in_info,
                        kis_packet *outpack, uint8_t *data, uint8_t *moddata);
int MangleFuzzyCryptPacket(const kis_packet *packet, const packet_info *in_info,
                           kis_packet *outpack, uint8_t *data, uint8_t *moddata);

vector<string> GetPacketStrings(const packet_info *in_info, const kis_packet *packet);

// Sort packet_infos
class SortPacketInfos {
public:
    inline bool operator() (const packet_info x, const packet_info y) const {
        if (x.ts.tv_sec < y.ts.tv_sec ||
            (x.ts.tv_sec == y.ts.tv_sec && x.ts.tv_usec < y.ts.tv_usec))
            return 1;
        return 0;
    }
};


#endif

