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
#define MAX_PACKET_LEN 10240

#define SSID_SIZE 32

#define MAC_LEN 6
#define MAC_STR_LEN ((MAC_LEN * 2) + 6)

#define BEACON_INFO_LEN 128

// 64 bit ntoh/hton
#ifdef WORDS_BIGENDIAN
#define kis_hton64(x) (x)
#define kis_ntoh64(x) (x)
#else
#define kis_hton64(x) kis_swap64((x))
#define kis_ntoh64(x) kis_swap64((x))
#endif

#define kis_swap64(x) \
({ \
    uint64_t __x = (x); \
    ((uint64_t)( \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000000000ffULL) << 56) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
            (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
})

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

#define kptoh64(p) (uint64_t) ((uint64_t) * ((uint8_t *)(p) + 7) << 56 | \
                               (uint64_t) * ((uint8_t *)(p) + 6) << 48 | \
                               (uint64_t) * ((uint8_t *)(p) + 5) << 40 | \
                               (uint64_t) * ((uint8_t *)(p) + 4) << 32 | \
                               (uint64_t) * ((uint8_t *)(p) + 3) << 24 | \
                               (uint64_t) * ((uint8_t *)(p) + 2) << 16 | \
                               (uint64_t) * ((uint8_t *)(p) + 1) << 8 | \
                               (uint64_t) * ((uint8_t *)(p) + 0) << 0)

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
    proto_iapp
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
    uint64_t longmac;
    uint64_t longmask;
    int error;

    // Convert a string mac address to the long-int storage format, with mask conversion
    // if present.
    void string2long(const char *in) {
        short unsigned int *bs_in = new short unsigned int[MAC_LEN];

        error = 0;
        longmac = 0;
        longmask = (uint64_t) -1;

        // Get the MAC
        if (sscanf(in, "%hX:%hX:%hX:%hX:%hX:%hX",
                   &bs_in[0], &bs_in[1], &bs_in[2], &bs_in[3], &bs_in[4], &bs_in[5]) == 6) {

            for (int x = 0; x < MAC_LEN; x++)
                longmac |= (uint64_t) bs_in[x] << ((MAC_LEN - x - 1) * 8);

            // If it has a mask component, get that
            char *in_mask = strchr(in, '/');
            if (in_mask != NULL) {
                longmask = 0;

                // See if it's numerical or expanded
                if (strchr(in_mask + 1, ':') != NULL) {
                    // expanded, sscanf hex octets
                    if (sscanf(in_mask + 1, "%hX:%hX:%hX:%hX:%hX:%hX",
                               &bs_in[0], &bs_in[1], &bs_in[2],
                               &bs_in[3], &bs_in[4], &bs_in[5]) == 6) {

                        for (int x = 0; x < MAC_LEN; x++)
                            longmask |= (uint64_t) bs_in[x] << ((MAC_LEN - x - 1) * 8);
                    } else {
                        error = 1;
                    }
                } else {
                    // numerical, scan and shift
                    int nummask;
                    if (sscanf(in_mask + 1, "%d", &nummask) == 1) {
                        if (nummask == 48)
                            nummask = 0;

                        longmask = ((uint64_t) -1 << (48 - nummask));

                    } else {
                        error = 1;
                    }
                }
            }

        } else {
            error = 1;
        }

        delete[] bs_in;
    }

    mac_addr() {
        longmac = 0;
        longmask = (uint64_t) -1;
        error = 0;
    }

    mac_addr(const uint8_t *in) {
        longmac = 0;
        longmask = (uint64_t) -1;
        error = 0;

        for (int x = 0; x < MAC_LEN; x++)
            longmac |= (uint64_t) in[x] << ((MAC_LEN - x - 1) * 8);
    }

    mac_addr(int) {
        longmac = 0;
        longmask = (uint64_t) -1;
        error = 0;
    }

    mac_addr(const char *in) {
        string2long(in);
    }

    // Masked MAC compare
    inline bool operator== (const mac_addr& op) const {
        if (longmask < op.longmask)
            return ((longmac & longmask) == (op.longmac & longmask));

        return ((longmac & op.longmask) == (op.longmac & op.longmask));
    }

    // MAC compare
    inline bool operator!= (const mac_addr& op) const {
        if (longmask < op.longmask)
            return ((longmac & longmask) != (op.longmac & longmask));

        return ((longmac & op.longmask) != (op.longmac & op.longmask));
    }

    // mac less-than-eq
    inline bool operator<=(const mac_addr& op) const {
        return (longmac & op.longmask) == (op.longmac & op.longmask);
    }

    // MAC less-than for STL sorts...
    inline bool operator< (const mac_addr& op) const {
        return ((longmac & longmask) < (op.longmac & longmask));
    }

    mac_addr& operator= (const mac_addr& op) {
        longmac = op.longmac;
        longmask = op.longmask;
        error = op.error;
        return *this;
    }

    mac_addr& operator= (const char *in) {
        string2long(in);

        return *this;
    }

    inline uint8_t index64(uint64_t val, int index) const {
        // Bitshift kung-foo
        return (uint8_t) ((uint64_t) (val & ((uint64_t) 0xFF << ((MAC_LEN - index - 1) * 8))) >>
                          ((MAC_LEN - index - 1) * 8));
    }

    inline const uint8_t operator[] (const int& index) const {
        int mdex = index;
        if (index < 0 || index >= MAC_LEN)
            mdex = 0;

        return index64(longmac, mdex);
    }

    inline string Mac2String() const {
        char tempstr[MAC_STR_LEN];

        snprintf(tempstr, MAC_STR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
                 (*this)[0], (*this)[1], (*this)[2],
                 (*this)[3], (*this)[4], (*this)[5]);
        return tempstr;
    }

    inline string MacMask2String() const {
        uint64_t maskedmac = longmac & longmask;

        char tempstr[(MAC_STR_LEN * 2) + 1];

        snprintf(tempstr, (MAC_STR_LEN * 2) + 1, "%02X:%02X:%02X:%02X:%02X:%02X/%02X:%02X:%02X:%02X:%02X:%02X",
                 index64(maskedmac, 0), index64(maskedmac, 1), index64(maskedmac, 2),
                 index64(maskedmac, 3), index64(maskedmac, 4), index64(maskedmac, 5),
                 index64(longmask, 0), index64(longmask, 1), index64(longmask, 2),
                 index64(longmask, 3), index64(longmask, 4), index64(longmask, 5));
        return tempstr;
    }

};

// A templated container for storing groups of masked mac addresses.  A stl-map will work for single
// macs, but we need this for smart mask matching on more complex sets.
// Iterators in this class only work as incremental, because thats all I need right now.
// This whole thing is really an ugly, ugly kluge, and if I really had any need for it to be
// more extendable I'd rewrite it to use std::iterator and other good stuff.  But, I don't,
// it works, and I need to move on to other areas.
template<class T>
class macmap {
protected:
    typedef struct mask_vec_content {
        mac_addr mac;
        T value;
    };

    typedef struct mask_vec_offsets {
        unsigned int first;
        unsigned int last;
    };

    class SortMaskVec {
    public:
        inline bool operator() (const macmap::mask_vec_content x, const macmap::mask_vec_content y) const {
            return (x.mac < y.mac);
        }
    };

public:
    // This isn't quite like STL iterators, because I'm too damned lazy to deal with all
    // the nasty STL hoop-jumping.  This does provide a somewhat-stl-ish interface to
    // iterating through the singleton and masked maps
    class iterator {
        friend class macmap;

    public:
        iterator(macmap<T> *in_owner) {
            owner = in_owner;

            if (owner->singleton_map.size() > 0) {
                singleton_itr = owner->singleton_map.begin();
                vector_itr = -1;
                first = singleton_itr->first;
                second = &(singleton_itr->second);
            } else if (owner->mask_vec.size() > 0) {
                singleton_itr = owner->singleton_map.end();
                vector_itr = 0;
                first = owner->mask_vec[0].mac;
                second = &(owner->mask_vec[0].value);
            } else {
                singleton_itr = owner->singleton_map.end();
                vector_itr = owner->mask_vec.size();
            }
        }

        // Prefix
        iterator& operator++() {
            if (singleton_itr == owner->singleton_map.end()) {
                if ((++vector_itr) < (int) owner->mask_vec.size()) {
                    first = owner->mask_vec[vector_itr].mac;
                    second = &(owner->mask_vec[vector_itr].value);
                }
            } else if (++singleton_itr == owner->singleton_map.end()) {
                if ((++vector_itr) < (int) owner->mask_vec.size()) {
                    first = owner->mask_vec[vector_itr].mac;
                    second = &(owner->mask_vec[vector_itr].value);
                }
            } else {
                first = singleton_itr->first;
                second = &(singleton_itr->second);
            }

            return *this;
        }

        // Postfix
        iterator operator++(int) {
            iterator tmp = *this;
            ++*this;
            return tmp;
        }

        // equal
        inline bool operator==(const iterator& op) const {
            return (singleton_itr == op.singleton_itr) && (vector_itr == op.vector_itr);
        }

        // not
        inline bool operator!=(const iterator& op) const {
            return (singleton_itr != op.singleton_itr) || (vector_itr != op.vector_itr);
        }

        // pointer fake
        iterator *operator->() {
            return this;
        }

        mac_addr first;
        T *second;

    protected:
        void assign(typename map<mac_addr, T>::iterator in_itr) {
            singleton_itr = in_itr;
            vector_itr = -1;

            if (in_itr != owner->singleton_map.end()) {
                first = singleton_itr->first;
                second = &(singleton_itr->second);
            }
        }

        void assign(int in_itr) {
            singleton_itr = owner->singleton_map.end();
            vector_itr = in_itr;

            if (in_itr < (int) owner->mask_vec.size()) {
                first = owner->mask_vec[vector_itr].mac;
                second = &(owner->mask_vec[vector_itr].value);
            }
        }

        typename map<mac_addr, T>::iterator singleton_itr;
        int vector_itr;
        macmap<T> *owner;
    };

    iterator begin() {
        iterator ret(this);

        return ret;
    }

    iterator end() {
        iterator ret(this);
        ret.singleton_itr = singleton_map.end();
        ret.vector_itr = mask_vec.size();

        return ret;
    }

    // The caller will rebuild the index before using us...
    void fast_insert(mac_addr in_mac, T in_data) {
        // Single macs go into the singleton map
        if (in_mac.longmask == (uint64_t) -1) {
            singleton_map[in_mac] = in_data;
            return;
        }

        // Put them into the vector
        mask_vec_content content;
        content.mac = in_mac;
        content.value = in_data;
        mask_vec.push_back(content);
    }
    
    // This is a very expensive insert but it builds a system that allows
    // for fast searching, which is where we REALLY need the speed.
    void insert(mac_addr in_mac, T in_data) {
        // Single macs go into the singleton map
        if (in_mac.longmask == (uint64_t) -1) {
            singleton_map[in_mac] = in_data;
            return;
        }

        // Put them into the vector
        mask_vec_content content;
        content.mac = in_mac;
        content.value = in_data;
        mask_vec.push_back(content);

        reindex();
    }

    // Do a relatively fast find...
    iterator find(mac_addr in_mac) {
        iterator ret(this);

        if (in_mac.longmask == (uint64_t) -1) {
            // Look in the singleton map... This is very fast.
            typename map<mac_addr, T>::iterator sitr = singleton_map.find(in_mac);
            if (sitr != singleton_map.end()) {
                ret.assign(sitr);
                return ret;
            }
        }

        if (vec_offset_map.find(in_mac) != vec_offset_map.end()) {
            // We matched a large key in the vector map.  The vector is sorted
            // in decreasing granularity, so the first one we match we can count
            // as good and get out of here
            mask_vec_offsets oft = vec_offset_map[in_mac];
            for (unsigned int x = oft.last; x >= oft.first; x--) {
                if (in_mac <= mask_vec[x].mac) {
                    ret.assign(x);
                    return ret;
                }
            }
        }

        return end();
    }

    void erase(mac_addr in_mac) {
        iterator itr = find(in_mac);

        if (itr == end())
            return;

        if (itr.singleton_itr != singleton_map.end()) {
            singleton_map.erase(itr.singleton_itr);
            reindex();
            return;
        }

        if (itr.vector_itr >= 0 && itr.vector_itr < (int) mask_vec.size()) {
            mask_vec.erase(mask_vec.begin() + itr.vector_itr);
            reindex();
            return;
        }

    }

    inline T& operator[](mac_addr& index) {
        iterator foo = find(index);

        // This isn't very clean but its better than heap corruption 
        // and other horrible stuff
        if (foo == end()) {
            fprintf(stderr, "Something tried to use macmap[] to reference an "
                    "element that doesn't exist.  Fix me.\n");
            exit(1);
        }

        return *(foo->second);
    }

    int size() {
        return singleton_map.size() + mask_vec.size();
    }

    void reindex(void) {
        // Order it
        if (mask_vec.size() == 0)
            return;

        stable_sort(mask_vec.begin(), mask_vec.end(), SortMaskVec());

        // Clear our old map of content
        vec_offset_map.clear();

        // Split it into offset groups
        mask_vec_offsets ofst;
        ofst.last = mask_vec.size() - 1;
        ofst.first = mask_vec.size() - 1;
        mac_addr owner = mask_vec[ofst.last].mac;
        for (unsigned int x = 0; x < mask_vec.size(); x++) {
            // Masked compare... is it still a subset of us?
            if (owner != mask_vec[x].mac) {
                vec_offset_map[owner] = ofst;
                ofst.first = x;
                ofst.last = x;
                owner = mask_vec[x].mac;
            } else {
                ofst.last = x;
            }
        }
        // Clean up the last stuff
        vec_offset_map[owner] = ofst;
        vec_offset_map[owner] = ofst;
    }

protected:
    map<mac_addr, T> singleton_map;
    vector<mask_vec_content> mask_vec;
    map<mac_addr, mask_vec_offsets> vec_offset_map;
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
                 map<int, int> *tag_cache_map);
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

