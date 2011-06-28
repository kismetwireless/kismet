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
#include "packet_ieee80211.h"

// This is the main switch for how big the vector is.  If something ever starts
// bumping up against this we'll need to increase it, but that'll slow down 
// generating a packet (slightly) so I'm leaving it relatively low.
#define MAX_PACKET_COMPONENTS	64

// Maximum length of a frame
#define MAX_PACKET_LEN			8192

// Same as defined in libpcap/system, but we need to know the basic dot11 DLT
// even when we don't have pcap
#define KDLT_IEEE802_11			105

// High-level packet component so that we can provide our own destructors
class packet_component {
public:
    packet_component() { self_destruct = 1; };
	virtual ~packet_component() { }
	int self_destruct;
};

// Overall packet container that holds packet information
class kis_packet {
public:
    // Time of packet creation
    struct timeval ts;

    // Do we know this is in error from the capture source
    // itself?
    int error;

	// Actual vector of bits in the packet
	vector<packet_component *> content_vec;
   
    // Init stuff
    kis_packet() {
        error = 0;

		// Stock and init the content vector
		content_vec.resize(MAX_PACKET_COMPONENTS, NULL);
		/*
		for (unsigned int y = 0; y < MAX_PACKET_COMPONENTS; y++)
			content_vec[y] = NULL;
		*/
    }

    ~kis_packet() {
        // Delete everything we contain when we die.  I hope whomever put
        // it there expected this.
		for (unsigned int y = 0; y < MAX_PACKET_COMPONENTS; y++) {
			packet_component *pcm = content_vec[y];

			if (pcm == NULL)
				continue;

			// If it's marked for self-destruction, delete it.  Otherwise, 
			// someone else is responsible for removing it.
			if (pcm->self_destruct)
				delete pcm;

			content_vec[y] = NULL;
        }
    }
   
    inline void insert(const unsigned int index, packet_component *data) {
		if (index >= MAX_PACKET_COMPONENTS)
			return;
        content_vec[index] = data;
    }
    inline void *fetch(const unsigned int index) {
		if (index >= MAX_PACKET_COMPONENTS)
			return NULL;

		return content_vec[index];
    }
    inline void erase(const unsigned int index) {
		if (index >= MAX_PACKET_COMPONENTS)
			return;

        // Delete it if we can - both from our array and from 
        // memory.  Whatever inserted it had better expect this
        // to happen or it will be very unhappy
		if (content_vec[index] != NULL) {
			if (content_vec[index]->self_destruct)
				delete content_vec[index];

			content_vec[index] = NULL;
        }
    }
    inline packet_component *operator[] (const unsigned int& index) const {
		if (index >= MAX_PACKET_COMPONENTS)
			return NULL;

		return content_vec[index];
    }
};

// Arbitrary data chunk, decapsulated from the link headers
class kis_datachunk : public packet_component {
public:
    uint8_t *data;
    unsigned int length;
	int dlt;
	uint16_t source_id;
   
    kis_datachunk() {
		self_destruct = 1; // Our delete() handles everything
        data = NULL;
        length = 0;
		source_id = 0;
    }

    virtual ~kis_datachunk() {
        delete[] data;
        length = 0;
    }

	virtual void set_data(uint8_t *in_data, unsigned int in_length) {
		if (data != NULL)
			delete[] data;

		data = new uint8_t[in_length];
		length = in_length;
		memcpy(data, in_data, length);
	}
};

class kis_packet_checksum : public kis_datachunk {
public:
	int checksum_valid;
	uint32_t *checksum_ptr;

	kis_packet_checksum() : kis_datachunk() {
		checksum_valid = 0;
	}

	virtual void set_data(uint8_t *in_data, unsigned int in_length) {
		kis_datachunk::set_data(in_data, in_length);
		checksum_ptr = (uint32_t *) data;
	}
};

class kis_addr_info : public packet_component {
public:
	kis_addr_info() {
		self_destruct = 1;
	}

	mac_addr source, dest;
};

// String reference
class kis_string_info : public packet_component {
public:
	kis_string_info() {
		self_destruct = 1;
	}

	vector<string> extracted_strings;
};

typedef struct {
	string text;
	mac_addr bssid;
	mac_addr source;
	mac_addr dest;
} string_proto_info;

// some protocols we do try to track
enum kis_protocol_info_type {
    proto_unknown,
    proto_udp, 
	proto_tcp, 
	proto_arp, 
	proto_dhcp_offer,
	proto_dhcp_discover,
    proto_cdp,
    proto_turbocell,
	proto_netstumbler_probe,
	proto_lucent_probe,
    proto_iapp,
    proto_leap,
    proto_ttls,
    proto_tls,
    proto_peap,
	proto_eap_unknown,
    proto_isakmp,
    proto_pptp,
};

class kis_data_packinfo : public packet_component {
public:
	kis_data_packinfo() {
		self_destruct = 1; // Safe to delete us
		proto = proto_unknown;
		ip_source_port = 0;
		ip_dest_port = 0;
		ip_source_addr.s_addr = 0;
		ip_dest_addr.s_addr = 0;
		ip_netmask_addr.s_addr = 0;
		ip_gateway_addr.s_addr = 0;
		field1 = 0;
        ivset[0] = ivset[1] = ivset[2] = 0;
	}

	kis_protocol_info_type proto;

	// IP info, we re-use a subset of the kis_protocol_info_type enum to fill
	// in where we got our IP data from.  A little klugey, but really no reason
	// not to do it
	int ip_source_port;
	int ip_dest_port;
	in_addr ip_source_addr;
	in_addr ip_dest_addr;
	in_addr ip_netmask_addr;
	in_addr ip_gateway_addr;
	kis_protocol_info_type ip_type;

	// The two CDP fields we really care about for anything
	string cdp_dev_id;
	string cdp_port_id;

	// DHCP Discover data
	string discover_host, discover_vendor;

	// IV
	uint8_t ivset[3];

	// An extra field that can be filled in
	int field1;

};

// Layer 1 radio info record for kismet
class kis_layer1_packinfo : public packet_component {
public:
	kis_layer1_packinfo() {
		self_destruct = 1;  // Safe to delete us
		signal_dbm = noise_dbm = 0;
		signal_rssi = noise_rssi = 0;
		carrier = carrier_unknown;
		encoding = encoding_unknown;
		datarate = 0;
		freq_mhz = 0;
		accuracy = 0;
	}

	// How "accurate" are we?  Higher == better.  Nothing uses this yet
	// but we might as well track it here.
	int accuracy;

	// Frequency seen on
	int freq_mhz;

    // Connection info
    int signal_dbm, signal_rssi;
    int noise_dbm, noise_rssi;

    // What carrier brought us this packet?
    phy_carrier_type carrier;

    // What encoding?
    phy_encoding_type encoding;

    // What data rate?
    int datarate;

	// Checksum, if checksumming is enabled; Only of the non-header 
	// data
	uint32_t content_checkum;
};

#endif

