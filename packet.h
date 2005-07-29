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

// High-level packet component so that we can provide our own destructors
class packet_component {
public:
    ~packet_component() { self_destruct = 1; };
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
		content_vec.reserve(64);
		for (unsigned int y = 0; y < MAX_PACKET_COMPONENTS; y++)
			content_vec.push_back(NULL);
    }

    ~kis_packet() {
        // Delete everything we contain when we die.  I hope whomever put
        // it there expected this.
		for (unsigned int y = 0; y < MAX_PACKET_COMPONENTS; y++) {
			if (content_vec[y] == NULL)
				continue;

			if (content_vec[y]->self_destruct)
				delete content_vec[y];
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

// Arbitrary 802.11 data chunk
class kis_datachunk : public packet_component {
public:
    uint8_t *data;
    int length;
   
    kis_datachunk() {
        data = NULL;
        length = 0;
    }

    ~kis_datachunk() {
        delete[] data;
        length = 0;
    }
};

// Info from the IEEE 802.11 frame headers for kismet
class kis_ieee80211_packinfo : public packet_component {
public:
    kis_ieee80211_packinfo() {
        corrupt = 0;
        header_offset = 0;
        type = packet_unknown;
        subtype = packet_sub_unknown;
        mgt_reason_code = 0;
        ssid_len = 0;
		ssid_blank = 0;
        source_mac = mac_addr(0);
        dest_mac = mac_addr(0);
        bssid_mac = mac_addr(0);
        other_mac = mac_addr(0);
        distrib = distrib_unknown;
        wep = 0;
        fuzzywep = 0;
        ess = 0;
        channel = 0;
        encrypted = 0;
        beacon_interval = 0;
        beacon_info[0] = '\0';
        ivset = 0;
        maxrate = 0;
        timestamp = 0;
        sequence_number = 0;
        frag_number = 0;
		fragmented = 0;
        duration = 0;
        datasize = 0;
    }

    // Corrupt 802.11 frame
    int corrupt;
   
    // Offset to data components in frame
    int header_offset;
    
    ieee_80211_type type;
    ieee_80211_subtype subtype;
  
    uint8_t mgt_reason_code;
    
    // Raw SSID
    char ssid[SSID_SIZE+1];
    int ssid_len;
	// Is the SSID empty spaces?
	int ssid_blank;

    // Address set
    mac_addr source_mac;
    mac_addr dest_mac;
    mac_addr bssid_mac;
    mac_addr other_mac;
    
    ieee_80211_disttype distrib;
    
    int wep;
    int fuzzywep;

    // Was it flagged as ess? (ap)
    int ess;

    // What channel?
    int channel;

    // Is this encrypted?
    int encrypted;
    int beacon_interval;

    // Some cisco APs seem to fill in this info field
    char beacon_info[BEACON_INFO_LEN];

    uint32_t ivset;

    double maxrate;

    uint64_t timestamp;
    int sequence_number;
    int frag_number;
	int fragmented;

    int duration;

    int datasize;
};

// Layer 1 radio info record for kismet
class kis_layer1_packinfo : public packet_component {
public:
	kis_layer1_packinfo() {
		signal = noise = 0;
		carrier = carrier_unknown;
		encoding = encoding_unknown;
		datarate = 0;
		channel = 0;
		accuracy = 0;
	}

	// How "accurate" are we?  Higher == better.  Nothing uses this yet
	// but we might as well track it here.
	int accuracy;
	
	// Channel packet seen on
	int channel;

    // Connection info
    int signal;
    int noise;

    // What carrier brought us this packet?
    phy_carrier_type carrier;

    // What encoding?
    phy_encoding_type encoding;

    // What data rate?
    int datarate;
};

#endif

