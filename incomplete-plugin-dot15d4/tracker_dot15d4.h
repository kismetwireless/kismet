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

#ifndef __TRACKER_DOT15D4_H__
#define __TRACKER_DOT15D4_H__

#include "config.h"

#include "globalregistry.h"
#include "packet_dot15d4.h"

// Since we don't have a mac address we have to identify by other attributes
class dot15d4_network_id {
public:
	dot15d4_network_id() {
		source_addr = dest_addr = 0;
		source_pan = dest_pan = 0;
		crypt = 0;
		channel = 0;
	}

	// Build a network for searching out of a packet
	dot15d4_network_id(dot15d4_packinfo *pack) {
		dot15d4_network_id();

		source_addr = pack->source_addr;
		dest_addr = pack->dest_addr;
		source_pan = pack->source_pan;
		dest_pan = pack->dest_pan;
		crypt = pack->crypt;
		channel = pack->channel;
	}

	inline dot15d4_network_id operator= (const dot15d4_network_id& in) {
		source_addr = in.source_addr;
		dest_addr = in.dest_addr;
		source_pan = in.source_pan;
		dest_pan = in.dest_pan;
		crypt = in.crypt;

		return *this;
	}

	inline bool operator== (const dot15d4_network_id& op) const {
		if (source_addr == op.source_addr &&
			dest_addr == op.dest_addr &&
			source_pan == op.source_pan &&
			dest_pan == op.dest_pan &&
			crypt == op.crypt &&
			channel == op.channel) {
			return 1;
		}

		return 0;
	}

	inline bool operator< (const dot15d4_network_id& op) const {
		if (source_addr < op.source_addr &&
			dest_addr < op.dest_addr &&
			source_pan < op.source_pan &&
			dest_pan < op.dest_pan &&
			crypt < op.crypt &&
			channel < op.channel) {
			return 1;
		}

		return 0;
	}

	uint64_t source_addr, dest_addr;
	unsigned int source_pan;
	unsigned int dest_pan;
	unsigned int crypt;
	unsigned int channel;
};

class dot15d4_network {
public:
	dot15d4_network() {
		first_time = 0;
		last_time = 0;

		num_packets = 0;
		num_beacons = 0;
		num_data = 0;
		num_cmd = 0;

		dirty = 0;
	}

	dot15d4_network_id netid;

	int num_packets, num_beacons, num_data, num_cmd;

	time_t first_time, last_time;

	int dirty;
};

class Tracker_Dot15d4 {
public:
	Tracker_Dot15d4() { fprintf(stderr, "FATAL OOPS: tracker_dot15d4()\n"); exit(1); }
	Tracker_Dot15d4(GlobalRegistry *in_globalreg);

	int chain_handler(kis_packet *in_pack);

	void BlitDevices(int in_fd);

protected:
	GlobalRegistry *globalreg;

	map<dot15d4_network_id, dot15d4_network *> tracked_devs;

	int D15D4DEV_ref;
	int timer_ref;
};

#endif

