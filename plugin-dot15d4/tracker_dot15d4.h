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

// There isn't a whole lot to track and src/dst/pan are going to conflict
// a lot so we're just tracking them as a communication between two devices
class dot154_network {
public:
	dot154_network() {
		source_addr = dest_addr = 0;
		source_pan = dest_pan = 0;
		crypt = 0;

		first_time = 0;
		last_time = 0;

		num_packets = 0;
	}

	inline dot154_network operator= (const dot154_network& in) {
		source_addr = in.source_addr;
		dest_addr = in.dest_addr;
		source_pan = in.source_pan;
		dest_pan = in.dest_pan;
		crypt = in.crypt;

		first_time = in.first_time;
		last_time = in.last_time;

		num_packets = in.num_packets;

		return *this;
	}

	inline bool operator== (const dot154_network& op) const {
		if (source_addr == op.source_addr &&
			dest_addr == op.dest_addr &&
			source_pan == op.source_pan &&
			dest_pan == op.dest_pan &&
			crypt == op.crypt) {
			return 1;
		}

		return 0;
	}

	uint64_t source_addr, dest_addr;
	unsigned int source_pan;
	unsigned int dest_pan;
	unsigned int crypt;

	time_t first_time, last_time;

	int num_packets;
};

class Tracker_Dot15d4 {
public:
	Tracker_Dot15d4() { fprintf(stderr, "FATAL OOPS: tracker_dot15d4()\n"); exit(1); }
	Tracker_Dot15d4(GlobalRegistry *in_globalreg);

	int chain_handler(kis_packet *in_pack);

protected:
	GlobalRegistry *globalreg;

	map<dot154_network *, int> tracked_devs;
};

#endif
