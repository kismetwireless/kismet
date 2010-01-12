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

#include <config.h>

#include <globalregistry.h>
#include <gpscore.h>

#include "packet_btscan.h"

// Fwd def of logger
class Dumpfile_Btscantxt;

class btscan_network {
public:
	btscan_network() {
		first_time = last_time = 0;

		packets = 0;
	}

	mac_addr bd_addr;
	string bd_name, bd_class;
	time_t first_time, last_time;
	unsigned int packets;

	kis_gps_data gpsdata;

	unsigned int dirty;
};

class Tracker_BTScan {
public:
	Tracker_BTScan() { fprintf(stderr, "FATAL OOPS: tracker_dot15d4()\n"); exit(1); }
	Tracker_BTScan(GlobalRegistry *in_globalreg);

	int chain_handler(kis_packet *in_pack);

	void BlitDevices(int in_fd);

protected:
	GlobalRegistry *globalreg;

	map<mac_addr, btscan_network *> tracked_devs;

	int BTSCANDEV_ref;
	int timer_ref;

	// Friends with the logger for direct access
	friend class Dumpfile_Btscantxt;
};

#endif

