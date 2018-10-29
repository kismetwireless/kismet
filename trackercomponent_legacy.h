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

#ifndef __TRACKERCOMPONENT_LEGACY_H__
#define __TRACKERCOMPONENT_LEGACY_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "packet.h"
#include "packetchain.h"
#include "timetracker.h"
#include "uuid.h"
#include "configfile.h"
#include "devicetracker.h"
#include "phyhandler.h"
#include "devicetracker_component.h"
#include "packinfo_signal.h"

/* Legacy devicetracker stuff which will be supplanted by trackercomponent.h versions which use
 * exportable/introspectable backends */

class kis_ip_data {
public:
	kis_ip_data() {
		ip_type = ipdata_unknown;
		ip_addr_block.s_addr = 0;
		ip_netmask.s_addr = 0;
		ip_gateway.s_addr = 0;
	}

	kis_ipdata_type ip_type;

	in_addr ip_addr_block;
	in_addr ip_netmask;
	in_addr ip_gateway;

	inline kis_ip_data& operator= (const kis_ip_data& in) {
		ip_addr_block.s_addr = in.ip_addr_block.s_addr;
		ip_netmask.s_addr = in.ip_netmask.s_addr;
		ip_gateway.s_addr = in.ip_gateway.s_addr;
		ip_type = in.ip_type;

		return *this;
	}
};

// SNR info

#define KIS_SIGNAL_DBM_BOGUS_MIN	0
#define KIS_SIGNAL_DBM_BOGUS_MAX	-256
#define KIS_SIGNAL_RSSI_BOGUS_MIN	1024
#define KIS_SIGNAL_RSSI_BOGUS_MAX	0

// Seenby records for tracking the packet sources which have seen this device
// and how much of the device they've seen
class kis_seenby_data {
public:
	time_t first_time;
	time_t last_time;
	uint32_t num_packets;

	// Map of frequencies seen by this device
    std::map<unsigned int, unsigned int> freq_mhz_map;
};

class kis_tag_data {
public:
    std::string value;
	bool dirty;
};

#endif

