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

#ifndef __CHANNELTRACKER_H__
#define __CHANNELTRACKER_H__

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
#include "packetchain.h"
#include "kis_netframe.h"
#include "timetracker.h"
#include "netracker.h"
#include "packet.h"

class Channeltracker {
public:
	struct channel_record {
		channel_record() {
			channel = 0;
			channel_time_on = 0;
			packets = 0;
			packets_delta = 0;
			usec_used = 0;
			bytes_seen = 0;
			bytes_delta = 0;
			sent_reset = 0;

			max_signal_dbm = -256;
			max_signal_rssi = 0;
			max_noise_dbm = -256;
			max_noise_rssi = 0;
		}

		int sent_reset;

		uint32_t channel;

		int channel_time_on;

		int packets;
		int packets_delta;

		// Signal data (within the past polling period)
		int max_signal_dbm;
		int max_signal_rssi;
		int max_noise_dbm;
		int max_noise_rssi;

		// Usec used 
		long int usec_used;

		// Total and delta
		long int bytes_seen;
		long int bytes_delta;

		// Total on this channel
		macmap<int> seen_networks;
		macmap<int> delta_networks;
	};

	Channeltracker() {
		fprintf(stderr, "FATAL OOPS:  Channeltracker called without globalreg\n");
		exit(1);
	}

	Channeltracker(GlobalRegistry *in_globalreg);
	~Channeltracker();

	void ChainHandler(kis_packet *in_pack);
	void ChanTimer();

protected:
	GlobalRegistry *globalreg;

	map<uint32_t, channel_record *> channel_map;

	int chan_timer_id;
	int chan_proto_id;
};

#endif

