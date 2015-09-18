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
#include "kis_netframe.h"
#include "timetracker.h"
#include "filtercore.h"
#include "gpscore.h"
#include "uuid.h"
#include "configfile.h"
#include "devicetracker.h"
#include "phyhandler.h"
#include "trackercomponent.h"
#include "packinfo_signal.h"

class Packinfo_Sig_Combo;

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

struct kis_signal_data {
	kis_signal_data() {
		// These all go to 0 since we don't know if it'll be positive or
		// negative
		last_signal_dbm = last_noise_dbm = KIS_SIGNAL_DBM_BOGUS_MIN;
		min_signal_dbm = min_noise_dbm = KIS_SIGNAL_DBM_BOGUS_MIN;
		max_signal_dbm = max_noise_dbm = KIS_SIGNAL_DBM_BOGUS_MAX;

		last_signal_rssi = last_noise_rssi = KIS_SIGNAL_RSSI_BOGUS_MIN;
		min_signal_rssi = min_noise_rssi = KIS_SIGNAL_RSSI_BOGUS_MIN;
		max_signal_rssi = max_noise_rssi = KIS_SIGNAL_RSSI_BOGUS_MAX;

		peak_lat = peak_lon = 0;
		peak_alt = KIS_GPS_ALT_BOGUS_MIN;

		maxseenrate = 0;
		encodingset = 0;
		carrierset = 0;
	}

	int last_signal_dbm, last_noise_dbm;
	int min_signal_dbm, min_noise_dbm;
	int max_signal_dbm, max_noise_dbm;

	int last_signal_rssi, last_noise_rssi;
	int min_signal_rssi, min_noise_rssi;
	int max_signal_rssi, max_noise_rssi;
	// Peak locations
	double peak_lat, peak_lon, peak_alt;

	// Max rate
	int maxseenrate;

	// Seen encodings
	uint32_t encodingset;
	uint32_t carrierset;

	inline kis_signal_data& operator= (const kis_signal_data& in) {
		last_signal_dbm = in.last_signal_dbm;
		last_noise_dbm = in.last_noise_dbm;

		min_signal_dbm = in.min_signal_dbm;
		max_signal_dbm = in.max_signal_dbm;

		min_noise_dbm = in.min_noise_dbm;
		max_noise_dbm = in.max_noise_dbm;

		last_signal_rssi = in.last_signal_rssi;
		last_noise_rssi = in.last_noise_rssi;

		min_signal_rssi = in.min_signal_rssi;
		max_signal_rssi = in.max_signal_rssi;

		min_noise_rssi = in.min_noise_rssi;
		max_noise_rssi = in.max_noise_rssi;

		peak_lat = in.peak_lat;
		peak_lon = in.peak_lon;
		peak_alt = in.peak_alt;

		maxseenrate = in.maxseenrate;

		encodingset = in.encodingset;
		carrierset = in.carrierset;

		return *this;
	}

	inline kis_signal_data& operator+= (const Packinfo_Sig_Combo& in) {
		if (in.lay1 != NULL) {
			int gpscopy = 0;

			if (in.lay1->signal_dbm < min_signal_dbm &&
				in.lay1->signal_dbm != 0)
				min_signal_dbm = in.lay1->signal_dbm;

			if (in.lay1->signal_rssi < min_signal_rssi &&
				in.lay1->signal_rssi != 0)
				min_signal_rssi = in.lay1->signal_rssi;

			if (in.lay1->signal_dbm > max_signal_dbm &&
				in.lay1->signal_dbm != 0) {
				max_signal_dbm = in.lay1->signal_dbm;
				gpscopy = 1;
			}

			if (in.lay1->signal_rssi > max_signal_rssi &&
				in.lay1->signal_rssi != 0) {
				max_signal_rssi = in.lay1->signal_rssi;
				gpscopy = 1;
			}

			if (in.lay1->noise_dbm < min_noise_dbm &&
				in.lay1->noise_dbm != 0)
				min_noise_dbm = in.lay1->noise_dbm;

			if (in.lay1->noise_rssi < min_noise_rssi &&
				in.lay1->noise_rssi != 0)
				min_noise_rssi = in.lay1->noise_rssi;

			if (in.lay1->noise_dbm > max_noise_dbm &&
				in.lay1->noise_dbm != 0)
				max_noise_dbm = in.lay1->noise_dbm;

			if (in.lay1->noise_rssi > max_noise_rssi &&
				in.lay1->noise_rssi != 0) 
				max_noise_rssi = in.lay1->noise_rssi;

			if (in.lay1->signal_rssi != 0)
				last_signal_rssi = in.lay1->signal_rssi;
			if (in.lay1->signal_dbm != 0)
				last_signal_dbm = in.lay1->signal_dbm;
			if (in.lay1->noise_rssi != 0)
				last_noise_rssi = in.lay1->noise_rssi;
			if (in.lay1->noise_dbm != 0)
				last_noise_dbm = in.lay1->noise_dbm;

			carrierset |= in.lay1->carrier;
			encodingset |= in.lay1->encoding;

			if (in.lay1->datarate > maxseenrate)
				maxseenrate = in.lay1->datarate;

			if (gpscopy && in.gps != NULL) {
				peak_lat = in.gps->lat;
				peak_lon = in.gps->lon;
				peak_alt = in.gps->alt;
			}
		}

		return *this;
	}

	inline kis_signal_data& operator+= (const kis_signal_data& in) {
		if (in.min_signal_dbm < min_signal_dbm)
			min_signal_dbm = in.min_signal_dbm;

		if (in.min_signal_rssi < min_signal_rssi)
			min_signal_rssi = in.min_signal_rssi;

		if (in.max_signal_dbm > max_signal_dbm) {
			max_signal_dbm = in.max_signal_dbm;
			peak_lat = in.peak_lat;
			peak_lon = in.peak_lon;
			peak_alt = in.peak_alt;
		}

		if (in.max_signal_rssi > max_signal_rssi) {
			max_signal_rssi = in.max_signal_rssi;
			peak_lat = in.peak_lat;
			peak_lon = in.peak_lon;
			peak_alt = in.peak_alt;
		}

		if (in.min_noise_dbm < min_noise_dbm)
			min_noise_dbm = in.min_noise_dbm;

		if (in.min_noise_rssi < min_noise_rssi)
			min_noise_rssi = in.min_noise_rssi;

		if (in.max_noise_dbm > max_noise_dbm)
			max_noise_dbm = in.max_noise_dbm;

		if (in.max_noise_rssi > max_noise_rssi)
			max_noise_rssi = in.max_noise_rssi;

		encodingset |= in.encodingset;
		carrierset |= in.carrierset;

		if (maxseenrate < in.maxseenrate)
			maxseenrate = in.maxseenrate;

		return *this;
	}
};

// Seenby records for tracking the packet sources which have seen this device
// and how much of the device they've seen
class kis_seenby_data {
public:
	time_t first_time;
	time_t last_time;
	uint32_t num_packets;

	// Map of frequencies seen by this device
	map<unsigned int, unsigned int> freq_mhz_map;
};

class kis_tag_data {
public:
	string value;
	bool dirty;
};

#endif

