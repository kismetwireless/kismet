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

#ifndef __PHY_80211_H__
#define __PHY_80211_H__

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
#include "filtercore.h"
#include "gpscore.h"
#include "packet.h"
#include "uuid.h"
#include "configfile.h"

#include "devicetracker.h"

/*
 * 802.11 PHY handlers
 * Uses new devicetracker code
 *
 * Re-implements networktracker, packetdissectors
 * Ultimately all 802.11 related code will live here, such as alerts, etc.
 */

enum dot11_ssid_type {
	dot11_ssid_beacon = 0,
	dot11_ssid_proberesp = 1,
	dot11_ssid_probereq = 2,
	dot11_ssid_file = 3,
};

struct dot11_advertised_ssid {
	dot11_advertised_ssid() {
		checksum = 0;
		type = dot11_ssid_beacon;
		mac = mac_addr(0);
		ssid = "";
		beacon_info = "";
		cryptset = 0;
		ssid_cloaked = 0;
		first_time = 0;
		last_time = 0;
		dirty = 0;
		maxrate = 0;
		beaconrate = 0;
		packets = 0;
		beacons = 0;
		dot11d_country = "XXX";
	}

	inline dot11_advertised_ssid& operator= (const dot11_advertised_ssid& in) {
		checksum = in.checksum;
		type = in.type;
		mac = in.mac;
		ssid = in.ssid;
		ssid_cloaked = in.ssid_cloaked;
		beacon_info = in.beacon_info;
		cryptset = in.cryptset;
		first_time = in.first_time;
		last_time = in.last_time;
		dirty = in.dirty;
		maxrate = in.maxrate;
		beaconrate = in.beaconrate;
		packets = in.packets;

		beacons = in.beacons;

		dot11d_country = in.dot11d_country; 

		dot11d_vec = in.dot11d_vec;

		dirty = in.dirty;

		return *this;
	}

	uint32_t checksum;

	dot11_ssid_type type;

	mac_addr mac;

	string ssid;
	string beacon_info;

	// Cryptset and decrypted
	uint64_t cryptset;

	// Is the SSID hidden
	int ssid_cloaked;

	// First and last times we saw this SSID
	time_t first_time;
	time_t last_time;

	// Advertised maximum rate
	double maxrate;

	// Beacon rate in # of beacons per second
	int beaconrate;

	// Number of packets seen advertising this ssid
	int packets;

	// Number of beacons seen in the last second (for calculating loss)
	int beacons;

	string dot11d_country;
	vector<dot11d_range_info> dot11d_vec;

	// SSID is dirty and should be resent
	int dirty;
};

enum dot11_network_type {
	dot11_network_ap = 0,
	dot11_network_adhoc = 1,
	dot11_network_probe = 2,
	dot11_network_turbocell = 3,
	dot11_network_data = 4,
	dot11_network_mixed = 255,
	dot11_network_remove = 256
};

// fwd def
class dot11_tracked_client;

class dot11_tracked_network : public tracker_component {
public:
	dot11_network_type type;
	mac_addr bssid;

	string manuf;

	// Clients associated w/ the network, they're unique/unmasked so
	// we don't need a macmap
	map<mac_addr, dot11_tracked_client *> client_map;

	// Advertised SSID data, by checksum
	map<uint32_t, dot11_advertised_ssid *> ssid_map;

	// Cryptset from data packets not known to be linked to a SSID
	uint64_t data_cryptset;

	// One of the SSIDs decrypted?
	int decrypted;

	// Best-guess IP
	kis_ip_data guess_ipdata;

	// State tracking elements
	// Number of client disconnects (decayed per second)
	int client_disconnects;
	// Last sequence
	int last_sequence;
	// Last BSS
	uint64_t bss_timestamp;

	// Map of IVs seen, potentially a really bad idea for RAM, should
	// only be enabled for selected networks
	map<uint32_t, int> iv_map;
	// Number of duplicate IVs
	unsigned int dupeiv_packets;
	// Do we track IVs on this network?
	int track_ivs;

	// CDP data
	string cdp_dev_id;
	string cdp_port_id;

	// Fragments and retries
	unsigned int fragments;
	unsigned int retries;

	// Record is dirty
	int dirty;

	// Fields for the client to use
	void *groupptr;
	dot11_advertised_ssid *lastssid;

	// Map of sources which have seen this network
	// map<uuid, source_data *> source_map;
};

enum dot11_client_type {
	dot11_client_unknown = 0,
	dot11_client_fromds = 1,
	dot11_client_tods = 2,
	dot11_client_interds = 3,
	dot11_client_established = 4,
	dot11_client_adhoc = 5,
	dot11_client_remove = 6
};

class dot11_tracked_client : public tracker_component {
public:
	dot11_client_type type;

	int decrypted;

	mac_addr bssid;

	string manuf;

	int last_sequence;

	uint64_t data_cryptset;

	kis_ip_data guess_ipdata;

	int fragments;
	int retries;

	// CDP info
	string cdp_dev_id, cdp_port_id;

	// DHCP info
	string dhcp_host, dhcp_vendor;

	// Probed SSID data
	map<uint32_t, dot11_advertised_ssid *> ssid_map;

	dot11_tracked_network *netptr;

	string dot11d_country;
	vector<dot11d_range_info> dot11d_vec;

};

class Kis_80211_Phy : public Kis_Phy_Handler {
public:
	// Stub
	Kis_80211_Phy() { }

	// Inherited functionality
	Kis_80211_Phy(GlobalRegistry *in_globalreg) :
		Kis_Phy_Handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  Devicetracker *in_tracker,
											  int in_phyid) {
		return new Kis_80211_Phy(in_globalreg, in_tracker, in_phyid);
	}

	// Strong constructor
	Kis_80211_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
				  int in_phyid);

	// Post-dissection packet classifier kicked from Devicetracker
	virtual int HandlePacket(kis_packet *in_pack);

	// Timer events passed from Devicetracker
	virtual int TimerKick();
};

#endif
