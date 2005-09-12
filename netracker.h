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

#ifndef __NETRACKER_H__
#define __NETRACKER_H__

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

// Cache file versioning
#define NETRACKER_SSIDCACHE_VERSION 	2
#define NETRACKER_IPCACHE_VERSION 		2

// Core network tracker hooks to call back into our core tracker
// elements
int kis_80211_netracker_hook(CHAINCALL_PARMS);
int kis_80211_datatracker_hook(CHAINCALL_PARMS);

// Timer event to update
int NetrackerUpdateTimer(TIMEEVENT_PARMS);

// Tcp server elements
enum NETWORK_fields {
    NETWORK_bssid, NETWORK_type, NETWORK_ssid, NETWORK_beaconinfo,
    NETWORK_llcpackets, NETWORK_datapackets, NETWORK_cryptpackets,
    NETWORK_weakpackets, NETWORK_channel, NETWORK_wep, NETWORK_firsttime,
    NETWORK_lasttime, NETWORK_atype, NETWORK_rangeip, NETWORK_netmaskip,
	NETWORK_gatewayip, NETWORK_gpsfixed,
    NETWORK_minlat, NETWORK_minlon, NETWORK_minalt, NETWORK_minspd,
    NETWORK_maxlat, NETWORK_maxlon, NETWORK_maxalt, NETWORK_maxspd,
    NETWORK_octets, NETWORK_cloaked, NETWORK_beaconrate, NETWORK_maxrate,
    NETWORK_manufkey, NETWORK_manufscore,
    NETWORK_quality, NETWORK_signal, NETWORK_noise,
    NETWORK_bestquality, NETWORK_bestsignal, NETWORK_bestnoise,
    NETWORK_bestlat, NETWORK_bestlon, NETWORK_bestalt,
    NETWORK_agglat, NETWORK_agglon, NETWORK_aggalt, NETWORK_aggpoints,
    NETWORK_datasize, NETWORK_tcnid, NETWORK_tcmode, NETWORK_tsat,
    NETWORK_carrierset, NETWORK_maxseenrate, NETWORK_encodingset,
    NETWORK_decrypted, NETWORK_dupeiv, NETWORK_bsstimestamp,
	NETWORK_cdpdevice, NETWORK_cdpport, NETWORK_fragments, NETWORK_retries,
	NETWORK_newpackets,
	NETWORK_maxfield
};

enum CLIENT_fields {
    CLIENT_bssid, CLIENT_mac, CLIENT_type, CLIENT_firsttime, CLIENT_lasttime,
    CLIENT_manufkey, CLIENT_manufscore,
    CLIENT_llcpackets, CLIENT_datapackets, CLIENT_cryptpackets, CLIENT_weakpackets,
    CLIENT_gpsfixed,
    CLIENT_minlat, CLIENT_minlon, CLIENT_minalt, CLIENT_minspd,
    CLIENT_maxlat, CLIENT_maxlon, CLIENT_maxalt, CLIENT_maxspd,
    CLIENT_agglat, CLIENT_agglon, CLIENT_aggalt, CLIENT_aggpoints,
    CLIENT_maxrate,
    CLIENT_quality, CLIENT_signal, CLIENT_noise,
    CLIENT_bestquality, CLIENT_bestsignal, CLIENT_bestnoise,
    CLIENT_bestlat, CLIENT_bestlon, CLIENT_bestalt,
    CLIENT_atype, CLIENT_ip, CLIENT_gatewayip, CLIENT_datasize, CLIENT_maxseenrate, 
	CLIENT_encodingset, CLIENT_carrierset, CLIENT_decrypted, CLIENT_wep,
	CLIENT_channel, CLIENT_fragments, CLIENT_retries, CLIENT_newpackets,
	CLIENT_maxfield
};

enum REMOVE_fields {
    REMOVE_bssid
};

extern char *NETWORK_fields_text[];
extern char *CLIENT_fields_text[];
extern char *REMOVE_fields_text[];

// Enums explicitly defined for the ease of client writers
enum network_type {
	network_ap = 0,
	network_adhoc = 1,
	network_probe = 2,
	network_turbocell = 3,
	network_data = 4,
	network_remove = 256
};

enum client_type {
	client_unknown = 0,
	client_fromds = 1,
	client_tods = 2,
	client_interds = 3,
	client_established = 4,
	client_adhoc = 5,
	client_remove = 6
};

enum ipdata_type {
	ipdata_unknown = 0,
	ipdata_factoryguess = 1,
	ipdata_udptcp = 2,
	ipdata_arp = 3,
	ipdata_dhcp = 4,
	ipdata_group = 5
};

// Netracker itself
class Netracker {
public:
	// Forward defs
	class tracked_network;
	class tracked_client;

	typedef struct ip_data {
		ip_data() {
			ip_type = ipdata_unknown;
			ip_addr_block.s_addr = 0;
			ip_netmask.s_addr = 0;
			ip_gateway.s_addr = 0;
		}

		ipdata_type ip_type;

		in_addr ip_addr_block;
		in_addr ip_netmask;
		in_addr ip_gateway;

		ip_data& operator= (const ip_data& in) {
			ip_addr_block.s_addr = in.ip_addr_block.s_addr;
			ip_netmask.s_addr = in.ip_netmask.s_addr;
			ip_gateway.s_addr = in.ip_gateway.s_addr;
			ip_type = in.ip_type;

			return *this;
		}
	};

	typedef struct gps_data {
		gps_data() {
			gps_valid = 0;
			// Pick absurd initial values to be clearly out-of-bounds
			min_lat = 90;
			max_lat = -90;
			min_lon = 180;
			max_lon = -180;
			min_alt = 100000;
			max_alt = -100000;
			min_spd = 100000;
			max_spd = -100000;

			aggregate_lat = aggregate_lon = aggregate_alt = 0;
			aggregate_points = 0;
		}

		int gps_valid;
		double min_lat, min_lon, min_alt, min_spd;
		double max_lat, max_lon, max_alt, max_spd;
		// Aggregate/avg center position
		long double aggregate_lat, aggregate_lon, aggregate_alt;
		long aggregate_points;
	};

	// SNR info
	typedef struct signal_data {
		signal_data() {
			// These all go to 0 since we don't know if it'll be positive or
			// negative
			last_signal = last_noise = 0;
			max_signal = max_noise = 0;

			peak_lat = peak_lon = peak_alt = 0;

			maxseenrate = 0;
			encodingset = 0;
			carrierset = 0;
		}

		int last_signal, last_noise;
		int max_signal, max_noise;
		// Peak locations
		double peak_lat, peak_lon, peak_alt;

		// Max rate
		int maxseenrate;

		// Seen encodings
		uint32_t encodingset;
		uint32_t carrierset;
	};

	class tracked_network {
	public:
		tracked_network() {
			type = network_ap;
			llc_packets = data_packets = crypt_packets = fmsweak_packets = 0;
			channel = 0;
			cryptset = 0;
			decrypted = 0;
			bssid = mac_addr(0);
			ssid_cloaked = ssid_uncloaked = 0;
			last_time = first_time = 0;
			maxrate = 0;
			beaconrate = 0;
			client_disconnects = 0;
			last_sequence = 0;
			bss_timestamp = 0;
			datasize = 0;
			dupeiv_packets = 0;
			dirty = 0;
			fragments = 0;
			retries = 0;
			new_packets = 0;
		}

		// What we last saw it as
		network_type type;

		string ssid;
		string beacon_info;

		// Aggregate packet counts
		int llc_packets;
		int data_packets;
		int crypt_packets;
		int fmsweak_packets;

		int channel;

		int cryptset;
		int decrypted;

		mac_addr bssid;

		// Is the SSID hidden
		int ssid_cloaked;
		// And have we exposed it
		int ssid_uncloaked;

		time_t last_time;
		time_t first_time;

		// GPS info
		Netracker::gps_data gpsdata;

		// SNR info
		Netracker::signal_data snrdata;

		// Maximum advertised rate
		double maxrate;
		// Beacon interval
		int beaconrate;

		// Guesstimated IP data
		Netracker::ip_data guess_ipdata;

		// state tracking elements
		// Number of client disconnects (decayed per second)
		int client_disconnects;
		// Last sequence value
		int last_sequence;
		// last BSS timestamp
		uint64_t bss_timestamp;

		// Amount of data seen
		uint64_t datasize;

		// Map of IVs seen (Is this a really bad idea for ram?  Probably.  Consider
		// nuking this if it can't be compressed somehow at runtime.  Or make it a 
		// config variable for people with ram to burn)
		map<uint32_t, int> iv_map;
		// Number of duplicate IV counts
		int dupeiv_packets;

		string cdp_dev_id;
		string cdp_port_id;

		// Fragment and retry rates
		int fragments;
		int retries;

		// Number of packets since last tick
		int new_packets;

		// Network is dirty and should be pushed out
		int dirty;
	};

	class tracked_client {
	public:
		tracked_client() {
			type = client_unknown;
			last_time = first_time = 0;
			cryptset = decrypted = 0;
			channel = 0;
			llc_packets = data_packets = crypt_packets = fmsweak_packets = 0;
			maxrate = 0;
			last_sequence = 0;
			datasize = 0;
			netptr = NULL;
			fragments = 0;
			retries = 0;
			new_packets = 0;
			dirty = 0;
		}

		// DS detected type
		client_type type;

		// timestamps
		time_t last_time;
		time_t first_time;

		// Crypt and decrypt sets
		int cryptset;
		int decrypted;

		// MAC of client
		mac_addr mac;

		// MAC of network
		mac_addr bssid;

		// Last seen channel
		int channel;

		Netracker::gps_data gpsdata;
		Netracker::signal_data snrdata;

		// Individual packet counts
		int llc_packets;
		int data_packets;
		int crypt_packets;
		int fmsweak_packets;

		// Manufacturer info - MAC address key to the manuf map and score
		// for easy mapping
		/*
		manuf *manuf_ref;
		int manuf_score;
		*/

		// Maximum advertised rate during a probe
		double maxrate;

		// Last sequence number seen
		int last_sequence;

		// Amount of data seen
		uint64_t datasize;

		// Guesstimated IP data
		ip_data guess_ipdata;

		// Fragments and retries for packet stats
		int fragments;
		int retries;

		// Packets since last push
		int new_packets;

		// Do we need to push an update?
		int dirty;

		// Pointer to the network we belong to, for fast compares
		Netracker::tracked_network *netptr;
	};

	Netracker();
	Netracker(GlobalRegistry *in_globalreg);
	~Netracker();

	int AddFilter(string in_filter);

	typedef map<mac_addr, Netracker::tracked_network *>::iterator track_iter;
	typedef map<mac_addr, Netracker::tracked_client *>::iterator client_iter;
	typedef map<mac_addr, Netracker::ip_data>::iterator ipcache_iter;
	typedef map<mac_addr, string>::iterator ssidcache_iter;
	typedef multimap<mac_addr, Netracker::tracked_client *>::iterator ap_client_itr;

protected:
	GlobalRegistry *globalreg;

	// Actually handle the chain events
	int netracker_chain_handler(kis_packet *in_pack);
	int datatracker_chain_handler(kis_packet *in_pack);

	// Read and write the cache files
	int ReadSSIDCache();
	int WriteSSIDCache();
	int ReadIPCache();
	int WriteIPCache();

	// Move a client between networks
	void MoveClientNetwork(Netracker::tracked_client *cli, 
						   Netracker::tracked_network *net);
	// Combine networks (probe into normal)
	void MergeNetwork(Netracker::tracked_network *net1,
					  Netracker::tracked_network *net2);

	// Kick the timer event to update all the clients
	int TimerKick();

	// Associate probes w/ networks
	int track_probenets;

	// All networks
	map<mac_addr, Netracker::tracked_network *> tracked_map;
	// Probe association to network that owns it
	map<mac_addr, Netracker::tracked_network *> probe_assoc_map;
	// All clients
	map<mac_addr, Netracker::tracked_client *> client_map;

	// Cached data
	map<mac_addr, Netracker::ip_data> bssid_ip_map;
	map<mac_addr, string> bssid_cloak_map;

	// AP BSSID to client
	multimap<mac_addr, Netracker::tracked_client *> ap_client_map;

	// Manufacturer maps
	/*
	macmap<vector<manuf *> > ap_manuf_map;
	macmap<vector<manuf *> > client_manuf_map;
	*/

	// Cache files paths and states
	string ssid_cache_path, ip_cache_path;
	int ssid_cache_track, ip_cache_track;

	// Alert references
	int alert_chan_ref;
	int alert_dhcpcon_ref;
	int alert_bcastdcon_ref;
	int alert_airjackssid_ref;

	// Timer refs
	int netrackereventid;

	// Command refs
	int addfiltercmd_ref;

	// Filter core for tracker
	FilterCore *track_filter;

	// Let the hooks call directly in
	friend int kis_80211_netracker_hook(CHAINCALL_PARMS);
	friend int kis_80211_datatracker_hook(CHAINCALL_PARMS);
	friend void Protocol_NETWORK_enable(PROTO_ENABLE_PARMS);
	friend void Protocol_CLIENT_enable(PROTO_ENABLE_PARMS);
	friend int NetrackerUpdateTimer(TIMEEVENT_PARMS);
};

int Protocol_NETWORK(PROTO_PARMS); 
int Protocol_CLIENT(PROTO_PARMS); 
// BSSID
int Protocol_REMOVE(PROTO_PARMS);

void Protocol_NETWORK_enable(PROTO_ENABLE_PARMS);
void Protocol_CLIENT_enable(PROTO_ENABLE_PARMS);

int Netracker_Clicmd_ADDFILTER(CLIENT_PARMS);

// Hooks into the packet component trackers
class kis_netracker_netinfo : public packet_component {
public:
	kis_netracker_netinfo() {
		self_destruct = 1; // OK to delete us, we're only a pointer container
		netref = NULL;
	}

	Netracker::tracked_network *netref;
};

class kis_netracker_cliinfo : public packet_component {
public:
	kis_netracker_cliinfo() {
		self_destruct = 1; // OK to delete us, we're only a pointer container
		cliref = NULL;
	}

	Netracker::tracked_client *cliref;
};


#endif

