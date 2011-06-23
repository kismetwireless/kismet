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
#include "gpscore.h"
#include "packet.h"
#include "uuid.h"
#include "configfile.h"
#include "devicetracker.h"
#include "phy_80211.h"

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
enum BSSID_fields {
    BSSID_bssid, BSSID_type,
    BSSID_llcpackets, BSSID_datapackets, BSSID_cryptpackets,
	BSSID_manuf, BSSID_channel, BSSID_firsttime, BSSID_lasttime, 
	BSSID_atype, BSSID_rangeip, BSSID_netmaskip,
	BSSID_gatewayip, BSSID_gpsfixed,
    BSSID_minlat, BSSID_minlon, BSSID_minalt, BSSID_minspd,
    BSSID_maxlat, BSSID_maxlon, BSSID_maxalt, BSSID_maxspd,
    BSSID_signal_dbm, BSSID_noise_dbm, 
	BSSID_minsignal_dbm, BSSID_minnoise_dbm,
    BSSID_maxsignal_dbm, BSSID_maxnoise_dbm,
    BSSID_signal_rssi, BSSID_noise_rssi, 
	BSSID_minsignal_rssi, BSSID_minnoise_rssi,
    BSSID_maxsignal_rssi, BSSID_maxnoise_rssi,
    BSSID_bestlat, BSSID_bestlon, BSSID_bestalt,
    BSSID_agglat, BSSID_agglon, BSSID_aggalt, BSSID_aggpoints,
    BSSID_datasize, BSSID_tcnid, BSSID_tcmode, BSSID_tsat,
    BSSID_carrierset, BSSID_maxseenrate, BSSID_encodingset,
    BSSID_decrypted, BSSID_dupeiv, BSSID_bsstimestamp,
	BSSID_cdpdevice, BSSID_cdpport, BSSID_fragments, BSSID_retries,
	BSSID_newpackets, BSSID_freqmhz, BSSID_datacryptset,
	BSSID_maxfield
};

enum SSID_fields {
	SSID_mac, SSID_checksum, SSID_type, SSID_ssid,
	SSID_beaconinfo, SSID_cryptset, SSID_cloaked,
	SSID_firsttime, SSID_lasttime, SSID_maxrate, SSID_beaconrate,
	SSID_packets, SSID_beacons, SSID_dot11d,
	SSID_maxfield
};

enum CLIENT_fields {
    CLIENT_bssid, CLIENT_mac, CLIENT_type, CLIENT_firsttime, CLIENT_lasttime,
    CLIENT_manuf, CLIENT_llcpackets, CLIENT_datapackets, CLIENT_cryptpackets, 
    CLIENT_gpsfixed,
    CLIENT_minlat, CLIENT_minlon, CLIENT_minalt, CLIENT_minspd,
    CLIENT_maxlat, CLIENT_maxlon, CLIENT_maxalt, CLIENT_maxspd,
    CLIENT_agglat, CLIENT_agglon, CLIENT_aggalt, CLIENT_aggpoints,
    CLIENT_signal_dbm, CLIENT_noise_dbm, 
	CLIENT_minsignal_dbm, CLIENT_minnoise_dbm,
    CLIENT_maxsignal_dbm, CLIENT_maxnoise_dbm,
    CLIENT_signal_rssi, CLIENT_noise_rssi, 
	CLIENT_minsignal_rssi, CLIENT_minnoise_rssi,
    CLIENT_maxsignal_rssi, CLIENT_maxnoise_rssi,
    CLIENT_bestlat, CLIENT_bestlon, CLIENT_bestalt,
    CLIENT_atype, CLIENT_ip, CLIENT_gatewayip, CLIENT_datasize, CLIENT_maxseenrate, 
	CLIENT_encodingset, CLIENT_carrierset, CLIENT_decrypted, 
	CLIENT_channel, CLIENT_fragments, CLIENT_retries, CLIENT_newpackets,
	CLIENT_freqmhz, CLIENT_cdpdevice, CLIENT_cdpport, CLIENT_dot11d,
	CLIENT_dhcphost, CLIENT_dhcpvendor, CLIENT_datacryptset,
	CLIENT_maxfield
};

enum BSSIDSRC_fields {
	BSSIDSRC_bssid, BSSIDSRC_uuid, BSSIDSRC_lasttime, BSSIDSRC_numpackets,
    BSSIDSRC_signal_dbm, BSSIDSRC_noise_dbm, 
	BSSIDSRC_minsignal_dbm, BSSIDSRC_minnoise_dbm,
    BSSIDSRC_maxsignal_dbm, BSSIDSRC_maxnoise_dbm,
    BSSIDSRC_signal_rssi, BSSIDSRC_noise_rssi, 
	BSSIDSRC_minsignal_rssi, BSSIDSRC_minnoise_rssi,
    BSSIDSRC_maxsignal_rssi, BSSIDSRC_maxnoise_rssi,
	BSSIDSRC_maxfield
};

enum CLISRC_fields {
	CLISRC_bssid, CLISRC_mac, CLISRC_uuid, CLISRC_lasttime, CLISRC_numpackets,
    CLISRC_signal_dbm, CLISRC_noise_dbm, 
	CLISRC_minsignal_dbm, CLISRC_minnoise_dbm,
    CLISRC_maxsignal_dbm, CLISRC_maxnoise_dbm,
    CLISRC_signal_rssi, CLISRC_noise_rssi, 
	CLISRC_minsignal_rssi, CLISRC_minnoise_rssi,
    CLISRC_maxsignal_rssi, CLISRC_maxnoise_rssi,
	CLISRC_maxfield
};

enum NETTAG_fields {
	NETTAG_bssid, NETTAG_tag, NETTAG_value,
	NETTAG_maxfield
};

enum CLITAG_fields {
	CLITAG_bssid, CLITAG_mac, CLITAG_tag, CLITAG_value,
	CLITAG_maxfield
};

enum REMOVE_fields {
    REMOVE_bssid
};

// Enums explicitly defined for the ease of client writers
enum network_type {
	network_ap = 0,
	network_adhoc = 1,
	network_probe = 2,
	network_turbocell = 3,
	network_data = 4,
	network_mixed = 255,
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

enum ssid_type {
	ssid_beacon = 0,
	ssid_proberesp = 1,
	ssid_probereq = 2,
	ssid_file = 3,
};

// Netracker itself
class Netracker {
public:
	// Forward defs
	class tracked_network;
	class tracked_client;

	struct source_data {
		source_data() {
			last_seen = 0;
			num_packets = 0;
		}

		uuid source_uuid;
		time_t last_seen;
		uint32_t num_packets;
		mac_addr bssid;
		mac_addr mac;

		kis_signal_data snrdata;
	};

	// Advertised SSID data for multi-ssid networks
	// Each SSID advertised can have its own advertised limits
	struct adv_ssid_data {
		adv_ssid_data() {
			checksum = 0;
			type = ssid_beacon;
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

		inline adv_ssid_data& operator= (const adv_ssid_data& in) {
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

		ssid_type type;

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
		vector<dot11_11d_range_info> dot11d_vec;

		// SSID is dirty and should be resent
		int dirty;
	};

	// Fwd def for our map
	class tracked_client;

	class ssid_alert_data {
	public:
		ssid_alert_data() {
#ifdef HAVE_LIBPCRE
			ssid_re = NULL;
			ssid_study = NULL;
#endif
		}
		string name;

#ifdef HAVE_LIBPCRE
		pcre *ssid_re;
		pcre_extra *ssid_study;
		string filter;
#endif
		string ssid;

		macmap<int> allow_mac_map;
	};

	class tracked_network {
	public:
		tracked_network() {
			type = network_ap;
			llc_packets = data_packets = crypt_packets = 0;
			channel = 0;
			bssid = mac_addr(0);
			decrypted = 0;
			last_time = first_time = 0;
			client_disconnects = 0;
			last_sequence = 0;
			bss_timestamp = 0;
			datasize = 0;
			dupeiv_packets = 0;
			dirty = 0;
			fragments = 0;
			retries = 0;
			new_packets = 0;
			groupptr = NULL;
			lastssid = NULL;
			alert = 0;
			data_cryptset = 0;
		}

		// What we last saw it as
		network_type type;

		mac_addr bssid;

		// Aggregate packet counts
		int llc_packets;
		int data_packets;
		int crypt_packets;

		string manuf;

		// Clients seen associated with this network - we don't need
		// to use a macmap since they'll all be unique/unmasked
		map<mac_addr, Netracker::tracked_client *> client_map;

		// Advertised SSID data, often only 1 item
		map<uint32_t, Netracker::adv_ssid_data *> ssid_map;

		// Channel reported by packets
		int channel;
		// Last-seen frequency
		map<unsigned int, unsigned int> freq_mhz_map;

		time_t last_time;
		time_t first_time;

		// Cryptset seen from data packets not linked to a SSID
		uint64_t data_cryptset;

		// One of the SSIDs decrypted?
		int decrypted;

		// GPS info
		kis_gps_data gpsdata;

		// SNR info
		kis_signal_data snrdata;

		// Guesstimated IP data
		kis_ip_data guess_ipdata;

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

		// Fragment and retries within the last second
		int fragments;
		int retries;

		// Number of packets since last tick
		int new_packets;

		// Network is dirty and should be pushed out
		int dirty;

		// Client pointers to do "stuff"
		void *groupptr;
		adv_ssid_data *lastssid;

		// Map of sources which have seen this network
		map<uuid, source_data *> source_map;

		// Alert triggered
		int alert;

		// Map of arbitrary tags associated with this network
		// Tags are case sensitive!
		map<string, string> arb_tag_map;
	};

	// Mini-client for counting global unique clients
	class tracked_mini_client {
	public:
		tracked_mini_client() {
			mac = mac_addr(0);
			last_bssid_mac = mac_addr(0);
			num_bssids = 0;
		}

		mac_addr mac;
		mac_addr last_bssid_mac;
		int num_bssids;
	};

	class tracked_client {
	public:
		tracked_client() {
			type = client_unknown;
			mac = mac_addr(0);
			last_time = first_time = 0;
			decrypted = 0;
			channel = 0;
			llc_packets = data_packets = crypt_packets = 0;
			last_sequence = 0;
			datasize = 0;
			netptr = NULL;
			fragments = 0;
			retries = 0;
			new_packets = 0;
			dirty = 0;
			dot11d_country = "XXX";
			data_cryptset = 0;
		}

		// DS detected type
		client_type type;

		// timestamps
		time_t last_time;
		time_t first_time;

		// Crypt and decrypt sets
		int decrypted;

		// MAC of client
		mac_addr mac;

		// MAC of network
		mac_addr bssid;

		// Last seen channel
		int channel;
		// Last seen frequency
		map<unsigned int, unsigned int> freq_mhz_map;

		kis_gps_data gpsdata;
		kis_signal_data snrdata;

		// Individual packet counts
		int llc_packets;
		int data_packets;
		int crypt_packets;

		// Manufacturer info - MAC address key to the manuf map and score
		// for easy mapping
		string manuf;

		// Last sequence number seen
		int last_sequence;

		// Data cryptset
		uint64_t data_cryptset;

		// Amount of data seen
		uint64_t datasize;

		// Guesstimated IP data
		kis_ip_data guess_ipdata;

		// Fragments and retries for packet stats
		int fragments;
		int retries;

		// CDP tracking
		string cdp_dev_id;
		string cdp_port_id;

		// DHCP discovery tracking
		string dhcp_host, dhcp_vendor;

		// Packets since last push
		int new_packets;

		// Do we need to push an update?
		int dirty;

		// Probed ssid data
		map<uint32_t, Netracker::adv_ssid_data *> ssid_map;

		// Pointer to the network we belong to, for fast compares
		Netracker::tracked_network *netptr;

		// Map of sources which have seen this network
		map<uuid, source_data *> source_map;

		string dot11d_country;
		vector<dot11_11d_range_info> dot11d_vec;

		// Map of arbitrary tags associated with this network
		// Tags are case sensitive!
		map<string, string> arb_tag_map;
	};

	Netracker();
	Netracker(GlobalRegistry *in_globalreg);
	~Netracker();

	int FetchNumNetworks();
	int FetchNumPackets();
	int FetchNumDatapackets();
	int FetchNumCryptpackets();
	int FetchNumErrorpackets();
	int FetchNumFiltered();
	int FetchNumClients();
	int FetchNumLLCpackets();
	int FetchPacketRate();

	int AddFilter(string in_filter);
	int AddNetcliFilter(string in_filter);

	void SetNetworkTag(mac_addr in_net, string in_tag, string in_data, 
					   int in_persistent);
	void ClearNetworkTag(mac_addr in_net, string in_tag);
	string GetNetworkTag(mac_addr in_net, string in_tag);

	void SetClientTag(mac_addr in_net, mac_addr in_cli, string in_tag,
					  string in_data, int in_persistent);
	void ClearClientTag(mac_addr in_net, mac_addr in_cli, string in_tag);
	string GetClientTag(mac_addr in_net, mac_addr in_cli, string in_tag);

	// Fetch the internal maps.  Touching these is Bad.  Should only be used when
	// the chain API is insufficient, like logging xml/net ascii
	const map<mac_addr, Netracker::tracked_network *> FetchTrackedNets();
	const map<mac_addr, Netracker::tracked_network *> FetchProbeNets();

	typedef map<mac_addr, Netracker::tracked_network *>::iterator track_iter;
	typedef map<mac_addr, Netracker::tracked_client *>::iterator client_iter;
	typedef map<mac_addr, kis_ip_data>::iterator ipcache_iter;
	typedef map<mac_addr, string>::iterator ssidcache_iter;
	typedef map<mac_addr, Netracker::tracked_mini_client *>::iterator client_mini_iter;

	static void Usage(char *argv);

protected:
	GlobalRegistry *globalreg;

	int num_packets;
	int num_datapackets;
	int num_cryptpackets;
	int num_errorpackets;
	int num_filterpackets;
	int num_packetdelta;
	int num_llcpackets;

	// Actually handle the chain events
	int netracker_chain_handler(kis_packet *in_pack);
	int datatracker_chain_handler(kis_packet *in_pack);

	// Build a SSID record
	Netracker::adv_ssid_data *BuildAdvSSID(uint32_t ssid_csum, 
										   dot11_packinfo *packinfo,
										   kis_packet *in_pack);

	// Kick the timer event to update all the clients
	int TimerKick();

	// Save SSID map
	void SaveSSID();
	void SaveTags();

	// Associate probes w/ networks
	int track_probenets;

	// All networks
	map<mac_addr, Netracker::tracked_network *> tracked_map;
	// Probe association to network that owns it
	map<mac_addr, Netracker::tracked_network *> probe_assoc_map;

	// Cached data
	map<mac_addr, kis_ip_data> bssid_ip_map;
	map<mac_addr, string> bssid_cloak_map;

	// Mini-client map for unique counting
	map<mac_addr, Netracker::client_mini_iter *> client_mini_map;

	// Vector of dirty elements for pushing out to clients, quicker than
	// walking the map every tick
	vector<Netracker::tracked_network *> dirty_net_vec;
	vector<Netracker::tracked_client *> dirty_cli_vec;

	vector<Netracker::ssid_alert_data *> apspoof_vec;

	// Manufacturer maps
	/*
	macmap<vector<manuf *> > ap_manuf_map;
	macmap<vector<manuf *> > client_manuf_map;
	*/

	// Cache files paths and states
	string ssid_cache_path, ip_cache_path;
	int ssid_cache_track, ip_cache_track;

	// Alert references
	int alert_chan_ref, alert_dhcpcon_ref, alert_bcastdcon_ref, alert_airjackssid_ref,
		alert_wepflap_ref, alert_dhcpname_ref, alert_dhcpos_ref, alert_adhoc_ref,
		alert_ssidmatch_ref;

	// Timer refs
	int netrackereventid;

	// Command refs
	int addfiltercmd_ref, addnetclifiltercmd_ref, addnettagcmd_ref, delnettagcmd_ref,
		addclitagcmd_ref, delclitagcmd_ref;

	// Filter core for tracker
	FilterCore *track_filter;
	// Filter core for network client
	FilterCore *netcli_filter;

	// Nonglobal protocols
	int proto_ref_bssidsrc, proto_ref_clisrc, proto_ref_nettag, proto_ref_clitag;

	// SSID cloak file as a config
	ConfigFile *ssid_conf, *tag_conf;
	time_t conf_save;

	// Let the hooks call directly in
	friend int kis_80211_netracker_hook(CHAINCALL_PARMS);
	friend int kis_80211_datatracker_hook(CHAINCALL_PARMS);
	friend void Protocol_BSSID_enable(PROTO_ENABLE_PARMS);
	friend void Protocol_SSID_enable(PROTO_ENABLE_PARMS);
	friend void Protocol_CLIENT_enable(PROTO_ENABLE_PARMS);
	friend void Protocol_NETTAG_enable(PROTO_ENABLE_PARMS);
	friend void Protocol_CLITAG_enable(PROTO_ENABLE_PARMS);
	friend int NetrackerUpdateTimer(TIMEEVENT_PARMS);
};

int Protocol_NETWORK(PROTO_PARMS); 
int Protocol_CLIENT(PROTO_PARMS); 
// BSSID
int Protocol_REMOVE(PROTO_PARMS);

void Protocol_NETWORK_enable(PROTO_ENABLE_PARMS);
void Protocol_CLIENT_enable(PROTO_ENABLE_PARMS);

int Netracker_Clicmd_ADDFILTER(CLIENT_PARMS);
int Netracker_Clicmd_ADDNETCLIFILTER(CLIENT_PARMS);

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

