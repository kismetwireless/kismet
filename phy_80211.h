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

	CODE IN BOTH phy_80211.cc AND phy_80211_dissectors.cc
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

// Dot11d struct
struct dot11_11d_range_info {
	dot11_11d_range_info() {
		startchan = 0;
		numchan = 0;
		txpower = 0;
	}

	int startchan, numchan, txpower;
};

struct dot11_ssid {
	dot11_ssid() {
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

	inline dot11_ssid& operator= (const dot11_ssid& in) {
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
	vector<dot11_11d_range_info> dot11d_vec;

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
class dot11_client;

class dot11_ap : public tracker_component {
public:
	dot11_network_type type;
	mac_addr bssid;

	// Clients associated w/ the network, they're unique/unmasked so
	// we don't need a macmap
	map<mac_addr, dot11_client *> client_map;

	// Advertised SSID data, by checksum
	map<uint32_t, dot11_ssid *> ssid_map;

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
	dot11_ssid *lastssid;

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

class dot11_client : public tracker_component {
public:
	dot11_client_type type;

	int decrypted;

	// Who we most recently talked to
	mac_addr last_bssid;

	// Who we've talked to
	vector<mac_addr> bssid_list;

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
	map<uint32_t, dot11_ssid *> ssid_map;

	// Most recent SSID
	dot11_ssid *last_ssid;

	dot11_ap *netptr;

	string dot11d_country;
	vector<dot11_11d_range_info> dot11d_vec;

};

class dot11_ssid_alert {
public:
	dot11_ssid_alert() {
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

// Dot11 SSID max len
#define DOT11_PROTO_SSID_LEN	32

// Wep keys
#define DOT11_WEPKEY_MAX		32
#define DOT11_WEPKEY_STRMAX		((DOT11_WEPKEY_MAX * 2) + DOT11_WEPKEY_MAX)

class dot11_wep_key {
public:
    int fragile;
    mac_addr bssid;
    unsigned char key[DOT11_WEPKEY_MAX];
    unsigned int len;
    unsigned int decrypted;
    unsigned int failed;
};

// dot11 packet components

// Info from the IEEE 802.11 frame headers for kismet
class dot11_packinfo : public packet_component {
public:
    dot11_packinfo() {
		self_destruct = 1; // Our delete() handles this
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
		cryptset = 0;
		decrypted = 0;
        fuzzywep = 0;
		fmsweak = 0;
        ess = 0;
		ibss = 0;
		channel = 0;
        encrypted = 0;
        beacon_interval = 0;
        maxrate = 0;
        timestamp = 0;
        sequence_number = 0;
        frag_number = 0;
		fragmented = 0;
		retry = 0;
        duration = 0;
        datasize = 0;
		qos = 0;
		ssid_csum = 0;
		dot11d_country = "XXX";
    }

    // Corrupt 802.11 frame
    int corrupt;
   
    // Offset to data components in frame
    unsigned int header_offset;
    
    ieee_80211_type type;
    ieee_80211_subtype subtype;
  
    uint8_t mgt_reason_code;
    
    // Raw SSID
	string ssid;
	// Length of the SSID header field
    int ssid_len;
	// Is the SSID empty spaces?
	int ssid_blank;

    // Address set
    mac_addr source_mac;
    mac_addr dest_mac;
    mac_addr bssid_mac;
    mac_addr other_mac;
    
    ieee_80211_disttype distrib;
 
	uint64_t cryptset;
	int decrypted; // Might as well put this in here?
    int fuzzywep;
	int fmsweak;

    // Was it flagged as ess? (ap)
    int ess;
	int ibss;

	// What channel does it report
	int channel;

    // Is this encrypted?
    int encrypted;
    int beacon_interval;

	uint16_t qos;

    // Some cisco APs seem to fill in this info field
	string beacon_info;

    double maxrate;

    uint64_t timestamp;
    int sequence_number;
    int frag_number;
	int fragmented;
	int retry;

    int duration;

    int datasize;

	uint32_t ssid_csum;

	string dot11d_country;
	vector<dot11_11d_range_info> dot11d_vec;
};


class Kis_80211_Phy : public Kis_Phy_Handler {
public:
	// Stub
	Kis_80211_Phy() { }
	~Kis_80211_Phy();

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

	// 802.11 packet dissectors, defined in phy_80211_dissectors.cc
	// Helper functions for decoding ieee tagparms, etc
	int GetIEEETagOffsets(unsigned int init_offset, kis_datachunk *in_chunk,
						  map<int, vector<int> > *tag_cache_map);

	int WPACipherConv(uint8_t cipher_index);
	int WPAKeyMgtConv(uint8_t mgt_index);

	// Dot11 decoders, wep decryptors, etc
	int PacketWepDecryptor(kis_packet *in_pack);
	int PacketDot11dissector(kis_packet *in_pack);
	int PacketDot11dataDissector(kis_packet *in_pack);
	int PacketDot11stringDissector(kis_packet *in_pack);

	// static incase some other component wants to use it
	static kis_datachunk *DecryptWEP(dot11_packinfo *in_packinfo,
									 kis_datachunk *in_chunk, 
									 unsigned char *in_key, int in_key_len,
									 unsigned char *in_id);

	// TODO - what do we do with the strings?  Can we make them phy-neutral?
	// int packet_dot11string_dissector(kis_packet *in_pack);

	// 802.11 packet classifier to common for the devicetracker layer
	int ClassifierDot11(kis_packet *in_pack);

	// Dot11 tracker for building phy-specific elements
	int TrackerDot11(kis_packet *in_pack);

	// Timer events passed from Devicetracker
	virtual int TimerKick();

	int AddFilter(string in_filter);
	int AddNetcliFilter(string in_filter);

	void SetStringExtract(int in_extr);

	void AddWepKey(mac_addr bssid, uint8_t *key, unsigned int len, int temp);

	virtual void BlitDevices(int in_fd, vector<kis_tracked_device *> *devlist);

	virtual void ExportLogRecord(kis_tracked_device *in_device, string in_logtype, 
								 FILE *in_logfile, int in_lineindent);

	// We need to return something cleaner for xsd namespace
	virtual string FetchPhyXsdNs() {
		return "phy80211";
	}

protected:
	int LoadWepkeys();

	// Build a SSID record
	dot11_ssid *BuildSSID(uint32_t ssid_csum,
						  dot11_packinfo *packinfo,
						  kis_packet *in_pack);

	// Save the SSID cache
	void SaveSSID();

	map<mac_addr, string> bssid_cloak_map;

	string ssid_cache_path, ip_cache_path;
	int ssid_cache_track, ip_cache_track;

	// Device components
	int dev_comp_net, dev_comp_client;

	// Packet components
	int pack_comp_80211, pack_comp_basicdata, pack_comp_mangleframe,
		pack_comp_strings, pack_comp_checksum, pack_comp_linkframe,
		pack_comp_decap, pack_comp_common;

	// Do we do any data dissection or do we hide it all (legal safety
	// cutout)
	int dissect_data;

	// Do we pull strings?
	int dissect_strings, dissect_all_strings;

	FilterCore *string_filter;
	macmap<int> string_nets;

	// Dissector alert references
	int alert_netstumbler_ref, alert_nullproberesp_ref, alert_lucenttest_ref,
		alert_msfbcomssid_ref, alert_msfdlinkrate_ref, alert_msfnetgearbeacon_ref,
		alert_longssid_ref, alert_disconinvalid_ref, alert_deauthinvalid_ref,
		alert_dhcpclient_ref;

	// Are we allowed to send wepkeys to the client (server config)
	int client_wepkey_allowed;
	// Map of wepkeys to BSSID (or bssid masks)
	macmap<dot11_wep_key *> wepkeys;

	// Generated WEP identity / base
	unsigned char wep_identity[256];

	// Tracker alert references
	int alert_chan_ref, alert_dhcpcon_ref, alert_bcastdcon_ref, alert_airjackssid_ref,
		alert_wepflap_ref, alert_dhcpname_ref, alert_dhcpos_ref, alert_adhoc_ref,
		alert_ssidmatch_ref;

	// Command refs
	int addfiltercmd_ref, addnetclifiltercmd_ref;

	// Filter core for tracker
	FilterCore *track_filter;
	// Filter core for network client
	FilterCore *netcli_filter;

	// Protocol references
	int proto_ref_bssidsrc, proto_ref_clisrc;

	// SSID cloak file as a config file
	ConfigFile *ssid_conf;
	time_t conf_save;

	// probe assoc to owning network
	map<mac_addr, kis_tracked_device *> probe_assoc_map;

	vector<dot11_ssid_alert *> apspoof_vec;

};

#endif
