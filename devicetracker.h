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

#ifndef __DEVICE_TRACKER_H__
#define __DEVICE_TRACKER_H__

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

// How big the main vector of components is, if we ever get more than this
// many tracked components we'll need to expand this but since it ties to 
// memory and track record creation it starts relatively low
#define MAX_TRACKER_COMPONENTS	64

#define KIS_PHY_ANY	-1
#define KIS_PHY_UNKNOWN -2

// Basic unit being tracked in a tracked device
class tracker_component {
public:
	tracker_component() { self_destruct = 1; }
	virtual ~tracker_component() { }

	int self_destruct;
};

enum kis_ipdata_type {
	ipdata_unknown = 0,
	ipdata_factoryguess = 1,
	ipdata_udptcp = 2,
	ipdata_arp = 3,
	ipdata_dhcp = 4,
	ipdata_group = 5
};

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

class Packinfo_Sig_Combo {
public:
	Packinfo_Sig_Combo(kis_layer1_packinfo *l1, kis_gps_packinfo *gp) {
		lay1 = l1;
		gps = gp;
	}

	kis_layer1_packinfo *lay1;
	kis_gps_packinfo *gps;
};

// SNR info
struct kis_signal_data {
	kis_signal_data() {
		// These all go to 0 since we don't know if it'll be positive or
		// negative
		last_signal_dbm = last_noise_dbm = 0;
		min_signal_dbm = min_noise_dbm = 0;
		max_signal_dbm = max_noise_dbm = -256;

		last_signal_rssi = last_noise_rssi = 0;
		min_signal_rssi = min_noise_rssi = 1024;
		max_signal_rssi = max_noise_rssi = 0;

		peak_lat = peak_lon = peak_alt = 0;

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

// Fwd ktd
class kis_tracked_device;

// Common values across all PHY types, as the PHY is capable of filling them in
class kis_device_common : public tracker_component {
public:
	kis_tracked_device *device;

	// Tracked PHY type
	int phy_type;

	// Time values
	time_t first_time;
	time_t last_time;

	// Total packets
	int packets;

	// Link level packets (mgmt frames, etc)
	int llc_packets;
	// PHY level failures on errors
	int error_packets;

	// Data and encrypted data
	int data_packets;
	int crypt_packets;

	// Amount of data seen
	uint64_t datasize;

	// # of packets since last tick
	int new_packets;

	// Logical channel as per PHY type
	int channel;

	// Frequency
	int frequency;

	// raw freqs seen mapped to # of times seen
	map<unsigned int, unsigned int> freq_mhz_map;

	// GPS info
	kis_gps_data gpsdata;

	// SNR
	kis_signal_data snrdata;

	// Alert triggered on this device
	int alert;

	// Arbitrary tags associated with this device
	// Tags are case sensitive
	map<string, string> arb_tag_map;

	// We need to be sent
	int dirty;

	kis_device_common() {
		device = NULL;

		phy_type = KIS_PHY_UNKNOWN;

		first_time = last_time = 0;

		packets = 0;

		llc_packets = data_packets = crypt_packets = error_packets = 0;

		datasize = 0;

		new_packets = 0;

		channel = 0;

		frequency = 0;

		alert = 0;

		dirty = 0;
	}
};

// Container that holds tracked information & a unique key.  Key should be unique
// across all PHY types & must be generated in consistent way
class kis_tracked_device {
public:
	mac_addr key;

	int phy_type;

	vector<tracker_component *> content_vec;

	kis_tracked_device() {
		phy_type = KIS_PHY_UNKNOWN;
		content_vec.resize(MAX_TRACKER_COMPONENTS, NULL);
	}

	~kis_tracked_device() {
		for (unsigned int y = 0; y < MAX_TRACKER_COMPONENTS; y++) {
			tracker_component *tcm = content_vec[y];

			if (tcm == NULL)
				continue;

			if (tcm->self_destruct)
				delete tcm;

			content_vec[y] = NULL;
		}
	}

	inline void insert(const unsigned int index, tracker_component *data) {
		if (index >= MAX_TRACKER_COMPONENTS)
			return;
		content_vec[index] = data;
	}

	inline void *fetch(const unsigned int index) {
		if (index >= MAX_TRACKER_COMPONENTS)
			return NULL;

		return content_vec[index];
	}

	inline void erase(const unsigned int index) {
		if (index >= MAX_TRACKER_COMPONENTS)
			return;

		if (content_vec[index] != NULL) {
			if (content_vec[index]->self_destruct)
				delete content_vec[index];

			content_vec[index] = NULL;
		}
	}

	inline tracker_component *operator[] (const unsigned int& index) const {
		if (index >= MAX_TRACKER_COMPONENTS)
			return NULL;

		return content_vec[index];
	}
};

// Packinfo references
class kis_tracked_device_info : public packet_component {
public:
	kis_tracked_device_info() {
		self_destruct = 1;
		devref = NULL;
	}

	kis_tracked_device *devref;
};

// fwd
class Devicetracker;

// Handler element for a phy
//  Registered with Devicetracker
//  Devicetracker feeds packets to phyhandlers, no need to register with packet 
//   chain on each
//  Registered phy id is passed from devicetracker
//
// 	Subclasses are expected to handle:
// 	  Packets from a new PHY (via DLT or packet components) and translate them
// 	   into trackable entries in DeviceTracker
// 	  Appropriate network sentences to export non-common tracking data for this phy
// 	  Logging in plaintext and xml
class Kis_Phy_Handler {
public:
	Kis_Phy_Handler() { fprintf(stderr, "fatal oops: kis_phy_handler();\n"); exit(1); }

	// Create a 'weak' handler which provides enough structure to call CreatePhyHandler
	Kis_Phy_Handler(GlobalRegistry *in_globalreg) {
		globalreg = in_globalreg;
		devicetracker = NULL;
		phyid = -1;
		phyname = "NONE";
	}

	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  Devicetracker *in_tracker,
											  int in_phyid) = 0;

	Kis_Phy_Handler(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
					int in_phyid) {
		globalreg = in_globalreg;
		phyid = in_phyid;
		devicetracker = in_tracker;
	}

	virtual string FetchPhyName() { return phyname; }
	virtual int FetchPhyId() { return phyid; }

	// Packet kick, passed from devicetracker
	virtual int HandlePacket(kis_packet *in_pack) = 0;

	// Timer event carried from devicetracker, for sending updated 
	// phy-specific records, etc
	virtual int TimerKick() = 0;

	// To do: Logging functions

protected:
	GlobalRegistry *globalreg;
	Devicetracker *devicetracker;

	string phyname;
	int phyid;
};
	
class Devicetracker {
public:
	Devicetracker() { fprintf(stderr, "FATAL OOPS: Kis_Tracker()\n"); exit(0); }
	Devicetracker(GlobalRegistry *in_globalreg);
	~Devicetracker();

	// Register a phy handler weak class, used to instantiate the strong class
	// inside devtracker
	int RegisterPhyHandler(Kis_Phy_Handler *in_weak_handler);
	// Register a tracked device component
	int RegisterDeviceComponent(string in_component);

	int FetchNumDevices(int in_phy);
	int FetchNumPackets(int in_phy);
	int FetchNumDatapackets(int in_phy);
	int FetchNumCryptpackets(int in_phy);
	int FetchNumErrorpackets(int in_phy);
	int FetchNumFilterpackets(int in_phy);
	int FetchPacketRate(int in_phy);

	int AddFilter(string in_filter);
	int AddNetCliFilter(string in_filter);

	void SetDeviceTag(mac_addr in_device, string in_tag, string in_data,
					  int in_persistent);
	void ClearDeviceTag(mac_addr in_device, string in_tag);
	string FetchDeviceTag(mac_addr in_device, string in_tag);

	// Look for an existing device record
	kis_tracked_device *FetchDevice(mac_addr in_device);
	
	// Make a device record
	kis_tracked_device *GenerateDevice(mac_addr in_device);

	// Fetch the internal maps. Touching these is generally Bad.  Should
	// only be used when the chain API is insufficient for something, 
	// like linking in directly for xml/net logging.
	const map<mac_addr, kis_tracked_device *> FetchTrackedDevices();

	static void Usage(char *argv);

	// Kick the timer event to update the network clients
	int TimerKick();

	// Send all devices to everyone
	void BlitDevices(int in_fd);

protected:
	void SaveTags();

	GlobalRegistry *globalreg;

	int next_componentid;
	map<string, int> component_str_map;
	map<int, string> component_id_map;

	// Total # of packets
	int num_packets;
	int num_errorpackets;
	int num_filterpackets;
	int num_packetdelta;

	// Per-phy #s of packets
	map<int, int> phy_packets;
	map<int, int> phy_errorpackets;
	map<int, int> phy_filterpackets;
	map<int, int> phy_packetdelta;

	// Common device component
	int devcomp_ref_common;

	// Timer id for main timer kick
	int timerid;

	// Network protocols
	int proto_ref_commondevice;
	int proto_ref_trackinfo;
	int proto_ref_devtag;

	// Tracked devices
	map<mac_addr, kis_tracked_device *> tracked_map;
	// Vector of tracked devices so we can iterate them quickly
	vector<kis_tracked_device *> tracked_vec;

	// Vector of dirty elements for pushing to clients, better than walking
	// the map every tick, looking for dirty records
	vector<kis_tracked_device *> dirty_device_vec;

	// Filtering
	FilterCore *track_filter;

	// Tag records as a config file
	ConfigFile *tag_conf;
	time_t conf_save;

	// Registered PHY types
	int next_phy_id;
	map<int, Kis_Phy_Handler *> phy_handler_map;

};

#endif

