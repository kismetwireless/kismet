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

#ifndef __KIS_CLIENT_DEVICETRACKER_H__
#define __KIS_CLIENT_DEVICETRACKER_H__

#include "config.h"

#include "globalregistry.h"
#include "devicetracker.h"
#include "kis_panel_network.h"

class Client_Devicetracker;

// client PHY handlers are registered with the client devicetracker
// creation is deferred until a phymap is seen which defines a phy of the
// requested name

class Client_Phy_Handler {
public:
	Client_Phy_Handler() {
		fprintf(stderr, "FATAL OOPS: Client_Phy_Handler\n");
		exit(1);
	}

	Client_Phy_Handler(GlobalRegistry *in_globalreg) {
		globalreg = in_globalreg;
		devicetracker = NULL;
		phyid = -1;
		phyname = "NONE";
	}

	Client_Phy_Handler(GlobalRegistry *in_globalreg, Client_Devicetracker *in_tracker,
					   int in_phyid) {
		globalreg = in_globalreg;
		phyid = in_phyid;
		devicetracker = in_tracker;
	}

	virtual Client_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
												 Client_Devicetracker *in_tracker) = 0;

	virtual string FetchPhyName() { return phyname; }
	virtual int FetchPhyId() { return phyid; }

	// We have to be able to set the phyid after creation time since we need a phymap
	// sentence to tell us how to map them
	virtual void SetPhyId(int in_phyid) {
		phyid = in_phyid;
	}

	// Called when netclient triggers, passed by the clientdevicetracker layer
	virtual void NetClientConfigure(KisNetClient *in_cli, int in_recon) = 0;
	virtual void NetClientAdd(KisNetClient *in_cli, int add) = 0;

protected:
	GlobalRegistry *globalreg;

	Client_Devicetracker *devicetracker;
	int phyid;

	string phyname;
};

// This seems like a lot of duplication but I'm not sure how to better handle it
class Client_Devicetracker {
public:
	Client_Devicetracker() {
		fprintf(stderr, "FATAL OOPS: ClientDevicetracker()\n");
		exit(1);
	}

	Client_Devicetracker(GlobalRegistry *in_globalreg);

	~Client_Devicetracker();

	int RegisterPhyHandler(Client_Phy_Handler *in_weak_handler);
	int RegisterDeviceComponent(string in_component);

	Client_Phy_Handler *FetchPhyHandler(int in_phy);

	vector<kis_tracked_device *> *FetchDevices(int in_phy);

	int FetchNumDevices(int in_phy);
	int FetchNumPackets(int in_phy);
	int FetchNumDatapackets(int in_phy);
	int FetchNumCryptpackets(int in_phy);
	int FetchNumErrorpackets(int in_phy);
	int FetchPacketRate(int in_phy);

	void SetDeviceTag(mac_addr in_device, string in_tag, string in_data,
					  int in_persistent);
	void ClearDeviceTag(mac_addr in_device, string in_tag);

	typedef map<mac_addr, kis_tracked_device *>::iterator device_itr;
	typedef map<mac_addr, kis_tracked_device *>::const_iterator const_device_itr;

	void NetClientConfigure(KisNetClient *in_cli, int in_recon);
	void NetClientAdd(KisNetClient *in_cli, int add);

	void Proto_DEVICE(CLIPROTO_CB_PARMS);
	void Proto_PHYMAP(CLIPROTO_CB_PARMS);

protected:
	GlobalRegistry *globalreg;

	int next_componentid;
	map<string, int> component_str_map;
	map<int, string> component_id_map;

	// Total # of packets
	int num_packets;
	int num_datapackets;
	int num_errorpackets;
	int num_packetdelta;

	// Per-phy #s of packets
	map<int, int> phy_packets;
	map<int, int> phy_datapackets;
	map<int, int> phy_errorpackets;
	map<int, int> phy_filterpackets;
	map<int, int> phy_packetdelta;

	// Per-phy device list
	map<int, vector<kis_tracked_device *> *> phy_device_vec;

	// Per-phy dirty list
	map<int, vector<kis_tracked_device *> *> phy_dirty_vec;

	// Common device component
	int devcomp_ref_common;

	// Tracked devices
	map<mac_addr, kis_tracked_device *> tracked_map;
	// Vector of tracked devices so we can iterate them quickly
	vector<kis_tracked_device *> tracked_vec;

	// Vector of dirty elements for pushing to clients, better than walking
	// the map every tick, looking for dirty records
	vector<kis_tracked_device *> dirty_device_vec;

	// Registered & Identified PHY types
	map<int, Client_Phy_Handler *> phy_handler_map;

	vector<Client_Phy_Handler *> unassigned_phy_vec;

	// KPI and network client references
	KisPanelInterface *kpi;
	int cli_addref;
};

#endif


