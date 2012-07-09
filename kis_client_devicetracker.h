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
#include "kis_clinetframe.h"

class Client_Devicetracker;

class Kis_DevDetails_Panel;
class Kis_Free_Text;

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
												 Client_Devicetracker *in_tracker,
												 int in_phyid) = 0;

	virtual string FetchPhyName() { return phyname; }
	virtual int FetchPhyId() { return phyid; }

	// Called by client_devicetracker when configuring the network server,
	// should not be registered by the phy handler itself.  Because adding is
	// brokered by the devicetracker, there is no netclientadd callback
	virtual void NetClientConfigure(KisNetClient *in_cli, int in_recon) = 0;

	// Panel UI is initialized; do anything reasonable, like adding sort and
	// columns, etc
	virtual void PanelInitialized() = 0;

	// Initialized a details panel; do anything reasonable, like adding
	// custom menu items or widgets pertaining to this type of device
	virtual void PanelDetails(Kis_DevDetails_Panel *in_panel,
							  kis_tracked_device *in_dev) = 0;

	// Details panel is drawing a device we own; do something reasonable, like
	// add our phy-specific component text to the details list
	virtual void PanelDetailsText(Kis_Free_Text *in_textbox, 
								  kis_tracked_device *in_dev) = 0;

protected:
	GlobalRegistry *globalreg;

	Client_Devicetracker *devicetracker;
	int phyid;

	string phyname;
};

// Callback when a *DEVICE sentence is received and a device updated
#define DEVICERX_PARMS kis_tracked_device *device, void *aux, \
	GlobalRegistry *globalreg
typedef void (*DeviceRXEnableCB)(DEVICERX_PARMS);

// Callback when a *PHYMAP sentence is received and the phy list changes
#define PHYRX_PARMS int phy_id, void *aux, GlobalRegistry *globalreg
typedef void (*PhyRXEnableCB)(PHYRX_PARMS);

// This seems like a lot of duplication but I'm not sure how to better handle it
class Client_Devicetracker {
public:
	Client_Devicetracker() {
		fprintf(stderr, "FATAL OOPS: ClientDevicetracker()\n");
		exit(1);
	}

	Client_Devicetracker(GlobalRegistry *in_globalreg);

	~Client_Devicetracker();

	void RegisterPhyHandler(Client_Phy_Handler *in_weak_handler);
	int RegisterDeviceComponent(string in_component);
	string FetchDeviceComponentName(int in_id);

	Client_Phy_Handler *FetchPhyHandler(int in_phy);
	string FetchPhyName(int in_phy);

	vector<kis_tracked_device *> *FetchDevices(int in_phy);
	kis_tracked_device *FetchDevice(mac_addr in_mac);

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
	void Proto_DEVTAG(CLIPROTO_CB_PARMS);
	void Proto_DEVICEDONE(CLIPROTO_CB_PARMS);

	// Register a callback to trigger on device updates
	int RegisterDevicerxCallback(DeviceRXEnableCB in_callback, void *in_aux);
	void RemoveDevicerxCallback(int in_id);

	// Register a new callback, on new phys only or on any update
	int RegisterPhyrxCallback(PhyRXEnableCB in_callback, void *in_aux, bool on_any);
	void RemovePhyrxCallback(int in_id);

	// Callback to ping phy handlers that the panel interface is
	// initialized to resolve load order issues
	void PanelInitialized();

protected:
	class observed_phy {
	public:
		int phy_id;
		string phy_name;
		Client_Phy_Handler *handler;

		observed_phy() {
			phy_id = KIS_PHY_UNKNOWN;
			phy_name = "NONE";
			handler = NULL;
		}
	};

	class devicerx_cb_rec {
	public:
		int id;
		DeviceRXEnableCB callback;
		void *aux;
	};

	class phyrx_cb_rec {
	public:
		int id;
		PhyRXEnableCB callback;
		void *aux;
		bool on_any;
	};

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

	// Common device component
	int devcomp_ref_common;

	// Tracked devices
	map<mac_addr, kis_tracked_device *> tracked_map;
	// Vector of tracked devices so we can iterate them quickly
	vector<kis_tracked_device *> tracked_vec;

	// Registered & Identified PHY types
	map<int, observed_phy *> phy_handler_map;

	vector<Client_Phy_Handler *> unassigned_phy_vec;

	// KPI and network client references
	KisPanelInterface *kpi;
	int cli_addref;

	// Proto fields
	string proto_phymap_fields, proto_device_fields, 
		   proto_devtag_fields, proto_devicedone_fields;
	int proto_phymap_fields_num, proto_device_fields_num, 
		proto_devtag_fields_num, proto_devicedone_fields_num;

	vector<devicerx_cb_rec *> devicerx_cb_vec;
	int next_devicerx_id;

	vector<phyrx_cb_rec *> phyrx_cb_vec;
	int next_phyrx_id;
};

#endif


