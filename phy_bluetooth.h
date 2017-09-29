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

#ifndef __PHY_BLUETOOTH_H__
#define __PHY_BLUETOOTH_H__

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
#include "timetracker.h"
#include "packet.h"
#include "gpstracker.h"
#include "uuid.h"

#include "devicetracker.h"
#include "devicetracker_component.h"
#include "kis_net_microhttpd.h"

class bluetooth_tracked_device;

class bluetooth_packinfo : public packet_component {
public:
    bluetooth_packinfo() {
        self_destruct = 1;
    }

    mac_addr address;
    string name;
    vector<uuid> service_uuid_vec;
    int txpower;
    int type;
};

class bluetooth_tracked_device : public tracker_component {
public:
    bluetooth_tracked_device(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bluetooth_tracked_device(GlobalRegistry *in_globalreg, int in_id, 
            SharedTrackerElement e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new bluetooth_tracked_device(globalreg, get_id()));
    }

    __ProxyTrackable(service_uuid_vec, TrackerElement, service_uuid_vec);
    __Proxy(txpower, int16_t, int16_t, int16_t, txpower);

protected:
    virtual void register_fields() {
        RegisterField("bluetooth.device.service_uuid_vec", TrackerVector,
                "advertised service UUIDs", &service_uuid_vec);
        RegisterField("bluetooth.device.txpower", TrackerInt16,
                "advertised transmit power", &txpower);
    }

    virtual void reserve_fields(SharedTrackerElement e) {
        tracker_component::reserve_fields(e);

    }

    SharedTrackerElement service_uuid_vec;
    SharedTrackerElement txpower;
};

class Kis_Bluetooth_Phy : public Kis_Phy_Handler {
public:
	// Stub
	~Kis_Bluetooth_Phy();

	// Inherited functionality
	Kis_Bluetooth_Phy(GlobalRegistry *in_globalreg) :
		Kis_Phy_Handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  Devicetracker *in_tracker,
											  int in_phyid) {
		return new Kis_Bluetooth_Phy(in_globalreg, in_tracker, in_phyid);
	}

	// Strong constructor
	Kis_Bluetooth_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
            int in_phyid);

	// Bluetooth device record classifier to common for the devicetracker layer
	static int CommonClassifierBluetooth(CHAINCALL_PARMS);
   
    // Tracker entry
	static int PacketTrackerBluetooth(CHAINCALL_PARMS);

    // Load stored data
    virtual void LoadPhyStorage(SharedTrackerElement in_storage, 
            SharedTrackerElement in_device);

protected:
    shared_ptr<Alertracker> alertracker;
    shared_ptr<Packetchain> packetchain;
    shared_ptr<EntryTracker> entrytracker;
    shared_ptr<Devicetracker> devicetracker;

    int bluetooth_device_entry_id;

	// Device components
	int dev_comp_bluetooth, dev_comp_common;

	// Packet components
	int pack_comp_btdevice, pack_comp_common, pack_comp_l1info;
};

#endif
