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
    std::string name;
    std::vector<uuid> service_uuid_vec;
    int txpower;
    int type;
};

class bluetooth_tracked_device : public tracker_component {
public:
    bluetooth_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bluetooth_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bluetooth_tracked_device(int in_id, 
            std::shared_ptr<TrackerElementMap> e) : 
        tracker_component(in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("bluetooth_tracked_device");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __ProxyTrackable(service_uuid_vec, TrackerElementVector, service_uuid_vec);
    __Proxy(txpower, int16_t, int16_t, int16_t, txpower);

protected:
    virtual void register_fields() override {
        RegisterField("bluetooth.device.service_uuid_vec",
                "advertised service UUIDs", &service_uuid_vec);
        RegisterField("bluetooth.device.txpower", 
                "advertised transmit power", &txpower);
    }

    virtual void reserve_fields(std::shared_ptr<TrackerElementMap> e) override {
        tracker_component::reserve_fields(e);

    }

    std::shared_ptr<TrackerElementVector> service_uuid_vec;
    std::shared_ptr<TrackerElementInt16> txpower;
};

class Kis_Bluetooth_Phy : public Kis_Phy_Handler {
public:
	// Stub
	virtual ~Kis_Bluetooth_Phy();

	// Inherited functionality
	Kis_Bluetooth_Phy(GlobalRegistry *in_globalreg) :
		Kis_Phy_Handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  int in_phyid) {
		return new Kis_Bluetooth_Phy(in_globalreg, in_phyid);
	}

	// Strong constructor
	Kis_Bluetooth_Phy(GlobalRegistry *in_globalreg, int in_phyid);

	// Bluetooth device record classifier to common for the devicetracker layer
	static int CommonClassifierBluetooth(CHAINCALL_PARMS);
   
    // Tracker entry
	static int PacketTrackerBluetooth(CHAINCALL_PARMS);

    // Load stored data
    virtual void LoadPhyStorage(SharedTrackerElement in_storage, 
            SharedTrackerElement in_device);

protected:
    std::shared_ptr<Alertracker> alertracker;
    std::shared_ptr<Packetchain> packetchain;
    std::shared_ptr<EntryTracker> entrytracker;
    std::shared_ptr<Devicetracker> devicetracker;

    int bluetooth_device_entry_id;

	// Device components
	int dev_comp_bluetooth, dev_comp_common;

	// Packet components
	int pack_comp_btdevice, pack_comp_common, pack_comp_l1info;
};

#endif
