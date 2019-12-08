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

#ifndef __PHY_BTLE_H__
#define __PHY_BTLE_H__

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

#ifndef DLT_BLUETOOTH_LE_LL
#define DLT_BLUETOOTH_LE_LL	251
#endif

// Future btle attributes
class btle_tracked_device : public tracker_component {
public:
    btle_tracked_device() : 
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_device(int in_id, 
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_device");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<tracker_element> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

protected:
    virtual void register_fields() override { 
        tracker_component::register_fields();
    }
};

class kis_btle_phy : public kis_phy_handler {
public:
    kis_btle_phy(global_registry *in_globalreg) :
        kis_phy_handler(in_globalreg) { }

    kis_btle_phy(global_registry *in_globalreg, int in_phyid);

    virtual ~kis_btle_phy();

    virtual kis_phy_handler *create_phy_handler(global_registry *in_globalreg, int in_phyid) override {
        return new kis_btle_phy(in_globalreg, in_phyid);
    }

    static int dissector(CHAINCALL_PARMS);
    static int common_classifier(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device) override;


protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int dev_comp_common;
    int pack_comp_common, pack_comp_linkframe, pack_comp_decap;

    int btle_device_id;
};

#endif

