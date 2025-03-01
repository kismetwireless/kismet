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

#ifndef __PHY_802154_H__
#define __PHY_802154_H__

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

#include "tap_802_15_4.h"

#ifndef KDLT_IEEE802_15_4_TAP
#define KDLT_IEEE802_15_4_TAP             283
#endif

#ifndef KDLT_IEEE802_15_4_NOFCS
#define KDLT_IEEE802_15_4_NOFCS           230
#endif

/* Largely a placeholder for future possible data; right now we can't decode
 * much of anything */
class kis_802154_tracked_device : public tracker_component {
public:
    kis_802154_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    kis_802154_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_802154_tracked_device(int in_id,
        std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("802154_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

protected:

    virtual void register_fields() override {

    }
};

class kis_802154_phy : public kis_phy_handler {
public:
    kis_802154_phy() :
        kis_phy_handler() { }

    kis_802154_phy(int in_phyid);

    virtual ~kis_802154_phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) {
        return new kis_802154_phy(in_phyid);
    }

    static int dissector802154(CHAINCALL_PARMS);
    static int commonclassifier802154(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device);


protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int kis_802154_device_entry_id;
    int dev_comp_common;
    int pack_comp_common, pack_comp_l1info, pack_comp_linkframe;

    int dlt;

};

#endif

