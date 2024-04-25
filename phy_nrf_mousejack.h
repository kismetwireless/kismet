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

#ifndef __PHY_NRF_MOUSEJACK_H__
#define __PHY_NRF_MOUSEJACK_H__

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

/* Largely a placeholder for future possible data; right now we can't decode
 * much of anything */
class mousejack_tracked_device : public tracker_component {
public:
    mousejack_tracked_device() : 
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    mousejack_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    mousejack_tracked_device(int in_id, 
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    mousejack_tracked_device(const mousejack_tracked_device *p) :
        tracker_component{p} {

        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("mousejack_tracked_device");
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

class Kis_Mousejack_Phy : public kis_phy_handler {
public:
    Kis_Mousejack_Phy() :
        kis_phy_handler() { }

    Kis_Mousejack_Phy(int in_phyid);

    virtual ~Kis_Mousejack_Phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) {
        return new Kis_Mousejack_Phy(in_phyid);
    }

    static int DissectorMousejack(CHAINCALL_PARMS);
    static int CommonClassifierMousejack(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device);


protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int mousejack_device_entry_id;
    int dev_comp_common;
    int pack_comp_common, pack_comp_linkframe;

    int dlt;

    std::shared_ptr<tracker_element_string> mj_manuf_amazon;
    std::shared_ptr<tracker_element_string> mj_manuf_logitech;
    std::shared_ptr<tracker_element_string> mj_manuf_microsoft;
    std::shared_ptr<tracker_element_string> mj_manuf_nrf;

};

#endif

