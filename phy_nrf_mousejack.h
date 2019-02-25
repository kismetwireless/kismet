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
#include "kis_net_microhttpd.h"

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
            std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("mousejack_tracked_device");
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

protected:

    virtual void register_fields() override {

    }
};

class Kis_Mousejack_Phy : public Kis_Phy_Handler {
public:
    Kis_Mousejack_Phy(GlobalRegistry *in_globalreg) :
        Kis_Phy_Handler(in_globalreg) { }

    Kis_Mousejack_Phy(GlobalRegistry *in_globalreg, int in_phyid);

    virtual ~Kis_Mousejack_Phy();

    virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg, int in_phyid) {
        return new Kis_Mousejack_Phy(in_globalreg, in_phyid);
    }

    static int DissectorMousejack(CHAINCALL_PARMS);
    static int CommonClassifierMousejack(CHAINCALL_PARMS);

    virtual void LoadPhyStorage(SharedTrackerElement in_storage,
            SharedTrackerElement in_device);


protected:
    std::shared_ptr<Packetchain> packetchain;
    std::shared_ptr<EntryTracker> entrytracker;
    std::shared_ptr<Devicetracker> devicetracker;

    int mousejack_device_entry_id;
    int dev_comp_common;
    int pack_comp_common, pack_comp_linkframe;

    int dlt;

    std::shared_ptr<TrackerElementString> mj_manuf_amazon;
    std::shared_ptr<TrackerElementString> mj_manuf_logitech;
    std::shared_ptr<TrackerElementString> mj_manuf_microsoft;
    std::shared_ptr<TrackerElementString> mj_manuf_nrf;

};

#endif

