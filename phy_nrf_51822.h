
#ifndef __PHY_NRF_51822_H__
#define __PHY_NRF_51822_H__

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
class nrf51822_tracked_device : public tracker_component {
public:
    nrf51822_tracked_device() : 
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    nrf51822_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    nrf51822_tracked_device(int in_id, 
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("nrf51822_tracked_device");
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

    }
};

class Kis_NRF51822_Phy : public kis_phy_handler {
public:
    Kis_NRF51822_Phy(global_registry *in_globalreg) :
        kis_phy_handler(in_globalreg) { }

    Kis_NRF51822_Phy(global_registry *in_globalreg, int in_phyid);

    virtual ~Kis_NRF51822_Phy();

    virtual kis_phy_handler *create_phy_handler(global_registry *in_globalreg, int in_phyid) {
        return new Kis_NRF51822_Phy(in_globalreg, in_phyid);
    }

    static int DissectorNRF51822(CHAINCALL_PARMS);
    static int CommonClassifierNRF51822(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device);


protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int nrf51822_device_entry_id;
    int dev_comp_common;
    int pack_comp_common, pack_comp_linkframe;

    int dlt;

//    std::shared_ptr<TrackerElementString> mj_manuf_amazon;
//    std::shared_ptr<TrackerElementString> mj_manuf_logitech;
//    std::shared_ptr<TrackerElementString> mj_manuf_microsoft;
    std::shared_ptr<tracker_element_string> mj_manuf_ti;

};

#endif

