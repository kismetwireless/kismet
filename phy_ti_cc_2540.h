
#ifndef __PHY_TI_CC2540_H__
#define __PHY_TI_CC2540_H__

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
class ticc2540_tracked_device : public tracker_component {
public:
    ticc2540_tracked_device() : 
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    ticc2540_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    ticc2540_tracked_device(int in_id, 
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("ticc2540_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual std::shared_ptr<tracker_element> clone_type(int id) noexcept {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(id);
        return r;
    }

protected:

    virtual void register_fields() override {

    }
};

class Kis_TICC2540_Phy : public kis_phy_handler {
public:
    Kis_TICC2540_Phy() :
        kis_phy_handler() { }

    Kis_TICC2540_Phy(int in_phyid);

    virtual ~Kis_TICC2540_Phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) {
        return new Kis_TICC2540_Phy(in_phyid);
    }

    static int DissectorTICC2540(CHAINCALL_PARMS);
    static int CommonClassifierTICC2540(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device);


protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int ticc2540_device_entry_id;
    int dev_comp_common;
    int pack_comp_common, pack_comp_linkframe;

    int dlt;

//    std::shared_ptr<TrackerElementString> mj_manuf_amazon;
//    std::shared_ptr<TrackerElementString> mj_manuf_logitech;
//    std::shared_ptr<TrackerElementString> mj_manuf_microsoft;
    std::shared_ptr<tracker_element_string> mj_manuf_ti;

};

#endif

