
#ifndef __PHY_RZ_KILLERBEE_H__
#define __PHY_RZ_KILLERBEE_H__

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
class rzkillerbee_tracked_device : public tracker_component {
public:
    rzkillerbee_tracked_device() : 
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rzkillerbee_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    rzkillerbee_tracked_device(int in_id, 
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("rzkillerbee_tracked_device");
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

class Kis_RZ_KILLERBEE_Phy : public kis_phy_handler {
public:
    Kis_RZ_KILLERBEE_Phy(global_registry *in_globalreg) :
        kis_phy_handler(in_globalreg) { }

    Kis_RZ_KILLERBEE_Phy(global_registry *in_globalreg, int in_phyid);

    virtual ~Kis_RZ_KILLERBEE_Phy();

    virtual kis_phy_handler *create_phy_handler(global_registry *in_globalreg, int in_phyid) {
        return new Kis_RZ_KILLERBEE_Phy(in_globalreg, in_phyid);
    }

    static int DissectorRZ_KILLERBEE(CHAINCALL_PARMS);
    static int CommonClassifierRZ_KILLERBEE(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device);


protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int rzkillerbee_device_entry_id;
    int dev_comp_common;
    int pack_comp_common, pack_comp_linkframe;

    int dlt;

    std::shared_ptr<tracker_element_string> mj_manuf_rzkb;

};

#endif

