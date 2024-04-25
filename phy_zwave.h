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

#ifndef __PHY_ZWAVE_H__
#define __PHY_ZWAVE_H__

#include "config.h"
#include "globalregistry.h"
#include "trackedelement.h"
#include "devicetracker_component.h"
#include "phyhandler.h"

/* phy-zwave
 *
 * A very basic phy handler which creates a REST endpoint for posting JSON-encoded
 * data from a killerzee+rfcat
 *
 * This will need to be improved to wrap the supporting code.
 *
 * This will need to be improved to do more than detect a homeid and device.
 */

class zwave_tracked_device : public tracker_component {
public:
    zwave_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    zwave_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    zwave_tracked_device(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("zwave_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(homeid, uint32_t, uint32_t, uint32_t, homeid);
    __Proxy(deviceid, uint8_t, uint8_t, uint8_t, deviceid);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("zwave.device.home_id", "Z-Wave network Home ID packed as U32", &homeid);
        register_field("zwave.device.device_id", "Z-Wave network device ID", &deviceid);
    }

    // 4-byte homeid
    std::shared_ptr<tracker_element_uint32> homeid;
    // 1 byte device id
    std::shared_ptr<tracker_element_uint8> deviceid;
};

class Kis_Zwave_Phy : public kis_phy_handler {
public:
    virtual ~Kis_Zwave_Phy();

    Kis_Zwave_Phy() :
        kis_phy_handler() { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(int in_phyid) {
		return new Kis_Zwave_Phy(in_phyid);
	}

    Kis_Zwave_Phy(int in_phyid);

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int zwave_device_id;

    int pack_comp_common;

    mac_addr id_to_mac(uint32_t in_homeid, uint8_t in_deviceid);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_record(nlohmann::json in_json);

    std::shared_ptr<tracker_element_string> zwave_manuf;

};

#endif

