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
#include "kis_net_microhttpd.h"
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

    zwave_tracked_device(const zwave_tracked_device *p) :
        tracker_component{p} {

        homeid = tracker_element_clone_adaptor(p->homeid);
        deviceid = tracker_element_clone_adaptor(p->deviceid);

        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("zwave_tracked_device");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
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

class Kis_Zwave_Phy : public kis_phy_handler, public kis_net_httpd_cppstream_handler {
public:
    virtual ~Kis_Zwave_Phy();

    Kis_Zwave_Phy(global_registry *in_globalreg) :
        kis_phy_handler(in_globalreg),
        kis_net_httpd_cppstream_handler() { 
            bind_httpd_server();
        };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(global_registry *in_globalreg, int in_phyid) {
		return new Kis_Zwave_Phy(in_globalreg, in_phyid);
	}

    Kis_Zwave_Phy(global_registry *in_globalreg, int in_phyid);

    // HTTPD API
    virtual bool httpd_verify_path(const char *path, const char *method);

    virtual void httpd_create_stream_response(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    virtual KIS_MHD_RETURN httpd_post_complete(kis_net_httpd_connection *concls);

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int zwave_device_id;

    int pack_comp_common;

    mac_addr id_to_mac(uint32_t in_homeid, uint8_t in_deviceid);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_record(Json::Value in_json);

    std::shared_ptr<tracker_element_string> zwave_manuf;

};

#endif

