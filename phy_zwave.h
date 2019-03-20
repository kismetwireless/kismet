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
#include "kismet_json.h"

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

    zwave_tracked_device(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("zwave_tracked_device");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    __Proxy(homeid, uint32_t, uint32_t, uint32_t, homeid);
    __Proxy(deviceid, uint8_t, uint8_t, uint8_t, deviceid);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("zwave.device.home_id", "Z-Wave network Home ID packed as U32", &homeid);
        RegisterField("zwave.device.device_id", "Z-Wave network device ID", &deviceid);
    }

    // 4-byte homeid
    std::shared_ptr<TrackerElementUInt32> homeid;
    // 1 byte device id
    std::shared_ptr<TrackerElementUInt8> deviceid;
};

class Kis_Zwave_Phy : public Kis_Phy_Handler, public Kis_Net_Httpd_CPPStream_Handler {
public:
    virtual ~Kis_Zwave_Phy();

    Kis_Zwave_Phy(GlobalRegistry *in_globalreg) :
        Kis_Phy_Handler(in_globalreg),
        Kis_Net_Httpd_CPPStream_Handler() { 
            Bind_Httpd_Server();
        };

	// Build a strong version of ourselves
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg, int in_phyid) {
		return new Kis_Zwave_Phy(in_globalreg, in_phyid);
	}

    Kis_Zwave_Phy(GlobalRegistry *in_globalreg, int in_phyid);

    // HTTPD API
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *concls);

protected:
    std::shared_ptr<Packetchain> packetchain;
    std::shared_ptr<EntryTracker> entrytracker;
    std::shared_ptr<Devicetracker> devicetracker;

    int zwave_device_id;

    int pack_comp_common;

    mac_addr id_to_mac(uint32_t in_homeid, uint8_t in_deviceid);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_record(Json::Value in_json);

    std::shared_ptr<TrackerElementString> zwave_manuf;

};

#endif

