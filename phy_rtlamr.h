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

#ifndef __PHY_RTLAMR_H__
#define __PHY_RTLAMR_H__

#include "config.h"
#include "globalregistry.h"
#include "kis_net_microhttpd.h"
#include "trackedelement.h"
#include "devicetracker_component.h"
#include "phyhandler.h"
#include "kismet_json.h"

/* Similar to the extreme aggregator, a consumption aggregator which ignores empty
 * slots while aggregating and otherwise selects the most extreme value when a 
 * slot overlaps.  This fits a lot of generic situations in RTLAMR sensors which
 * only report a few times a second (if that).
 */
class rtlamr_empty_aggregator {
public:
    // Select the most extreme value
    static int64_t combine_element(const int64_t a, const int64_t b) {
        if (a == default_val())
            return b;

        if (b == default_val())
            return a;

        if (a < 0 && b < 0) {
            if (a < b)
                return a;

            return b;
        } else if (a > 0 && b > 0) {
            if (a > b)
                return a;

            return b;
        } else if (a == 0) {
            return b;
        } else if (b == 0) {
            return a;
        } else if (a < b) {
            return a;
        }

        return b;
    }

    // Simple average
    static int64_t combine_vector(std::shared_ptr<TrackerElementVectorDouble> e) {
        int64_t avg = 0;
        int64_t avg_c = 0;

        for (auto i : *e) {
            if (i != default_val()) {
                avg += i;
                avg_c++;
            }
        }

        if (avg_c == 0)
            return default_val();

        return avg / avg_c;
    }

    // Default 'empty' value, no legit signal would be 0
    static int64_t default_val() {
        return (int64_t) -9999;
    }

    static std::string name() {
        return "rtlamr_empty";
    }
};


// Base rtl device record
class rtlamr_tracked_common : public tracker_component {
public:
    rtlamr_tracked_common() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtlamr_tracked_common(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtlamr_tracked_common(int in_id, 
            std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtlamr_tracked_common");
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

    __Proxy(model, std::string, std::string, std::string, model);
    __Proxy(rtlid, std::string, std::string, std::string, rtlid);
    __Proxy(rtlchannel, std::string, std::string, std::string, rtlchannel);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("rtlamr.device.model", "Sensor model", &model);
        RegisterField("rtlamr.device.id", "Sensor ID", &rtlid);
        RegisterField("rtlamr.device.rtlchannel", "Sensor sub-channel", &rtlchannel);
    }

    std::shared_ptr<TrackerElementString> model;

    // Device id, could be from the "id" or the "device" record
    std::shared_ptr<TrackerElementString> rtlid;

    // RTL subchannel, if one is available (many powermeters report one)
    std::shared_ptr<TrackerElementString> rtlchannel;

    // Battery as a string
    //std::shared_ptr<TrackerElementString> battery;
};

// Thermometer type rtl data, derived from the rtl device.  This adds new
// fields for powermeters but uses the same base IDs
class rtlamr_tracked_powermeter : public tracker_component {
public:
    rtlamr_tracked_powermeter() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtlamr_tracked_powermeter(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtlamr_tracked_powermeter(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtlamr_tracked_powermeter");
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

    __Proxy(consumption, double, double, double, consumption);

    typedef kis_tracked_rrd<rtlamr_empty_aggregator> rrdt;
    __ProxyTrackable(consumption_rrd, rrdt, consumption_rrd);
    //here replace consumption

protected:
    virtual void register_fields() override {
        RegisterField("rtlamr.device.consumption", "Consumption", &consumption);
        RegisterField("rtlamr.device.consumption_rrd", "Consumption history RRD", &consumption_rrd);
    }

    // Basic temp in C, from multiple sensors; we might have to convert to C
    // for some types of sensors
    std::shared_ptr<TrackerElementDouble> consumption;
    std::shared_ptr<kis_tracked_rrd<rtlamr_empty_aggregator>> consumption_rrd;

};

class Kis_RTLAMR_Phy : public Kis_Phy_Handler {
public:
    virtual ~Kis_RTLAMR_Phy();

    Kis_RTLAMR_Phy(GlobalRegistry *in_globalreg) :
        Kis_Phy_Handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg, int in_phyid) override {
		return new Kis_RTLAMR_Phy(in_globalreg, in_phyid);
	}

    Kis_RTLAMR_Phy(GlobalRegistry *in_globalreg, int in_phyid);

    static int PacketHandler(CHAINCALL_PARMS);

protected:
    // Convert a JSON record to a RTL-based device key
    mac_addr json_to_mac(Json::Value in_json);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_rtl(Json::Value in_json, kis_packet *packet);

    bool is_powermeter(Json::Value json);

    void add_powermeter(Json::Value json, std::shared_ptr<TrackerElementMap> rtlholder);

    double f_to_c(double f);


protected:
    std::shared_ptr<Packetchain> packetchain;
    std::shared_ptr<EntryTracker> entrytracker;
    std::shared_ptr<Devicetracker> devicetracker;

    int rtlamr_holder_id, rtlamr_common_id, rtlamr_powermeter_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta;

    std::shared_ptr<TrackerElementString> rtl_manuf;

};

#endif

