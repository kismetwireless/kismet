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
    static int64_t combine_vector(std::shared_ptr<tracker_element_vector_double> e) {
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

// AMR meter device
class rtlamr_tracked_meter : public tracker_component {
public:
    rtlamr_tracked_meter() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtlamr_tracked_meter(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtlamr_tracked_meter(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    rtlamr_tracked_meter(const rtlamr_tracked_meter *p) :
        tracker_component{p} {

        __ImportField(meter_id, p);
        __ImportField(meter_type, p);
        __ImportField(meter_type_code, p);
        __ImportField(phy_tamper_flags, p);
        __ImportField(endpoint_tamper_flags, p);
        __ImportField(consumption, p);
        __ImportField(consumption_rrd, p);

        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("rtlamr_tracked_meter");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
    }

    __Proxy(meter_id, uint64_t, uint64_t, uint64_t, meter_id);
    __Proxy(meter_type, std::string, std::string, std::string, meter_type);
    __Proxy(meter_type_code, uint16_t, uint16_t, uint16_t, meter_type_code);
    __Proxy(phy_tamper_flags, uint8_t, uint8_t, uint8_t, phy_tamper_flags);
    __Proxy(endpoint_tamper_flags, uint8_t, uint8_t, uint8_t, endpoint_tamper_flags);
    __Proxy(consumption, double, double, double, consumption);

    typedef kis_tracked_rrd<rtlamr_empty_aggregator> rrdt;
    __ProxyTrackable(consumption_rrd, rrdt, consumption_rrd);

protected:
    virtual void register_fields() override {
        register_field("rtlamr.device.meter_id", "Meter ID", &meter_id);

        register_field("rtlamr.device.meter_type", "Meter type", &meter_type);
        register_field("rtlamr.device.meter_type_code", "Meter type code", &meter_type_code);
        register_field("rtlamr.device.phy_tamper_flags", "Physical tamper flags", &phy_tamper_flags);
        register_field("rtlamr.device.endpoint_tamper_flags", "Endpoint tamper flags", &endpoint_tamper_flags);

        register_field("rtlamr.device.consumption", "Consumption", &consumption);
        register_field("rtlamr.device.consumption_rrd", "Consumption history RRD", &consumption_rrd);
    }

    std::shared_ptr<tracker_element_uint64> meter_id;

    std::shared_ptr<tracker_element_string> meter_type;
    std::shared_ptr<tracker_element_uint16> meter_type_code;

    std::shared_ptr<tracker_element_uint8> phy_tamper_flags;
    std::shared_ptr<tracker_element_uint8> endpoint_tamper_flags;

    std::shared_ptr<tracker_element_double> consumption;

    std::shared_ptr<kis_tracked_rrd<rtlamr_empty_aggregator>> consumption_rrd;
};

class kis_rtlamr_phy : public kis_phy_handler {
public:
    virtual ~kis_rtlamr_phy();

    kis_rtlamr_phy(global_registry *in_globalreg) :
        kis_phy_handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(global_registry *in_globalreg, int in_phyid) override {
		return new kis_rtlamr_phy(in_globalreg, in_phyid);
	}

    kis_rtlamr_phy(global_registry *in_globalreg, int in_phyid);

    static int PacketHandler(CHAINCALL_PARMS);

protected:
    // Convert a JSON record to a RTL-based device key
    mac_addr json_to_mac(Json::Value in_json);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_rtl(Json::Value in_json, kis_packet *packet);

    bool is_amr_meter(Json::Value json);

    void add_amr_meter(Json::Value json, std::shared_ptr<kis_tracked_device_base> rtlholder);

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int rtlamr_meter_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta, pack_comp_radiodata;

    std::shared_ptr<tracker_element_string> rtl_manuf;

};

#endif

