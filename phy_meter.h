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

#ifndef __PHY_METER_H__
#define __PHY_METER_H__

#include "config.h"
#include "globalregistry.h"
#include "trackedelement.h"
#include "devicetracker_component.h"
#include "phyhandler.h"

/* Similar to the extreme aggregator, a consumption aggregator which ignores empty
 * slots while aggregating and otherwise selects the most extreme value when a 
 * slot overlaps.  This fits a lot of generic situations in RTLAMR sensors which
 * only report a few times a second (if that).
 */
class meter_empty_aggregator {
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
        return "meter_empty";
    }
};

// AMR meter device
class tracked_meter : public tracker_component {
public:
    tracked_meter() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_meter(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    tracked_meter(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_meter");
    }

    virtual std::shared_ptr<tracker_element> clone_type() override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(meter_id, uint64_t, uint64_t, uint64_t, meter_id);
    __Proxy(meter_type, std::string, std::string, std::string, meter_type);
    __Proxy(meter_type_code, uint16_t, uint16_t, uint16_t, meter_type_code);
    __Proxy(phy_tamper_flags, uint8_t, uint8_t, uint8_t, phy_tamper_flags);
    __Proxy(endpoint_tamper_flags, uint8_t, uint8_t, uint8_t, endpoint_tamper_flags);
    __Proxy(consumption, double, double, double, consumption);

    typedef kis_tracked_rrd<meter_empty_aggregator> rrdt;
    __ProxyTrackable(consumption_rrd, rrdt, consumption_rrd);

protected:
    virtual void register_fields() override {
        register_field("meter.device.meter_id", "Meter ID", &meter_id);

        register_field("meter.device.meter_type", "Meter type", &meter_type);
        register_field("meter.device.meter_type_code", "Meter type code", &meter_type_code);
        register_field("meter.device.phy_tamper_flags", "Physical tamper flags", &phy_tamper_flags);
        register_field("amr.device.endpoint_tamper_flags", "Endpoint tamper flags", &endpoint_tamper_flags);

        register_field("amr.device.consumption", "Consumption", &consumption);
        register_field("amr.device.consumption_rrd", "Consumption history RRD", &consumption_rrd);
    }

    std::shared_ptr<tracker_element_uint64> meter_id;

    std::shared_ptr<tracker_element_string> meter_type;
    std::shared_ptr<tracker_element_uint16> meter_type_code;

    std::shared_ptr<tracker_element_uint8> phy_tamper_flags;
    std::shared_ptr<tracker_element_uint8> endpoint_tamper_flags;

    std::shared_ptr<tracker_element_double> consumption;

    std::shared_ptr<kis_tracked_rrd<meter_empty_aggregator>> consumption_rrd;
};

class kis_meter_phy : public kis_phy_handler {
public:
    virtual ~kis_meter_phy();

    kis_meter_phy() :
        kis_phy_handler() { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
		return new kis_meter_phy(in_phyid);
	}

    kis_meter_phy(int in_phyid);

    static int PacketHandler(CHAINCALL_PARMS);

protected:
    // Convert a JSON record to a device key
    mac_addr json_to_mac(nlohmann::json in_json);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool rtlamr_json_to_phy(nlohmann::json in_json, std::shared_ptr<kis_packet> packet);

    bool is_amr_meter(nlohmann::json json);

    void add_amr_meter(nlohmann::json json, std::shared_ptr<kis_tracked_device_base> phyholder);

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int tracked_meter_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta, pack_comp_radiodata;

    std::shared_ptr<tracker_element_string> meter_manuf;

};

#endif

