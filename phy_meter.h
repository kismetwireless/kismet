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

/* A monotonicly increasing aggregator which always takes the highest value */
class meter_monotonic_aggregator {
public:
    // Select the most extreme value
    static int64_t combine_element(const int64_t a, const int64_t b) {
        if (a == default_val())
            return b;

        if (b == default_val())
            return a;

        if (a < b)
            return b;

        return a;
    }

    // Simple average
    static int64_t combine_vector(std::shared_ptr<tracker_element_vector_double> e) {
        int64_t max = default_val();

        for (auto i : *e) {
            if (i == default_val())
                continue; 

            if (i < max) 
                continue; 

            max = i;

        }

        return max;
    }

    static int64_t default_val() {
        return (int64_t) -999999;
    }

    static std::string name() {
        return "meter_monotonic";
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

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
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

    typedef kis_tracked_rrd<meter_monotonic_aggregator> rrdt;
    __ProxyTrackable(consumption_rrd, rrdt, consumption_rrd);

	__ProxyTrackable(model_vec, tracker_element_string_map, model_vec);

protected:
    virtual void register_fields() override {
        register_field("meter.device.meter_id", "Meter ID", &meter_id);

        register_field("meter.device.meter_type", "Meter type", &meter_type);
        register_field("meter.device.meter_type_code", "Meter type code", &meter_type_code);
        register_field("meter.device.phy_tamper_flags", "Physical tamper flags", &phy_tamper_flags);
        register_field("meter.device.endpoint_tamper_flags", "Endpoint tamper flags", &endpoint_tamper_flags);

        register_field("meter.device.consumption", "Consumption", &consumption);
        register_field("meter.device.consumption_rrd", "Consumption history RRD", &consumption_rrd);

        register_field("meter.device.model_vec", "List of meter models", &model_vec);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e); 

        model_vec->set_as_key_vector(true);
    }

    std::shared_ptr<tracker_element_uint64> meter_id;

    std::shared_ptr<tracker_element_string> meter_type;
    std::shared_ptr<tracker_element_uint16> meter_type_code;

	std::shared_ptr<tracker_element_string_map> model_vec;

    std::shared_ptr<tracker_element_uint8> phy_tamper_flags;
    std::shared_ptr<tracker_element_uint8> endpoint_tamper_flags;

    std::shared_ptr<tracker_element_double> consumption;

    std::shared_ptr<kis_tracked_rrd<meter_monotonic_aggregator>> consumption_rrd;
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

	// Static, public function for other phys (like phy_sensor) to be able to 
	// ignore devices that meter wants to classify
	static bool is_meter(const nlohmann::json& json);

protected:
    // Convert a JSON record to a device key
    mac_addr json_to_mac(nlohmann::json in_json);
    mac_addr synth_mac(std::string model, uint64_t id);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool rtlamr_json_to_phy(nlohmann::json in_json, std::shared_ptr<kis_packet> packet);
    bool rtl433_json_to_phy(nlohmann::json in_json, std::shared_ptr<kis_packet> packet);

    bool is_amr_meter(nlohmann::json json);

    void add_amr_meter(nlohmann::json json, std::shared_ptr<kis_tracked_device_base> phyholder);

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int tracked_meter_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta, pack_comp_radiodata, pack_comp_device;

    std::shared_ptr<tracker_element_string> meter_manuf;

};

#endif

