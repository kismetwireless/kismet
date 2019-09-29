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

#ifndef __PHY_RTLADSB_H__
#define __PHY_RTLADSB_H__

#include "config.h"
#include "globalregistry.h"
#include "kis_net_microhttpd.h"
#include "trackedelement.h"
#include "devicetracker_component.h"
#include "phyhandler.h"
#include "kismet_json.h"

/* Similar to the extreme aggregator, a consumption aggregator which ignores empty
 * slots while aggregating and otherwise selects the most extreme value when a 
 * slot overlaps.  This fits a lot of generic situations in RTLADSB sensors which
 * only report a few times a second (if that).
 */
class rtladsb_empty_aggregator {
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
        return "rtladsb_empty";
    }
};


// Base rtl device record
class rtladsb_tracked_common : public tracker_component {
public:
    rtladsb_tracked_common() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtladsb_tracked_common(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtladsb_tracked_common(int in_id, 
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("rtladsb_tracked_common");
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

    __Proxy(model, std::string, std::string, std::string, model);
    __Proxy(rtlid, std::string, std::string, std::string, rtlid);
    __Proxy(rtlchannel, std::string, std::string, std::string, rtlchannel);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("rtladsb.device.model", "Sensor model", &model);
        register_field("rtladsb.device.id", "Sensor ID", &rtlid);
        register_field("rtladsb.device.rtlchannel", "Sensor sub-channel", &rtlchannel);
    }

    std::shared_ptr<tracker_element_string> model;

    // Device id, could be from the "id" or the "device" record
    std::shared_ptr<tracker_element_string> rtlid;

    // RTL subchannel, if one is available (many adsb messages report one)
    std::shared_ptr<tracker_element_string> rtlchannel;

    // Battery as a string
    //std::shared_ptr<tracker_element_string> battery;
};

// Thermometer type rtl data, derived from the rtl device.  This adds new
// fields for adsb but uses the same base IDs
class rtladsb_tracked_adsb : public tracker_component {
public:
    rtladsb_tracked_adsb() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtladsb_tracked_adsb(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtladsb_tracked_adsb(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("rtladsb_tracked_adsb");
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

    __Proxy(icao, std::string, std::string, std::string, icao);
    __Proxy(regid, std::string, std::string, std::string, regid);
    __Proxy(mdl, std::string, std::string, std::string, mdl);
    __Proxy(atype, std::string, std::string, std::string, atype);
    __Proxy(aoperator, std::string, std::string, std::string, aoperator);
    __Proxy(callsign, std::string, std::string, std::string, callsign);
    __Proxy(altitude, double, double, double, altitude);
    __Proxy(speed, double, double, double, speed);
    __Proxy(heading, double, double, double, heading);
    __Proxy(gsas, std::string, std::string, std::string, gsas);

    __Proxy(odd_raw_lat, double, double, double, odd_raw_lat);
    __Proxy(odd_raw_lon, double, double, double, odd_raw_lon);
    __Proxy(odd_ts, uint64_t, time_t, time_t, odd_ts);
    __Proxy(even_raw_lat, double, double, double, even_raw_lat);
    __Proxy(even_raw_lon, double, double, double, even_raw_lon);
    __Proxy(even_ts, uint64_t, time_t, time_t, even_ts);

    __Proxy(latitude, double, double, double, latitude);
    __Proxy(longitude, double, double, double, longitude);


    //typedef kis_tracked_rrd<rtladsb_empty_aggregator> rrdt;
    //__ProxyTrackable(consumption_rrd, rrdt, consumption_rrd);

protected:
    virtual void register_fields() override {
        register_field("rtladsb.device.icao", "ICAO", &icao);
        register_field("rtladsb.device.regid", "REGID", &regid);
        register_field("rtladsb.device.mdl", "MDL", &mdl);
        register_field("rtladsb.device.atype", "Type", &atype);
        register_field("rtladsb.device.aoperator", "Operator", &aoperator);
        register_field("rtladsb.device.callsign", "Callsign", &callsign);
        register_field("rtladsb.device.altitude", "Altitude", &altitude);
        register_field("rtladsb.device.speed", "Speed", &speed);
        register_field("rtladsb.device.heading", "Heading", &heading);
        register_field("rtladsb.device.gsas", "GSAS", &gsas);

        register_field("rtladsb.device.odd_raw_lat", "Odd-packet raw latitude", &odd_raw_lat);
        register_field("rtladsb.device.odd_raw_lon", "Odd-packet raw longitude", &odd_raw_lon);
        register_field("rtladsb.device.odd_ts", "Timestamp of last odd-packet", &odd_ts);
        register_field("rtladsb.device.even_raw_lat", "even-packet raw latitude", &even_raw_lat);
        register_field("rtladsb.device.even_raw_lon", "even-packet raw longitude", &even_raw_lon);
        register_field("rtladsb.device.even_ts", "Timestamp of last even-packet", &even_ts);

        register_field("rtladsb.device.latitude", "Calculated latitude", &latitude);
        register_field("rtladsb.device.longitude", "Calculated longitude", &longitude);
    }

    // Basic temp in C, from multiple sensors; we might have to convert to C
    // for some types of sensors
    std::shared_ptr<tracker_element_string> icao;
    std::shared_ptr<tracker_element_string> regid;
    std::shared_ptr<tracker_element_string> mdl;
    std::shared_ptr<tracker_element_string> atype;
    std::shared_ptr<tracker_element_string> aoperator;
    std::shared_ptr<tracker_element_string> callsign;
    std::shared_ptr<tracker_element_double> altitude; 
    std::shared_ptr<tracker_element_double> speed;
    std::shared_ptr<tracker_element_double> heading;
    std::shared_ptr<tracker_element_string> gsas;

    // Aggregate location records from multiple packets to derive the actual
    // location.  These are raw adsb locations.
    std::shared_ptr<tracker_element_double> odd_raw_lat;
    std::shared_ptr<tracker_element_double> odd_raw_lon;
    std::shared_ptr<tracker_element_uint64> odd_ts;
    std::shared_ptr<tracker_element_double> even_raw_lat;
    std::shared_ptr<tracker_element_double> even_raw_lon;
    std::shared_ptr<tracker_element_uint64> even_ts;

    // Calculated lat/lon
    std::shared_ptr<tracker_element_double> latitude;
    std::shared_ptr<tracker_element_double> longitude;
};

class kis_rtladsb_phy : public kis_phy_handler {
public:
    virtual ~kis_rtladsb_phy();

    kis_rtladsb_phy(global_registry *in_globalreg) :
        kis_phy_handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(global_registry *in_globalreg, int in_phyid) override {
		return new kis_rtladsb_phy(in_globalreg, in_phyid);
	}

    kis_rtladsb_phy(global_registry *in_globalreg, int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

protected:
    // Convert a JSON record to a RTL-based device key
    mac_addr json_to_mac(Json::Value in_json);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_rtl(Json::Value in_json, kis_packet *packet);

    bool is_adsb(Json::Value json);

    std::shared_ptr<rtladsb_tracked_adsb> add_adsb(Json::Value json, std::shared_ptr<tracker_element_map> rtlholder);

    double f_to_c(double f);

    int cpr_mod(int a, int b);
    int cpr_nl(double lat);
    int cpr_n(double lat, int odd);
    double cpr_dlon(double lat, int odd);
    void decode_cpr(std::shared_ptr<rtladsb_tracked_adsb> adsb);

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int rtladsb_holder_id, rtladsb_common_id, rtladsb_adsb_id;
    //std::string rtladsb_icao_id;
    //FIX HERE, rtladsb_powermeter_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta;

    std::shared_ptr<tracker_element_string> rtl_manuf;

};

#endif

