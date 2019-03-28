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

#ifndef __PHY_RTL433_H__
#define __PHY_RTL433_H__

#include "config.h"
#include "globalregistry.h"
#include "kis_net_microhttpd.h"
#include "trackedelement.h"
#include "devicetracker_component.h"
#include "phyhandler.h"
#include "kismet_json.h"

/* Similar to the extreme aggregator, a temperature aggregator which ignores empty
 * slots while aggregating and otherwise selects the most extreme value when a 
 * slot overlaps.  This fits a lot of generic situations in RTL433 sensors which
 * only report a few times a second (if that).
 */
class rtl433_empty_aggregator {
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
        return "rtl433_empty";
    }
};


// Base rtl device record
class rtl433_tracked_common : public tracker_component {
public:
    rtl433_tracked_common() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtl433_tracked_common(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtl433_tracked_common(int in_id, 
            std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtl433_tracked_common");
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
    __Proxy(battery, std::string, std::string, std::string, battery);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("rtl433.device.model", "Sensor model", &model);
        RegisterField("rtl433.device.id", "Sensor ID", &rtlid);
        RegisterField("rtl433.device.rtlchannel", "Sensor sub-channel", &rtlchannel);
        RegisterField("rtl433.device.battery", "Sensor battery level", &battery);
    }

    std::shared_ptr<TrackerElementString> model;

    // Device id, could be from the "id" or the "device" record
    std::shared_ptr<TrackerElementString> rtlid;

    // RTL subchannel, if one is available (many thermometers report one)
    std::shared_ptr<TrackerElementString> rtlchannel;

    // Battery as a string
    std::shared_ptr<TrackerElementString> battery;
};

// Thermometer type rtl data, derived from the rtl device.  This adds new
// fields for thermometers but uses the same base IDs
class rtl433_tracked_thermometer : public tracker_component {
public:
    rtl433_tracked_thermometer() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtl433_tracked_thermometer(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtl433_tracked_thermometer(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtl433_tracked_thermometer");
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

    __Proxy(temperature, double, double, double, temperature);
    __Proxy(humidity, int32_t, int32_t, int32_t, humidity);

    typedef kis_tracked_rrd<rtl433_empty_aggregator> rrdt;
    __ProxyTrackable(temperature_rrd, rrdt, temperature_rrd);
    __ProxyTrackable(humidity_rrd, rrdt, humidity_rrd);

protected:
    virtual void register_fields() override {
        RegisterField("rtl433.device.temperature", "Temperature in degrees Celsius", &temperature);
        RegisterField("rtl433.device.temperature_rrd", "Temperature history RRD", &temperature_rrd);
        RegisterField("rtl433.device.humidity", "Humidity", &humidity);
        RegisterField("rtl433.device.humidity_rrd", "Humidity history RRD", &humidity_rrd);
    }

    // Basic temp in C, from multiple sensors; we might have to convert to C
    // for some types of sensors
    std::shared_ptr<TrackerElementDouble> temperature;
    std::shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator>> temperature_rrd;

    // Basic humidity in percentage, from multiple sensors
    std::shared_ptr<TrackerElementInt32> humidity;
    std::shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator>> humidity_rrd;
};

// Weather station type data
class rtl433_tracked_weatherstation : public tracker_component {
public:
    rtl433_tracked_weatherstation() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtl433_tracked_weatherstation(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtl433_tracked_weatherstation(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtl433_tracked_weatherstation");
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

    __Proxy(wind_dir, int32_t, int32_t, int32_t, wind_dir);
    __Proxy(wind_speed, int32_t, int32_t, int32_t, wind_speed);
    __Proxy(wind_gust, int32_t, int32_t, int32_t, wind_gust);
    __Proxy(rain, int32_t, int32_t, int32_t, rain);
    __Proxy(uv_index, int32_t, int32_t, int32_t, uv_index);
    __Proxy(lux, int32_t, int32_t, int32_t, lux);

    typedef kis_tracked_rrd<rtl433_empty_aggregator> rrdt;
    __ProxyTrackable(wind_dir_rrd, rrdt, wind_dir_rrd);
    __ProxyTrackable(wind_speed_rrd, rrdt, wind_speed_rrd);
    __ProxyTrackable(wind_gust_rrd, rrdt, wind_gust_rrd);
    __ProxyTrackable(rain_rrd, rrdt, rain_rrd);
    __ProxyTrackable(uv_index_rrd, rrdt, uv_index_rrd);
    __ProxyTrackable(lux_rrd, rrdt, lux_rrd);

protected:
    virtual void register_fields() override {
        RegisterField("rtl433.device.wind_dir", "Wind direction in degrees", &wind_dir);
        RegisterField("rtl433.device.wind_dir_rrd", "Wind direction RRD", &wind_dir_rrd);

        RegisterField("rtl433.device.weatherstation.wind_speed", "Wind speed in Kph", &wind_speed);
        RegisterField("rtl433.device.wind_speed_rrd", "Wind speed RRD", &wind_speed_rrd);

        RegisterField("rtl433.device.wind_gust", "Wind gust in Kph", &wind_gust);
        RegisterField("rtl433.device.wind_gust_rrd", "Wind gust RRD", &wind_gust_rrd);

        RegisterField("rtl433.device.rain", "Measured rain", &rain);
        RegisterField("rtl433.device.rain_rrd", "Rain RRD", &rain_rrd);

        RegisterField("rtl433.device.uv_index", "UV index", &uv_index);
        RegisterField("rtl433.device.uv_index_rrd", "UV Index RRD", &uv_index_rrd);

        RegisterField("rtl433.device.lux", "Lux", &lux);
        RegisterField("rtl433.device.lux_rrd", "Lux RRD", &lux_rrd);
    }

    // Wind direction in degrees
    std::shared_ptr<TrackerElementInt32> wind_dir;
    std::shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator>> wind_dir_rrd;

    // Wind speed in kph (might have to convert for some sensors)
    std::shared_ptr<TrackerElementInt32> wind_speed;
    std::shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator>> wind_speed_rrd;

    std::shared_ptr<TrackerElementInt32> wind_gust;
    std::shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator>> wind_gust_rrd;

    // Rain (in whatever the sensor reports it in)
    std::shared_ptr<TrackerElementInt32> rain;
    std::shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator>> rain_rrd;

    // UV
    std::shared_ptr<TrackerElementInt32> uv_index;
    std::shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator>> uv_index_rrd;

    // Lux
    std::shared_ptr<TrackerElementInt32> lux;
    std::shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator>> lux_rrd;
};

class rtl433_tracked_lightningsensor : public tracker_component {
public:
    rtl433_tracked_lightningsensor() :
        tracker_component() {
            register_fields();
            reserve_fields(nullptr);
        }

    rtl433_tracked_lightningsensor(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(nullptr);
        }

    rtl433_tracked_lightningsensor(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtl433_tracked_lightningsensor");
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

    __Proxy(strike_count, uint64_t, uint64_t, uint64_t, strike_count);
    __Proxy(storm_distance, uint64_t, uint64_t, uint64_t, storm_distance);
    __Proxy(storm_active, uint8_t, bool, bool, storm_active);
    __Proxy(lightning_rfi, uint64_t, uint64_t, uint64_t, lightning_rfi);

protected:
    // {"time" : "2019-02-24 22:12:13", "model" : "Acurite Lightning 6045M", "id" : 15580, "channel" : "B", "temperature_F" : 38.300, "humidity" : 53, "strike_count" : 1, "storm_dist" : 8, "active" : 1, "rfi" : 0, "ussb1" : 0, "battery" : "OK", "exception" : 0, "raw_msg" : "bcdc6f354edb81886e"}
    
    virtual void register_fields() override {
        RegisterField("rtl433.device.lightning_strike_count", "Strike count", &strike_count);
        RegisterField("rtl433.device.lightning_storm_distance", "Storm distance (no unit)", &storm_distance);
        RegisterField("rtl433.device.lightning_storm_active", "Storm active", &storm_active);
        RegisterField("rtl433.device.lightning_rfi", "Lightning radio frequency interference", &lightning_rfi);
    }

    std::shared_ptr<TrackerElementUInt64> strike_count;
    std::shared_ptr<TrackerElementUInt64> storm_distance;
    std::shared_ptr<TrackerElementUInt8> storm_active;
    std::shared_ptr<TrackerElementUInt64> lightning_rfi;
};

// TPMS tire pressure sensors
class rtl433_tracked_tpms : public tracker_component {
public:
    rtl433_tracked_tpms() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtl433_tracked_tpms(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtl433_tracked_tpms(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtl433_tracked_tpms");
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

    __Proxy(pressure_bar, double, double, double, pressure_bar);
    __Proxy(pressure_kpa, double, double, double, pressure_kpa);
    __Proxy(flags, std::string, std::string, std::string, flags);
    __Proxy(state, std::string, std::string, std::string, state);
    __Proxy(checksum, std::string, std::string, std::string, checksum);
    __Proxy(code, std::string, std::string, std::string, code);

protected:
    virtual void register_fields() override {
        RegisterField("rtl433.device.tpms.pressure_bar", "Pressure, in bars", &pressure_bar);
        RegisterField("rtl433.device.tpms.pressure_kpa", "Pressure, in kPa", &pressure_kpa);
        RegisterField("rtl433.device.tpms.flags", "TPMS flags", &flags);
        RegisterField("rtl433.device.tpms.state", "TPMS state", &state);
        RegisterField("rtl433.device.tpms.checksum", "TPMS checksum", &checksum);
        RegisterField("rtl433.device.tpms.code", "TPMS code", &code);
    }

    std::shared_ptr<TrackerElementDouble> pressure_bar;
    std::shared_ptr<TrackerElementDouble> pressure_kpa;
    std::shared_ptr<TrackerElementString> flags;
    std::shared_ptr<TrackerElementString> state;
    std::shared_ptr<TrackerElementString> checksum;
    std::shared_ptr<TrackerElementString> code;
};

// Switch panels
class rtl433_tracked_switch : public tracker_component {
public:
    rtl433_tracked_switch() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtl433_tracked_switch(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtl433_tracked_switch(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtl433_tracked_switch");
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

    __ProxyTrackable(switch_vec, TrackerElementVector, switch_vec);

    SharedTrackerElement make_switch_entry(int x) {
        auto e = std::make_shared<TrackerElementInt32>(switch_vec_entry_id, x);
        return e;
    }

protected:
    virtual void register_fields() override {
        RegisterField("rtl433.device.switch_vec", "Switch settings", &switch_vec);
        switch_vec_entry_id = 
            RegisterField("rtl433.device.switch.position", 
                    TrackerElementFactory<TrackerElementInt32>(),
                    "Switch position");
    }

    std::shared_ptr<TrackerElementVector> switch_vec;
    int switch_vec_entry_id;

};

class Kis_RTL433_Phy : public Kis_Phy_Handler {
public:
    virtual ~Kis_RTL433_Phy();

    Kis_RTL433_Phy(GlobalRegistry *in_globalreg) :
        Kis_Phy_Handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg, int in_phyid) override {
		return new Kis_RTL433_Phy(in_globalreg, in_phyid);
	}

    Kis_RTL433_Phy(GlobalRegistry *in_globalreg, int in_phyid);

    static int PacketHandler(CHAINCALL_PARMS);

protected:
    // Convert a JSON record to a RTL-based device key
    mac_addr json_to_mac(Json::Value in_json);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_rtl(Json::Value in_json, kis_packet *packet);

    bool is_weather_station(Json::Value json);
    bool is_thermometer(Json::Value json);
    bool is_tpms(Json::Value json);
    bool is_switch(Json::Value json);
    bool is_lightning(Json::Value json);

    void add_weather_station(Json::Value json, std::shared_ptr<TrackerElementMap> rtlholder);
    void add_thermometer(Json::Value json, std::shared_ptr<TrackerElementMap> rtlholder);
    void add_tpms(Json::Value json, std::shared_ptr<TrackerElementMap> rtlholder);
    void add_switch(Json::Value json, std::shared_ptr<TrackerElementMap> rtlholder);
    void add_lightning(Json::Value json, std::shared_ptr<TrackerElementMap> rtlholder);

    double f_to_c(double f);


protected:
    std::shared_ptr<Packetchain> packetchain;
    std::shared_ptr<EntryTracker> entrytracker;
    std::shared_ptr<Devicetracker> devicetracker;

    int rtl433_holder_id, rtl433_common_id, rtl433_thermometer_id, 
        rtl433_weatherstation_id, rtl433_tpms_id, rtl433_switch_id,
        rtl433_lightning_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta;

    std::shared_ptr<TrackerElementString> rtl_manuf;

};

#endif

