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

#ifndef __PHY_SENSOR_H__
#define __PHY_SENSOR_H__ 

#include "config.h"
#include "globalregistry.h"
#include "trackedelement.h"
#include "devicetracker_component.h"
#include "phyhandler.h"

/* Originally the rtl-433 phy, now abstracted to a common phy for sensors.
 * Predominately reads from the rtl-433 json, but is logically abstracted for 
 * future radio support */

/* Similar to the extreme aggregator, a temperature aggregator which ignores empty
 * slots while aggregating and otherwise selects the most extreme value when a 
 * slot overlaps.  This fits a lot of generic situations in sensors which
 * only report a few times a second (if that).
 */
class sensor_empty_aggregator {
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
        return "sensor_empty";
    }
};

// Base rtl device record
class sensor_tracked_common : public tracker_component {
public:
    sensor_tracked_common() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    sensor_tracked_common(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    sensor_tracked_common(int in_id, 
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("sensor_tracked_common");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(model, std::string, std::string, std::string, model);
    __Proxy(rtlid, std::string, std::string, std::string, rtlid);
    __Proxy(subchannel, std::string, std::string, std::string, subchannel);
    __Proxy(battery, std::string, std::string, std::string, battery);
    __Proxy(rssi, std::string, std::string, std::string, rssi);
    __Proxy(snr, std::string, std::string, std::string, snr);
    __Proxy(noise, std::string, std::string, std::string, noise);

    __Proxy(lastrecord, std::string, std::string, std::string, lastrecord);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("sensor.device.model", "Sensor model", &model);
        register_field("sensor.device.id", "Sensor ID", &rtlid);
        register_field("sensor.device.subchannel", "Sensor sub-channel", &subchannel);
        register_field("sensor.device.battery", "Sensor battery level", &battery);
        register_field("sensor.device.rssi", "Sensor rssi level", &rssi);
        register_field("sensor.device.snr", "Sensor snr level", &snr);
        register_field("sensor.device.noise", "Sensor noise level", &noise);
        register_field("sensor.device.last_record", "Last seen record", &lastrecord);
    }

    std::shared_ptr<tracker_element_string> model;

    // Device id, could be from the "id" or the "device" record
    std::shared_ptr<tracker_element_string> rtlid;

    // RTL subchannel, if one is available (many thermometers report one)
    std::shared_ptr<tracker_element_string> subchannel;

    std::shared_ptr<tracker_element_string> battery;
    std::shared_ptr<tracker_element_string> rssi;
    std::shared_ptr<tracker_element_string> snr;
    std::shared_ptr<tracker_element_string> noise;
    std::shared_ptr<tracker_element_string> lastrecord;
};

// Thermometer type rtl data, derived from the rtl device.  This adds new
// fields for thermometers but uses the same base IDs
class sensor_tracked_thermometer : public tracker_component {
public:
    sensor_tracked_thermometer() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    sensor_tracked_thermometer(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    sensor_tracked_thermometer(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("sensor_tracked_thermometer");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(temperature, double, double, double, temperature);

    typedef kis_tracked_rrd<sensor_empty_aggregator> rrdt;
    __ProxyTrackable(temperature_rrd, rrdt, temperature_rrd);

protected:
    virtual void register_fields() override {
        register_field("sensor.device.temperature", "Temperature (C)", &temperature);
        register_field("sensor.device.temperature_rrd", "Temperature history RRD", &temperature_rrd);
    }

    // Basic temp in C, from multiple sensors; we might have to convert to C
    // for some types of sensors
    std::shared_ptr<tracker_element_double> temperature;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> temperature_rrd;
};

// Weather station type data
class sensor_tracked_weatherstation : public tracker_component {
public:
    sensor_tracked_weatherstation() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    sensor_tracked_weatherstation(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    sensor_tracked_weatherstation(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("sensor_tracked_weatherstation");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(wind_dir, int32_t, int32_t, int32_t, wind_dir);
    __Proxy(wind_speed, double, double, double, wind_speed);
    __Proxy(wind_gust, double, double, double, wind_gust);
    __Proxy(rain, double, double, double, rain);
    __Proxy(rain_raw, double, double, double, rain_raw);
    __Proxy(uv_index, double, double, double, uv_index);
    __Proxy(lux, int32_t, int32_t, int32_t, lux);

    typedef kis_tracked_rrd<sensor_empty_aggregator> rrdt;
    __ProxyTrackable(wind_dir_rrd, rrdt, wind_dir_rrd);
    __ProxyTrackable(wind_speed_rrd, rrdt, wind_speed_rrd);
    __ProxyTrackable(wind_gust_rrd, rrdt, wind_gust_rrd);
    __ProxyTrackable(rain_rrd, rrdt, rain_rrd);
    __ProxyTrackable(uv_index_rrd, rrdt, uv_index_rrd);
    __ProxyTrackable(lux_rrd, rrdt, lux_rrd);

protected:
    virtual void register_fields() override {
        register_field("sensor.device.wind_dir", "Wind direction (degrees)", &wind_dir);
        register_field("sensor.device.wind_dir_rrd", "Wind direction RRD", &wind_dir_rrd);

        register_field("sensor.device.wind_speed", "Wind speed (KPH)", &wind_speed);
        register_field("sensor.device.wind_speed_rrd", "Wind speed RRD", &wind_speed_rrd);

        register_field("sensor.device.wind_gust", "Wind gust (KPH)", &wind_gust);
        register_field("sensor.device.wind_gust_rrd", "Wind gust RRD", &wind_gust_rrd);

        register_field("sensor.device.rain", "Measured rain", &rain);
        register_field("sensor.device.rain_raw", "Measured rain (raw)", &rain_raw);
        register_field("sensor.device.rain_rrd", "Rain RRD", &rain_rrd);

        register_field("sensor.device.uv_index", "UV index", &uv_index);
        register_field("sensor.device.uv_index_rrd", "UV Index RRD", &uv_index_rrd);

        register_field("sensor.device.lux", "Lux", &lux);
        register_field("sensor.device.lux_rrd", "Lux RRD", &lux_rrd);
    }

    // Wind direction in degrees
    std::shared_ptr<tracker_element_int32> wind_dir;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> wind_dir_rrd;

    // Wind speed in kph (might have to convert for some sensors)
    std::shared_ptr<tracker_element_double> wind_speed;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> wind_speed_rrd;

    std::shared_ptr<tracker_element_double> wind_gust;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> wind_gust_rrd;

    // Rain (in whatever the sensor reports it in)
    std::shared_ptr<tracker_element_double> rain;
    std::shared_ptr<tracker_element_double> rain_raw;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> rain_rrd;

    // UV
    std::shared_ptr<tracker_element_double> uv_index;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> uv_index_rrd;

    // Lux
    std::shared_ptr<tracker_element_int32> lux;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> lux_rrd;
};

class sensor_tracked_lightningsensor : public tracker_component {
public:
    sensor_tracked_lightningsensor() :
        tracker_component() {
            register_fields();
            reserve_fields(nullptr);
        }

    sensor_tracked_lightningsensor(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(nullptr);
        }

    sensor_tracked_lightningsensor(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("sensor_tracked_lightningsensor");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(strike_count, uint64_t, uint64_t, uint64_t, strike_count);

    typedef kis_tracked_rrd<sensor_empty_aggregator> rrdt;
    __ProxyTrackable(strike_count_rrd, rrdt, strike_count_rrd);

    __Proxy(storm_distance, uint64_t, uint64_t, uint64_t, storm_distance);
    __Proxy(storm_active, uint8_t, bool, bool, storm_active);
    __Proxy(lightning_rfi, uint64_t, uint64_t, uint64_t, lightning_rfi);

protected:
    // {"time" : "2019-02-24 22:12:13", "model" : "Acurite Lightning 6045M", "id" : 15580, "channel" : "B", "temperature_F" : 38.300, "humidity" : 53, "strike_count" : 1, "storm_dist" : 8, "active" : 1, "rfi" : 0, "ussb1" : 0, "battery" : "OK", "exception" : 0, "raw_msg" : "bcdc6f354edb81886e"}
    
    virtual void register_fields() override {
        register_field("sensor.device.lightning_strike_count", "Strike count", &strike_count);
        register_field("sensor.device.lightning_strike_count_rrd", "Strike count RRD", &strike_count_rrd);
        register_field("sensor.device.lightning_storm_distance", "Storm distance (no unit)", &storm_distance);
        register_field("sensor.device.lightning_storm_active", "Storm active", &storm_active);
        register_field("sensor.device.lightning_rfi", "Lightning radio frequency interference", &lightning_rfi);
    }

    std::shared_ptr<tracker_element_uint64> strike_count;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> strike_count_rrd;

    std::shared_ptr<tracker_element_uint64> storm_distance;
    std::shared_ptr<tracker_element_uint8> storm_active;
    std::shared_ptr<tracker_element_uint64> lightning_rfi;
};

// TPMS tire pressure sensors
class sensor_tracked_tpms : public tracker_component {
public:
    sensor_tracked_tpms() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    sensor_tracked_tpms(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    sensor_tracked_tpms(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("sensor_tracked_tpms");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(freq, double, double, double, freq);
    __Proxy(temperature, double, double, double, temperature);
    __Proxy(pressure_bar, double, double, double, pressure_bar);
    __Proxy(pressure_psi, double, double, double, pressure_psi)
    __Proxy(pressure_kpa, double, double, double, pressure_kpa);
    __Proxy(flags, std::string, std::string, std::string, flags);
    __Proxy(state, std::string, std::string, std::string, state);
    __Proxy(checksum, std::string, std::string, std::string, checksum);
    __Proxy(code, std::string, std::string, std::string, code);

protected:
    virtual void register_fields() override {
        register_field("sensor.device.tpms.freq", "Freq (as detected)", &freq);
        register_field("sensor.device.tpms.temperature", "Temperature, in C", &temperature);
        register_field("sensor.device.tpms.pressure_bar", "Pressure, in bars", &pressure_bar);
        register_field("sensor.device.tpms.pressure_psi", "Pressure, in PSI", &pressure_psi);
        register_field("sensor.device.tpms.pressure_kpa", "Pressure, in kPa", &pressure_kpa);
        register_field("sensor.device.tpms.flags", "TPMS flags", &flags);
        register_field("sensor.device.tpms.state", "TPMS state", &state);
        register_field("sensor.device.tpms.checksum", "TPMS checksum", &checksum);
        register_field("sensor.device.tpms.code", "TPMS code", &code);
    }

    std::shared_ptr<tracker_element_double> freq;
    std::shared_ptr<tracker_element_double> temperature;
    std::shared_ptr<tracker_element_double> pressure_psi;
    std::shared_ptr<tracker_element_double> pressure_bar;
    std::shared_ptr<tracker_element_double> pressure_kpa;
    std::shared_ptr<tracker_element_string> flags;
    std::shared_ptr<tracker_element_string> state;
    std::shared_ptr<tracker_element_string> checksum;
    std::shared_ptr<tracker_element_string> code;
};

// Switch panels
class sensor_tracked_switch : public tracker_component {
public:
    sensor_tracked_switch() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    sensor_tracked_switch(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    sensor_tracked_switch(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("sensor_tracked_switch");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    //__ProxyTrackable(switch_vec, tracker_element_vector, switch_vec);
    __Proxy(switch1, std::string, std::string, std::string, switch1);
    __Proxy(switch2, std::string, std::string, std::string, switch2);
    __Proxy(switch3, std::string, std::string, std::string, switch3);
    __Proxy(switch4, std::string, std::string, std::string, switch4);
    __Proxy(switch5, std::string, std::string, std::string, switch5);

    //shared_tracker_element make_switch_entry(int x) {
    //    auto e = std::make_shared<tracker_element_int32>(switch_vec_entry_id, x);
    //    return e;
   // }

protected:
    virtual void register_fields() override {
        //register_field("sensor.device.switch_vec", "Switch settings", &switch_vec);
        //switch_vec_entry_id = 
        //    register_field("sensor.device.switch.position", 
        //            tracker_element_factory<tracker_element_int32>(),
        //            "Switch position");
        register_field("sensor.device.switch.1", "Switch 1", &switch1);
        register_field("sensor.device.switch.2", "Switch 2", &switch2);
        register_field("sensor.device.switch.3", "Switch 3", &switch3);
        register_field("sensor.device.switch.4", "Switch 4", &switch4);
        register_field("sensor.device.switch.5", "Switch 5", &switch5);
    }

    //std::shared_ptr<tracker_element_vector> switch_vec;
    //int switch_vec_entry_id;
    std::shared_ptr<tracker_element_string> switch1;
    std::shared_ptr<tracker_element_string> switch2;
    std::shared_ptr<tracker_element_string> switch3;
    std::shared_ptr<tracker_element_string> switch4;
    std::shared_ptr<tracker_element_string> switch5;

};

// Insteon
class sensor_tracked_insteon : public tracker_component {
public:
    sensor_tracked_insteon() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    sensor_tracked_insteon(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    sensor_tracked_insteon(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("sensor_tracked_insteon");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(from_id, std::string, std::string, std::string, from_id);
    __Proxy(to_id, std::string, std::string, std::string, to_id);
    __Proxy(msg_type, std::string, std::string, std::string, msg_type);
    __Proxy(msg_str, std::string, std::string, std::string, msg_str);
    __Proxy(hopsmax, std::string, std::string, std::string, hopsmax);
    __Proxy(hopsleft, std::string, std::string, std::string, hopsleft);

protected:
    virtual void register_fields() override {
        register_field("sensor.device.from_id", "From", &from_id);
        register_field("sensor.device.to_id", "To", &to_id);
        register_field("sensor.device.msg_type", "Message Type", &msg_type);
        register_field("sensor.device.msg_str", "Message String", &msg_str);
        register_field("sensor.device.hopsmax", "Hops Max", &hopsmax);
        register_field("sensor.device.hopsleft", "Hops Left", &hopsleft);
    }
    std::shared_ptr<tracker_element_string> from_id;
    std::shared_ptr<tracker_element_string> to_id;
    std::shared_ptr<tracker_element_string> msg_type;
    std::shared_ptr<tracker_element_string> msg_str;
    std::shared_ptr<tracker_element_string> hopsmax;
    std::shared_ptr<tracker_element_string> hopsleft;
};

class sensor_tracked_moisture : public tracker_component {
public:
    sensor_tracked_moisture() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    sensor_tracked_moisture(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    sensor_tracked_moisture(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("sensor_tracked_moisture");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(moisture, int32_t, int32_t, int32_t, moisture);

    typedef kis_tracked_rrd<sensor_empty_aggregator> rrdt;
    __ProxyTrackable(moisture_rrd, rrdt, moisture_rrd);

protected:
    virtual void register_fields() override {
        register_field("sensor.device.moisture", "Moisture", &moisture);
        register_field("sensor.device.moisture_rrd", "Moisture RRD", &moisture_rrd);
    }

    std::shared_ptr<tracker_element_int32> moisture;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> moisture_rrd;
};

class sensor_tracked_aqi : public tracker_component {
// {"time": "2023-07-12 01:57:03", "model": "Fineoffset-WH0290", "id": 146, "battery_ok": 0.6, "pm2_5_ug_m3": 11, "estimated_pm10_0_ug_m3": 10, "family": 65, "unknown1": 0, "mic": "CRC", "mod": "FSK", "freq1": 914.941, "freq2": 915.037, "rssi": -7.18, "snr": 17.482, "noise": -24.662}
public:
    sensor_tracked_aqi() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    sensor_tracked_aqi(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    sensor_tracked_aqi(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("sensor_tracked_aqi");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    typedef kis_tracked_rrd<sensor_empty_aggregator> rrdt;

    __Proxy(pm2_5, uint32_t, uint32_t, uint32_t, pm2_5);
    __ProxyTrackable(pm2_5_rrd, rrdt, pm2_5_rrd);
    __Proxy(pm10, uint32_t, uint32_t, uint32_t, pm10);
    __ProxyTrackable(pm10_rrd, rrdt, pm10_rrd);

protected:
    virtual void register_fields() override {
        register_field("sensor.device.pm2_5", "Estimated PM2.5 particulate", &pm2_5);
        register_field("sensor.device.pm2_5_rrd", "Estimated PM2.5 particulate RRD", &pm2_5_rrd);
        register_field("sensor.device.pm10", "Estimated PM10 particulate", &pm10);
        register_field("sensor.device.pm10_rrd", "Estimated PM10 particulate RRD", &pm10_rrd);
    }

    std::shared_ptr<tracker_element_uint32> pm2_5;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> pm2_5_rrd;

    std::shared_ptr<tracker_element_uint32> pm10;
    std::shared_ptr<kis_tracked_rrd<sensor_empty_aggregator>> pm10_rrd;
};



class kis_sensor_phy : public kis_phy_handler {
public:
    virtual ~kis_sensor_phy();

    kis_sensor_phy() :
        kis_phy_handler() { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
		return new kis_sensor_phy(in_phyid);
	}

    kis_sensor_phy(int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

protected:
    // Convert a JSON record to a RTL-based device key
    mac_addr json_to_mac(nlohmann::json in_json);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_rtl(nlohmann::json in_json, std::shared_ptr<kis_packet> packet);

    bool is_weather_station(nlohmann::json json);
    bool is_thermometer(nlohmann::json json);
    bool is_tpms(nlohmann::json json);
    bool is_switch(nlohmann::json json);
    bool is_insteon(nlohmann::json json);
    bool is_lightning(nlohmann::json json);
    bool is_moisture(nlohmann::json json);
    bool is_aqi(nlohmann::json json);

    void add_weather_station(nlohmann::json json, std::shared_ptr<tracker_element_map> sensorholder);
    void add_thermometer(nlohmann::json json, std::shared_ptr<tracker_element_map> sensorholder);
    void add_tpms(nlohmann::json json, std::shared_ptr<tracker_element_map> sensorholder);
    void add_switch(nlohmann::json json, std::shared_ptr<tracker_element_map> sensorholder);
    void add_insteon(nlohmann::json json, std::shared_ptr<tracker_element_map> sensorholder);
    void add_lightning(nlohmann::json json, std::shared_ptr<tracker_element_map> sensorholder);
    void add_moisture(nlohmann::json json, std::shared_ptr<tracker_element_map> sensorholder);
    void add_aqi(nlohmann::json json, std::shared_ptr<tracker_element_map> sensorholder);

    double f_to_c(double f);


protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int sensor_holder_id, sensor_common_id, sensor_thermometer_id, 
        sensor_weatherstation_id, sensor_tpms_id, sensor_switch_id,
        sensor_insteon_id, sensor_lightning_id, sensor_moisture_id,
        sensor_aqi_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta;

    std::shared_ptr<tracker_element_string> sensor_manuf;

    bool track_last_record;
};

#endif
