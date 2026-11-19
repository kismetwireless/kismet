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

#ifndef __ENVIRONMENT_H__
#define __ENVIRONMENT_H__

#include "config.h"

#include <algorithm>
#include <array>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "battery.h"
#include "environment_report.h"
#include "trackedcomponent.h"
#include "trackedelement.h"
#include "trackedrrd.h"
#include "uuid.h"

// Environmental sensors (temperatures, fans, batteries) of the host and of data
// sources, for /system/environment

using kis_tracked_env_rrd = kis_tracked_rrd<kis_tracked_rrd_gauge_aggregator>;

class tracked_env_battery : public tracker_component {
public:
    tracked_env_battery() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_env_battery(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_env_battery(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_env_battery");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~tracked_env_battery() { }

    __Proxy(state, std::string, std::string, std::string, state);
    __Proxy(external_power, int8_t, int8_t, int8_t, external_power);
    __Proxy(voltage, double, double, double, voltage);
    __Proxy(remaining, uint32_t, uint32_t, uint32_t, remaining);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_string> state;
    std::shared_ptr<tracker_element_int8> external_power;
    std::shared_ptr<tracker_element_double> voltage;
    std::shared_ptr<tracker_element_uint32> remaining;
};

class tracked_env_sensor : public tracker_component {
public:
    tracked_env_sensor() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_env_sensor(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_env_sensor(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_env_sensor");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~tracked_env_sensor() { }

    __Proxy(sensor_id, std::string, std::string, std::string, sensor_id);
    __Proxy(label, std::string, std::string, std::string, label);
    __Proxy(kind, std::string, std::string, std::string, kind);
    __Proxy(units, std::string, std::string, std::string, units);
    __Proxy(sensor_value, double, double, double, sensor_value);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __Proxy(origin, std::string, std::string, std::string, origin);
    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);
    __Proxy(source_name, std::string, std::string, std::string, source_name);
    __ProxyDynamicTrackable(rrd, kis_tracked_env_rrd, rrd, rrd_id);
    __ProxyDynamicTrackable(battery, tracked_env_battery, battery, battery_id);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_string> sensor_id;
    std::shared_ptr<tracker_element_string> label;
    std::shared_ptr<tracker_element_string> kind;
    std::shared_ptr<tracker_element_string> units;
    std::shared_ptr<tracker_element_double> sensor_value;
    std::shared_ptr<tracker_element_uint64> last_time;
    std::shared_ptr<tracker_element_string> origin;
    std::shared_ptr<tracker_element_uuid> source_uuid;
    std::shared_ptr<tracker_element_string> source_name;
    std::shared_ptr<kis_tracked_env_rrd> rrd;
    uint16_t rrd_id;
    std::shared_ptr<tracked_env_battery> battery;
    uint16_t battery_id;
};

// The current value of a sensor, for the ENVIRONMENT event and the kismetdb snapshot;
// the fields share their names with tracked_env_sensor
class tracked_env_reading : public tracker_component {
public:
    tracked_env_reading() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_env_reading(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_env_reading(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_env_reading");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~tracked_env_reading() { }

    __Proxy(label, std::string, std::string, std::string, label);
    __Proxy(kind, std::string, std::string, std::string, kind);
    __Proxy(sensor_value, double, double, double, sensor_value);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);
    __Proxy(source_name, std::string, std::string, std::string, source_name);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_string> label;
    std::shared_ptr<tracker_element_string> kind;
    std::shared_ptr<tracker_element_double> sensor_value;
    std::shared_ptr<tracker_element_uint64> last_time;
    std::shared_ptr<tracker_element_uuid> source_uuid;
    std::shared_ptr<tracker_element_string> source_name;
};

class tracked_env_status : public tracker_component {
public:
    tracked_env_status() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_env_status(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_env_status(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_env_status");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~tracked_env_status() { }

    __Proxy(history, uint8_t, bool, bool, history);
    __Proxy(dropped_reports, uint64_t, uint64_t, uint64_t, dropped_reports);
    __ProxyIncDec(dropped_reports, uint64_t, uint64_t, dropped_reports);
    __Proxy(dropped_sensors, uint64_t, uint64_t, uint64_t, dropped_sensors);
    __ProxyIncDec(dropped_sensors, uint64_t, uint64_t, dropped_sensors);
    __Proxy(source_report_sec, uint32_t, uint32_t, uint32_t, source_report_sec);
    __Proxy(source_stale_sec, uint32_t, uint32_t, uint32_t, source_stale_sec);
    __ProxyTrackable(sensors, tracker_element_string_map, sensors);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_uint8> history;
    std::shared_ptr<tracker_element_uint64> dropped_reports;
    std::shared_ptr<tracker_element_uint64> dropped_sensors;
    std::shared_ptr<tracker_element_uint32> source_report_sec;
    std::shared_ptr<tracker_element_uint32> source_stale_sec;
    std::shared_ptr<tracker_element_string_map> sensors;
};

// A reading of a host sensor
struct env_host_reading {
    std::string id;
    std::string label;
    env_kind kind = env_kind::thermal;
    double value = 0;

    // battery only
    kis_battery_state batt_state = kis_battery_state::unknown;
    int8_t ext_power = -1;
    double voltage = 0;
    uint32_t remaining_s = 0;
};

// Host sensor readers; each takes the sysfs class directory so tests can use fixture trees.
// Thermal zones: <root>/thermal_zoneN, ids system-thermal-N
void env_read_thermal_zones(const std::string& root, std::vector<env_host_reading>& out);
// hwmon temperatures and fans, for builds without libsensors: <root>/hwmonN, ids
// <name>-hwmonN-tempK and <name>-hwmonN-fanK
void env_read_hwmon(const std::string& root, std::vector<env_host_reading>& out);
// System batteries as readings, ids system-battery-<name>
void env_battery_readings(const std::vector<kis_battery_reading>& batteries, int ext_online,
        std::vector<env_host_reading>& out);

struct env_store_config {
    bool history = true;
    // per kind
    size_t host_max_sensors = 32;
    // per data source; 0 disables data source reports
    size_t source_max_sensors = 8;
    size_t source_total_max = 256;
    // ms; reports closer than half of this are dropped
    uint32_t report_ms = 5000;
};

// The sensor records and their limits.  Not locked; the owner holds its lock around
// every call and around serializing the status.
class environment_store {
public:
    environment_store(const env_store_config& in_config);

    std::shared_ptr<tracked_env_status> get_status() { return status; }
    const env_store_config& get_config() const { return config; }

    // Record a host sensor; false if the host cap for its kind is reached
    bool record_host(const env_host_reading& in_reading, time_t in_now);

    // Record a data source report; false if it was dropped (reports are off, or it came
    // too soon after the last one).  in_mono_ms is a monotonic clock for the rate limit.
    bool record_source(const uuid& in_uuid, const std::string& in_name, const env_report& in_report,
            time_t in_now, uint64_t in_mono_ms);

    void count_dropped_report() { status->inc_dropped_reports(); }

    // Remove the sensors of data sources which no longer exist, and data source sensors
    // not updated within stale_sec(); returns how many
    size_t sweep(const std::unordered_set<uuid>& in_live, time_t in_now);

    // Dead remote sources can stay listed, so stale sensors age out on their own
    time_t stale_sec() const {
        return std::max<time_t>(3600, static_cast<time_t>(config.report_ms / 1000) * 20);
    }

    // The thermal sensors only, sharing the sensor records
    std::shared_ptr<tracked_env_status> thermal_view();

    // A copy of the status and every sensor without the history, safe to serialize
    // after the owner's lock is released
    std::shared_ptr<tracked_env_status> current();

    // Copies of every current value, keyed like the sensors
    std::shared_ptr<tracker_element_string_map> readings();

    size_t source_sensor_count(const uuid& in_uuid) const;
    size_t source_total() const { return source_total_count; }

    static std::string source_key(const uuid& in_uuid, const std::string& in_id) {
        return in_uuid.as_string() + "/" + in_id;
    }

protected:
    env_store_config config;

    int status_id;
    int sensor_id;
    int reading_id;

    std::shared_ptr<tracked_env_status> status;

    std::array<size_t, 4> host_counts;
    size_t source_total_count;

    struct source_state {
        uint64_t last_report_ms = 0;
        bool reported = false;
        size_t count = 0;
    };

    std::unordered_map<uuid, source_state> sources;

    std::shared_ptr<tracked_env_status> copy_header();
    std::shared_ptr<tracked_env_sensor> new_sensor(const std::string& in_key, env_kind in_kind);
    void update_sensor(const std::shared_ptr<tracked_env_sensor>& sensor, double in_value,
            time_t in_last_time, time_t in_now);
};

#endif
