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

#ifndef __SYSTEM_MONITOR_H__
#define __SYSTEM_MONITOR_H__

#include "config.h"

#include <string>

#include "kis_mutex.h"
#include "trackedelement.h"
#include "timetracker.h"
#include "devicetracker_component.h"
#include "devicetracker.h"
#include "kis_net_beast_httpd.h"

class event_bus;

class tracked_system_status : public tracker_component {
public:
    tracked_system_status() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_system_status(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_system_status(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~tracked_system_status() { }

    __Proxy(battery_perc, int32_t, int32_t, int32_t, battery_perc);
    __Proxy(battery_charging, std::string, std::string, std::string, battery_charging);
    __Proxy(battery_ac, uint8_t, bool, bool, battery_ac);
    __Proxy(battery_remaining, uint32_t, uint32_t, uint32_t, battery_remaining);

    __Proxy(timestamp_sec, uint64_t, uint64_t, uint64_t, timestamp_sec);
    __Proxy(timestamp_usec, uint64_t, uint64_t, uint64_t, timestamp_usec);
    __ProxyTrackable(timestamp_sec, tracker_element_uint64, timestamp_sec);
    __ProxyTrackable(timestamp_usec, tracker_element_uint64, timestamp_usec);

    __Proxy(timestamp_start_sec, uint64_t, time_t, time_t, timestamp_start_sec);

    __Proxy(memory, uint64_t, uint64_t, uint64_t, memory);
    __Proxy(devices, uint64_t, uint64_t, uint64_t, devices);

    __Proxy(username, std::string, std::string, std::string, username);
    __Proxy(server_version, std::string, std::string, std::string, server_version);
    __Proxy(server_git, std::string, std::string, std::string, server_git);
    __Proxy(build_time, std::string, std::string, std::string, build_time);

    __Proxy(server_name, std::string, std::string, std::string, server_name);
    __Proxy(server_description, std::string, std::string, std::string, server_description);
    __Proxy(server_location, std::string, std::string, std::string, server_location);

    __ProxyTrackable(memory_rrd, kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>, memory_rrd);
    __ProxyTrackable(devices_rrd, kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>, devices_rrd);

    __ProxyTrackable(sensors_fans, tracker_element_string_map, sensors_fans);
    __ProxyTrackable(sensors_temp, tracker_element_string_map, sensors_temp);

    __Proxy(num_fields, uint64_t, uint64_t, uint64_t, num_fields);
    __Proxy(num_components, uint64_t, uint64_t, uint64_t, num_components);
    __Proxy(num_http_connections, uint64_t, uint64_t, uint64_t, num_http_connections);

    __Proxy(string_cache_sz, uint64_t, uint64_t, uint64_t, string_cache_sz);

    __Proxy(cpu_available, uint8_t, bool, bool, cpu_available);
    __Proxy(cpu_count, uint32_t, uint32_t, uint32_t, cpu_count);
    __Proxy(cpu_total, double, double, double, cpu_total);
    __Proxy(cpu_kismet, double, double, double, cpu_kismet);

    virtual void pre_serialize() override;

protected:
    kis_mutex monitor_mutex;

    virtual void register_fields() override;

    std::shared_ptr<device_tracker> devicetracker;

    std::shared_ptr<tracker_element_int32> battery_perc;
    std::shared_ptr<tracker_element_string> battery_charging;
    std::shared_ptr<tracker_element_uint8> battery_ac;
    std::shared_ptr<tracker_element_uint32> battery_remaining;
    std::shared_ptr<tracker_element_uint64> timestamp_sec;
    std::shared_ptr<tracker_element_uint64> timestamp_usec;
    std::shared_ptr<tracker_element_uint64> timestamp_start_sec;
    std::shared_ptr<tracker_element_uint64> memory;
    std::shared_ptr<tracker_element_string> username;
    std::shared_ptr<tracker_element_string> server_name;
    std::shared_ptr<tracker_element_string> server_description;
    std::shared_ptr<tracker_element_string> server_location;
    std::shared_ptr<tracker_element_string> server_version;
    std::shared_ptr<tracker_element_string> server_git;
    std::shared_ptr<tracker_element_string> build_time;

    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> memory_rrd;
    std::shared_ptr<tracker_element_uint64> devices;
    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator> > devices_rrd;

    std::shared_ptr<tracker_element_string_map> sensors_fans;
    std::shared_ptr<tracker_element_string_map> sensors_temp;

    std::shared_ptr<tracker_element_uint64> num_fields;
    std::shared_ptr<tracker_element_uint64> num_components;
    std::shared_ptr<tracker_element_uint64> num_http_connections;

    std::shared_ptr<tracker_element_uint64> string_cache_sz;

    std::shared_ptr<tracker_element_uint8> cpu_available;
    std::shared_ptr<tracker_element_uint32> cpu_count;
    std::shared_ptr<tracker_element_double> cpu_total;
    std::shared_ptr<tracker_element_double> cpu_kismet;
};

// Detailed memory use, for /system/memory; sizes in kB, 0 where unknown
class tracked_memory_status : public tracker_component {
public:
    tracked_memory_status() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_memory_status(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_memory_status(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~tracked_memory_status() { }

    __Proxy(peak_rss, uint64_t, uint64_t, uint64_t, peak_rss);
    __Proxy(virtual_size, uint64_t, uint64_t, uint64_t, virtual_size);
    __Proxy(rss_anon, uint64_t, uint64_t, uint64_t, rss_anon);
    __Proxy(rss_file, uint64_t, uint64_t, uint64_t, rss_file);
    __Proxy(rss_shmem, uint64_t, uint64_t, uint64_t, rss_shmem);
    __Proxy(swap, uint64_t, uint64_t, uint64_t, swap);
    __Proxy(threads, uint64_t, uint64_t, uint64_t, threads);

    __Proxy(system_total, uint64_t, uint64_t, uint64_t, system_total);
    __Proxy(system_available, uint64_t, uint64_t, uint64_t, system_available);
    __ProxyTrackable(system_used_rrd, kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>, system_used_rrd);

    __Proxy(heap_known, uint8_t, bool, bool, heap_known);
    __Proxy(heap_used, uint64_t, uint64_t, uint64_t, heap_used);
    __Proxy(heap_free, uint64_t, uint64_t, uint64_t, heap_free);
    __Proxy(heap_mmap, uint64_t, uint64_t, uint64_t, heap_mmap);

    __ProxyTrackable(num_fields_rrd, kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>, num_fields_rrd);

    __Proxy(startup_time, uint64_t, uint64_t, uint64_t, startup_time);
    __Proxy(startup_rss, uint64_t, uint64_t, uint64_t, startup_rss);
    __Proxy(startup_rss_anon, uint64_t, uint64_t, uint64_t, startup_rss_anon);
    __Proxy(startup_heap_used, uint64_t, uint64_t, uint64_t, startup_heap_used);
    __Proxy(startup_heap_mmap, uint64_t, uint64_t, uint64_t, startup_heap_mmap);
    __Proxy(startup_fields, uint64_t, uint64_t, uint64_t, startup_fields);

    __Proxy(datasources, uint64_t, uint64_t, uint64_t, datasources);
    __Proxy(datasource_estimate, uint64_t, uint64_t, uint64_t, datasource_estimate);
    __Proxy(packet_pool, uint64_t, uint64_t, uint64_t, packet_pool);
    __Proxy(packet_pool_estimate, uint64_t, uint64_t, uint64_t, packet_pool_estimate);
    __Proxy(dedupe_packets, uint64_t, uint64_t, uint64_t, dedupe_packets);
    __Proxy(dedupe_estimate, uint64_t, uint64_t, uint64_t, dedupe_estimate);

    __ProxyTrackable(settings, tracker_element_string_map, settings);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_uint64> peak_rss;
    std::shared_ptr<tracker_element_uint64> virtual_size;
    std::shared_ptr<tracker_element_uint64> rss_anon;
    std::shared_ptr<tracker_element_uint64> rss_file;
    std::shared_ptr<tracker_element_uint64> rss_shmem;
    std::shared_ptr<tracker_element_uint64> swap;
    std::shared_ptr<tracker_element_uint64> threads;

    std::shared_ptr<tracker_element_uint64> system_total;
    std::shared_ptr<tracker_element_uint64> system_available;
    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> system_used_rrd;

    std::shared_ptr<tracker_element_uint8> heap_known;
    std::shared_ptr<tracker_element_uint64> heap_used;
    std::shared_ptr<tracker_element_uint64> heap_free;
    std::shared_ptr<tracker_element_uint64> heap_mmap;

    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> num_fields_rrd;

    std::shared_ptr<tracker_element_uint64> startup_time;
    std::shared_ptr<tracker_element_uint64> startup_rss;
    std::shared_ptr<tracker_element_uint64> startup_rss_anon;
    std::shared_ptr<tracker_element_uint64> startup_heap_used;
    std::shared_ptr<tracker_element_uint64> startup_heap_mmap;
    std::shared_ptr<tracker_element_uint64> startup_fields;

    std::shared_ptr<tracker_element_uint64> datasources;
    std::shared_ptr<tracker_element_uint64> datasource_estimate;
    std::shared_ptr<tracker_element_uint64> packet_pool;
    std::shared_ptr<tracker_element_uint64> packet_pool_estimate;
    std::shared_ptr<tracker_element_uint64> dedupe_packets;
    std::shared_ptr<tracker_element_uint64> dedupe_estimate;

    std::shared_ptr<tracker_element_string_map> settings;
};

using kis_tracked_gauge_rrd = kis_tracked_rrd<kis_tracked_rrd_gauge_aggregator>;

// One temperature sensor, for /system/thermal; temperatures in degrees C
class tracked_thermal_sensor : public tracker_component {
public:
    tracked_thermal_sensor() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_thermal_sensor(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_thermal_sensor(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~tracked_thermal_sensor() { }

    __Proxy(name, std::string, std::string, std::string, name);
    __Proxy(label, std::string, std::string, std::string, label);
    __Proxy(temp, double, double, double, temp);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __ProxyDynamicTrackable(temp_rrd, kis_tracked_gauge_rrd, temp_rrd, temp_rrd_id);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_string> name;
    std::shared_ptr<tracker_element_string> label;
    std::shared_ptr<tracker_element_double> temp;
    std::shared_ptr<tracker_element_uint64> last_time;
    std::shared_ptr<kis_tracked_gauge_rrd> temp_rrd;
    uint16_t temp_rrd_id;
};

// Every temperature sensor seen since the server started, for /system/thermal
class tracked_thermal_status : public tracker_component {
public:
    tracked_thermal_status() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_thermal_status(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_thermal_status(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~tracked_thermal_status() { }

    __Proxy(history, uint8_t, bool, bool, history);
    __ProxyTrackable(sensors, tracker_element_string_map, sensors);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_uint8> history;
    std::shared_ptr<tracker_element_string_map> sensors;
};

// CPU load and its history, for /system/cpu; loads are percentages of all the CPUs
class tracked_cpu_status : public tracker_component {
public:
    tracked_cpu_status() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_cpu_status(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_cpu_status(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~tracked_cpu_status() { }

    __ProxyTrackable(total_rrd, kis_tracked_gauge_rrd, total_rrd);
    __ProxyTrackable(kismet_rrd, kis_tracked_gauge_rrd, kismet_rrd);

protected:
    virtual void register_fields() override;

    std::shared_ptr<kis_tracked_gauge_rrd> total_rrd;
    std::shared_ptr<kis_tracked_gauge_rrd> kismet_rrd;
};

class Systemmonitor : public lifetime_global, public time_tracker_event {
public:
    static std::string global_name() { return "SYSTEMMONITOR"; }

    static std::shared_ptr<Systemmonitor> create_systemmonitor() {
        std::shared_ptr<Systemmonitor> mon(new Systemmonitor());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    Systemmonitor();

public:
    virtual ~Systemmonitor();

    // time_tracker callback
    virtual int timetracker_event(int eventid) override;

    // Record the memory Kismet uses once it has loaded, before any data source opens
    void record_startup_memory();

    static std::string event_timestamp() { return "TIMESTAMP"; }
    static std::string event_battery() { return "BATTERY"; }
    static std::string event_stats() { return "STATISTICS"; }
    static std::string event_thermal() { return "THERMAL"; }

protected:
    kis_mutex monitor_mutex;

    std::shared_ptr<event_bus> eventbus;
    int logopen_evt_id;

    std::shared_ptr<kis_net_web_tracked_endpoint> monitor_endp;
    std::shared_ptr<kis_net_web_tracked_endpoint> user_monitor_endp;
    std::shared_ptr<kis_net_web_tracked_endpoint> timestamp_endp;

    std::shared_ptr<device_tracker> devicetracker;

    std::shared_ptr<tracked_system_status> status;

    std::shared_ptr<tracked_memory_status> memstatus;
    std::shared_ptr<kis_net_web_tracked_endpoint> memory_endp;
    // Heap stats walk every malloc arena under its lock, so they're only read
    // for /system/memory, and at most this often
    time_t heap_read_time;

    void update_proc_memory();
    void update_heap_memory();
    // Data source and packet pool counts, and what they hold, for /system/memory
    void update_capture_memory();

    std::shared_ptr<tracked_thermal_status> thermal;
    std::shared_ptr<kis_net_web_tracked_endpoint> thermal_endp;
    int thermal_sensor_id;
    bool thermal_history;
    size_t thermal_max_sensors;

    void update_temps();
    void record_temp(const std::string& name, const std::string& label, double temp);

    std::shared_ptr<tracked_cpu_status> cpustatus;
    std::shared_ptr<kis_net_web_tracked_endpoint> cpu_endp;
    // The last /proc/stat and /proc/self/stat counters, in clock ticks
    uint64_t cpu_last_total;
    uint64_t cpu_last_idle;
    uint64_t cpu_last_proc;
    bool cpu_primed;

    void update_cpu();

    long mem_per_page;

    std::shared_ptr<time_tracker> timetracker;
    int event_timer_id;
    int kismetdb_log_timer;

};

#endif

