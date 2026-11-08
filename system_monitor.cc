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

#include "config.h"

#include <algorithm>
#include <atomic>
#include <memory>

#include <fstream>
#include <unistd.h>

#include <pwd.h>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

#ifdef HAVE_SENSORS_SENSORS_H
#include <sensors/sensors.h>
#endif

#include "battery.h"
#include "entrytracker.h"
#include "eventbus.h"
#include "fmt.h"
#include "globalregistry.h"
#include "json_adapter.h"
#include "kis_databaselogfile.h"
#include "system_monitor.h"
#include "util.h"
#include "version.h"

Systemmonitor::Systemmonitor() :
    lifetime_global() {

    monitor_mutex.set_name("systemmonitor");

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();
    eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();
    timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();

    status = std::make_shared<tracked_system_status>();

#ifdef SYS_LINUX
    // Get the bytes per page
    mem_per_page = sysconf(_SC_PAGESIZE);
#endif

    timer_id = timetracker->register_timer(SERVER_TIMESLICES_SEC, NULL, 1, this);

    // No longer include the link to the devicetracker rrd since it's not protected under our
    // mutex here
    // status->insert(devicetracker->get_packets_rrd());

    // Set the startup time
    status->set_timestamp_start_sec(Globalreg::globalreg->last_tv_sec);

    // Get the userid
    char *pwbuf;
    ssize_t pwbuf_sz;
    struct passwd pw, *pw_result = NULL;
    std::stringstream uidstr;

    if ((pwbuf_sz = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1) {
        pwbuf_sz = 8192;
    }

    pwbuf = new char[pwbuf_sz];

    if (getpwuid_r(getuid(), &pw, pwbuf, pwbuf_sz, &pw_result) != 0 || 
            pw_result == NULL) {
        uidstr << getuid();
    } else {
        uidstr << pw_result->pw_name;
    }

    delete[] pwbuf;

    status->set_username(uidstr.str());

    status->insert(Globalreg::globalreg->server_uuid);

    status->set_server_version(fmt::format("{}.{}.{}-{}", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, VERSION_GIT_COMMIT));
    status->set_server_git(VERSION_GIT_COMMIT);
    status->set_build_time(VERSION_BUILD_TIME);

    memstatus = std::make_shared<tracked_memory_status>();
    heap_read_time = 0;

    // Shared with the status, so both report the same values
    memstatus->insert(status->get_tracker_memory());
    memstatus->insert(status->get_tracker_memory_rrd());
    memstatus->insert(status->get_tracker_devices());
    memstatus->insert(status->get_tracker_devices_rrd());
    memstatus->insert(status->get_tracker_num_fields());
    memstatus->insert(status->get_tracker_num_components());
    memstatus->insert(status->get_tracker_num_http_connections());
    memstatus->insert(status->get_tracker_string_cache_sz());

    // The device tracker settings which change how much memory devices use
    auto memsettings = memstatus->get_settings();
    memsettings->insert("tracker_device_timeout",
            std::make_shared<tracker_element_int64>(0, devicetracker->get_device_idle_expiration()));
    memsettings->insert("tracker_device_packets",
            std::make_shared<tracker_element_uint64>(0, devicetracker->get_device_idle_min_packets()));
    memsettings->insert("tracker_max_devices",
            std::make_shared<tracker_element_uint64>(0, devicetracker->get_max_num_devices()));
    memsettings->insert("track_device_rrds",
            std::make_shared<tracker_element_uint8>(0, !devicetracker->get_ram_no_rrd()));
    memsettings->insert("track_device_seenby_views",
            std::make_shared<tracker_element_uint8>(0, devicetracker->get_map_seenby_views()));
    memsettings->insert("track_device_phy_views",
            std::make_shared<tracker_element_uint8>(0, devicetracker->get_map_phy_views()));
    memsettings->insert("keep_per_datasource_stats",
            std::make_shared<tracker_element_uint8>(0, devicetracker->get_track_persource_history()));
    memsettings->insert("keep_location_cloud_history",
            std::make_shared<tracker_element_uint8>(0, devicetracker->get_track_history_cloud()));

    status->set_server_name(Globalreg::globalreg->kismet_config->fetch_opt("server_name"));
    status->set_server_description(Globalreg::globalreg->kismet_config->fetch_opt("server_description"));
    status->set_server_location(Globalreg::globalreg->kismet_config->fetch_opt("server_location"));

#if defined(SYS_LINUX) and defined(HAVE_SENSORS_SENSORS_H)
    sensors_init(NULL);
#endif

    thermal_sensor_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.system.thermal.sensor",
                tracker_element_factory<tracked_thermal_sensor>(), "temperature sensor");

    thermal = std::make_shared<tracked_thermal_status>();
    thermal_history = Globalreg::globalreg->kismet_config->fetch_opt_bool("system_thermal_history", true);
    thermal_max_sensors =
        std::clamp(Globalreg::globalreg->kismet_config->fetch_opt_as<unsigned int>("system_thermal_max_sensors", 32),
                1U, 1024U);
    thermal->set_history(thermal_history);

    auto httpd = 
        Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    monitor_endp = std::make_shared<kis_net_web_tracked_endpoint>(status, monitor_mutex);
    httpd->register_route("/system/status", {"GET", "POST"}, httpd->RO_ROLE, {}, monitor_endp);

    user_monitor_endp = std::make_shared<kis_net_web_tracked_endpoint>(
            [this](std::shared_ptr<kis_net_beast_httpd_connection>) -> std::shared_ptr<tracker_element> {
                auto use = std::make_shared<tracker_element_map>();
                use->insert(status->get_tracker_username());
                return use;
                }, monitor_mutex);
    httpd->register_unauth_route("/system/user_status", {"GET", "POST"}, {}, user_monitor_endp);

    memory_endp = std::make_shared<kis_net_web_tracked_endpoint>(
            [this](std::shared_ptr<kis_net_beast_httpd_connection>) -> std::shared_ptr<tracker_element> {
                update_heap_memory();
                return memstatus;
            }, monitor_mutex);
    httpd->register_route("/system/memory", {"GET", "POST"}, httpd->RO_ROLE, {}, memory_endp);

    thermal_endp = std::make_shared<kis_net_web_tracked_endpoint>(thermal, monitor_mutex);
    httpd->register_route("/system/thermal", {"GET", "POST"}, httpd->RO_ROLE, {}, thermal_endp);

    timestamp_endp = 
        std::make_shared<kis_net_web_tracked_endpoint>(
            [this](std::shared_ptr<kis_net_beast_httpd_connection>) -> std::shared_ptr<tracker_element> {
                auto tse = std::make_shared<tracker_element_map>();

                tse->insert(status->get_tracker_timestamp_sec());
                tse->insert(status->get_tracker_timestamp_usec());

                struct timeval now;
                gettimeofday(&now, NULL);

                status->set_timestamp_sec(now.tv_sec);
                status->set_timestamp_usec(now.tv_usec);

                return tse;
            }, monitor_mutex);
    httpd->register_route("/system/timestamp", {"GET", "POST"}, httpd->RO_ROLE, {}, timestamp_endp);

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_system_status", true)) {
        auto snap_time_s = 
            Globalreg::globalreg->kismet_config->fetch_opt_as<unsigned int>("kis_log_system_status_rate", 30);

        kismetdb_log_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * snap_time_s, nullptr, 1, 
                    [this](int) -> int {
                        auto kismetdb = Globalreg::fetch_global_as<kis_database_logfile>();

                        if (kismetdb == nullptr)
                            return 1;

                        kis_lock_guard<kis_mutex> lk(monitor_mutex);

                        struct timeval tv;
                        gettimeofday(&tv, nullptr);

                        std::stringstream js;

                        Globalreg::globalreg->entrytracker->serialize("json", js, status, NULL);

                        kismetdb->log_snapshot(nullptr, tv, "SYSTEM", js.str());

                        return 1;
                    });
    } else {
        kismetdb_log_timer = -1;
    }

    // Always drop a SYSTEM snapshot as soon as the log opens
    logopen_evt_id = 
        eventbus->register_listener(kis_database_logfile::event_log_open(),
            [this](std::shared_ptr<eventbus_event> evt) {
                auto kismetdb = Globalreg::fetch_global_as<kis_database_logfile>();

                if (kismetdb == nullptr)
                    return;

                kis_lock_guard<kis_mutex> lk(monitor_mutex);

                struct timeval tv;
                gettimeofday(&tv, nullptr);

                std::stringstream js;

                Globalreg::globalreg->entrytracker->serialize("json", js, status, NULL);

                kismetdb->log_snapshot(nullptr, tv, "SYSTEM", js.str());
            });

    event_timer_id = 
        timetracker->register_timer(std::chrono::seconds(1), true, 
                [this](int) -> int {
                kis_lock_guard<kis_mutex> lg(monitor_mutex, "system monitor eventtimer");

                status->pre_serialize();

                auto tse = std::make_shared<tracker_element_map>();

                tse->insert(status->get_tracker_timestamp_sec());
                tse->insert(status->get_tracker_timestamp_usec());

                /*
                struct timeval now;
                gettimeofday(&now, NULL);

                status->set_timestamp_sec(now.tv_sec);
                status->set_timestamp_usec(now.tv_usec);
                */

                auto evt = eventbus->get_eventbus_event(event_timestamp());
                evt->get_event_content()->insert(event_timestamp(), tse);
                eventbus->publish(evt);

                auto bate = std::make_shared<tracker_element_map>();
                bate->insert(status->get_tracker_battery_ac());
                bate->insert(status->get_tracker_battery_perc());
                bate->insert(status->get_tracker_battery_charging());
                bate->insert(status->get_tracker_battery_remaining());

                auto bevt = eventbus->get_eventbus_event(event_battery());
                bevt->get_event_content()->insert(event_battery(), bate);
                eventbus->publish(bevt);

                auto sevt = eventbus->get_eventbus_event(event_stats());
                auto sate = std::make_shared<tracker_element_map>();

                sate->insert(status->get_tracker_num_fields());
                sate->insert(status->get_tracker_num_components());
                sate->insert(status->get_tracker_num_http_connections());
                sate->insert(status->get_tracker_memory());
                sate->insert(status->get_tracker_devices());

                sevt->get_event_content()->insert(event_stats(), sate);
                eventbus->publish(sevt);

                // A copy, since the sensor map is refilled on every read while the
                // event is serialized on other threads
                auto temps = std::make_shared<tracker_element_string_map>(status->get_sensors_temp()->get_id());
                for (const auto& t : *status->get_sensors_temp())
                    temps->insert(t.first, std::make_shared<tracker_element_double>(0,
                                std::static_pointer_cast<tracker_element_double>(t.second)->get()));

                auto tevt = eventbus->get_eventbus_event(event_thermal());
                auto tate = std::make_shared<tracker_element_map>();
                tate->insert(temps);
                tevt->get_event_content()->insert(event_thermal(), tate);
                eventbus->publish(tevt);


                status->post_serialize();

                return 1;
                });

}

Systemmonitor::~Systemmonitor() {
    // Before taking the lock; the timer callbacks take it too
    timetracker->remove_timer(timer_id);
    timetracker->remove_timer(kismetdb_log_timer);
    timetracker->remove_timer(event_timer_id);

    kis_lock_guard<kis_mutex> lk(monitor_mutex);

    Globalreg::globalreg->remove_global("SYSTEMMONITOR");

    eventbus->remove_listener(logopen_evt_id);
}

void tracked_memory_status::register_fields() {
    register_field("kismet.system.memory.peak_rss", "peak memory RSS in kbytes", &peak_rss);
    register_field("kismet.system.memory.virtual", "virtual memory size in kbytes", &virtual_size);
    register_field("kismet.system.memory.rss_anon", "anonymous (heap and stack) RSS in kbytes", &rss_anon);
    register_field("kismet.system.memory.rss_file", "file-backed RSS (program and libraries) in kbytes", &rss_file);
    register_field("kismet.system.memory.rss_shmem", "shared memory RSS in kbytes", &rss_shmem);
    register_field("kismet.system.memory.swap", "memory swapped out in kbytes", &swap);
    register_field("kismet.system.memory.threads", "number of threads", &threads);

    register_field("kismet.system.memory.system_total", "system memory in kbytes", &system_total);
    register_field("kismet.system.memory.system_available",
            "system memory available in kbytes", &system_available);
    register_field("kismet.system.memory.system_used_rrd", "system memory used RRD", &system_used_rrd);

    register_field("kismet.system.memory.heap_known", "heap stats are available", &heap_known);
    register_field("kismet.system.memory.heap_used", "heap in use in kbytes", &heap_used);
    register_field("kismet.system.memory.heap_free", "heap held free by the allocator in kbytes", &heap_free);
    register_field("kismet.system.memory.heap_mmap", "large allocations mapped separately in kbytes", &heap_mmap);

    register_field("kismet.system.num_fields_rrd", "tracked element fields RRD", &num_fields_rrd);

    register_field("kismet.system.memory.settings", "device tracker settings affecting memory", &settings);
}

void Systemmonitor::update_proc_memory() {
#ifdef SYS_LINUX
    // VmHWM etc are in kB; missing lines (older kernels) stay 0
    std::ifstream sf("/proc/self/status");
    std::string line;

    static constexpr const char *keys[] = {
        "VmHWM:", "VmSize:", "RssAnon:", "RssFile:", "RssShmem:", "VmSwap:", "Threads:"
    };
    constexpr size_t nkeys = sizeof(keys) / sizeof(keys[0]);

    while (std::getline(sf, line)) {
        size_t k;
        uint64_t v;

        for (k = 0; k < nkeys; k++)
            if (line.compare(0, strlen(keys[k]), keys[k]) == 0)
                break;

        if (k >= nkeys || sscanf(line.c_str() + strlen(keys[k]), "%" SCNu64, &v) != 1)
            continue;

        switch (k) {
            case 0: memstatus->set_peak_rss(v); break;
            case 1: memstatus->set_virtual_size(v); break;
            case 2: memstatus->set_rss_anon(v); break;
            case 3: memstatus->set_rss_file(v); break;
            case 4: memstatus->set_rss_shmem(v); break;
            case 5: memstatus->set_swap(v); break;
            case 6: memstatus->set_threads(v); break;
        }
    }

    std::ifstream mf("/proc/meminfo");
    uint64_t total = 0, avail = 0;

    while (std::getline(mf, line) && (total == 0 || avail == 0)) {
        uint64_t v;

        if (sscanf(line.c_str(), "MemTotal: %" SCNu64, &v) == 1)
            total = v;
        else if (sscanf(line.c_str(), "MemAvailable: %" SCNu64, &v) == 1)
            avail = v;
    }

    memstatus->set_system_total(total);
    memstatus->set_system_available(avail);

    if (total > 0 && avail > 0 && avail <= total)
        memstatus->get_system_used_rrd()->add_sample(total - avail, Globalreg::globalreg->last_tv_sec);
#endif

    memstatus->get_num_fields_rrd()->add_sample(Globalreg::n_tracked_fields.load(std::memory_order_acquire),
            Globalreg::globalreg->last_tv_sec);
}

// __GLIBC_PREREQ only exists on glibc, so it can't share an #if with the test for it
#if defined(__GLIBC__)
#if __GLIBC_PREREQ(2, 33)
#define KIS_HAVE_MALLINFO2 1
#endif
#endif

void Systemmonitor::update_heap_memory() {
#ifdef KIS_HAVE_MALLINFO2
    if (heap_read_time != 0 && Globalreg::globalreg->last_tv_sec - heap_read_time < 5)
        return;

    heap_read_time = Globalreg::globalreg->last_tv_sec;

    auto mi = mallinfo2();

    memstatus->set_heap_known(true);
    memstatus->set_heap_used(mi.uordblks / 1024);
    memstatus->set_heap_free(mi.fordblks / 1024);
    memstatus->set_heap_mmap(mi.hblkhd / 1024);
#endif
}

void tracked_system_status::register_fields() {
    register_field("kismet.system.battery.percentage", "remaining battery percentage", &battery_perc);
    register_field("kismet.system.battery.charging", "battery charging state", &battery_charging);
    register_field("kismet.system.battery.ac", "on AC power", &battery_ac);
    register_field("kismet.system.battery.remaining", 
            "battery remaining in seconds", &battery_remaining);
    register_field("kismet.system.timestamp.sec", "system timestamp, seconds", &timestamp_sec);
    register_field("kismet.system.timestamp.usec", "system timestamp, usec", &timestamp_usec);
    register_field("kismet.system.timestamp.start_sec", 
            "system startup timestamp, seconds", &timestamp_start_sec);
    register_field("kismet.system.memory.rss", "memory RSS in kbytes", &memory);
    register_field("kismet.system.devices.count", "number of devices in devicetracker", &devices);
    register_field("kismet.system.user", "user Kismet is running as", &username);
    register_field("kismet.system.version", "Kismet version string", &server_version);
    register_field("kismet.system.git", "Git commit string", &server_git);
    register_field("kismet.system.build_time", "Server build time", &build_time);
    register_field("kismet.system.server_name", "Arbitrary name of server instance", &server_name);
    register_field("kismet.system.server_description", "Arbitrary server description", &server_description);
    register_field("kismet.system.server_location", "Arbitrary server location string", &server_location);

    register_field("kismet.system.memory.rrd", "memory used RRD", &memory_rrd); 
    register_field("kismet.system.devices.rrd", "device count RRD", &devices_rrd);

    register_field("kismet.system.sensors.fan", "fan sensors", &sensors_fans);
    register_field("kismet.system.sensors.temp", "temperature sensors", &sensors_temp);

    register_field("kismet.system.num_fields", "number of allocated tracked element fields", &num_fields);
    register_field("kismet.system.num_components", "number of allocated tracked element components", &num_components);
    register_field("kismet.system.num_http_connections", "number of concurrent http connections", &num_http_connections);

    register_field("kismet.system.string_cache_size", "number of strings in cache", &string_cache_sz);
}

int Systemmonitor::timetracker_event(int eventid) {
    kis_lock_guard<kis_mutex> lg(monitor_mutex, "system monitor timer");

    int num_devices = devicetracker->fetch_num_devices();

    // Grab the devices
    status->set_devices(num_devices);
    status->get_devices_rrd()->add_sample(num_devices, Globalreg::globalreg->last_tv_sec);

    update_proc_memory();

#ifdef SYS_LINUX
    // Grab the memory from /proc
    std::string procline;
    std::ifstream procfile;

    procfile.open("/proc/self/stat");

    if (procfile.good()) {
        std::getline(procfile, procline);
        procfile.close();

        // Find the last paren because status is 'pid (name) stuff'.
        // Memory is nominally field 24, so we find the last paren, add a 
        // space, and split the rest
        size_t paren = procline.find_last_of(")");

        if (paren != std::string::npos) {
            std::vector<std::string> toks = 
                str_tokenize(procline.substr(paren + 1, procline.length()), " ");

            if (toks.size() > 22) {
                unsigned long int m;

                if (sscanf(toks[22].c_str(), "%lu", &m) == 1) {
                    m *= mem_per_page;

                    m /= 1024;

                    status->set_memory(m);
                    status->get_memory_rrd()->add_sample(m, Globalreg::globalreg->last_tv_sec);
                }
            }
        }
    }

#endif

    update_temps();

    return 1;
}

void tracked_thermal_sensor::register_fields() {
    register_field("kismet.system.thermal.sensor.name",
            "sensor name, as in kismet.system.sensors.temp", &name);
    register_field("kismet.system.thermal.sensor.label", "what the sensor measures", &label);
    register_field("kismet.system.thermal.sensor.temp", "last temperature, in degrees C", &temp);
    register_field("kismet.system.thermal.sensor.last_time", "last time the sensor was read", &last_time);
    temp_rrd_id =
        register_dynamic_field("kismet.system.thermal.sensor.rrd",
                "temperature history, in degrees C", &temp_rrd);
}

void tracked_thermal_status::register_fields() {
    register_field("kismet.system.thermal.history", "temperature history is kept", &history);
    register_field("kismet.system.thermal.sensors", "temperature sensors, by name", &sensors);
}

// Called with monitor_mutex held
void Systemmonitor::record_temp(const std::string& name, const std::string& label, double temp) {
    time_t now = Globalreg::globalreg->last_tv_sec;

    status->get_sensors_temp()->insert(name, std::make_shared<tracker_element_double>(0, temp));

    auto sensors = thermal->get_sensors();
    std::shared_ptr<tracked_thermal_sensor> sensor;

    auto si = sensors->find(name);
    if (si == sensors->end()) {
        // Sensors are kept once seen, so a host with many is capped
        if (sensors->size() >= thermal_max_sensors)
            return;

        sensor = std::make_shared<tracked_thermal_sensor>(thermal_sensor_id);
        sensor->set_name(name);
        sensor->set_label(label);
        sensors->insert(name, sensor);
    } else {
        sensor = std::static_pointer_cast<tracked_thermal_sensor>(si->second);
    }

    sensor->set_temp(temp);
    sensor->set_last_time(now);

    if (thermal_history)
        sensor->get_temp_rrd()->add_sample(temp, now);
}

// Called with monitor_mutex held
void Systemmonitor::update_temps() {
#if defined(SYS_LINUX)
    status->get_sensors_fans()->clear();
    status->get_sensors_temp()->clear();

#if defined(HAVE_SENSORS_SENSORS_H)
    int sensor_nr = 0;
    while (auto chip = sensors_get_detected_chips(NULL, &sensor_nr)) {
        int i = 0;
        while (auto fi = sensors_get_features(chip, &i)) {
            const sensors_subfeature *sf;

            if (fi->type == SENSORS_FEATURE_TEMP)
                sf = sensors_get_subfeature(chip, fi, SENSORS_SUBFEATURE_TEMP_INPUT);
            else if (fi->type == SENSORS_FEATURE_FAN)
                sf = sensors_get_subfeature(chip, fi, SENSORS_SUBFEATURE_FAN_INPUT);
            else
                continue;

            double val;

            if (sf == nullptr || sensors_get_value(chip, sf->number, &val) < 0)
                continue;

            char chipname[64];
            if (sensors_snprintf_chip_name(chipname, sizeof(chipname), chip) < 0)
                chipname[0] = 0;

            // Either can be NULL
            const char *adapter_name = sensors_get_adapter_name(&chip->bus);
            char *label = sensors_get_label(chip, fi);

            auto label_s = munge_to_printable(label != nullptr ? label : "");
            auto chip_s = munge_to_printable(chipname);

            auto synth_name = fmt::format("{}-{}-{}", chip_s, label_s,
                    munge_to_printable(adapter_name != nullptr ? adapter_name : ""));

            free(label);

            if (fi->type == SENSORS_FEATURE_TEMP)
                record_temp(synth_name, fmt::format("{} ({})", label_s, chip_s), val);
            else
                status->get_sensors_fans()->insert(synth_name,
                        std::make_shared<tracker_element_double>(0, val));
        }
    }
#endif

    // Thermal zones of newer kernels, in millidegrees; zone 0 keeps its old name
    // of system-thermal-0
    for (unsigned int z = 0; z < 64; z++) {
        auto zone = fmt::format("/sys/class/thermal/thermal_zone{}", z);

        FILE *tempf = fopen(fmt::format("{}/temp", zone).c_str(), "r");

        if (tempf == nullptr) {
            if (access(zone.c_str(), F_OK) != 0)
                break;
            continue;
        }

        long mdeg;
        int r = fscanf(tempf, "%ld", &mdeg);
        fclose(tempf);

        // Zones that can't be read right now (a sleeping device) fail the read
        if (r != 1)
            continue;

        std::string label = fmt::format("thermal zone {}", z);

        FILE *typef = fopen(fmt::format("{}/type", zone).c_str(), "r");
        if (typef != nullptr) {
            char type[64];
            if (fgets(type, sizeof(type), typef) != nullptr) {
                type[strcspn(type, "\r\n")] = 0;
                if (type[0] != 0)
                    label = munge_to_printable(type);
            }
            fclose(typef);
        }

        record_temp(fmt::format("system-thermal-{}", z), label, mdeg / 1000.0);
    }
#endif
}

void tracked_system_status::pre_serialize() {
    kis_lock_guard<kis_mutex> lk(monitor_mutex);

    kis_battery_info batinfo;
    fetch_battery_info(&batinfo);

    set_battery_perc(batinfo.percentage);
    if (batinfo.ac && batinfo.charging) {
        set_battery_charging("charging");
    } else if (batinfo.ac && !batinfo.charging) {
        set_battery_charging("charged");
    } else if (!batinfo.ac) {
        set_battery_charging("discharging");
    }

    set_battery_ac(batinfo.ac);
    set_battery_remaining(batinfo.remaining_sec);

    struct timeval now;
    gettimeofday(&now, NULL);

    set_timestamp_sec(now.tv_sec);
    set_timestamp_usec(now.tv_usec);

    set_num_fields(Globalreg::n_tracked_fields.load(std::memory_order_acquire));
    set_num_components(Globalreg::n_tracked_components.load(std::memory_order_acquire));
    set_num_http_connections(Globalreg::n_tracked_http_connections.load(std::memory_order_acquire));

    unsigned int csize = 0;
    unsigned long cbytes = 0;
    Globalreg::cache_string_stats(csize, cbytes);

    set_string_cache_sz(csize);

} 

