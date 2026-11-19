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
#include <cmath>
#include <memory>
#include <unordered_set>

#include <fstream>
#include <unistd.h>

#include <pwd.h>
#include <sys/resource.h>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

#ifdef HAVE_SENSORS_SENSORS_H
#include <sensors/sensors.h>
#endif

#include "alertracker.h"
#include "battery.h"
#include "datasourcetracker.h"
#include "entrytracker.h"
#include "eventbus.h"
#include "fmt.h"
#include "globalregistry.h"
#include "json_adapter.h"
#include "kis_databaselogfile.h"
#include "kis_pcapng_ring_logfile.h"
#include "kis_pcapnglogfile.h"
#include "manuf.h"
#include "packetchain.h"
#include "phy_80211.h"
#include "phy_sensor.h"
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
    memsettings->insert("tracker_device_presize",
            std::make_shared<tracker_element_uint64>(0, devicetracker->get_device_presize()));

    if (Globalreg::globalreg->manufdb != nullptr)
        memsettings->insert("manuf_lookup",
                std::make_shared<tracker_element_uint8>(0, Globalreg::globalreg->manufdb->get_lookup_enabled()));

    auto alertracker = Globalreg::fetch_global_as<alert_tracker>();
    if (alertracker != nullptr)
        memsettings->insert("alertbacklog",
                std::make_shared<tracker_element_uint64>(0, alertracker->get_alert_backlog()));

    auto packetchain = Globalreg::fetch_global_as<packet_chain>();
    if (packetchain != nullptr) {
        memsettings->insert("packet_backlog_warning",
                std::make_shared<tracker_element_uint64>(0, packetchain->get_backlog_warning()));
        memsettings->insert("packet_backlog_limit",
                std::make_shared<tracker_element_uint64>(0, packetchain->get_backlog_limit()));
    }

    // The data limit in force, whether ulimit_mbytes or the shell that started Kismet set it
    struct rlimit datalimit;
    uint64_t datalimit_mb = 0;
    if (getrlimit(RLIMIT_DATA, &datalimit) == 0 && datalimit.rlim_cur != RLIM_INFINITY)
        datalimit_mb = static_cast<uint64_t>(datalimit.rlim_cur) / (1024 * 1024);
    memsettings->insert("ulimit_mbytes", std::make_shared<tracker_element_uint64>(0, datalimit_mb));

    memsettings->insert("pcapng_log_buffer_mb",
            std::make_shared<tracker_element_uint64>(0, kis_pcapng_logfile::configured_buffer_bytes() / (1024 * 1024)));
    memsettings->insert("pcapng_ring_file_size_mb",
            std::make_shared<tracker_element_uint64>(0,
                kis_pcapng_ring_logfile::configured_file_size_bytes() / (1024 * 1024)));
    memsettings->insert("pcapng_ring_file_count",
            std::make_shared<tracker_element_uint64>(0, kis_pcapng_ring_logfile::configured_file_count()));

    auto sensorphy = dynamic_cast<kis_sensor_phy *>(devicetracker->fetch_phy_handler_by_name("RFSENSOR"));
    if (sensorphy != nullptr)
        memsettings->insert("rtl433_track_last",
                std::make_shared<tracker_element_uint8>(0, sensorphy->get_track_last_record()));

    auto dot11phy = dynamic_cast<kis_80211_phy *>(devicetracker->fetch_phy_handler_by_name("IEEE802.11"));
    if (dot11phy != nullptr) {
        memsettings->insert("dot11_keep_eapol",
                std::make_shared<tracker_element_uint8>(0, dot11phy->get_keep_eapol()));
        memsettings->insert("dot11_keep_ietags",
                std::make_shared<tracker_element_uint8>(0, dot11phy->get_keep_ie_tags()));
        memsettings->insert("dot11_fingerprint_devices",
                std::make_shared<tracker_element_uint8>(0, dot11phy->get_fingerprint_devices()));
        memsettings->insert("dot11_11d_country_full",
                std::make_shared<tracker_element_uint8>(0, dot11phy->get_11d_country_full()));
        memsettings->insert("dot11_view_accesspoints",
                std::make_shared<tracker_element_uint8>(0, dot11phy->get_view_accesspoints()));
        memsettings->insert("dot11_ap_only_survey",
                std::make_shared<tracker_element_uint8>(0, dot11phy->get_ap_only_survey()));

        auto ssidtracker = dot11phy->get_ssidtracker();
        if (ssidtracker != nullptr) {
            memsettings->insert("dot11_view_ssids",
                    std::make_shared<tracker_element_uint8>(0, ssidtracker->get_tracking_enabled()));
            memsettings->insert("dot11_max_ssid_groups",
                    std::make_shared<tracker_element_uint64>(0, ssidtracker->get_max_ssid_groups()));
        }
    }

    status->set_server_name(Globalreg::globalreg->kismet_config->fetch_opt("server_name"));
    status->set_server_description(Globalreg::globalreg->kismet_config->fetch_opt("server_description"));
    status->set_server_location(Globalreg::globalreg->kismet_config->fetch_opt("server_location"));

#if defined(SYS_LINUX) and defined(HAVE_SENSORS_SENSORS_H)
    sensors_init(NULL);
#endif

    // The system_thermal_ options are the old names of the first two
    auto conf = Globalreg::globalreg->kismet_config;
    env_store_config envconf;
    envconf.history = conf->fetch_opt_bool("environment_history",
            conf->fetch_opt_bool("system_thermal_history", true));
    envconf.host_max_sensors =
        std::clamp(conf->fetch_opt_as<unsigned int>("environment_max_sensors",
                    conf->fetch_opt_as<unsigned int>("system_thermal_max_sensors", 32)), 1U, 1024U);
    envconf.source_max_sensors =
        std::clamp(conf->fetch_opt_as<unsigned int>("environment_source_max_sensors", 8), 0U, 32U);
    envconf.source_total_max = 256;
    envconf.report_ms =
        std::clamp(conf->fetch_opt_as<unsigned int>("environment_source_report_sec", 5), 1U, 3600U) * 1000;

    env_report_ms = envconf.source_max_sensors > 0 ? envconf.report_ms : 0;

    environment = std::make_unique<environment_store>(envconf);

    {
        // Batteries and sensors are there to read from the first request on
        host_env_scan scan;
        scan_host_environment(scan);
        kis_lock_guard<kis_mutex> lk(monitor_mutex, "system monitor startup sensors");
        record_host_environment(scan);
    }

    cpustatus = std::make_shared<tracked_cpu_status>();
    cpustatus->insert(status->get_tracker_cpu_available());
    cpustatus->insert(status->get_tracker_cpu_count());
    cpustatus->insert(status->get_tracker_cpu_total());
    cpustatus->insert(status->get_tracker_cpu_kismet());
    cpu_last_total = cpu_last_idle = cpu_last_proc = 0;
    cpu_primed = false;

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
                update_capture_memory();
                return memstatus;
            }, monitor_mutex);
    httpd->register_route("/system/memory", {"GET", "POST"}, httpd->RO_ROLE, {}, memory_endp);

    environment_endp = std::make_shared<kis_net_web_tracked_endpoint>(environment->get_status(), monitor_mutex);
    httpd->register_route("/system/environment", {"GET", "POST"}, httpd->RO_ROLE, {}, environment_endp);

    // The same records, thermal sensors only
    thermal_endp = std::make_shared<kis_net_web_tracked_endpoint>(
            [this](std::shared_ptr<kis_net_beast_httpd_connection>) -> std::shared_ptr<tracker_element> {
                return environment->thermal_view();
            }, monitor_mutex);
    httpd->register_route("/system/thermal", {"GET", "POST"}, httpd->RO_ROLE, {}, thermal_endp);

    // Current values without the history, copied under the monitor lock and
    // serialized after it is released; the endpoint lock is its own
    environment_current_endp = std::make_shared<kis_net_web_tracked_endpoint>(
            [this](std::shared_ptr<kis_net_beast_httpd_connection>) -> std::shared_ptr<tracker_element> {
                kis_lock_guard<kis_mutex> lk(monitor_mutex, "system monitor environment current");
                return environment->current();
            });
    httpd->register_route("/system/environment_current", {"GET", "POST"}, httpd->RO_ROLE, {},
            environment_current_endp);

    cpu_endp = std::make_shared<kis_net_web_tracked_endpoint>(cpustatus, monitor_mutex);
    httpd->register_route("/system/cpu", {"GET", "POST"}, httpd->RO_ROLE, {}, cpu_endp);

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

                        struct timeval tv;
                        gettimeofday(&tv, nullptr);

                        std::stringstream js;
                        std::shared_ptr<tracker_element_string_map> readings;

                        {
                            kis_lock_guard<kis_mutex> lk(monitor_mutex);

                            Globalreg::globalreg->entrytracker->serialize("json", js, status, NULL);

                            // Copies of the current values; the histories stay out of the log
                            readings = environment->readings();
                        }

                        kismetdb->log_snapshot(nullptr, tv, "SYSTEM", js.str());

                        if (readings->size() > 0) {
                            std::stringstream envjs;
                            auto envmap = std::make_shared<tracker_element_map>();
                            envmap->insert(readings);
                            Globalreg::globalreg->entrytracker->serialize("json", envjs, envmap, NULL);
                            kismetdb->log_snapshot(nullptr, tv, "ENVIRONMENT", envjs.str());
                        }

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
                std::shared_ptr<tracker_element_string_map> readings;

                {
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

                // Copies; the loads are rewritten on every read
                sate->insert(std::make_shared<tracker_element_uint8>(status->get_tracker_cpu_available()->get_id(),
                            status->get_cpu_available()));
                sate->insert(std::make_shared<tracker_element_double>(status->get_tracker_cpu_total()->get_id(),
                            status->get_cpu_total()));
                sate->insert(std::make_shared<tracker_element_double>(status->get_tracker_cpu_kismet()->get_id(),
                            status->get_cpu_kismet()));

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

                // Copies, published once the lock is released
                readings = environment->readings();
                }

                auto eevt = eventbus->get_eventbus_event(event_environment());
                auto eate = std::make_shared<tracker_element_map>();
                eate->insert(readings);
                eevt->get_event_content()->insert(event_environment(), eate);
                eventbus->publish(eevt);

                return 1;
                });

    env_sweep_timer =
        timetracker->register_timer(std::chrono::seconds(60), true,
                [this](int) -> int {
                    sweep_environment();
                    return 1;
                });

    timer_id = timetracker->register_timer(SERVER_TIMESLICES_SEC, NULL, 1, this);

}

Systemmonitor::~Systemmonitor() {
    // Before taking the lock; the timer callbacks take it too
    timetracker->remove_timer(timer_id);
    timetracker->remove_timer(kismetdb_log_timer);
    timetracker->remove_timer(event_timer_id);
    timetracker->remove_timer(env_sweep_timer);

    kis_lock_guard<kis_mutex> lk(monitor_mutex);

    Globalreg::globalreg->remove_global(env_report_sink::global_name());
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

    register_field("kismet.system.memory.startup_time",
            "when Kismet had loaded, before opening data sources (unix time), 0 until then", &startup_time);
    register_field("kismet.system.memory.startup_rss",
            "memory RSS in kbytes once Kismet had loaded, before opening data sources", &startup_rss);
    register_field("kismet.system.memory.startup_rss_anon",
            "anonymous RSS in kbytes once Kismet had loaded, before opening data sources", &startup_rss_anon);
    register_field("kismet.system.memory.startup_heap_used",
            "heap in use in kbytes once Kismet had loaded, before opening data sources, 0 when unknown",
            &startup_heap_used);
    register_field("kismet.system.memory.startup_heap_mmap",
            "large allocations mapped separately in kbytes once Kismet had loaded, before opening data sources",
            &startup_heap_mmap);
    register_field("kismet.system.memory.startup_fields",
            "tracked element fields once Kismet had loaded, before opening data sources", &startup_fields);

    register_field("kismet.system.memory.datasources", "number of data sources", &datasources);
    register_field("kismet.system.memory.datasource_estimate",
            "estimated heap each data source holds in Kismet, in kbytes, not counting its devices or "
            "its capture helper process", &datasource_estimate);
    register_field("kismet.system.memory.packet_pool", "freed packets kept for reuse", &packet_pool);
    register_field("kismet.system.memory.packet_pool_estimate",
            "estimated heap held by freed packets kept for reuse, in kbytes", &packet_pool_estimate);
    register_field("kismet.system.memory.dedupe_packets",
            "recent packets kept to recognize duplicates", &dedupe_packets);
    register_field("kismet.system.memory.dedupe_estimate",
            "estimated heap held by recent packets kept to recognize duplicates, in kbytes", &dedupe_estimate);

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

// Measured with empty and busy pcapfile sources and synthetic 802.11 beacons on x86_64
// Linux; estimates for working out what devices cost, not exact.  A packet in the duplicate
// window keeps its components and frame; a pooled packet has been reset.
constexpr uint64_t DATASOURCE_ESTIMATE_KB = 480;
constexpr uint64_t POOLED_PACKET_ESTIMATE_BYTES = 2150;
constexpr uint64_t DEDUPE_PACKET_ESTIMATE_BYTES = 4600;

void Systemmonitor::update_capture_memory() {
    auto datasourcetracker = Globalreg::fetch_global_as<datasource_tracker>();
    memstatus->set_datasources(datasourcetracker != nullptr ? datasourcetracker->get_num_datasources() : 0);
    memstatus->set_datasource_estimate(DATASOURCE_ESTIMATE_KB);

    auto packetchain = Globalreg::fetch_global_as<packet_chain>();
    const uint64_t pooled = packetchain != nullptr ? packetchain->get_packet_pool_size() : 0;
    memstatus->set_packet_pool(pooled);
    memstatus->set_packet_pool_estimate(pooled * POOLED_PACKET_ESTIMATE_BYTES / 1024);

    const uint64_t dedupe = packetchain != nullptr ? packetchain->get_dedupe_packets() : 0;
    memstatus->set_dedupe_packets(dedupe);
    memstatus->set_dedupe_estimate(dedupe * DEDUPE_PACKET_ESTIMATE_BYTES / 1024);

    // Packet processing starts after this list is made, so its thread count is filled in here
    if (packetchain != nullptr && packetchain->get_packet_threads() > 0)
        memstatus->get_settings()->insert("kismet_packet_threads",
                std::make_shared<tracker_element_uint64>(0, packetchain->get_packet_threads()));
}

void Systemmonitor::record_startup_memory() {
    kis_lock_guard<kis_mutex> lk(monitor_mutex, "startup memory");

#ifdef SYS_LINUX
    std::ifstream sf("/proc/self/status");
    std::string line;

    while (std::getline(sf, line)) {
        uint64_t v;

        if (sscanf(line.c_str(), "VmRSS: %" SCNu64, &v) == 1)
            memstatus->set_startup_rss(v);
        else if (sscanf(line.c_str(), "RssAnon: %" SCNu64, &v) == 1)
            memstatus->set_startup_rss_anon(v);
    }
#endif

#ifdef KIS_HAVE_MALLINFO2
    auto mi = mallinfo2();
    memstatus->set_startup_heap_used(mi.uordblks / 1024);
    memstatus->set_startup_heap_mmap(mi.hblkhd / 1024);
#endif

    memstatus->set_startup_fields(Globalreg::n_tracked_fields.load(std::memory_order_acquire));
    memstatus->set_startup_time(time(nullptr));
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

    register_field("kismet.system.cpu.available", "CPU load can be read", &cpu_available);
    register_field("kismet.system.cpu.count", "number of CPUs online", &cpu_count);
    register_field("kismet.system.cpu.total", "CPU load of the system, percent of all CPUs", &cpu_total);
    register_field("kismet.system.cpu.kismet",
            "CPU load of the Kismet server process, percent of all CPUs", &cpu_kismet);
}

void tracked_cpu_status::register_fields() {
    register_field("kismet.system.cpu.total_rrd", "CPU load of the system RRD", &total_rrd);
    register_field("kismet.system.cpu.kismet_rrd", "CPU load of the Kismet server RRD", &kismet_rrd);
}

// Called with monitor_mutex held
void Systemmonitor::update_cpu() {
#ifdef SYS_LINUX
    // cpu user nice system idle iowait irq softirq steal; guest time is already in user
    uint64_t user, nice, sys, idle, iowait, irq, softirq, steal;
    uint64_t utime, stime;

    FILE *sf = fopen("/proc/stat", "r");
    if (sf == nullptr)
        return;

    int r = fscanf(sf, "cpu %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
            " %" SCNu64 " %" SCNu64, &user, &nice, &sys, &idle, &iowait, &irq, &softirq, &steal);
    fclose(sf);

    // Kernels before 2.6.11 have no steal
    if (r == 7)
        steal = 0;
    else if (r != 8)
        return;

    std::ifstream pf("/proc/self/stat");
    std::string procline;

    if (!std::getline(pf, procline))
        return;

    // 'pid (name) state ...'; the name can hold spaces and parens, so the fields
    // start after the last paren.  utime and stime are fields 14 and 15.
    auto paren = procline.find_last_of(')');
    if (paren == std::string::npos ||
            sscanf(procline.c_str() + paren + 1, " %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %" SCNu64
                " %" SCNu64, &utime, &stime) != 2)
        return;

    uint64_t total = user + nice + sys + idle + iowait + irq + softirq + steal;
    uint64_t idle_all = idle + iowait;
    uint64_t proc = utime + stime;

    auto ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    status->set_cpu_count(ncpu > 0 ? ncpu : 0);

    // Counters only go up; anything else (a counter wrapping, or the first read)
    // starts over from this read
    if (cpu_primed && total > cpu_last_total && idle_all >= cpu_last_idle && proc >= cpu_last_proc) {
        double dtotal = total - cpu_last_total;
        double busy = dtotal - std::min<double>(dtotal, idle_all - cpu_last_idle);
        double sys_pct = std::clamp(100.0 * busy / dtotal, 0.0, 100.0);
        double kis_pct = std::clamp(100.0 * (proc - cpu_last_proc) / dtotal, 0.0, 100.0);

        status->set_cpu_available(true);
        status->set_cpu_total(sys_pct);
        status->set_cpu_kismet(kis_pct);

        auto now = Globalreg::globalreg->last_tv_sec.load();
        cpustatus->get_total_rrd()->add_sample(sys_pct, now);
        cpustatus->get_kismet_rrd()->add_sample(kis_pct, now);
    }

    cpu_last_total = total;
    cpu_last_idle = idle_all;
    cpu_last_proc = proc;
    cpu_primed = true;
#endif
}

int Systemmonitor::timetracker_event(int eventid) {
    // Sensor files are read before taking the lock
    host_env_scan scan;
    scan_host_environment(scan);

    kis_lock_guard<kis_mutex> lg(monitor_mutex, "system monitor timer");

    int num_devices = devicetracker->fetch_num_devices();

    // Grab the devices
    status->set_devices(num_devices);
    status->get_devices_rrd()->add_sample(num_devices, Globalreg::globalreg->last_tv_sec);

    update_proc_memory();
    update_cpu();

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

    record_host_environment(scan);

    return 1;
}

// Without monitor_mutex; libsensors is only used from the timer
void Systemmonitor::scan_host_environment(host_env_scan& scan) {
#if defined(SYS_LINUX)
    std::vector<kis_battery_reading> batteries;
    int ext_online;

    // The battery files are read once for the summary and the per-battery records.  A
    // kernel old enough to have /proc/acpi/battery keeps the old summary only.
    if (access("/proc/acpi/battery", F_OK) == 0) {
        fetch_battery_info(&scan.battery);
    } else {
        fetch_linux_power_supplies("/sys/class/power_supply", batteries, ext_online);
        aggregate_battery_info(batteries, ext_online, &scan.battery);
        env_battery_readings(batteries, ext_online, scan.readings);
    }

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

            if (!std::isfinite(val))
                continue;

            env_host_reading r;
            r.id = synth_name;
            r.value = val;

            if (fi->type == SENSORS_FEATURE_TEMP) {
                r.kind = env_kind::thermal;
                r.label = fmt::format("{} ({})", label_s, chip_s);
                scan.legacy_temps.push_back({synth_name, val});
            } else {
                r.kind = env_kind::fan;
                r.label = fmt::format("{} ({})", label_s, chip_s);
                scan.legacy_fans.push_back({synth_name, val});
            }

            scan.readings.push_back(r);
        }
    }
#else
    // Without libsensors, the same hwmon devices straight from sysfs
    env_read_hwmon("/sys/class/hwmon", scan.readings);
#endif

    std::vector<env_host_reading> zones;
    env_read_thermal_zones("/sys/class/thermal", zones);

    for (auto& z : zones) {
        scan.legacy_temps.push_back({z.id, z.value});
        scan.readings.push_back(std::move(z));
    }
#else
    fetch_battery_info(&scan.battery);
#endif
}

// Called with monitor_mutex held
void Systemmonitor::record_host_environment(const host_env_scan& scan) {
    time_t now = Globalreg::globalreg->last_tv_sec;

    status->set_battery_perc(scan.battery.percentage);
    if (scan.battery.ac && scan.battery.charging) {
        status->set_battery_charging("charging");
    } else if (scan.battery.ac && !scan.battery.charging) {
        status->set_battery_charging("charged");
    } else if (!scan.battery.ac) {
        status->set_battery_charging("discharging");
    }

    status->set_battery_ac(scan.battery.ac);
    status->set_battery_remaining(scan.battery.remaining_sec);

#if defined(SYS_LINUX)
    status->get_sensors_fans()->clear();
    status->get_sensors_temp()->clear();

    for (const auto& t : scan.legacy_temps)
        status->get_sensors_temp()->insert(t.first, std::make_shared<tracker_element_double>(0, t.second));

    for (const auto& f : scan.legacy_fans)
        status->get_sensors_fans()->insert(f.first, std::make_shared<tracker_element_double>(0, f.second));
#endif

    for (const auto& r : scan.readings)
        environment->record_host(r, now);
}

void Systemmonitor::sweep_environment() {
    auto datasourcetracker = Globalreg::fetch_global_as<datasource_tracker>();

    if (datasourcetracker == nullptr)
        return;

    // Source uuids are read before taking monitor_mutex, under the tracker's own locks
    std::unordered_set<uuid> live;

    class uuid_worker : public datasource_tracker_worker {
    public:
        uuid_worker(std::unordered_set<uuid>& in_live) : live{in_live} { }
        virtual void handle_datasource(shared_datasource in_src) override {
            live.insert(in_src->get_source_uuid());
        }
        virtual void finalize() override { }
    protected:
        std::unordered_set<uuid>& live;
    };

    uuid_worker worker(live);
    datasourcetracker->iterate_datasources(&worker);

    kis_lock_guard<kis_mutex> lk(monitor_mutex, "system monitor environment sweep");
    environment->sweep(live, time(0));
}

bool Systemmonitor::env_source_report(const uuid& in_uuid, const std::string& in_name,
        const env_report& in_report) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    const uint64_t mono_ms = static_cast<uint64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;

    kis_lock_guard<kis_mutex> lk(monitor_mutex, "system monitor environment report");
    return environment->record_source(in_uuid, in_name, in_report, Globalreg::globalreg->last_tv_sec, mono_ms);
}

void Systemmonitor::env_source_report_dropped() {
    kis_lock_guard<kis_mutex> lk(monitor_mutex, "system monitor environment drop");
    environment->count_dropped_report();
}

void tracked_system_status::pre_serialize() {
    kis_lock_guard<kis_mutex> lk(monitor_mutex);

    // The battery is read by the system monitor timer, with the other sensors

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

