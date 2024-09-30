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

#include <memory>

#include <fstream>
#include <unistd.h>

#include <pwd.h>

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

    status->set_server_name(Globalreg::globalreg->kismet_config->fetch_opt("server_name"));
    status->set_server_description(Globalreg::globalreg->kismet_config->fetch_opt("server_description"));
    status->set_server_location(Globalreg::globalreg->kismet_config->fetch_opt("server_location"));

#if defined(SYS_LINUX) and defined(HAVE_SENSORS_SENSORS_H)
    sensors_init(NULL);
#endif

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


                status->post_serialize();

                return 1;
                });

}

Systemmonitor::~Systemmonitor() {
    kis_lock_guard<kis_mutex> lk(monitor_mutex);

    Globalreg::globalreg->remove_global("SYSTEMMONITOR");

    timetracker->remove_timer(timer_id);
    timetracker->remove_timer(kismetdb_log_timer);
    timetracker->remove_timer(event_timer_id);

    eventbus->remove_listener(logopen_evt_id);
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

#if defined(SYS_LINUX)
    status->get_sensors_fans()->clear();
    status->get_sensors_temp()->clear();

#if defined(HAVE_SENSORS_SENSORS_H)
    int sensor_nr = 0;
    while (auto chip = sensors_get_detected_chips(NULL, &sensor_nr)) {
        int i = 0;
        while (auto fi = sensors_get_features(chip, &i)) {
            char *label;
            char chipname[64];
            const char* adapter_name;
            double val;
            const sensors_subfeature *sf;

            std::string synth_name;

            switch (fi->type) {
                case SENSORS_FEATURE_TEMP:
                    sf = sensors_get_subfeature(chip, fi, SENSORS_SUBFEATURE_TEMP_INPUT);

                    if (sf == nullptr)
                        break;

                    adapter_name = sensors_get_adapter_name(&chip->bus);
                    sensors_snprintf_chip_name(chipname, 64, chip);
                    label = sensors_get_label(chip, fi);
                    sensors_get_value(chip, sf->number, &val);

                    synth_name = fmt::format("{}-{}-{}", 
                            munge_to_printable(chipname),
                            munge_to_printable(label),
                            munge_to_printable(adapter_name));

                    status->get_sensors_temp()->insert(synth_name, 
                            std::make_shared<tracker_element_double>(0, val));

                    free(label);

                    break;

                case SENSORS_FEATURE_FAN:
                    sf = sensors_get_subfeature(chip, fi, SENSORS_SUBFEATURE_FAN_INPUT);

                    if (sf == nullptr)
                        break;

                    adapter_name = sensors_get_adapter_name(&chip->bus);
                    sensors_snprintf_chip_name(chipname, 64, chip);
                    label = sensors_get_label(chip, fi);
                    sensors_get_value(chip, sf->number, &val);

                    synth_name = fmt::format("{}-{}-{}", 
                            munge_to_printable(chipname),
                            munge_to_printable(label),
                            munge_to_printable(adapter_name));

                    status->get_sensors_fans()->insert(synth_name, 
                            std::make_shared<tracker_element_double>(0, val));

                    free(label);

                    break;
                default:
                    break;
            }
        }
    }
#endif

    // Try reading the system temperature for newer linuxes
    FILE *tempf = fopen("/sys/class/thermal/thermal_zone0/temp", "r");

    if (tempf != NULL) {
        std::string synth_name = "system-thermal-0";
        double temp;

        if (fscanf(tempf, "%lf", &temp) == 1) {
            temp = temp / 1000;
            status->get_sensors_temp()->insert(synth_name, std::make_shared<tracker_element_double>(0, temp));
        }


        fclose(tempf);
    }

#endif

    return 1;
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

    set_num_fields(Globalreg::n_tracked_fields);
    set_num_components(Globalreg::n_tracked_components);
    set_num_http_connections(Globalreg::n_tracked_http_connections);

    unsigned int csize = 0;
    unsigned long cbytes = 0;
    Globalreg::cache_string_stats(csize, cbytes);

    set_string_cache_sz(csize);

} 

