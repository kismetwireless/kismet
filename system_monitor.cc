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
    LifetimeGlobal() {

    devicetracker = Globalreg::FetchMandatoryGlobalAs<Devicetracker>();
    eventbus = Globalreg::FetchMandatoryGlobalAs<Eventbus>();

    status = std::make_shared<tracked_system_status>();

#ifdef SYS_LINUX
    // Get the bytes per page
    mem_per_page = sysconf(_SC_PAGESIZE);
#endif

    struct timeval trigger_tm;
    trigger_tm.tv_sec = time(0) + 1;
    trigger_tm.tv_usec = 0;

    auto timetracker = Globalreg::FetchMandatoryGlobalAs<Timetracker>();
    timer_id = 
        timetracker->RegisterTimer(0, &trigger_tm, 0, this);

    // Link the RRD out of the devicetracker
    status->insert(devicetracker->get_packets_rrd());

    // Set the startup time
    status->set_timestamp_start_sec(time(0));

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

    status->set_server_uuid(Globalreg::globalreg->server_uuid);

    status->set_server_version(fmt::format("{}-{}-{}", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY));
    status->set_server_git(VERSION_GIT_COMMIT);
    status->set_build_time(VERSION_BUILD_TIME);

    status->set_server_name(Globalreg::globalreg->kismet_config->FetchOpt("server_name"));
    status->set_server_description(Globalreg::globalreg->kismet_config->FetchOpt("server_description"));
    status->set_server_location(Globalreg::globalreg->kismet_config->FetchOpt("server_location"));

#if defined(SYS_LINUX) and defined(HAVE_SENSORS_SENSORS_H)
    sensors_init(NULL);
#endif

    monitor_endp = 
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>("/system/status", 
                status, &monitor_mutex);
    user_monitor_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint>("/system/user_status", 
            [this](void) -> std::shared_ptr<TrackerElement> {
                auto use = std::make_shared<TrackerElementMap>();

                use->insert(status->get_tracker_username());

                return use;
            });
    timestamp_endp = 
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>("/system/timestamp", 
            [this](void) -> std::shared_ptr<TrackerElement> {
                auto tse = std::make_shared<TrackerElementMap>();

                tse->insert(status->get_tracker_timestamp_sec());
                tse->insert(status->get_tracker_timestamp_usec());

                struct timeval now;
                gettimeofday(&now, NULL);

                status->set_timestamp_sec(now.tv_sec);
                status->set_timestamp_usec(now.tv_usec);

                return tse;
            });

    if (Globalreg::globalreg->kismet_config->FetchOptBoolean("kis_log_system_status", true)) {
        auto snap_time_s = 
            Globalreg::globalreg->kismet_config->FetchOptAs<unsigned int>("kis_log_system_status_rate", 30);

        kismetdb_log_timer =
            timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * snap_time_s, nullptr, 1, 
                    [this](int) -> int {
                        auto kismetdb = Globalreg::FetchGlobalAs<KisDatabaseLogfile>();

                        if (kismetdb == nullptr)
                            return 1;

                        struct timeval tv;
                        gettimeofday(&tv, nullptr);

                        std::stringstream js;

                        {
                            local_locker l(&monitor_mutex);
                            Globalreg::globalreg->entrytracker->Serialize("json", js, status, NULL);
                        }

                        kismetdb->log_snapshot(nullptr, tv, "SYSTEM", js.str());

                        return 1;
                    });
    } else {
        kismetdb_log_timer = -1;
    }

    // Always drop a SYSTEM snapshot as soon as the log opens
    logopen_evt_id = 
        eventbus->register_listener(KisDatabaseLogfile::EventDblogOpened::log_type(),
            [this](std::shared_ptr<EventbusEvent> evt) {
                auto kismetdb = Globalreg::FetchGlobalAs<KisDatabaseLogfile>();

                if (kismetdb == nullptr)
                    return;

                struct timeval tv;
                gettimeofday(&tv, nullptr);

                std::stringstream js;

                {
                    local_locker l(&monitor_mutex);
                    Globalreg::globalreg->entrytracker->Serialize("json", js, status, NULL);
                }

                kismetdb->log_snapshot(nullptr, tv, "SYSTEM", js.str());
            });

}

Systemmonitor::~Systemmonitor() {
    local_locker lock(&monitor_mutex);

    Globalreg::globalreg->RemoveGlobal("SYSTEMMONITOR");

    auto timetracker = Globalreg::FetchGlobalAs<Timetracker>("TIMETRACKER");
    if (timetracker != nullptr) {
        timetracker->RemoveTimer(timer_id);
        timetracker->RemoveTimer(kismetdb_log_timer);
    }

    eventbus->remove_listener(logopen_evt_id);
}

void tracked_system_status::register_fields() {
    RegisterField("kismet.system.battery.percentage", "remaining battery percentage", &battery_perc);
    RegisterField("kismet.system.battery.charging", "battery charging state", &battery_charging);
    RegisterField("kismet.system.battery.ac", "on AC power", &battery_ac);
    RegisterField("kismet.system.battery.remaining", 
            "battery remaining in seconds", &battery_remaining);
    RegisterField("kismet.system.timestamp.sec", "system timestamp, seconds", &timestamp_sec);
    RegisterField("kismet.system.timestamp.usec", "system timestamp, usec", &timestamp_usec);
    RegisterField("kismet.system.timestamp.start_sec", 
            "system startup timestamp, seconds", &timestamp_start_sec);
    RegisterField("kismet.system.memory.rss", "memory RSS in kbytes", &memory);
    RegisterField("kismet.system.devices.count", "number of devices in devicetracker", &devices);
    RegisterField("kismet.system.user", "user Kismet is running as", &username);
    RegisterField("kismet.system.version", "Kismet version string", &server_version);
    RegisterField("kismet.system.git", "Git commit string", &server_git);
    RegisterField("kismet.system.build_time", "Server build time", &build_time);
    RegisterField("kismet.system.server_uuid", "UUID of kismet server", &server_uuid);
    RegisterField("kismet.system.server_name", "Arbitrary name of server instance", &server_name);
    RegisterField("kismet.system.server_description", "Arbitrary server description", &server_description);
    RegisterField("kismet.system.server_location", "Arbitrary server location string", &server_location);

    RegisterField("kismet.system.memory.rrd", "memory used RRD", &memory_rrd); 
    RegisterField("kismet.system.devices.rrd", "device count RRD", &devices_rrd);

    RegisterField("kismet.system.sensors.fan", "fan sensors", &sensors_fans);
    RegisterField("kismet.system.sensors.temp", "temperature sensors", &sensors_temp);
}

int Systemmonitor::timetracker_event(int eventid) {
    local_locker lock(&monitor_mutex);

    int num_devices = devicetracker->FetchNumDevices();

    // Grab the devices
    status->set_devices(num_devices);
    status->get_devices_rrd()->add_sample(num_devices, time(0));

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
                StrTokenize(procline.substr(paren + 1, procline.length()), " ");

            if (toks.size() > 22) {
                unsigned long int m;

                if (sscanf(toks[22].c_str(), "%lu", &m) == 1) {
                    m *= mem_per_page;

                    m /= 1024;

                    status->set_memory(m);
                    status->get_memory_rrd()->add_sample(m, time(0));
                }
            }
        }
    }

#endif

#if defined(SYS_LINUX) and defined(HAVE_SENSORS_SENSORS_H)
    status->get_sensors_fans()->clear();
    status->get_sensors_temp()->clear();

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
                            MungeToPrintable(chipname),
                            MungeToPrintable(label),
                            MungeToPrintable(adapter_name));

                    status->get_sensors_temp()->insert(synth_name, 
                            std::make_shared<TrackerElementDouble>(0, val));

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
                            MungeToPrintable(chipname),
                            MungeToPrintable(label),
                            MungeToPrintable(adapter_name));

                    status->get_sensors_fans()->insert(synth_name, 
                            std::make_shared<TrackerElementDouble>(0, val));

                    free(label);

                    break;
                default:
                    break;
            }
        }
    }


#endif

    // Reschedule
    struct timeval trigger_tm;
    trigger_tm.tv_sec = time(0) + 1;
    trigger_tm.tv_usec = 0;

    timer_id = 
        Globalreg::globalreg->timetracker->RegisterTimer(0, &trigger_tm, 0, this);

    return 1;
}

void tracked_system_status::pre_serialize() {
    local_locker lock(&monitor_mutex);

    kis_battery_info batinfo;
    Fetch_Battery_Info(&batinfo);

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
}

