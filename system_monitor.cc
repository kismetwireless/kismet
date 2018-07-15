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

#include "globalregistry.h"
#include "util.h"
#include "battery.h"
#include "entrytracker.h"
#include "system_monitor.h"
#include "json_adapter.h"

Systemmonitor::Systemmonitor() :
    tracker_component(),
    Kis_Net_Httpd_CPPStream_Handler(Globalreg::globalreg) {

    devicetracker =
        Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER");

    register_fields();
    reserve_fields(NULL);

#ifdef SYS_LINUX
    // Get the bytes per page
    mem_per_page = sysconf(_SC_PAGESIZE);
#endif

    struct timeval trigger_tm;
    trigger_tm.tv_sec = time(0) + 1;
    trigger_tm.tv_usec = 0;

    auto timetracker = Globalreg::FetchMandatoryGlobalAs<Timetracker>("TIMETRACKER");
    timer_id = 
        timetracker->RegisterTimer(0, &trigger_tm, 0, this);

    // Link the RRD out of the devicetracker
    insert(devicetracker->get_packets_rrd());

    // Set the startup time
    set_timestamp_start_sec(time(0));

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

    set_username(uidstr.str());

    set_server_uuid(Globalreg::globalreg->server_uuid);

    set_server_name(Globalreg::globalreg->kismet_config->FetchOpt("server_name"));
    set_server_description(Globalreg::globalreg->kismet_config->FetchOpt("server_description"));
    set_server_location(Globalreg::globalreg->kismet_config->FetchOpt("server_location"));

#if defined(SYS_LINUX) and defined(HAVE_SENSORS_SENSORS_H)
    sensors_init(NULL);
#endif

}

Systemmonitor::~Systemmonitor() {
    local_locker lock(&monitor_mutex);

    Globalreg::globalreg->RemoveGlobal("SYSTEMMONITOR");

    auto timetracker = Globalreg::FetchGlobalAs<Timetracker>("TIMETRACKER");
    if (timetracker != nullptr)
        timetracker->RemoveTimer(timer_id);
}

void Systemmonitor::register_fields() {
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
    RegisterField("kismet.system.server_uuid", "UUID of kismet server", &server_uuid);
    RegisterField("kismet.system.server_name", "Arbitrary name of server instance", &server_name);
    RegisterField("kismet.system.server_description", 
            "Arbitrary server description", &server_description);
    RegisterField("kismet.system.server_location", 
            "Arbitrary server location string", &server_location);

    RegisterField("kismet.system.memory.rrd", "memory used RRD", &memory_rrd); 
    RegisterField("kismet.system.devices.rrd", "device count RRD", &devices_rrd);

    RegisterField("kismet.system.sensors.fan", "fan sensors", &sensors_fans);
    RegisterField("kismet.system.sensors.temp", "temperature sensors", &sensors_temp);
}

int Systemmonitor::timetracker_event(int eventid) {
    local_locker lock(&monitor_mutex);

    int num_devices = devicetracker->FetchNumDevices();

    // Grab the devices
    set_devices(num_devices);
    devices_rrd->add_sample(num_devices, time(0));

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

                    set_memory(m);
                    memory_rrd->add_sample(m, time(0));
                }
            }
        }
    }

#endif

#if defined(SYS_LINUX) and defined(HAVE_SENSORS_SENSORS_H)
    sensors_fans->clear();
    sensors_temp->clear();

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

                    sensors_temp->insert(synth_name, 
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

                    sensors_fans->insert(synth_name, 
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

void Systemmonitor::pre_serialize() {
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

bool Systemmonitor::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    std::string stripped = Httpd_StripSuffix(path);

    if (!Httpd_CanSerialize(path))
        return false;

    if (stripped == "/system/status")
        return true;

    if (stripped == "/system/timestamp")
        return true;

    return false;
}

void Systemmonitor::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection __attribute__((unused)),
        const char *path, const char *method, 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    local_locker lock(&monitor_mutex);

    if (strcmp(method, "GET") != 0) {
        return;
    }

    std::string stripped = Httpd_StripSuffix(path);

    if (!Httpd_CanSerialize(path))
        return;

    if (stripped == "/system/status") {
        Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(path), stream,
                Globalreg::FetchMandatoryGlobalAs<Systemmonitor>("SYSTEMMONITOR"), 
                nullptr);

        return;
    } else if (stripped == "/system/timestamp") {
        auto tse = std::make_shared<TrackerElementMap>();

        tse->insert(timestamp_sec);
        tse->insert(timestamp_usec);

        struct timeval now;
        gettimeofday(&now, NULL);

        set_timestamp_sec(now.tv_sec);
        set_timestamp_usec(now.tv_usec);

        Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(path), stream, tse, NULL);

        return;
    } else {
        return;
    }
}

