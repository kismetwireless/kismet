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

#include "globalregistry.h"
#include "util.h"
#include "battery.h"
#include "entrytracker.h"
#include "system_monitor.h"
#include "msgpack_adapter.h"
#include "json_adapter.h"

Systemmonitor::Systemmonitor(GlobalRegistry *in_globalreg) :
    tracker_component(in_globalreg, 0),
    Kis_Net_Httpd_Stream_Handler(in_globalreg) {

    // Initialize as recursive to allow multiple locks in a single thread
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&monitor_mutex, &mutexattr);

    globalreg = in_globalreg;

    devicetracker =
        static_pointer_cast<Devicetracker>(globalreg->FetchGlobal("DEVICE_TRACKER"));

    register_fields();
    reserve_fields(NULL);

#ifdef SYS_LINUX
    // Get the bytes per page
    mem_per_page = sysconf(_SC_PAGESIZE);
#endif

    struct timeval trigger_tm;
    trigger_tm.tv_sec = globalreg->timestamp.tv_sec + 1;
    trigger_tm.tv_usec = 0;

    timer_id = 
        globalreg->timetracker->RegisterTimer(0, &trigger_tm, 0, this);
}

Systemmonitor::~Systemmonitor() {
    pthread_mutex_lock(&monitor_mutex);
    globalreg->RemoveGlobal("SYSTEM_MONITOR");
    globalreg->timetracker->RemoveTimer(timer_id);
    pthread_mutex_destroy(&monitor_mutex);
}

void Systemmonitor::register_fields() {
    battery_perc_id =
        RegisterField("kismet.system.battery.percentage", TrackerInt32,
                "remaining battery percentage", &battery_perc);
    battery_charging_id =
        RegisterField("kismet.system.battery.charging", TrackerString,
                "battery charging state", &battery_charging);
    battery_ac_id =
        RegisterField("kismet.system.battery.ac", TrackerUInt8,
                "on AC power", &battery_ac);
    battery_remaining_id =
        RegisterField("kismet.system.battery.remaining", TrackerUInt32,
                "battery remaining in seconds", &battery_remaining);

    mem_id = 
        RegisterField("kismet.system.memory.rss", TrackerUInt64,
                "memory RSS in kbytes", &memory);

    devices_id =
        RegisterField("kismet.system.devices.count", TrackerUInt64,
                "number of devices in devicetracker", &devices);

    shared_ptr<kis_tracked_rrd<> > rrd_builder(new kis_tracked_rrd<>(globalreg, 0));

    mem_rrd_id =
        RegisterComplexField("kismet.device.memory.rrd", rrd_builder, 
                "memory used RRD"); 

    devices_rrd_id =
        RegisterComplexField("kismet.device.devices.rrd", rrd_builder, 
                "device count RRD");
}

void Systemmonitor::reserve_fields(SharedTrackerElement e) {
    tracker_component::reserve_fields(e);

    if (e != NULL) {
        memory_rrd.reset(new kis_tracked_rrd<>(globalreg, mem_rrd_id,
                    e->get_map_value(mem_rrd_id)));
        devices_rrd.reset(new kis_tracked_rrd<>(globalreg, devices_rrd_id,
                    e->get_map_value(devices_rrd_id)));
    } else {
        memory_rrd.reset(new kis_tracked_rrd<>(globalreg, mem_rrd_id));
        devices_rrd.reset(new kis_tracked_rrd<>(globalreg, devices_rrd_id));
    }

    add_map(memory_rrd);
    add_map(devices_rrd);
}

int Systemmonitor::timetracker_event(int eventid) {
    local_locker lock(&monitor_mutex);

    int num_devices = devicetracker->FetchNumDevices(KIS_PHY_ANY);

    // Grab the devices
    set_devices(num_devices);
    devices_rrd->add_sample(num_devices, globalreg->timestamp.tv_sec);

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

        if (paren != string::npos) {
            vector<string> toks = 
                StrTokenize(procline.substr(paren + 1, procline.length()), " ");

            if (toks.size() > 22) {
                unsigned long int m;

                if (sscanf(toks[22].c_str(), "%lu", &m) == 1) {
                    m *= mem_per_page;

                    m /= 1024;

                    set_memory(m);
                    memory_rrd->add_sample(m, globalreg->timestamp.tv_sec);
                }
            }
        }
    }

#endif

    // Reschedule
    struct timeval trigger_tm;
    trigger_tm.tv_sec = globalreg->timestamp.tv_sec + 1;
    trigger_tm.tv_usec = 0;

    timer_id = 
        globalreg->timetracker->RegisterTimer(0, &trigger_tm, 0, this);

    return 1;
}

void Systemmonitor::pre_serialize() {
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
}

bool Systemmonitor::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    if (strcmp(path, "/system/status.msgpack") == 0)
        return true;
    if (strcmp(path, "/system/status.json") == 0)
        return true;

    return false;
}

void Systemmonitor::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        struct MHD_Connection *connection __attribute__((unused)),
        const char *path, const char *method, 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    local_locker lock(&monitor_mutex);

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (strcmp(path, "/system/status.msgpack") == 0) {
        MsgpackAdapter::Pack(globalreg, stream, 
            static_pointer_cast<Systemmonitor>(globalreg->FetchGlobal("SYSTEM_MONITOR")));
    } else if (strcmp(path, "/system/status.json") == 0) {
        JsonAdapter::Pack(globalreg, stream, 
            static_pointer_cast<Systemmonitor>(globalreg->FetchGlobal("SYSTEM_MONITOR")));
    }

}

