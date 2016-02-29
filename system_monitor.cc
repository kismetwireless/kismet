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
#include "battery.h"
#include "entrytracker.h"
#include "system_monitor.h"
#include "msgpack_adapter.h"

Systemmonitor::Systemmonitor(GlobalRegistry *in_globalreg) :
    tracker_component(in_globalreg, 0) {

    globalreg = in_globalreg;

    globalreg->InsertGlobal("SYSTEM_MONITOR", this);

    register_fields();
    reserve_fields(NULL);

    globalreg->httpd_server->RegisterHandler(this);
}

Systemmonitor::~Systemmonitor() {
    globalreg->RemoveGlobal("SYSTEM_MONITOR");

    globalreg->httpd_server->RemoveHandler(this);
}

void Systemmonitor::register_fields() {
    battery_perc_id =
        RegisterField("kismet.system.battery.percentage", TrackerInt32,
                "remaining battery percentage", (void **) &battery_perc);
    battery_charging_id =
        RegisterField("kismet.system.battery.charging", TrackerString,
                "battery charging state", (void **) &battery_charging);
    battery_ac_id =
        RegisterField("kismet.system.battery.ac", TrackerUInt8,
                "on AC power", (void **) &battery_ac);
    battery_remaining_id =
        RegisterField("kismet.system.battery.remaining", TrackerUInt32,
                "battery remaining in seconds", (void **) &battery_remaining);
}

bool Systemmonitor::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    if (strcmp(path, "/system/status.msgpack") == 0)
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

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (strcmp(path, "/system/status.msgpack") == 0) {

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

        MsgpackAdapter::Pack(globalreg, stream, this);

        return;
    }

}

