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
#include "kis_net_microhttpd.h"

class Systemmonitor : public tracker_component, public Kis_Net_Httpd_CPPStream_Handler,
    public LifetimeGlobal, public TimetrackerEvent {
public:
    static std::shared_ptr<Systemmonitor> create_systemmonitor() {
        std::shared_ptr<Systemmonitor> mon(new Systemmonitor());
        Globalreg::globalreg->RegisterLifetimeGlobal(mon);
        Globalreg::globalreg->InsertGlobal("SYSTEMMONITOR", mon);
        return mon;
    }

private:
    Systemmonitor();

public:
    virtual ~Systemmonitor();

    virtual bool Httpd_VerifyPath(const char *path, const char *method) override;

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) override;

    __Proxy(battery_perc, int32_t, int32_t, int32_t, battery_perc);
    __Proxy(battery_charging, std::string, std::string, std::string, battery_charging);
    __Proxy(battery_ac, uint8_t, bool, bool, battery_ac);
    __Proxy(battery_remaining, uint32_t, uint32_t, uint32_t, battery_remaining);

    __Proxy(timestamp_sec, uint64_t, uint64_t, uint64_t, timestamp_sec);
    __Proxy(timestamp_usec, uint64_t, uint64_t, uint64_t, timestamp_usec);

    __Proxy(timestamp_start_sec, uint64_t, time_t, time_t, timestamp_start_sec);

    __Proxy(memory, uint64_t, uint64_t, uint64_t, memory);
    __Proxy(devices, uint64_t, uint64_t, uint64_t, devices);

    __Proxy(username, std::string, std::string, std::string, username);

    __Proxy(server_uuid, uuid, uuid, uuid, server_uuid);
    __Proxy(server_name, std::string, std::string, std::string, server_name);
    __Proxy(server_description, std::string, std::string, std::string, server_description);
    __Proxy(server_location, std::string, std::string, std::string, server_location);

    virtual void pre_serialize() override;

    // Timetracker callback
    virtual int timetracker_event(int eventid) override;

protected:
    kis_recursive_timed_mutex monitor_mutex;

    virtual void register_fields() override;

    std::shared_ptr<Devicetracker> devicetracker;

    std::shared_ptr<TrackerElementUInt32> battery_perc;
    std::shared_ptr<TrackerElementString> battery_charging;
    std::shared_ptr<TrackerElementUInt8> battery_ac;
    std::shared_ptr<TrackerElementUInt32> battery_remaining;
    std::shared_ptr<TrackerElementUInt64> timestamp_sec;
    std::shared_ptr<TrackerElementUInt64> timestamp_usec;
    std::shared_ptr<TrackerElementUInt64> timestamp_start_sec;
    std::shared_ptr<TrackerElementUInt64> memory;
    std::shared_ptr<TrackerElementString> username;
    std::shared_ptr<TrackerElementUUID> server_uuid;
    std::shared_ptr<TrackerElementString> server_name;
    std::shared_ptr<TrackerElementString> server_description;
    std::shared_ptr<TrackerElementString> server_location;

    int mem_rrd_id;
    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> memory_rrd;

    int devices_id;
    std::shared_ptr<TrackerElementUInt64> devices;

    int devices_rrd_id;
    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator> > devices_rrd;

    long mem_per_page;
};

#endif

