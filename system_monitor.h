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
    static shared_ptr<Systemmonitor> create_systemmonitor(GlobalRegistry *in_globalreg) {
        shared_ptr<Systemmonitor> mon(new Systemmonitor(in_globalreg));
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal("SYSTEM_MONITOR", mon);
        return mon;
    }

private:
    Systemmonitor(GlobalRegistry *in_globalreg);

public:
    virtual ~Systemmonitor();

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    __Proxy(battery_perc, int32_t, int32_t, int32_t, battery_perc);
    __Proxy(battery_charging, string, string, string, battery_charging);
    __Proxy(battery_ac, uint8_t, bool, bool, battery_ac);
    __Proxy(battery_remaining, uint32_t, uint32_t, uint32_t, battery_remaining);

    __Proxy(timestamp_sec, uint64_t, uint64_t, uint64_t, timestamp_sec);
    __Proxy(timestamp_usec, uint64_t, uint64_t, uint64_t, timestamp_usec);

    __Proxy(memory, uint64_t, uint64_t, uint64_t, memory);
    __Proxy(devices, uint64_t, uint64_t, uint64_t, devices);

    virtual void pre_serialize();

    // Timetracker callback
    virtual int timetracker_event(int eventid);

protected:
    kis_recursive_timed_mutex monitor_mutex;

    virtual void register_fields();
    virtual void reserve_fields(SharedTrackerElement e);

    shared_ptr<Devicetracker> devicetracker;

    int battery_perc_id;
    SharedTrackerElement battery_perc;

    int battery_charging_id;
    SharedTrackerElement battery_charging;

    int battery_ac_id;
    SharedTrackerElement battery_ac;

    int battery_remaining_id;
    SharedTrackerElement battery_remaining;

    int timestamp_sec_id;
    SharedTrackerElement timestamp_sec;

    int timestamp_usec_id;
    SharedTrackerElement timestamp_usec;

    int mem_id;
    SharedTrackerElement memory;

    int mem_rrd_id;
    shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator> > memory_rrd;

    int devices_id;
    SharedTrackerElement devices;

    int devices_rrd_id;
    shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator> > devices_rrd;

    long mem_per_page;
};

#endif

