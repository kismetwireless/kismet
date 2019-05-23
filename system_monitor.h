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

class Eventbus;

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

    tracked_system_status(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    virtual ~tracked_system_status() { }

    __Proxy(battery_perc, int32_t, int32_t, int32_t, battery_perc);
    __Proxy(battery_charging, std::string, std::string, std::string, battery_charging);
    __Proxy(battery_ac, uint8_t, bool, bool, battery_ac);
    __Proxy(battery_remaining, uint32_t, uint32_t, uint32_t, battery_remaining);

    __Proxy(timestamp_sec, uint64_t, uint64_t, uint64_t, timestamp_sec);
    __Proxy(timestamp_usec, uint64_t, uint64_t, uint64_t, timestamp_usec);
    __ProxyTrackable(timestamp_sec, TrackerElementUInt64, timestamp_sec);
    __ProxyTrackable(timestamp_usec, TrackerElementUInt64, timestamp_usec);

    __Proxy(timestamp_start_sec, uint64_t, time_t, time_t, timestamp_start_sec);

    __Proxy(memory, uint64_t, uint64_t, uint64_t, memory);
    __Proxy(devices, uint64_t, uint64_t, uint64_t, devices);

    __Proxy(username, std::string, std::string, std::string, username);
    __Proxy(server_version, std::string, std::string, std::string, server_version);
    __Proxy(server_git, std::string, std::string, std::string, server_git);
    __Proxy(build_time, std::string, std::string, std::string, build_time);

    __Proxy(server_uuid, uuid, uuid, uuid, server_uuid);
    __Proxy(server_name, std::string, std::string, std::string, server_name);
    __Proxy(server_description, std::string, std::string, std::string, server_description);
    __Proxy(server_location, std::string, std::string, std::string, server_location);

    __ProxyTrackable(memory_rrd, kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>, memory_rrd);
    __ProxyTrackable(devices_rrd, kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>, devices_rrd);

    __ProxyTrackable(sensors_fans, TrackerElementStringMap, sensors_fans);
    __ProxyTrackable(sensors_temp, TrackerElementStringMap, sensors_temp);

    virtual void pre_serialize() override;

protected:
    kis_recursive_timed_mutex monitor_mutex;

    virtual void register_fields() override;

    std::shared_ptr<Devicetracker> devicetracker;

    std::shared_ptr<TrackerElementInt32> battery_perc;
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
    std::shared_ptr<TrackerElementString> server_version;
    std::shared_ptr<TrackerElementString> server_git;
    std::shared_ptr<TrackerElementString> build_time;

    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> memory_rrd;
    std::shared_ptr<TrackerElementUInt64> devices;
    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator> > devices_rrd;

    std::shared_ptr<TrackerElementStringMap> sensors_fans;
    std::shared_ptr<TrackerElementStringMap> sensors_temp;
};

class Systemmonitor : public LifetimeGlobal, public TimetrackerEvent {
public:
    static std::string global_name() { return "SYSTEMMONITOR"; }

    static std::shared_ptr<Systemmonitor> create_systemmonitor() {
        std::shared_ptr<Systemmonitor> mon(new Systemmonitor());
        Globalreg::globalreg->RegisterLifetimeGlobal(mon);
        Globalreg::globalreg->InsertGlobal(global_name(), mon);
        return mon;
    }

private:
    Systemmonitor();

public:
    virtual ~Systemmonitor();

    // Timetracker callback
    virtual int timetracker_event(int eventid) override;

protected:
    kis_recursive_timed_mutex monitor_mutex;

    std::shared_ptr<Eventbus> eventbus;
    int logopen_evt_id;

    std::shared_ptr<Kis_Net_Httpd_Simple_Tracked_Endpoint> monitor_endp;
    std::shared_ptr<Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint> user_monitor_endp;
    std::shared_ptr<Kis_Net_Httpd_Simple_Tracked_Endpoint> timestamp_endp;

    std::shared_ptr<Devicetracker> devicetracker;

    std::shared_ptr<tracked_system_status> status;

    long mem_per_page;

    int kismetdb_log_timer;
};

#endif

