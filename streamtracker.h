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

#ifndef __STREAMTRACKER_V2_H__
#define __STREAMTRACKER_V2_H__

#include "config.hpp"

#include <memory>

#include "globalregistry.h"
#include "trackedelement.h"
#include "kis_net_microhttpd.h"
#include "devicetracker_component.h"

class streaming_agent {
public:
    streaming_agent() {
        stream_id = 0;
        log_packets = 0;
        log_size = 0;
    }

    virtual ~streaming_agent() { };

    void stop_stream(string in_reason __attribute__((unused))) { };

    uint64_t get_log_size() { return log_size; }
    uint64_t get_log_packets() { return log_packets; }

    uint64_t get_stream_id() { return stream_id; }
    void set_stream_id(uint64_t id) { stream_id = id; }

protected:
    uint64_t stream_id;
    uint64_t log_size;
    uint64_t log_packets;
};

class streaming_info_record : public tracker_component {
public:
    streaming_info_record(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    streaming_info_record(GlobalRegistry *in_globalreg, int in_id, 
            SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new streaming_info_record(globalreg, get_id()));
    }

    __Proxy(log_name, string, string, string, log_name);
    __Proxy(log_type, string, string, string, log_type);
    __Proxy(log_path, string, string, string, log_path);
    __Proxy(log_description, string, string, string, log_description);

    __Proxy(log_packets, uint64_t, uint64_t, uint64_t, log_packets);
    __Proxy(log_size, uint64_t, uint64_t, uint64_t, log_size);

    virtual void pre_serialize() {
        // Due to other semantics it doesn't make sense to try to make the agent
        // itself a trackable component, we'll just grab it's data out when we're
        // about to serialize
        if (agent != NULL) {
            set_log_packets(agent->get_log_packets());
            set_log_size(agent->get_log_size());
        }
    }

protected:

    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.stream.name", TrackerString,
                "Stream / Log name", &log_name);

        RegisterField("kismet.stream.type", TrackerString,
                "Stream / Log type", &log_type);

        RegisterField("kismet.stream.path", TrackerString,
                "Log path or stream remote client", &log_path);

        RegisterField("kismet.stream.description", TrackerString,
                "Stream / Log description", &log_description);

        RegisterField("kismet.stream.packets", TrackerUInt64,
                "Number of packets (if known)", &log_packets);

        RegisterField("kismet.stream.size", TrackerUInt64,
                "Size of log, if known, in bytes", &log_size);
    }

    // Log name
    SharedTrackerElement log_name;

    // Arbitrary log type ('pcapng', 'netxml', 'foo')
    SharedTrackerElement log_type;

    // Log path (local directory or remote client
    SharedTrackerElement log_path;

    // Arbitrary description
    SharedTrackerElement log_description;

    // Number of packets, if known
    SharedTrackerElement log_packets;

    // Size of log, if known
    SharedTrackerElement log_size;

    shared_ptr<streaming_agent> agent;
};

#endif

