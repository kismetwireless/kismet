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

#ifndef __STREAMTRACKER_H__
#define __STREAMTRACKER_H__

#include "config.h"

#include <memory>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "trackedelement.h"
#include "kis_net_microhttpd.h"
#include "devicetracker_component.h"

class streaming_agent {
public:
    streaming_agent() {
        stream_id = 0;
        log_packets = 0;
        log_size = 0;
        max_size = 0;
        max_packets = 0;
        stream_paused = false;
    }

    virtual ~streaming_agent() { };

    virtual void stop_stream(string in_reason __attribute__((unused))) { };

    uint64_t get_log_size() { return log_size; }
    uint64_t get_log_packets() { return log_packets; }

    void set_max_size(uint64_t in_sz) { max_size = in_sz; }
    uint64_t get_max_size() { return max_size; }

    void set_max_packets(uint64_t in_pk) { max_packets = in_pk; }
    uint64_t get_max_packets() { return max_packets; }

    double get_stream_id() { return stream_id; }
    void set_stream_id(double id) { stream_id = id; }

    virtual bool check_over_size() { 
        return (max_size != 0 && log_size > max_size); 
    }

    virtual bool check_over_packets() { 
        return (max_packets != 0 && log_packets > max_packets); 
    }

    virtual bool get_stream_paused() { return stream_paused; }
    virtual void pause_stream() { stream_paused = true; }
    virtual void resume_stream() { stream_paused = false; }

protected:
    double stream_id;
    uint64_t log_size;
    uint64_t log_packets;

    uint64_t max_size;
    uint64_t max_packets;

    bool stream_paused;
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

    __Proxy(stream_id, double, double, double, stream_id);

    __Proxy(log_name, string, string, string, log_name);
    __Proxy(log_type, string, string, string, log_type);
    __Proxy(log_path, string, string, string, log_path);
    __Proxy(log_description, string, string, string, log_description);

    __Proxy(log_packets, uint64_t, uint64_t, uint64_t, log_packets);
    __Proxy(log_size, uint64_t, uint64_t, uint64_t, log_size);

    __Proxy(max_packets, uint64_t, uint64_t, uint64_t, max_packets);
    __Proxy(max_size, uint64_t, uint64_t, uint64_t, max_size);

    __Proxy(log_paused, uint8_t, bool, bool, log_paused);

    void set_agent(streaming_agent *in_agent) {
        agent = in_agent;
    }

    streaming_agent *get_agent() {
        return agent;
    }

    virtual void pre_serialize() {
        // Due to other semantics it doesn't make sense to try to make the agent
        // itself a trackable component, we'll just grab it's data out when we're
        // about to serialize
        if (agent != NULL) {
            set_stream_id(agent->get_stream_id());
            set_log_packets(agent->get_log_packets());
            set_log_size(agent->get_log_size());
            set_max_packets(agent->get_max_packets());
            set_max_size(agent->get_max_size());
            set_log_paused(agent->get_stream_paused());
        }
    }

protected:

    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.stream.stream_id", TrackerDouble,
                "Stream ID", &stream_id);

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

        RegisterField("kismet.stream.max_packets", TrackerUInt64,
                "Maximum number of packets", &max_packets);

        RegisterField("kismet.stream.max_size", TrackerUInt64,
                "Maximum allowed size (bytes)", &max_size);

        RegisterField("kismet.stream.paused", TrackerUInt8,
                "Stream processing paused", &log_paused);
    }

    // Internal ID
    SharedTrackerElement stream_id;

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

    // Maximum values, if any
    SharedTrackerElement max_size;
    SharedTrackerElement max_packets;

    SharedTrackerElement log_paused;

    streaming_agent *agent;
};

class StreamTracker : public Kis_Net_Httpd_CPPStream_Handler, public LifetimeGlobal {
public:
    static shared_ptr<StreamTracker> create_streamtracker(GlobalRegistry *in_globalreg) {
        shared_ptr<StreamTracker> mon(new StreamTracker(in_globalreg));
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal("STREAMTRACKER", mon);
        return mon;
    }

private:
    StreamTracker(GlobalRegistry *in_globalreg);

public:
    virtual ~StreamTracker();

    void register_streamer(streaming_agent *in_agent, string in_name,
            string in_type, string in_path, string in_description);
    void remove_streamer(double in_id);

    // HTTP API
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);
   
protected:
    kis_recursive_timed_mutex mutex;

    GlobalRegistry *globalreg;

    SharedTrackerElement tracked_stream_map;
    TrackerElementDoubleMap stream_map;

    shared_ptr<streaming_info_record> info_builder;
    int info_builder_id;

    double next_stream_id;
};

#endif

