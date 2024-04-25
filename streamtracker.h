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
#include "kis_net_beast_httpd.h"
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

    virtual void stop_stream(std::string in_reason __attribute__((unused))) { };

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
    streaming_info_record() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);

        set_stream_time(Globalreg::globalreg->last_tv_sec);
    }

    streaming_info_record(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);

        set_stream_time(Globalreg::globalreg->last_tv_sec);
    }

    streaming_info_record(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);

        set_stream_time(Globalreg::globalreg->last_tv_sec);
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(stream_id, double, double, double, stream_id);

    __Proxy(stream_time, uint64_t, uint64_t, uint64_t, stream_time);

    __Proxy(log_name, std::string, std::string, std::string, log_name);
    __Proxy(log_type, std::string, std::string, std::string, log_type);
    __Proxy(log_path, std::string, std::string, std::string, log_path);
    __Proxy(log_description, std::string, std::string, std::string, log_description);

    __Proxy(log_packets, uint64_t, uint64_t, uint64_t, log_packets);
    __Proxy(log_size, uint64_t, uint64_t, uint64_t, log_size);

    __Proxy(max_packets, uint64_t, uint64_t, uint64_t, max_packets);
    __Proxy(max_size, uint64_t, uint64_t, uint64_t, max_size);

    __Proxy(log_paused, uint8_t, bool, bool, log_paused);

    void set_agent(std::shared_ptr<streaming_agent> in_agent) {
        agent = in_agent;
    }

    std::shared_ptr<streaming_agent> get_agent() {
        return agent;
    }

    virtual void pre_serialize() override {
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

    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.stream.stream_id", "Stream ID", &stream_id);
        register_field("kismet.stream.time", 
                "Start time of stream (second since epoch)", &stream_time);
        register_field("kismet.stream.name", "Stream / Log name", &log_name);
        register_field("kismet.stream.type", "Stream / Log type", &log_type);
        register_field("kismet.stream.path", "Log path or stream remote client", &log_path);
        register_field("kismet.stream.description", "Stream / Log description", &log_description);
        register_field("kismet.stream.packets", "Number of packets (if known)", &log_packets);
        register_field("kismet.stream.size", "Size of log, if known, in bytes", &log_size);
        register_field("kismet.stream.max_packets", "Maximum number of packets", &max_packets);
        register_field("kismet.stream.max_size", "Maximum allowed size (bytes)", &max_size);
        register_field("kismet.stream.paused", "Stream processing paused", &log_paused);
    }

    std::shared_ptr<tracker_element_double> stream_id;
    std::shared_ptr<tracker_element_uint64> stream_time;
    std::shared_ptr<tracker_element_string> log_name;
    std::shared_ptr<tracker_element_string> log_type;
    std::shared_ptr<tracker_element_string> log_path;
    std::shared_ptr<tracker_element_string> log_description;
    std::shared_ptr<tracker_element_uint64> log_packets;
    std::shared_ptr<tracker_element_uint64> log_size;

    // Maximum values, if any
    std::shared_ptr<tracker_element_uint64> max_packets;
    std::shared_ptr<tracker_element_uint64> max_size;

    std::shared_ptr<tracker_element_uint8> log_paused;

    std::shared_ptr<streaming_agent> agent;
};

class stream_tracker : public lifetime_global {
public:
    static std::string global_name() { return "STREAMTRACKER"; }

    static std::shared_ptr<stream_tracker> create_streamtracker() {
        std::shared_ptr<stream_tracker> mon(new stream_tracker());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    stream_tracker();

public:
    virtual ~stream_tracker();

    double register_streamer(std::shared_ptr<streaming_agent> in_agent, std::string in_name,
            std::string in_type, std::string in_path, std::string in_description);
    void remove_streamer(double in_id);

    void cancel_streams();
   
protected:
    kis_mutex mutex;

    std::shared_ptr<tracker_element_double_map> tracked_stream_map;

    int info_builder_id;

    double next_stream_id;
};

#endif

