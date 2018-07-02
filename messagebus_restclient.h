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


#ifndef __MESSAGEBUS_REST_H__
#define __MESSAGEBUS_REST_H__

#include "config.h"

#include <string>
#include <vector>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "messagebus.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "kis_net_microhttpd.h"

class tracked_message : public tracker_component {
public:
    tracked_message() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_message(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_message(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("tracked_message");
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

    __Proxy(message, std::string, std::string, std::string, message);
    __Proxy(flags, int32_t, int32_t, int32_t, flags);
    __Proxy(timestamp, uint64_t, time_t, time_t, timestamp);

    void set_from_message(std::string in_msg, int in_flags) {
        set_message(in_msg);
        set_flags(in_flags);
        set_timestamp(time(0));
    }

    bool operator<(const tracked_message& comp) const {
        return get_timestamp() < comp.get_timestamp();
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.messagebus.message_string", "Message content", &message);
        RegisterField("kismet.messagebus.message_flags", "Message flags (per messagebus.h)", &flags);
        RegisterField("kismet.messagebus.message_time", "Message time_t", &timestamp);
    }

    std::shared_ptr<TrackerElementString> message;
    std::shared_ptr<TrackerElementInt32> flags;
    std::shared_ptr<TrackerElementUInt64> timestamp;
};

class RestMessageClient : public MessageClient, public Kis_Net_Httpd_CPPStream_Handler,
    public LifetimeGlobal {
public:
    static std::shared_ptr<RestMessageClient> 
        create_messageclient(GlobalRegistry *in_globalreg) {
        std::shared_ptr<RestMessageClient> mon(new RestMessageClient(in_globalreg, NULL));
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal("REST_MSG_CLIENT", mon);
        return mon;
    }

private:
    RestMessageClient(GlobalRegistry *in_globalreg, void *in_aux);

public:
	virtual ~RestMessageClient();

    virtual void ProcessMessage(std::string in_msg, int in_flags) override;

    virtual bool Httpd_VerifyPath(const char *path, const char *method) override;

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) override;

protected:
    kis_recursive_timed_mutex msg_mutex;

    std::list<std::shared_ptr<tracked_message> > message_list;

    int message_vec_id, message_entry_id, message_timestamp_id;
};


#endif

