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
#include "kis_net_beast_httpd.h"

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

    tracked_message(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    tracked_message(const tracked_message *p) :
        tracker_component{p} {

        __ImportField(message, p);
        __ImportField(flags, p);
        __ImportField(timestamp, p);

        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_message");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
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

        register_field("kismet.messagebus.message_string", "Message content", &message);
        register_field("kismet.messagebus.message_flags", "Message flags (per messagebus.h)", &flags);
        register_field("kismet.messagebus.message_time", "Message time_t", &timestamp);
    }

    std::shared_ptr<tracker_element_string> message;
    std::shared_ptr<tracker_element_int32> flags;
    std::shared_ptr<tracker_element_uint64> timestamp;
};

class rest_message_client : public message_client, public lifetime_global {
public:
    static std::shared_ptr<rest_message_client> 
        create_messageclient() {
        std::shared_ptr<rest_message_client> mon(new rest_message_client());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global("REST_MSG_CLIENT", mon);
        return mon;
    }

private:
    rest_message_client();

public:
	virtual ~rest_message_client();

    virtual void process_message(std::string in_msg, int in_flags) override;

protected:
    kis_recursive_timed_mutex msg_mutex;

    std::list<std::shared_ptr<tracked_message> > message_list;

    int message_vec_id, message_entry_id, message_timestamp_id;
};


#endif

