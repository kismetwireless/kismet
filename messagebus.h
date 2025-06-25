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


#ifndef __MESSAGEBUS_H__
#define __MESSAGEBUS_H__

#include "config.h"

#include <queue>
#include <string>
#include <vector>

#include "eventbus.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "timetracker.h"
#include "trackedcomponent.h"

// Message flags for queuing data
#define MSGFLAG_NONE    0
#define MSGFLAG_DEBUG   1
#define MSGFLAG_INFO    2
#define MSGFLAG_ERROR   4
#define MSGFLAG_ALERT   8
#define MSGFLAG_FATAL   16
// Don't propagate it past local display systems
#define MSGFLAG_LOCAL   32
// Force printing of the error in the shutdown messages, sort of a "fatal lite"
#define MSGFLAG_PRINT	64
#define MSGFLAG_ALL     (MSGFLAG_DEBUG | MSGFLAG_INFO | \
                         MSGFLAG_ERROR | MSGFLAG_ALERT | \
                         MSGFLAG_FATAL)
// Combine
#define MSGFLAG_PRINTERROR	(MSGFLAG_ERROR | MSGFLAG_PRINT)

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

    tracked_message(const tracked_message *p, const std::string& in_msg, int in_flags, time_t in_time) :
        tracker_component{p} {

            __ImportField(message, p);
            __ImportField(flags, p);
            __ImportField(timestamp, p);

            reserve_fields(nullptr);

            set_message(in_msg);
            set_flags(in_flags);
            set_timestamp(in_time);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_message");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::globalreg->entrytracker->new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(message, std::string, std::string, std::string, message);
    __Proxy(flags, int32_t, int32_t, int32_t, flags);
    __Proxy(timestamp, uint64_t, time_t, time_t, timestamp);

    void set_from_message(std::string in_msg, int in_flags) {
        set_message(in_msg);
        set_flags(in_flags);
        set_timestamp(Globalreg::globalreg->last_tv_sec);
    }

    bool operator<(const tracked_message& comp) const {
        return get_timestamp() < comp.get_timestamp();
    }

    void reset() {
        message->reset();
        flags->reset();
        timestamp->reset();
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

// Minimal stub of a messagebus that just holds the event IDs and passes it all into the eventbus now
class message_bus : public lifetime_global {
public:
    static std::string global_name() { return "MESSAGEBUS"; }

    static std::shared_ptr<message_bus> create_messagebus() {
        std::shared_ptr<message_bus> mon(new message_bus());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
	message_bus() :
        lifetime_global() {

        eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();
        timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();

        Globalreg::enable_pool_type<tracked_message>([](tracked_message *m) { m->reset(); });

        msg_proto =
            Globalreg::globalreg->entrytracker->register_and_get_field_as<tracked_message>("kismet.messagebus.message",
                    tracker_element_factory<tracked_message>(),
                    "Message");

        timer_id = timetracker->register_timer(
            std::chrono::seconds(1), true, [this](int) -> int {
                n_info_sec = 0; 
                return 1;
            });
    }

public:
	virtual ~message_bus() {
        Globalreg::globalreg->remove_global(global_name());
    }

    void set_info_throttle(unsigned int throttle_s) {
        throttle_info = throttle_s;
    }

    static std::string event_message() {
        return "MESSAGE";
    }

    void inject_message(const std::string msg, int flags) {
        // Force fatal messages out to stderr immediately
        if (flags & MSGFLAG_FATAL) {
            fprintf(stderr, "FATAL: %s\n", msg.c_str());
            fflush(stderr);
        }

        // Don't propogate debug messages into the eventbus or silly things can happen
        if (flags & MSGFLAG_DEBUG) {
            fprintf(stdout, "DEBUG: %s\n", msg.c_str());
            fflush(stdout);
            return;
        }

        // Throttle info messages if we're getting obliterated
        if ((flags & MSGFLAG_INFO) && throttle_info != 0 && n_info_sec > throttle_info)
            return;

        auto tracked_msg = std::make_shared<tracked_message>(msg_proto.get(), msg, flags, Globalreg::globalreg->last_tv_sec);
        auto evt = eventbus->get_eventbus_event(event_message());
        evt->get_event_content()->insert(event_message(), tracked_msg);
        eventbus->publish(evt);
    }

protected:
    std::shared_ptr<event_bus> eventbus;
    std::shared_ptr<time_tracker> timetracker;
    std::shared_ptr<tracked_message> msg_proto;

    int timer_id;

    unsigned int throttle_info;

    std::atomic<unsigned int> n_info_sec;
};

#endif

