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

/* Event bus
 *
 * A generic event bus system which allows various components to post events,
 * asynchronously, to other components.  While this adds a concerning layer of
 * complexity, it will ultimately allow for some optimizations of views,
 * filters, and other components.
 *
 * Event busses are handled as a push and subscription model; a new event
 * is created and pushed to all subscribers.  Subscribers can filter by
 * event type.
 *
 * Event types operate essentially as channels; a subscriber would subscribe
 * to multiple event names.
 *
 * Example events could be:
 *   DEVICETRACKER_NEW_DEVICE
 *   PHYTRACKER_NEW_PHY
 *   ALERTRACKER_NEW_ALERT
 */

#ifndef __EVENTBUS_H__
#define __EVENTBUS_H__

#include "config.h"

#include <functional>
#include <list>
#include <memory>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "trackedcomponent.h"

// Most basic event bus event that all other events are derived from
class eventbus_event : public tracker_component {
public:
    eventbus_event() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    eventbus_event(int in_id, const std::string& in_event) :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
        set_event_id(in_event);
    }
        
    virtual uint32_t get_signature() const override {
        return adler32_checksum("eventbus_event");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(event_id, std::string, std::string, std::string, event_id);
    __ProxyTrackable(event_content, tracker_element_string_map, event_content);

    void reset() {
        event_id->reset();
        event_content->reset();
    }

protected:
    std::shared_ptr<tracker_element_string> event_id;
    std::shared_ptr<tracker_element_string_map> event_content;

    virtual void register_fields() override {
        tracker_component::register_fields();
        register_field("kismet.eventbus.type", "Event type", &event_id);
        register_field("kismet.eventbus.content", "Event content", &event_content);
    }
};

class event_bus : public lifetime_global, public deferred_startup {
public:
    using cb_func = std::function<void (std::shared_ptr<eventbus_event>)>;

    static std::string global_name() { return "EVENTBUS"; }

    static std::shared_ptr<event_bus> create_eventbus() {
        std::shared_ptr<event_bus> mon(new event_bus());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->register_deferred_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
	event_bus();

public:
	virtual ~event_bus();

    void trigger_deferred_startup() override;

    unsigned long register_listener(const std::string& channel, cb_func cb);
    unsigned long register_listener(const std::list<std::string>& channels, cb_func cb);
    void remove_listener(unsigned long id);

    std::shared_ptr<eventbus_event> get_eventbus_event(const std::string& type);

    template<typename T>
    void publish(T event) {
        // kis_lock_guard<kis_mutex> lk(mutex, "eventbus publish");
        std::lock_guard<kis_mutex> lk(mutex);

        auto evt_cast = 
            std::static_pointer_cast<eventbus_event>(event);

        event_queue.push(evt_cast);
        event_cl.unlock(1);
    }

protected:
    // We need 2 mutexes - we have to block removing a callback while we're dispatching
    // an event, because we need to not lock up the entire event bus while we're 
    // sending out events
    kis_mutex mutex, handler_mutex;

    int eventbus_event_id;

    unsigned long next_cbl_id;

    struct callback_listener {
        callback_listener(const std::list<std::string>& channels, cb_func cb, unsigned long id) :
            cb{cb},
            channels{channels},
            id{id} { }

        cb_func cb;
        std::list<std::string> channels;
        unsigned long id;
    };

    // Map of event IDs to listener objects
    std::unordered_map<std::string, std::vector<std::shared_ptr<callback_listener>>> callback_table;
    std::unordered_map<unsigned long, std::shared_ptr<callback_listener>> callback_id_table;

    // Event pool and handler thread
    std::queue<std::shared_ptr<eventbus_event>> event_queue;
    std::thread event_dispatch_t;
    conditional_locker<int> event_cl;
    std::atomic<bool> shutdown;
    void event_queue_dispatcher();
    
};

#endif

