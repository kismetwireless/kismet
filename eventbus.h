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

#include <memory>
#include <string>

#include "globalregistry.h"
#include "kis_mutex.h"

// Most basic event bus event that all other events are derived from
class EventbusEvent {
public:
    EventbusEvent(const std::string& in_id) :
        event_id{in_id} { }

    std::string get_event() { 
        return event_id;
    }

protected:
    std::string event_id;
};

class Eventbus : public LifetimeGlobal {
public:
    static std::string global_name() { return "EVENTBUS"; }

    static std::shared_ptr<Eventbus> create_eventbus() {
        std::shared_ptr<Eventbus> mon(new Eventbus());
        Globalreg::globalreg->RegisterLifetimeGlobal(mon);
        Globalreg::globalreg->InsertGlobal(global_name(), mon);
        return mon;
    }

private:
	Eventbus();

public:
	virtual ~Eventbus();

protected:
    kis_recursive_timed_mutex mutex;

};

#endif

