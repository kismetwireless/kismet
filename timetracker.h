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

#ifndef __TIMETRACKER_H__
#define __TIMETRACKER_H__

#include "config.h"

#include <algorithm>
#include <chrono>
#include <list>
#include <map>
#include <stdio.h>
#include <string>
#include <time.h>
#include <vector>

#include <functional>

#include "globalregistry.h"
#include "kis_mutex.h"

// For ubertooth and a few older plugins that compile against both svn and old
#define KIS_NEW_TIMER_PARM	1

#define TIMEEVENT_PARMS time_tracker::timer_event *evt __attribute__ ((unused)), \
    void *auxptr __attribute__ ((unused)), global_registry *globalreg __attribute__ ((unused))

class time_tracker_event;

class time_tracker : public lifetime_global {
public:
    using slice = std::chrono::duration<int, std::ratio<1, 10>>;

    struct timer_event {
        int timer_id;

        // Event name
        std::string name;

        // Time running in ms
        double total_ms;
        double last_ms;

        // Is the timer cancelled?
        std::atomic<bool> timer_cancelled;

        // Time it was scheduled
        struct timeval schedule_tm;

        // Explicit trigger time or number of 100000us timeslices
        struct timeval trigger_tm;
        int timeslices;

        // Event is rescheduled again once it expires, if it's a timesliced event
        int recurring;

        // Event, if we were passed a class
        time_tracker_event *event;

        // Function if we were passed a lambda
        std::function<int (int)> event_func;

        // C function, if we weren't
        int (*callback)(timer_event *, void *, global_registry *);
        void *callback_parm;
    };

    // Sort alerts by alert trigger time
    class sort_timer_events_trigger {
    public:
        inline bool operator() (std::shared_ptr<time_tracker::timer_event> x, 
								std::shared_ptr<time_tracker::timer_event> y) const {
            if ((x->trigger_tm.tv_sec < y->trigger_tm.tv_sec) ||
                ((x->trigger_tm.tv_sec == y->trigger_tm.tv_sec) && 
				 (x->trigger_tm.tv_usec < y->trigger_tm.tv_usec)))
                return 1;

            return 0;
        }
    };

    static std::string global_name() { return "TIMETRACKER"; }

    static std::shared_ptr<time_tracker> create_timetracker() {
        std::shared_ptr<time_tracker> mon(new time_tracker());
        Globalreg::globalreg->timetracker = mon.get();
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    time_tracker();

public:
    virtual ~time_tracker();

    // Register an optionally recurring timer.  
    int register_timer(int in_timeslices, struct timeval *in_trigger,
                      int in_recurring, 
                      int (*in_callback)(timer_event *, void *, global_registry *),
                      void *in_parm);

    int register_timer(int timeslices, struct timeval *in_trigger,
            int in_recurring, time_tracker_event *event);

    int register_timer(int timeslices, struct timeval *in_trigger,
            int in_recurring, std::function<int (int)> event);

    int register_timer(const slice& in_timeslices,
            int in_recurring,
            int (*in_callbacK)(timer_event *, void *, global_registry *),
            void *in_parm); 

    int register_timer(const slice& in_timeslices,
            int in_recurring, std::function<int (int)> event);

    // Remove a timer that's going to execute
    int remove_timer(int timer_id);

    void spawn_timetracker_thread();

protected:
    kis_mutex time_mutex;

    std::vector<std::thread> time_workers;

    void time_dispatcher(void);

    // Do we have to re-sort the list of timers?
    std::atomic<bool> timer_sort_required;

    // Next timer ID to be assigned
    std::atomic<int> next_timer_id;

    std::map<int, std::shared_ptr<timer_event>> timer_map;
    std::vector<std::shared_ptr<timer_event>> sorted_timers;

    kis_mutex removed_id_mutex;
    std::vector<int> removed_timer_ids;

    std::thread time_dispatch_t;
    std::atomic<bool> shutdown;
};

class time_tracker_event {
public:
    // Called when event triggers
    virtual int timetracker_event(int event_id __attribute__ ((unused))) { return 0; };

protected:
    int timer_id;

};

#endif
