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

#include "config.h"

#include <sys/time.h>

#include "timetracker.h"

Timetracker::Timetracker() {
    fprintf(stderr, "Timetracker::Timetracker() called with no globalreg\n");
}

Timetracker::Timetracker(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    next_timer_id = 0;

	globalreg->start_time = time(0);
	gettimeofday(&(globalreg->timestamp), NULL);
}

Timetracker::~Timetracker() {
    // Free the events
    for (map<int, timer_event *>::iterator x = timer_map.begin();
         x != timer_map.end(); ++x)
        delete x->second;
}

int Timetracker::Tick() {
    // Handle scheduled events
    struct timeval cur_tm;
    gettimeofday(&cur_tm, NULL);
	globalreg->timestamp.tv_sec = cur_tm.tv_sec;
	globalreg->timestamp.tv_usec = cur_tm.tv_usec;
    timer_event *evt;

    for (unsigned int x = 0; x < sorted_timers.size(); x++) {
        evt = sorted_timers[x];

        if ((cur_tm.tv_sec < evt->trigger_tm.tv_sec) ||
            ((cur_tm.tv_sec == evt->trigger_tm.tv_sec) && 
			 (cur_tm.tv_usec < evt->trigger_tm.tv_usec))) {
			// fprintf(stderr, "debug - tick at %u %u - queue is all older\n", cur_tm.tv_sec, cur_tm.tv_usec);
            return 1;
		}

        // Call the function with the given parameters
        int ret;
        ret = (*evt->callback)(evt, evt->callback_parm, globalreg);

        if (ret > 0 && evt->timeslices != -1 && evt->recurring) {
            evt->schedule_tm.tv_sec = cur_tm.tv_sec;
            evt->schedule_tm.tv_usec = cur_tm.tv_usec;
            evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + (evt->timeslices / 10);
            evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + 
				(100000 * (evt->timeslices % 10));

            if (evt->trigger_tm.tv_usec > 999999) {
                evt->trigger_tm.tv_usec = evt->trigger_tm.tv_usec - 1000000;
                evt->trigger_tm.tv_sec++;
            }

            // Resort the list
            stable_sort(sorted_timers.begin(), sorted_timers.end(), 
						SortTimerEventsTrigger());
        } else {
            RemoveTimer(evt->timer_id);
        }

    }

    return 1;
}

int Timetracker::RegisterTimer(int in_timeslices, struct timeval *in_trigger,
                               int in_recurring, 
                               int (*in_callback)(TIMEEVENT_PARMS),
                               void *in_parm) {
    timer_event *evt = new timer_event;

    evt->timer_id = next_timer_id++;
    gettimeofday(&(evt->schedule_tm), NULL);

    if (in_trigger != NULL) {
        evt->trigger_tm.tv_sec = in_trigger->tv_sec;
        evt->trigger_tm.tv_usec = in_trigger->tv_usec;
        evt->timeslices = -1;
    } else {
        evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + (in_timeslices / 10);
        evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + (in_timeslices % 10);
        evt->timeslices = in_timeslices;
    }

    evt->recurring = in_recurring;
    evt->callback = in_callback;
    evt->callback_parm = in_parm;

    timer_map[evt->timer_id] = evt;
    sorted_timers.push_back(evt);

    // Resort the list
    stable_sort(sorted_timers.begin(), sorted_timers.end(), SortTimerEventsTrigger());

    return evt->timer_id;
}

int Timetracker::RemoveTimer(int in_timerid) {
    map<int, timer_event *>::iterator itr;

    itr = timer_map.find(in_timerid);

    if (itr != timer_map.end()) {
        for (unsigned int x = 0; x < sorted_timers.size(); x++) {
            if (sorted_timers[x]->timer_id == in_timerid)
                sorted_timers.erase(sorted_timers.begin() + x);
        }

        // Resort the list
        stable_sort(sorted_timers.begin(), sorted_timers.end(), SortTimerEventsTrigger());

        delete itr->second;
        timer_map.erase(itr);
        return 1;
    }

    return -1;
}

