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

#include "timetracker.h"

Timetracker::Timetracker() {
    next_timer_id = 0;
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
    for (map<int, timer_event *>::iterator evtitr = timer_map.begin();
         evtitr != timer_map.end(); ++evtitr) {
        timer_event *evt = evtitr->second;

        if ((evt->trigger_tm.tv_sec < cur_tm.tv_sec) ||
            (evt->trigger_tm.tv_sec == cur_tm.tv_sec &&
             evt->trigger_tm.tv_usec < cur_tm.tv_usec)) {

            // Call the function with the given parameters
            int ret;
            ret = (*evt->callback)(evt, evt->callback_parm);

            if (ret > 0 && evt->timeslices != -1 && evt->recurring) {
                evt->schedule_tm.tv_sec = cur_tm.tv_sec;
                evt->schedule_tm.tv_usec = cur_tm.tv_usec;
                evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + (evt->timeslices / 10);
                evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + (evt->timeslices % 10);
            } else {
                delete evt;
                timer_map.erase(evtitr);
            }

        }

    }

    return 1;
}

int Timetracker::RegisterTimer(int in_timeslices, struct timeval *in_trigger,
                               int in_recurring, int (*in_callback)(timer_event *, void *),
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

    return evt->timer_id;
}

int Timetracker::RemoveTimer(int in_timerid) {
    map<int, timer_event *>::iterator itr;

    itr = timer_map.find(in_timerid);

    if (itr != timer_map.end()) {
        delete itr->second;
        timer_map.erase(itr);
        return 1;
    }

    return -1;
}

