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

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

// Timer slices per second
#define SERVER_TIMESLICES_SEC 10

class Timetracker {
public:
    typedef struct timer_event {
        int timer_id;

        // Time it was scheduled
        struct timeval schedule_tm;

        // Explicit trigger time or number of 100000us timeslices
        struct timeval trigger_tm;
        int timeslices;

        // Event is rescheduled again once it expires, if it's a timesliced event
        int recurring;

        int (*callback)(timer_event *, void *);
        void *callback_parm;
    };

    Timetracker();
    ~Timetracker();

    // Tick and handle timers
    int Tick();

    // Register an optionally recurring timer.  Slices are 1/100th of a second,
    // the smallest linux can slice without getting into weird calls.
    int RegisterTimer(int in_timeslices, struct timeval *in_trigger,
                      int in_recurring, int (*in_callback)(timer_event *, void *),
                      void *in_parm);

    // Remove a timer that's going to execute
    int RemoveTimer(int timer_id);

protected:
    int next_timer_id;
    map<int, timer_event *> timer_map;
};

#endif
