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

#ifndef __SERVER_PLUGIN_H__
#define __SERVER_PLUGIN_H__

#include "config.h"

// Timer slices per second
#define SERVER_TIMESLICES_SEC 10

typedef struct server_timer_event {
    int timer_id;

    // Time it was scheduled
    struct timeval schedule_tm;

    // Explicit trigger time or number of 100000us timeslices
    struct timeval trigger_tm;
    int timeslices;

    // Event is rescheduled again once it expires, if it's a timesliced event
    int recurring;

    int (*callback)(server_timer_event *, void *);
    void *callback_parm;
};

// Register an optionally recurring timer.  Slices are 1/100th of a second (100000usec,
// or the smallest select can slice internally.)  Function itself is implemented in
// kismet_server for access to globals
int RegisterServerTimer(int in_timeslices, struct timeval *in_trigger,
                        int in_recurring, int (*in_callback)(server_timer_event *, void *),
                        void *in_parm);
// Remove a timer that's going to execute
int RemoveServerTimer(int timer_id);

#endif
