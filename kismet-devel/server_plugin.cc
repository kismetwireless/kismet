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
#include <map>

#include "server_plugin.h"

// timer events
int timer_id = 0;
map<int, server_timer_event *> timer_map;

int RegisterServerTimer(int in_timeslices, struct timeval *in_trigger,
                        int in_recurring, int (*in_callback)(server_timer_event *, void *),
                        void *in_parm) {
    server_timer_event *evt = new server_timer_event;

    evt->timer_id = timer_id++;
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

int RemoveServerTimer(int in_timerid) {
    map<int, server_timer_event *>::iterator itr;

    itr = timer_map.find(in_timerid);

    if (itr != timer_map.end()) {
        delete itr->second;
        timer_map.erase(itr);
        return 1;
    }

    return -1;
}

vector<ALERT_data *> pending_alerts;
vector<ALERT_data *> past_alerts;

void QueueAlert(const char *in_alert) {
    ALERT_data *adata = new ALERT_data;
    char tmpstr[128];
    timeval ts;
    gettimeofday(&ts, NULL);

    snprintf(tmpstr, 128, "%ld", (long int) ts.tv_sec);
    adata->sec = tmpstr;

    snprintf(tmpstr, 128, "%ld", (long int) ts.tv_usec);
    adata->usec = tmpstr;

    adata->text = in_alert;

    pending_alerts.push_back(adata);
}
