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
#include "server_protocols.h"
#include "timetracker.h"

#include <map>
#include <list>

extern Timetracker timetracker;

enum server_alert_time_unit {
    sat_second, sat_minute, sat_hour, sat_day
};

// A registered alert type
typedef struct server_alert_rec {
    int ref_index;
    string header;

    // Units limiting is measured in
    server_alert_time_unit limit_unit;
    // Alerts per unit
    int limit_rate;
    // Alerts sent before limiting takes hold
    int limit_burst;

    // How many alerts have been sent burst-mode (decremented once per unit)
    int burst_sent;

    // List of times we sent an alert... to handle throttling
    list<struct timeval *> alert_log;
};

typedef struct server_alert_event {
    struct timeval ts;
    string text;
    int type;
};

extern vector<ALERT_data *> pending_alerts;
extern vector<ALERT_data *> past_alerts;

// Queue an alert to be transmitted to the clients or inserted into the fifo stream
void QueueAlert(const char *in_text);

#endif
