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

#ifndef __ALERTRACKER_H__
#define __ALERTRACKER_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

#include "tcpserver.h"
#include "server_protocols.h"

static const int alert_time_unit_conv[] = {
    1, 60, 3600, 86400
};

enum alert_time_unit {
    sat_second, sat_minute, sat_hour, sat_day
};

class Alertracker {
public:
    // A registered alert type
    typedef struct alert_rec {
        int ref_index;
        string header;

        // Units limiting is measured in
        alert_time_unit limit_unit;
        // Alerts per unit
        int limit_rate;
        // Alerts sent before limiting takes hold
        int limit_burst;

        // How many alerts have been sent burst-mode (decremented once per unit)
        int burst_sent;

        // List of times we sent an alert... to handle throttling
        list<struct timeval *> alert_log;
    };

    Alertracker();
    ~Alertracker();

    // Tell us where to send packets
    void AddTcpServer(TcpServer *in_server);
    // Tell us the protocol ref
    void AddAlertProtoRef(int in_ref);
    // Set the alert backlog
    void SetAlertBacklog(int in_backlog);

    // Register an alert and get an alert reference number back.
    int RegisterAlert(const char *in_header, alert_time_unit in_unit, int in_rate,
                      int in_burst);

    // Find a reference from a name
    int FetchAlertRef(string in_header);

    // Will an alert succeed?
    int PotentialAlert(int in_ref);

    // Raise an alert
    int RaiseAlert(int in_ref, 
                   mac_addr bssid, mac_addr source, mac_addr dest, mac_addr other,
                   int in_channel, string in_text);

    // Send backlogged alerts
    void BlitBacklogged(int in_fd);

protected:
    // Check and age times
    int CheckTimes(alert_rec *arec);

    TcpServer *server;
    int protoref;

    int next_alert_id;

    map<string, int> alert_name_map;
    map<int, alert_rec *> alert_ref_map;

    unsigned int max_backlog;
    vector<ALERT_data *> alert_backlog;

};

#endif
