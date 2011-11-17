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

#include "globalregistry.h"
#include "messagebus.h"
#include "packetchain.h"
#include "timetracker.h"
#include "kis_netframe.h"

class kis_alert_info : public packet_component {
public:
	kis_alert_info() {
		tm.tv_sec = 0;
		tm.tv_usec = 0;
		channel = 0;

		// We do NOT self-destruct because we get cached in the alertracker
		// for playbacks.  It's responsible for discarding us
		self_destruct = 0;
	}

	string header;
	int phy;
	struct timeval tm;
	mac_addr bssid;
	mac_addr source;
	mac_addr dest;
	mac_addr other;
	int channel;
	string text;
};

class kis_alert_component : public packet_component {
public:
	kis_alert_component() {
		// We can self destruct because we won't clear out the vector
		// of actual alert info
		self_destruct = 1;
	}

	vector<kis_alert_info *> alert_vec;
};

enum ALERT_fields {
    ALERT_sec, ALERT_usec, ALERT_header, ALERT_bssid, ALERT_source,
    ALERT_dest, ALERT_other, ALERT_channel, ALERT_text, ALERT_phytype,
	ALERT_maxfield
};

int Protocol_ALERT(PROTO_PARMS); // kis_alert_info
void Protocol_ALERT_enable(PROTO_ENABLE_PARMS);

static const int alert_time_unit_conv[] = {
    1, 60, 3600, 86400
};

enum alert_time_unit {
    sat_second, sat_minute, sat_hour, sat_day
};

class Alertracker {
public:
    // A registered alert type
    struct alert_rec {
        int ref_index;
        string header;

		int phy;

        // Units limiting is measured in
        alert_time_unit limit_unit;
        // Alerts per unit
        int limit_rate;
		// Units burst is measured in
		alert_time_unit burst_unit;
        // Alerts sent before limiting takes hold
        int limit_burst;

        // How many alerts have been sent burst-mode (decremented once per unit)
        int burst_sent;
		// How many have we sent in total?
		int total_sent;

		// Last time we sent an alert, to tell if we can reset the burst or
		// rate counters
		time_t time_last;
    };

	// Simple struct from reading config lines
	struct alert_conf_rec {
		string header;
        alert_time_unit limit_unit;
        int limit_rate;
		alert_time_unit burst_unit;
        int limit_burst;
	};


    Alertracker();
    Alertracker(GlobalRegistry *in_globalreg);
    ~Alertracker();

    // Register an alert and get an alert reference number back.
    int RegisterAlert(const char *in_header, alert_time_unit in_unit, int in_rate,
                      alert_time_unit in_burstunit, int in_burst, int in_phy);

    // Find a reference from a name
    int FetchAlertRef(string in_header);

    // Will an alert succeed?
    int PotentialAlert(int in_ref);

    // Raise an alert ...
    int RaiseAlert(int in_ref, kis_packet *in_pack,
                   mac_addr bssid, mac_addr source, mac_addr dest, mac_addr other,
                   int in_channel, string in_text);

    // Send backlogged alerts
    void BlitBacklogged(int in_fd);

	// Load an alert reference from a config file (not tied only to the
	// kismet conf in globalreg)
	int ParseAlertStr(string alert_str, string *ret_name, 
					  alert_time_unit *ret_limit_unit, int *ret_limit_rate,
					  alert_time_unit *ret_limit_burst, int *ret_burst_rate);

	// Load alert rates from a config file...  Called on kismet_config by
	// default
	int ParseAlertConfig(ConfigFile *in_conf);

	// Activate a preconfigured alert from a file
	int ActivateConfiguredAlert(const char *in_header);
	int ActivateConfiguredAlert(const char *in_header, int in_phy);

	const vector<kis_alert_info *> *FetchBacklog();

protected:
    // Check and age times
    int CheckTimes(alert_rec *arec);

	// Parse a foo/bar rate/unit option
	int ParseRateUnit(string in_ru, alert_time_unit *ret_unit, int *ret_rate);

    GlobalRegistry *globalreg;

    int next_alert_id;

    map<string, int> alert_name_map;
    map<int, alert_rec *> alert_ref_map;

	vector<kis_alert_info *> alert_backlog;

    int num_backlog;

	map<string, alert_conf_rec *> alert_conf_map;
};

#endif
