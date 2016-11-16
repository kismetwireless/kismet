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
#include "kis_net_microhttpd.h"

// TODO move packet_component to a tracked system & just use the converted
// kis_alert_info in the future...

class kis_alert_info : public packet_component {
public:
	kis_alert_info() {
		tm.tv_sec = 0;
		tm.tv_usec = 0;
		channel = "0";

		// We do NOT self-destruct because we get cached in the alertracker
		// for playbacks.  It's responsible for discarding us
		self_destruct = 0;
	}

    uint64_t device_key;

	string header;
	int phy;
	struct timeval tm;
	mac_addr bssid;
	mac_addr source;
	mac_addr dest;
	mac_addr other;
	string channel;
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

class tracked_alert : public tracker_component {
public:
    tracked_alert(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_alert(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clon_type() {
        return new tracked_alert(globalreg, get_id());
    }

    __Proxy(device_key, uint64_t, uint64_t, uint64_t, device_key);

    __Proxy(header, string, string, string, header);
    __Proxy(phy, uint32_t, uint32_t, uint32_t, phy);
    __Proxy(timestamp_sec, uint64_t, uint64_t, uint64_t, timestamp_sec);
    __Proxy(timestamp_usec, uint64_t, uint64_t, uint64_t, timestamp_usec);

    void set_timestamp(struct timeval tv) {
        set_timestamp_sec(tv.tv_sec);
        set_timestamp_usec(tv.tv_usec);
    }

    __Proxy(transmitter_mac, mac_addr, mac_addr, mac_addr, transmitter_mac);
    __Proxy(source_mac, mac_addr, mac_addr, mac_addr, source_mac);
    __Proxy(dest_mac, mac_addr, mac_addr, mac_addr, dest_mac);
    __Proxy(other_mac, mac_addr, mac_addr, mac_addr, other_mac);

    __Proxy(channel, string, string, string, channel);
    __Proxy(frequency, double, double, double, frequency);

    __Proxy(text, string, string, string, text);

    void from_alert_info(kis_alert_info *info) {
        set_device_key(info->device_key);
        set_header(info->header);
        set_phy(info->phy);
        set_timestamp(info->tm);
        set_transmitter_mac(info->bssid);
        set_source_mac(info->source);
        set_dest_mac(info->dest);
        set_other_mac(info->other);
        set_channel(info->channel);
        set_text(info->text);
    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        device_key_id =
            RegisterField("ksimet.alert.device_key", TrackerUInt64,
                    "Device key of linked device", (void **) &device_key);

        header_id =
            RegisterField("kismet.alert.header", TrackerString,
                    "Alert type", (void **) &header);

        phy_id =
            RegisterField("kismet.alert.phy_id", TrackerUInt32,
                    "ID of phy generating alert", (void **) &phy);

        timestamp_sec_id =
            RegisterField("kismet.alert.timestamp_sec", TrackerUInt64,
                    "Timestamp (second component)", (void **) &timestamp_sec);

        timestamp_usec_id =
            RegisterField("kismet.alert.timestamp_usec", TrackerUInt64,
                    "Timestmap (microsecond component)", (void **) &timestamp_usec);

        transmitter_mac_id =
            RegisterField("kismet.alert.transmitter_mac", TrackerMac,
                    "Transmitter MAC address", (void **) &transmitter_mac);

        source_mac_id =
            RegisterField("kismet.alert.source_mac", TrackerMac,
                    "Source MAC address", (void **) &source_mac);

        dest_mac_id =
            RegisterField("kismet.alert.dest_mac", TrackerMac,
                    "Destination MAC address", (void **) &dest_mac);

        other_mac_id =
            RegisterField("kismet.alert.other_mac", TrackerMac,
                    "Other / Extra MAC address", (void **) &other_mac);

        channel_id =
            RegisterField("kismet.alert.channel", TrackerString,
                    "Phy-specific channel", (void **) &channel);

        frequency_id =
            RegisterField("kismet.alert.frequency", TrackerDouble,
                    "Frequency (khz)", (void **) &frequency);

        text_id =
            RegisterField("kismet.alert.text", TrackerString,
                    "Alert text", (void **) &text);
    }

    TrackerElement *device_key;
    int device_key_id;

    TrackerElement *header;
    int header_id;

    TrackerElement *phy;
    int phy_id;

    TrackerElement *timestamp_sec;
    int timestamp_sec_id;

    TrackerElement *timestamp_usec;
    int timestamp_usec_id;

    TrackerElement *transmitter_mac;
    int transmitter_mac_id;

    TrackerElement *source_mac;
    int source_mac_id;

    TrackerElement *dest_mac;
    int dest_mac_id;

    TrackerElement *other_mac;
    int other_mac_id;

    TrackerElement *channel;
    int channel_id;

    TrackerElement *frequency;
    int frequency_id;

    TrackerElement *text;
    int text_id;

};


static const int alert_time_unit_conv[] = {
    1, 60, 3600, 86400
};

enum alert_time_unit {
    sat_second, sat_minute, sat_hour, sat_day
};

class Alertracker : public Kis_Net_Httpd_Stream_Handler, LifetimeGlobal {
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


    Alertracker(GlobalRegistry *in_globalreg);
    virtual ~Alertracker();

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
                   string in_channel, string in_text);

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

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

protected:
    pthread_mutex_t alert_mutex;

    int alert_vec_id, alert_entry_id, alert_timestamp_id;

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
