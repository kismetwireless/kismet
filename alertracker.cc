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

#include <string>
#include <vector>
#include <sstream>

#include "alertracker.h"
#include "devicetracker.h"
#include "configfile.h"

#include "json_adapter.h"
#include "msgpack_adapter.h"

Alertracker::Alertracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_Stream_Handler(in_globalreg) {
	globalreg = in_globalreg;
	next_alert_id = 0;

    pthread_mutex_init(&alert_mutex, NULL);

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Alertracker called with null config\n");
		exit(1);
	}

	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS:  Alertracker called with null packetchain\n");
		exit(1);
	}

    globalreg->InsertGlobal("ALERTTRACKER", this);
    globalreg->alertracker = this;

	if (globalreg->kismet_config->FetchOpt("alertbacklog") != "") {
		int scantmp;
		if (sscanf(globalreg->kismet_config->FetchOpt("alertbacklog").c_str(), 
				   "%d", &scantmp) != 1 || scantmp < 0) {
			globalreg->messagebus->InjectMessage("Illegal value for 'alertbacklog' "
												 "in config file", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return;
		}
		num_backlog = scantmp;
	}

	// Parse config file vector of all alerts
	if (ParseAlertConfig(globalreg->kismet_config) < 0) {
		_MSG("Failed to parse alert values from Kismet config file", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

    alert_vec_id =
        globalreg->entrytracker->RegisterField("kismet.alert.list",
                TrackerVector, "list of alerts");
    alert_timestamp_id =
        globalreg->entrytracker->RegisterField("kismet.alert.timestamp",
                TrackerUInt64, "alert update timestamp");

    tracked_alert *alert_builder = new tracked_alert(globalreg, 0);
    alert_entry_id =
        globalreg->entrytracker->RegisterField("kismet.alert.alert",
                alert_builder, "Kismet alert");
    delete(alert_builder);

	// Register the alert component
	_PCM(PACK_COMP_ALERT) =
		globalreg->packetchain->RegisterPacketComponent("alert");

	// Register a KISMET alert type with no rate restrictions
	_ARM(ALERT_REF_KISMET) =
		RegisterAlert("KISMET", sat_day, 0, sat_day, 0, KIS_PHY_ANY);

	
	_MSG("Created alert tracker...", MSGFLAG_INFO);
}

Alertracker::~Alertracker() {
    pthread_mutex_lock(&alert_mutex);

    globalreg->RemoveGlobal("ALERTTRACKER");
    globalreg->alertracker = NULL;

	for (map<int, alert_rec *>::iterator x = alert_ref_map.begin();
		 x != alert_ref_map.end(); ++x)
		delete x->second;

    pthread_mutex_destroy(&alert_mutex);
}

int Alertracker::RegisterAlert(const char *in_header, alert_time_unit in_unit, 
							   int in_rate, alert_time_unit in_burstunit,
							   int in_burst, int in_phy) {
    local_locker lock(&alert_mutex);

	char err[1024];

	// Bail if this header is registered
	if (alert_name_map.find(in_header) != alert_name_map.end()) {
		snprintf(err, 1024, "RegisterAlert() header already registered '%s'",
				 in_header);
		globalreg->messagebus->InjectMessage(err, MSGFLAG_ERROR);
		return -1;
	}

	// Bail if the rates are impossible
	if (in_burstunit > in_unit) {
		snprintf(err, 1024, "Registering alert '%s' failed, time unit for "
				 "burst rate must be <= time unit for max rate", in_header);
		globalreg->messagebus->InjectMessage(err, MSGFLAG_ERROR);
		return -1;
	}

	alert_rec *arec = new alert_rec;

	arec->ref_index = next_alert_id++;
	arec->header = StrUpper(in_header);
	arec->limit_unit = in_unit;
	arec->burst_unit = in_burstunit;
	arec->limit_rate = in_rate;
	arec->limit_burst = in_burst;
	arec->burst_sent = 0;
	arec->time_last = 0;
	arec->phy = in_phy;

	alert_name_map[arec->header] = arec->ref_index;
	alert_ref_map[arec->ref_index] = arec;

	return arec->ref_index;
}

int Alertracker::FetchAlertRef(string in_header) {
    local_locker lock(&alert_mutex);

    if (alert_name_map.find(in_header) != alert_name_map.end())
        return alert_name_map[in_header];

    return -1;
}

int Alertracker::CheckTimes(alert_rec *arec) {
	// Is this alert rate-limited?  If not, shortcut out and send it
	if (arec->limit_rate == 0) {
		return 1;
	}

	struct timeval now;
	gettimeofday(&now, NULL);

	// If the last time we sent anything was longer than the main rate limit,
	// then we reset back to empty
	if (arec->time_last < (now.tv_sec - alert_time_unit_conv[arec->limit_unit])) {
		arec->total_sent = 0;
		arec->burst_sent = 0;
		return 1;
	}

	// If the last time we sent anything was longer than the burst rate, we can
	// reset the burst to 0
	if (arec->time_last < (now.tv_sec - alert_time_unit_conv[arec->burst_unit])) {
		arec->burst_sent = 0;
	}

	// If we're under the limit on both, we're good to go
	if (arec->burst_sent < arec->limit_burst && arec->total_sent < arec->limit_rate)
		return 1;

	return 0;
}

int Alertracker::PotentialAlert(int in_ref) {
    local_locker lock(&alert_mutex);

	map<int, alert_rec *>::iterator aritr = alert_ref_map.find(in_ref);

	if (aritr == alert_ref_map.end())
		return 0;

	alert_rec *arec = aritr->second;

	return CheckTimes(arec);
}

int Alertracker::RaiseAlert(int in_ref, kis_packet *in_pack,
							mac_addr bssid, mac_addr source, mac_addr dest, 
							mac_addr other, string in_channel, string in_text) {
    local_locker lock(&alert_mutex);

	map<int, alert_rec *>::iterator aritr = alert_ref_map.find(in_ref);

	if (aritr == alert_ref_map.end())
		return -1;

	alert_rec *arec = aritr->second;

	if (CheckTimes(arec) != 1)
		return 0;

	kis_alert_info *info = new kis_alert_info;

	info->header = arec->header;
	info->phy = arec->phy;
	gettimeofday(&(info->tm), NULL);

	info->bssid = bssid;
	info->source = source;
	info->dest  = dest;
	info->other = other;

	info->channel = in_channel;	

	info->text = in_text;

	// Increment and set the timers
	arec->burst_sent++;
	arec->total_sent++;
	arec->time_last = time(0);

	alert_backlog.push_back(info);
	if ((int) alert_backlog.size() > num_backlog) {
		delete alert_backlog[0];
		alert_backlog.erase(alert_backlog.begin());
	}

	// Try to get the existing alert info
	if (in_pack != NULL)  {
		kis_alert_component *acomp = 
			(kis_alert_component *) in_pack->fetch(_PCM(PACK_COMP_ALERT));

		// if we don't have an alert container, make one on this packet
		if (acomp == NULL) {
			acomp = new kis_alert_component;
			in_pack->insert(_PCM(PACK_COMP_ALERT), acomp);
		}

		// Attach it to the packet
		acomp->alert_vec.push_back(info);
	}

	// Send the text info
	globalreg->messagebus->InjectMessage((info->header + " " + info->text), 
										 MSGFLAG_ALERT);

	return 1;
}

int Alertracker::ParseAlertStr(string alert_str, string *ret_name, 
							   alert_time_unit *ret_limit_unit, int *ret_limit_rate,
							   alert_time_unit *ret_limit_burst, 
							   int *ret_burst_rate) {
	char err[1024];
	vector<string> tokens = StrTokenize(alert_str, ",");

	if (tokens.size() != 3) {
		snprintf(err, 1024, "Malformed limits for alert '%s'", alert_str.c_str());
		globalreg->messagebus->InjectMessage(err, MSGFLAG_ERROR);
		return -1;
	}

	(*ret_name) = StrLower(tokens[0]);

	if (ParseRateUnit(StrLower(tokens[1]), ret_limit_unit, ret_limit_rate) != 1 ||
		ParseRateUnit(StrLower(tokens[2]), ret_limit_burst, ret_burst_rate) != 1) {
		snprintf(err, 1024, "Malformed limits for alert '%s'", alert_str.c_str());
		globalreg->messagebus->InjectMessage(err, MSGFLAG_ERROR);
		return -1;
	}

	return 1;
}

// Split up a rate/unit string into real values
int Alertracker::ParseRateUnit(string in_ru, alert_time_unit *ret_unit,
							   int *ret_rate) {
	char err[1024];
	vector<string> units = StrTokenize(in_ru, "/");

	if (units.size() == 1) {
		// Unit is per minute if not specified
		(*ret_unit) = sat_minute;
	} else {
		// Parse the string unit
		if (units[1] == "sec" || units[1] == "second") {
			(*ret_unit) = sat_second;
		} else if (units[1] == "min" || units[1] == "minute") {
			(*ret_unit) = sat_minute;
		} else if (units[1] == "hr" || units[1] == "hour") { 
			(*ret_unit) = sat_hour;
		} else if (units[1] == "day") {
			(*ret_unit) = sat_day;
		} else {
			snprintf(err, 1024, "Alertracker - Invalid time unit for alert rate '%s'",
					 units[1].c_str());
			globalreg->messagebus->InjectMessage(err, MSGFLAG_ERROR);
			return -1;
		}
	}

	// Get the number
	if (sscanf(units[0].c_str(), "%d", ret_rate) != 1) {
		snprintf(err, 1024, "Alertracker - Invalid rate '%s' for alert",
				 units[0].c_str());
		globalreg->messagebus->InjectMessage(err, MSGFLAG_ERROR);
		return -1;
	}

	return 1;
}

int Alertracker::ParseAlertConfig(ConfigFile *in_conf) {
	vector<string> clines = in_conf->FetchOptVec("alert");

	for (unsigned int x = 0; x < clines.size(); x++) {
		alert_conf_rec *rec = new alert_conf_rec;

		if (ParseAlertStr(clines[x], &(rec->header), &(rec->limit_unit), 
						  &(rec->limit_rate), &(rec->burst_unit), 
						  &(rec->limit_burst)) < 0) {
			_MSG("Invalid alert line in config file: " + clines[x], MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
      delete rec;
			return -1;
		}

		alert_conf_map[StrLower(rec->header)] = rec;
	}

	return 1;
}

int Alertracker::ActivateConfiguredAlert(const char *in_header) {
	return ActivateConfiguredAlert(in_header, KIS_PHY_UNKNOWN);
}

int Alertracker::ActivateConfiguredAlert(const char *in_header, int in_phy) {
    alert_conf_rec *rec;

    {
        local_locker lock(&alert_mutex);

        string hdr = StrLower(in_header);

        if (alert_conf_map.find(hdr) == alert_conf_map.end()) {
            _MSG("Alert type " + string(in_header) + " not found in list of activated "
                    "alerts.", MSGFLAG_INFO);
            return -1;
        }

        rec = alert_conf_map[hdr];
    }

	return RegisterAlert(rec->header.c_str(), rec->limit_unit, rec->limit_rate, 
						 rec->burst_unit, rec->limit_burst, in_phy);
}

const vector<kis_alert_info *> *Alertracker::FetchBacklog() {
    local_locker lock(&alert_mutex);

	return (const vector<kis_alert_info *> *) &alert_backlog;
}

bool Alertracker::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0) {
        return false;
    }

    // Split URL and process
    vector<string> tokenurl = StrTokenize(path, "/");
    if (tokenurl.size() < 3)
        return false;

    if (tokenurl[1] == "alerts") {
        if (tokenurl[2] == "all_alerts.msgpack") {
            return true;
        } else if (tokenurl[2] == "all_alerts.json") {
            return true;
        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return false;

            if (tokenurl[4] == "alerts.msgpack")
                return true;
            else if (tokenurl[4] == "alerts.json")
                return true;
            else
                return false;
        }
    }

    return false;
}

void Alertracker::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        struct MHD_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    TrackerElementSerializer *serializer = NULL;
    time_t since_time = 0;
    bool wrap = false;

    if (strcmp(method, "GET") != 0) {
        return;
    }

    // Split URL and process
    vector<string> tokenurl = StrTokenize(path, "/");
    if (tokenurl.size() < 3)
        return;

    if (tokenurl[1] == "alerts") {
        if (tokenurl[2] == "all_alerts.msgpack") {
            serializer =
                new MsgpackAdapter::Serializer(globalreg, stream);
        } else if (tokenurl[2] == "all_alerts.json") {
            serializer =
                new JsonAdapter::Serializer(globalreg, stream);
        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return;

            long lastts;
            if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1)
                return;

            wrap = true;

            since_time = lastts;

            if (tokenurl[4] == "alerts.msgpack") {
                serializer =
                    new MsgpackAdapter::Serializer(globalreg, stream);
            } else if (tokenurl[4] == "alerts.json") {
                serializer =
                    new JsonAdapter::Serializer(globalreg, stream);
            } else {
                return;
            }
        }
    }

    if (serializer == NULL)
        return;

    {
        local_locker lock(&alert_mutex);

        TrackerElement *wrapper;
        TrackerElement *msgvec = 
            globalreg->entrytracker->GetTrackedInstance(alert_vec_id);
       
        // If we're doing a time-since, wrap the vector
        if (wrap) {
            wrapper = new TrackerElement(TrackerMap);
            wrapper->add_map(msgvec);

            TrackerElement *ts =
                globalreg->entrytracker->GetTrackedInstance(alert_timestamp_id);
            ts->set((uint64_t) globalreg->timestamp.tv_sec);
            wrapper->add_map(ts);
        } else {
            wrapper = msgvec;
        }

        for (vector<kis_alert_info *>::iterator i = alert_backlog.begin();
                i != alert_backlog.end(); ++i) {
            if (since_time < (*i)->tm.tv_sec) {
                tracked_alert *ta = new tracked_alert(globalreg, alert_entry_id);
                ta->from_alert_info(*i);
                msgvec->add_vector(ta);
            }
        }

        serializer->serialize(wrapper);

        delete(wrapper);
        delete(serializer);
    }
}

