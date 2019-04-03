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
#include "structured.h"
#include "kismet_json.h"
#include "base64.h"
#include "kis_databaselogfile.h"

Alertracker::Alertracker() :
    Kis_Net_Httpd_CPPStream_Handler() {

	next_alert_id = 0;

    packetchain = Globalreg::FetchMandatoryGlobalAs<Packetchain>();
    entrytracker = Globalreg::FetchMandatoryGlobalAs<EntryTracker>();

    alert_vec_id =
        entrytracker->RegisterField("kismet.alert.list",
                TrackerElementFactory<TrackerElementVector>(), 
                "list of alerts");

    alert_timestamp_id =
        entrytracker->RegisterField("kismet.alert.timestamp",
                TrackerElementFactory<TrackerElementDouble>(), 
                "alert update timestamp");

    alert_entry_id =
        entrytracker->RegisterField("kismet.alert.alert",
                TrackerElementFactory<tracked_alert>(),
                "Kismet alert");


    alert_defs_vec = 
        entrytracker->RegisterAndGetFieldAs<TrackerElementVector>("kismet.alert.definition_list",
                TrackerElementFactory<TrackerElementVector>(), 
                "Kismet alert definitions");

    alert_def_id =
        entrytracker->RegisterField("kismet.alert.alert_definition",
                TrackerElementFactory<tracked_alert_definition>(),
                "Kismet alert definition");

	// Register the alert component
    pack_comp_alert =
		packetchain->RegisterPacketComponent("alert");

	// Register a KISMET alert type with no rate restrictions
    alert_ref_kismet =
		RegisterAlert("KISMET", "Server events", sat_day, 0, sat_day, 0, KIS_PHY_ANY);


    Bind_Httpd_Server();

	if (Globalreg::globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Alertracker called with null config\n");
		exit(1);
	}

#ifdef PRELUDE
    // Start client Prelude
    int ret;
    ret = prelude_init(0, NULL);
    if (ret < 0) {
        _MSG("Alertracker - Failed to initialize Prelude SIEM connection", MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return;
    }

    PreludeInitClient(PRELUDE_ANALYZER_MODEL);
#endif

	if (Globalreg::globalreg->kismet_config->FetchOpt("alertbacklog") != "") {
		int scantmp;
		if (sscanf(Globalreg::globalreg->kismet_config->FetchOpt("alertbacklog").c_str(), 
				   "%d", &scantmp) != 1 || scantmp < 0) {
            _MSG("Illegal value for 'alertbacklog' in kismet.conf, expected number greater than zero.",
                    MSGFLAG_FATAL);
			Globalreg::globalreg->fatal_condition = 1;
			return;
		}
		num_backlog = scantmp;
	}

	// Parse config file vector of all alerts
	if (ParseAlertConfig(Globalreg::globalreg->kismet_config) < 0) {
		_MSG("Failed to parse alert values from Kismet config file", MSGFLAG_FATAL);
        Globalreg::globalreg->fatal_condition = 1;
		return;
	}

    log_alerts = Globalreg::globalreg->kismet_config->FetchOptBoolean("kis_log_alerts", true);
}

Alertracker::~Alertracker() {
    local_locker lock(&alert_mutex);

    Globalreg::globalreg->RemoveGlobal("ALERTTRACKER");
    Globalreg::globalreg->alertracker = NULL;

#ifdef PRELUDE
    prelude_deinit();
    delete prelude_client;
#endif
}

void Alertracker::PreludeInitClient(const char *analyzer_name) {
#ifdef PRELUDE
    try {
        string version = 
            globalreg->version_major + "." + 
            globalreg->version_minor + "." +
            globalreg->version_tiny;

        prelude_client = 
            new Prelude::ClientEasy(analyzer_name, 4, PRELUDE_ANALYZER_MODEL, 
                    PRELUDE_ANALYZER_CLASS, PRELUDE_ANALYZER_MANUFACTURER, version.c_str());
        prelude_client->start();
    } catch (Prelude::PreludeError const & error) {
        _MSG(std::string("Alertracker failed to initialize connection to Prelude: ") + 
                error.what(), MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;

        return;
    }
#endif
}

int Alertracker::RegisterAlert(std::string in_header, std::string in_description, 
        alert_time_unit in_unit, int in_rate, alert_time_unit in_burstunit,
        int in_burst, int in_phy) {
    local_locker lock(&alert_mutex);

	// Bail if this header is registered
	if (alert_name_map.find(in_header) != alert_name_map.end()) {
        _MSG("Tried to re-register duplicate alert " + in_header, MSGFLAG_ERROR);
		return -1;
	}

    // Make sure we're not going to overstep our range
    if ((unsigned int) in_burstunit > sat_day)
        in_burstunit = sat_day;
    if ((unsigned int) in_unit > sat_day)
        in_unit = sat_day;

    // Bail if the rates are impossible
    if (in_burstunit > in_unit) {
        _MSG("Failed to register alert " + in_header + ", time unit for "
                "burst rate must be less than or equal to the time unit "
                "for the max rate", MSGFLAG_ERROR);
        return -1;
    }

    auto arec =
        std::make_shared<tracked_alert_definition>(alert_def_id);

    arec->set_alert_ref(next_alert_id++);
    arec->set_header(StrUpper(in_header));
    arec->set_description(in_description);
    arec->set_limit_unit(in_unit);
    arec->set_limit_rate(in_rate);
    arec->set_burst_unit(in_burstunit);
    arec->set_limit_burst(in_burst);
    arec->set_phy(in_phy);
    arec->set_time_last(0);

    alert_name_map.insert(std::make_pair(arec->get_header(), arec->get_alert_ref()));
    alert_ref_map.insert(std::make_pair(arec->get_alert_ref(), arec));

    alert_defs_vec->push_back(arec);

	return arec->get_alert_ref();
}

int Alertracker::FetchAlertRef(std::string in_header) {
    local_locker lock(&alert_mutex);

    auto ni = alert_name_map.find(in_header);

    if (ni != alert_name_map.end())
        return ni->second;

    return -1;
}

int Alertracker::CheckTimes(shared_alert_def arec) {
    // Alerts limited to 0 are squelched
	if (arec->get_limit_rate() == 0) {
		return 0;
	}

	struct timeval now;
	gettimeofday(&now, NULL);

	// If the last time we sent anything was longer than the main rate limit,
	// then we reset back to empty
	if (arec->get_time_last() < (now.tv_sec - 
                alert_time_unit_conv[arec->get_limit_unit()])) {
		arec->set_total_sent(0);
		arec->set_burst_sent(0);
		return 1;
	}

	// If the last time we sent anything was longer than the burst rate, we can
	// reset the burst to 0
	if (arec->get_time_last() < (now.tv_sec - 
                alert_time_unit_conv[arec->get_burst_unit()])) {
		arec->set_burst_sent(0);
	}

	// If we're under the limit on both, we're good to go
	if (arec->get_burst_sent() < arec->get_limit_burst() && 
            arec->get_total_sent() < arec->get_limit_rate())
		return 1;

	return 0;
}

int Alertracker::PotentialAlert(int in_ref) {
    local_locker lock(&alert_mutex);

	std::map<int, shared_alert_def>::iterator aritr = alert_ref_map.find(in_ref);

	if (aritr == alert_ref_map.end())
		return 0;

	shared_alert_def arec = aritr->second;

	return CheckTimes(arec);
}

int Alertracker::RaiseAlert(int in_ref, kis_packet *in_pack,
							mac_addr bssid, mac_addr source, mac_addr dest, 
							mac_addr other, std::string in_channel, std::string in_text) {

    local_demand_locker lock(&alert_mutex);

    lock.lock();

	std::map<int, shared_alert_def>::iterator aritr = alert_ref_map.find(in_ref);

	if (aritr == alert_ref_map.end())
		return -1;

	shared_alert_def arec = aritr->second;

	if (CheckTimes(arec) != 1)
		return 0;

    lock.unlock();

	kis_alert_info *info = new kis_alert_info;

	info->header = arec->get_header();
	info->phy = arec->get_phy();
	gettimeofday(&(info->tm), NULL);

	info->bssid = bssid;
	info->source = source;
	info->dest  = dest;
	info->other = other;

	info->channel = in_channel;	

	info->text = in_text;

	// Increment and set the timers
    arec->inc_burst_sent(1);
    arec->inc_total_sent(1);
    arec->set_time_last(ts_to_double(info->tm));

    lock.lock();

	alert_backlog.push_back(info);
	if ((int) alert_backlog.size() > num_backlog) {
		delete alert_backlog[0];
		alert_backlog.erase(alert_backlog.begin());
	}

    lock.unlock();

	// Try to get the existing alert info
	if (in_pack != NULL)  {
        auto acomp = in_pack->fetch<kis_alert_component>(pack_comp_alert);

		// if we don't have an alert container, make one on this packet
		if (acomp == NULL) {
			acomp = new kis_alert_component;
			in_pack->insert(pack_comp_alert, acomp);
		}

		// Attach it to the packet
		acomp->alert_vec.push_back(info);
	}

#ifdef PRELUDE
	// Send alert to Prelude
	RaisePreludeAlert(in_ref, in_pack, info->bssid, info->source, 
            info->dest, info->other, info->channel, info->text);
#endif

	// Send the text info
	_MSG(info->header + " " + info->text, MSGFLAG_ALERT);

    if (log_alerts) {
        auto dbf = 
            Globalreg::FetchGlobalAs<KisDatabaseLogfile>("DATABASELOG");
        if (dbf != NULL) {
            auto ta = std::make_shared<tracked_alert>(alert_entry_id);
            ta->from_alert_info(info);
            dbf->log_alert(ta);
        }
    }

	return 1;
}

int Alertracker::RaiseOneShot(std::string in_header, std::string in_text, int in_phy) {
    local_demand_locker lock(&alert_mutex);

	kis_alert_info *info = new kis_alert_info;

	info->header = in_header;
	info->phy = in_phy;
	gettimeofday(&(info->tm), NULL);

	info->bssid = mac_addr(0);
	info->source = mac_addr(0);
	info->dest  = mac_addr(0);
	info->other = mac_addr(0);

	info->channel = "";	

	info->text = in_text;

    lock.lock();
	alert_backlog.push_back(info);
	if ((int) alert_backlog.size() > num_backlog) {
		delete alert_backlog[0];
		alert_backlog.erase(alert_backlog.begin());
	}
    lock.unlock();

#ifdef PRELUDE
	// Send alert to Prelude
	RaisePreludeOneShot(in_header, in_text);
#endif

	// Send the text info
	_MSG(info->header + " " + info->text, MSGFLAG_ALERT);

    if (log_alerts) {
        auto dbf =
            Globalreg::FetchGlobalAs<KisDatabaseLogfile>("DATABASELOG");
        if (dbf != NULL) {
            auto ta = std::make_shared<tracked_alert>(alert_entry_id);
            ta->from_alert_info(info);
            dbf->log_alert(ta);
        }
    }

	return 1;
}

int Alertracker::RaisePreludeAlert(int in_ref, kis_packet *in_pack,
        mac_addr bssid, mac_addr source, mac_addr dest,
        mac_addr other, std::string in_channel, std::string in_text) {

#ifdef PRELUDE
    mac_addr emptymac = mac_addr(0);

    Prelude::IDMEF idmef;

    // Classification
    idmef.set("alert.classification.text", "Suspicious network detected");

    // Source
    if (source != emptymac) {
        idmef.set("alert.source(0).node.address(0).category", "mac");
        idmef.set("alert.source(0).node.address(0).address", source.Mac2String().c_str());
    }

    // Target
    if (dest != emptymac) {
        idmef.set("alert.target(0).node.address(0).category", "mac");
        idmef.set("alert.target(0).node.address(0).address", dest.Mac2String().c_str());
    }

    // Assessment
    idmef.set("alert.assessment.impact.severity", "high");
    idmef.set("alert.assessment.impact.completion", "succeeded");
    idmef.set("alert.assessment.impact.description", in_text);

    // Additional Data
    if (bssid != emptymac) {
        idmef.set("alert.additional_data(>>).meaning", "BSSID");
        idmef.set("alert.additional_data(-1).data", bssid.Mac2String().c_str());
    }

    if (other != emptymac) {
        idmef.set("alert.additional_data(>>).meaning", "Other");
        idmef.set("alert.additional_data(-1).data", other.Mac2String().c_str());
    }

    idmef.set("alert.additional_data(>>).meaning", "Channel");
    idmef.set("alert.additional_data(-1).data", in_channel);

    idmef.set("alert.additional_data(>>).meaning", "in_ref");
    idmef.set("alert.additional_data(-1).data", in_ref);

    prelude_client->sendIDMEF(idmef);
#endif

    return 0;
}

int Alertracker::RaisePreludeOneShot(std::string in_header, std::string in_text) {
#ifdef PRELUDE
    mac_addr emptymac = mac_addr(0);

    Prelude::IDMEF idmef;

    // Classification
    idmef.set("alert.classification.text", "Suspicious network detected");

    // Assessment
    idmef.set("alert.assessment.impact.severity", "high");
    idmef.set("alert.assessment.impact.completion", "succeeded");
    idmef.set("alert.assessment.impact.description", in_text);

    idmef.set("alert.additional_data(>>).alert_type", "in_ref");
    idmef.set("alert.additional_data(-1).data", in_header);

    prelude_client->sendIDMEF(idmef);
#endif

    return 0;
}

int Alertracker::ParseAlertStr(std::string alert_str, std::string *ret_name, 
        alert_time_unit *ret_limit_unit, int *ret_limit_rate,
        alert_time_unit *ret_limit_burst, 
        int *ret_burst_rate) {

	std::vector<std::string> tokens = StrTokenize(alert_str, ",");

	if (tokens.size() != 3) {
        _MSG_ERROR("Malformed limits for alert '{}'", alert_str);
		return -1;
	}

	(*ret_name) = StrUpper(tokens[0]);

	if (ParseRateUnit(StrLower(tokens[1]), ret_limit_unit, ret_limit_rate) != 1 ||
		ParseRateUnit(StrLower(tokens[2]), ret_limit_burst, ret_burst_rate) != 1) {
        _MSG_ERROR("Malformed limits for alert '{}'", alert_str);
		return -1;
	}

	return 1;
}

// Split up a rate/unit string into real values
int Alertracker::ParseRateUnit(std::string in_ru, alert_time_unit *ret_unit,
							   int *ret_rate) {
	std::vector<std::string> units = StrTokenize(in_ru, "/");

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
            _MSG("Invalid time unit for alert rate '" + units[1] + "'", 
                    MSGFLAG_ERROR);
			return -1;
		}
	}

	// Get the number
	if (sscanf(units[0].c_str(), "%d", ret_rate) != 1) {
        _MSG("Invalid rate '" + units[0] + "' for alert", MSGFLAG_ERROR);
		return -1;
	}

	return 1;
}

int Alertracker::ParseAlertConfig(ConfigFile *in_conf) {
    std::vector<std::string> clines = in_conf->FetchOptVec("alert");

    for (unsigned int x = 0; x < clines.size(); x++) {
        alert_conf_rec *rec = new alert_conf_rec;

        if (ParseAlertStr(clines[x], &(rec->header), &(rec->limit_unit), 
                    &(rec->limit_rate), &(rec->burst_unit), 
                    &(rec->limit_burst)) < 0) {
            _MSG_FATAL("Invalid 'alert' config option {}; expected HEADER,rate,burstrate", clines[x]);
            Globalreg::globalreg->fatal_condition = 1;
            delete rec;
            return -1;
        }

        alert_conf_map.insert(std::make_pair(rec->header, rec));
    }

    return 1;
}

int Alertracker::DefineAlert(std::string name, alert_time_unit limit_unit, int limit_rate,
        alert_time_unit burst_unit, int burst_rate) {
    local_locker lock(&alert_mutex);

    auto ai = alert_conf_map.find(StrUpper(name));
    if (ai != alert_conf_map.end()) {
        _MSG_ERROR("alerttracker - tried to define alert '{}' twice.", name);
        return -1;
    }

    alert_conf_rec *rec = new alert_conf_rec;
    rec->header = StrUpper(name);
    rec->limit_unit = limit_unit;
    rec->limit_rate = limit_rate;
    rec->burst_unit = burst_unit;
    rec->limit_burst = burst_rate;

    alert_conf_map.insert(std::make_pair(rec->header, rec));

    return 1;
}

int Alertracker::ActivateConfiguredAlert(std::string in_header, std::string in_desc) {
	return ActivateConfiguredAlert(in_header, in_desc, KIS_PHY_UNKNOWN);
}

int Alertracker::ActivateConfiguredAlert(std::string in_header, std::string in_desc, int in_phy) {
    alert_conf_rec *rec;

    {
        local_locker lock(&alert_mutex);

        std::string hdr = StrUpper(in_header);

        auto hi = alert_conf_map.find(hdr);

        if (hi == alert_conf_map.end()) {
            _MSG_INFO("Using default rates of 10/min, 1/sec for alert '{}'", in_header);
            DefineAlert(in_header, sat_minute, 10, sat_second, 1);

            auto hi_full = alert_conf_map.find(hdr);
            if (hi_full == alert_conf_map.end()) {
                _MSG_ERROR("Failed to define default rate alert '{}'", in_header);
                return -1;
            }

            rec = hi_full->second;
        } else {
            rec = hi->second;
        }
    }

	return RegisterAlert(rec->header, in_desc, rec->limit_unit, rec->limit_rate, 
            rec->burst_unit, rec->limit_burst, in_phy);
}

int Alertracker::FindActivatedAlert(std::string in_header) {
    local_locker lock(&alert_mutex);

    for (auto x : alert_ref_map) {
        if (x.second->get_header() == in_header)
            return x.first;
    }

    return -1;
}

bool Alertracker::Httpd_VerifyPath(const char *path, const char *method) {
    if (!Httpd_CanSerialize(path))
        return false;

    if (strcmp(method, "GET") == 0) {
        // Split URL and process
        std::vector<std::string> tokenurl = StrTokenize(path, "/");
        if (tokenurl.size() < 3)
            return false;

        if (tokenurl[1] == "alerts") {
            if (Httpd_StripSuffix(tokenurl[2]) == "definitions") {
                return true;
            } else if (Httpd_StripSuffix(tokenurl[2]) == "all_alerts") {
                return true;
            } else if (tokenurl[2] == "last-time") {
                if (tokenurl.size() < 5)
                    return false;

                if (Httpd_CanSerialize(tokenurl[4]))
                    return true;

                return false;
            }
        }
        
        return false;
    } 

    if (strcmp(method, "POST") == 0) {
        std::string stripped = httpd->StripSuffix(path);

        if (stripped == "/alerts/definitions/define_alert")
            return true;

        if (stripped == "/alerts/raise_alert")
            return true;

        return false;
    }

    return false;
}

void Alertracker::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    double since_time = 0;
    bool wrap = false;

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (!Httpd_CanSerialize(path))
        return;

    // Split URL and process
    std::vector<std::string> tokenurl = StrTokenize(path, "/");
    if (tokenurl.size() < 3)
        return;

    if (tokenurl[1] == "alerts") {
        if (Httpd_StripSuffix(tokenurl[2]) == "definitions") {
            Httpd_Serialize(path, stream, alert_defs_vec);
            return;
        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return;

            std::stringstream ss(tokenurl[3]);
            ss >> since_time;

            wrap = true;
        }
    }

    std::shared_ptr<TrackerElement> transmit;
    std::shared_ptr<TrackerElementMap> wrapper;
    std::shared_ptr<TrackerElementVector> msgvec = std::make_shared<TrackerElementVector>(alert_vec_id);

    // If we're doing a time-since, wrap the vector
    if (wrap) {
        wrapper = std::make_shared<TrackerElementMap>();
        wrapper->insert(msgvec);

        auto ts = std::make_shared<TrackerElementDouble>(alert_timestamp_id, ts_now_to_double());
        wrapper->insert(ts);

        transmit = wrapper;
    } else {
        transmit = msgvec;
    }

    {
        local_locker lock(&alert_mutex);

        for (auto i : alert_backlog) {
            if (since_time < ts_to_double((i)->tm)) {
                auto ta = std::make_shared<tracked_alert>(alert_entry_id);
                ta->from_alert_info(i);
                msgvec->push_back(ta);
            }
        }
    }

    Httpd_Serialize(path, stream, transmit);
}

int Alertracker::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    std::string stripped = Httpd_StripSuffix(concls->url);
   
    if (!Httpd_CanSerialize(concls->url) ||
            (stripped != "/alerts/definitions/define_alert" &&
             stripped != "/alerts/raise_alert")) {
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
        return 1;
    }

    if (!httpd->HasValidSession(concls, true)) {
        concls->httpcode = 503;
        return MHD_NO;
    }

    SharedStructured structdata;

    try {
        if (concls->variable_cache.find("json") != concls->variable_cache.end()) {
            structdata.reset(new StructuredJson(concls->variable_cache["json"]->str()));
        } else {
            throw std::runtime_error("could not find data");
        }

        if (stripped == "/alerts/definitions/define_alert") {
            std::string name = structdata->getKeyAsString("name");
            std::string desc = structdata->getKeyAsString("description");

            alert_time_unit limit_unit;
            int limit_rate;

            alert_time_unit burst_unit;
            int burst_rate;

            if (ParseRateUnit(StrLower(structdata->getKeyAsString("throttle", "")),
                        &limit_unit, &limit_rate) < 0) {
                throw std::runtime_error("could not parse throttle limits");
            }

            if (ParseRateUnit(StrLower(structdata->getKeyAsString("burst", "")),
                        &burst_unit, &burst_rate) < 0) {
                throw std::runtime_error("could not parse burst limits");
            }

            int phyid = KIS_PHY_ANY;

            std::string phyname = structdata->getKeyAsString("phyname", "");

            if (phyname != "any" && phyname != "") {
                auto devicetracker = 
                    Globalreg::FetchMandatoryGlobalAs<Devicetracker>();
                Kis_Phy_Handler *phyh = devicetracker->FetchPhyHandlerByName(phyname);

                if (phyh == NULL)
                    throw std::runtime_error("could not find phy");

                phyid = phyh->FetchPhyId();
            }

            if (DefineAlert(name, limit_unit, limit_rate, burst_unit, burst_rate) < 0) {
                concls->httpcode = 503;
                throw std::runtime_error("could not add alert");
            }

            if (ActivateConfiguredAlert(name, desc, phyid) < 0) {
                concls->httpcode = 504;
                throw std::runtime_error("could not activate alert");
            }

            concls->response_stream << "Added alert";
            return 1;

        } else if (stripped == "/alerts/raise_alert") {
            std::string name = structdata->getKeyAsString("name");
    
            int aref = FetchAlertRef(name);

            if (aref < 0)
                throw std::runtime_error("unknown alert type");

            std::string text = structdata->getKeyAsString("text");

            std::string bssid = structdata->getKeyAsString("bssid", "");
            std::string source = structdata->getKeyAsString("source", "");
            std::string dest = structdata->getKeyAsString("dest", "");
            std::string other = structdata->getKeyAsString("other", "");
            std::string channel = structdata->getKeyAsString("channel", "");

            mac_addr bssid_mac, source_mac, dest_mac, other_mac;

            if (bssid.length() != 0) {
                bssid_mac = mac_addr(bssid);
            }
            if (source.length() != 0) {
                source_mac = mac_addr(source);
            }
            if (dest.length() != 0) {
                dest_mac = mac_addr(dest);
            }
            if (other.length() != 0) {
                other_mac = mac_addr(other);
            }

            if (bssid_mac.error || source_mac.error || 
                    dest_mac.error || other_mac.error) {
                throw std::runtime_error("invalid mac");
            }

            if (!PotentialAlert(aref)) 
                throw std::runtime_error("alert limit reached");

            RaiseAlert(aref, NULL, bssid_mac, source_mac, dest_mac, other_mac,
                    channel, text);

            concls->response_stream << "alert raised";

            return 1;
        }

    } catch (const std::exception& e) {
        concls->response_stream << "Invalid request " << e.what();

        if (concls->httpcode != 200)
            concls->httpcode = 400;
        return 1;
    }

    return MHD_NO;
}


