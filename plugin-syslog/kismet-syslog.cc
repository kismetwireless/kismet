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

#include <config.h>
#include <string>
#include <errno.h>
#include <time.h>

#include <pthread.h>

#include <sstream>
#include <iomanip>
#include <syslog.h>

#include <util.h>
#include <messagebus.h>
#include <packet.h>
#include <packetchain.h>
#include <packetsource.h>
#include <packetsourcetracker.h>
#include <timetracker.h>
#include <configfile.h>
#include <plugintracker.h>
#include <globalregistry.h>
#include <devicetracker.h>
#include <alertracker.h>
#include <version.h>
#include <gpscore.h>

GlobalRegistry *globalreg = NULL;

class SyslogMessageClient : public MessageClient {
public:
    SyslogMessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
        MessageClient(in_globalreg, in_aux) { 
		watch_mask = 0;

		vector<string> mtoks = 
			StrTokenize(StrLower(globalreg->kismet_config->FetchOpt("syslogtype")), ",");

		if (mtoks.size() == 0) {
			_MSG("Kismet-Syslog not redirecting any messages to syslog because no "
				 "syslogtype= directive found in kismet.conf", MSGFLAG_ERROR);
		}

		string logtext = "no";

		for (unsigned int x = 0; x < mtoks.size(); x++) {
			if (mtoks[x] == "no") {
				watch_mask = 0;
				break;
			} else if (mtoks[x] == "all") {
				watch_mask = MSGFLAG_ALL;
				logtext = "all";
				break;
			} else if (mtoks[x] == "info") {
				watch_mask |= MSGFLAG_INFO;
				logtext = StringAppend(logtext, "info", ", ");
			} else if (mtoks[x] == "error") {
				logtext = StringAppend(logtext, "error", ", ");
				watch_mask |= MSGFLAG_ERROR;
			} else if (mtoks[x] == "alert") {
				logtext = StringAppend(logtext, "alert", ", ");
				watch_mask |= MSGFLAG_ALERT;
			} else if (mtoks[x] == "fatal") {
				watch_mask |= MSGFLAG_FATAL;
				logtext = StringAppend(logtext, "fatal", ", ");
			}
		}

		_MSG("Kismet-Syslog redirecting " + logtext + " messages to syslog", MSGFLAG_INFO);
	}

	virtual ~SyslogMessageClient() { }
    void ProcessMessage(string in_msg, int in_flags) {
		if ((in_flags & watch_mask) == 0) {
			return;
		}

		syslog(LOG_CRIT, "%s", in_msg.c_str());
	}

protected:
	int watch_mask;
};


int alertsyslog_chain_hook(CHAINCALL_PARMS) {
	kis_alert_component *alrtinfo = NULL;

	if (in_pack->error)
		return 0;

	// Grab the alerts
	alrtinfo = (kis_alert_component *) in_pack->fetch(_PCM(PACK_COMP_ALERT));

	if (alrtinfo == NULL)
		return 0;

	for (unsigned int x = 0; x < alrtinfo->alert_vec.size(); x++) {
		syslog(LOG_CRIT, "%s server-ts=%u bssid=%s source=%s dest=%s channel=%u %s",
			   alrtinfo->alert_vec[x]->header.c_str(),
			   (unsigned int) alrtinfo->alert_vec[x]->tm.tv_sec,
			   alrtinfo->alert_vec[x]->bssid.Mac2String().c_str(),
			   alrtinfo->alert_vec[x]->source.Mac2String().c_str(),
			   alrtinfo->alert_vec[x]->dest.Mac2String().c_str(),
			   alrtinfo->alert_vec[x]->channel,
			   alrtinfo->alert_vec[x]->text.c_str());
	}

	return 1;
}

int syslog_unregister(GlobalRegistry *in_globalreg) {
	return 0;
}

int syslog_register(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	if (globalreg->kismet_instance != KISMET_INSTANCE_SERVER) {
		_MSG("Not initializing alertsyslog plugin, not running on a server.",
			 MSGFLAG_INFO);
		return 1;
	}

	openlog(globalreg->servername.c_str(), LOG_NDELAY, LOG_USER);

	globalreg->packetchain->RegisterHandler(&alertsyslog_chain_hook, NULL,
											CHAINPOS_LOGGING, -100);

	SyslogMessageClient *sysm = 
		new SyslogMessageClient(globalreg, NULL);
	globalreg->messagebus->RegisterClient(sysm, MSGFLAG_ALL);

	return 1;
}

extern "C" {
	int kis_plugin_info(plugin_usrdata *data) {
		data->pl_name = "SYSLOG";
		data->pl_version = string(VERSION_MAJOR) + "-" + string(VERSION_MINOR) + "-" +
			string(VERSION_TINY);
		data->pl_description = "SYSLOG Plugin";
		data->pl_unloadable = 0; // We can't be unloaded because we defined a source
		data->plugin_register = syslog_register;
		data->plugin_unregister = syslog_unregister;

		return 1;
	}

	void kis_revision_info(plugin_revision *prev) {
		if (prev->version_api_revision >= 1) {
			prev->version_api_revision = 1;
			prev->major = string(VERSION_MAJOR);
			prev->minor = string(VERSION_MINOR);
			prev->tiny = string(VERSION_TINY);
		}
	}
}

