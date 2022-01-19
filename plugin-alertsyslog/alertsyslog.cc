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
#include <timetracker.h>
#include <configfile.h>
#include <plugintracker.h>
#include <globalregistry.h>
#include <alertracker.h>
#include <version.h>

int pack_comp_alert;

int alertsyslog_chain_hook(CHAINCALL_PARMS) {
    std::shared_ptr<kis_alert_component> alrtinfo;

	if (in_pack->error)
		return 0;

	// Grab the alerts
    alrtinfo = in_pack->fetch<kis_alert_component>(pack_comp_alert);

	if (alrtinfo == NULL)
		return 0;

	for (unsigned int x = 0; x < alrtinfo->alert_vec.size(); x++) {
		syslog(LOG_CRIT, "%s server-ts=%u bssid=%s source=%s dest=%s channel=%s %s",
			   alrtinfo->alert_vec[x]->header.c_str(),
			   (unsigned int) alrtinfo->alert_vec[x]->tm.tv_sec,
			   alrtinfo->alert_vec[x]->bssid.mac_to_string().c_str(),
			   alrtinfo->alert_vec[x]->source.mac_to_string().c_str(),
			   alrtinfo->alert_vec[x]->dest.mac_to_string().c_str(),
			   alrtinfo->alert_vec[x]->channel.c_str(),
			   alrtinfo->alert_vec[x]->text.c_str());
	}

	return 1;
}

int alertsyslog_openlog(global_registry *in_globalreg) {
    // We can't use the templated fetch_global_as here because the template object code
    // won't exist in the server object
    std::shared_ptr<packet_chain> packetchain =
        std::static_pointer_cast<packet_chain>(in_globalreg->fetch_global(std::string("PACKETCHAIN")));

    if (packetchain == NULL) {
        _MSG("Unable to register syslog plugin, packetchain was unavailable",
                MSGFLAG_ERROR);
        return -1;
    }

    pack_comp_alert = packetchain->register_packet_component("alert");

    openlog(in_globalreg->servername.c_str(), LOG_NDELAY, LOG_USER);

    packetchain->register_handler(&alertsyslog_chain_hook, NULL,
            CHAINPOS_LOGGING, -100);

    return 1;
}

extern "C" {
    int kis_plugin_version_check(struct plugin_server_info *si) {
        si->plugin_api_version = KIS_PLUGINTRACKER_VERSION;
        si->kismet_major = VERSION_MAJOR;
        si->kismet_minor = VERSION_MINOR;
        si->kismet_tiny = VERSION_TINY;

        return 1;
    }

    int kis_plugin_activate(global_registry *in_globalreg) {
        return 1;
    }

    int kis_plugin_finalize(global_registry *in_globalreg) {
        return alertsyslog_openlog(in_globalreg);
    }

}

