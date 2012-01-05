/*
    This file is part of Kismet

	This file was derived directly from aircrack-ng, and most of the other files in 
	this directory come, almost unmodified, from that project.

	For more information about aircrack-ng, visit:
	http://aircrack-ng.org

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

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL. *  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so. *  If you
    do not wish to do so, delete this exception statement from your
    version. *  If you delete this exception statement from all source
    files in the program, then also delete it here.
*/

#include <config.h>
#include <string>
#include <errno.h>
#include <time.h>

#include <pthread.h>

#include <sstream>
#include <iomanip>

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
#include <netracker.h>
#include <alertracker.h>
#include <dumpfile_pcap.h>
#include <version.h>

#include "packetsource_linuxbt.h"
#include "packet_btscan.h"
#include "phy_btscan.h"

GlobalRegistry *globalreg = NULL;

int pack_comp_btscan;

int btscan_unregister(GlobalRegistry *in_globalreg) {
	return 0;
}

int btscan_register(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	globalreg->sourcetracker->AddChannelList("LINUXBTSCAN:0");

#ifdef USE_PACKETSOURCE_LINUXBT
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_LinuxBT(globalreg)) < 0 || globalreg->fatal_condition)
		return -1;
#endif

	if (globalreg->kismet_instance != KISMET_INSTANCE_SERVER) {
		_MSG("Not registering BTSCAN packet handlers, not running on a server.",
			 MSGFLAG_INFO);
		return 1;
	}

	pack_comp_btscan = globalreg->packetchain->RegisterPacketComponent("BTSCAN");

	if (globalreg->devicetracker->RegisterPhyHandler(new Btscan_Phy(globalreg)) < 0) {
		_MSG("Failed to install BTScan PHY handler", MSGFLAG_ERROR);
		return -1;
	}

	return 1;
}

extern "C" {
	int kis_plugin_info(plugin_usrdata *data) {
		data->pl_name = "BTSCAN";
		data->pl_version = string(VERSION_MAJOR) + "-" + string(VERSION_MINOR) + "-" +
			string(VERSION_TINY);
		data->pl_description = "Active Bluetooth scanning plugin";
		data->pl_unloadable = 0; // We can't be unloaded because we defined a source
		data->plugin_register = btscan_register;
		data->plugin_unregister = btscan_unregister;

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

