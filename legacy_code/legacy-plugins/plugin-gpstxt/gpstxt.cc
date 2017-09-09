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
#include <phy_80211.h>
#include <dumpfile.h>

GlobalRegistry *globalreg = NULL;

// GPSXML point logger
class Dumpfile_Gpstxt : public Dumpfile {
public:
	Dumpfile_Gpstxt() {
		fprintf(stderr, "FATAL OOPS: dumpfile_gpstxt()\n"); exit(1); 
	}

	Dumpfile_Gpstxt(GlobalRegistry *in_globalreg);
	virtual ~Dumpfile_Gpstxt();

	virtual int chain_handler(kis_packet *in_pack);
	virtual int Flush();
protected:
	FILE *txtfile;
	time_t last_track;
	int pack_comp_common;
	Devicetracker *devicetracker;
};
	
int dumpfilegpstxt_chain_hook(CHAINCALL_PARMS) {
	return ((Dumpfile_Gpstxt *) auxdata)->chain_handler(in_pack);
}

Dumpfile_Gpstxt::Dumpfile_Gpstxt(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {
	globalreg = in_globalreg;

	devicetracker = 
		(Devicetracker *) globalreg->FetchGlobal("DEVICE_TRACKER");

	if (devicetracker == NULL) {
		_MSG("Missing phy-neutral devicetracker, something is wrong.  "
			 "Trying to use this plugin on an older Kismet?",
			 MSGFLAG_ERROR);
		return;
	}

	pack_comp_common = 
		globalreg->packetchain->RegisterPacketComponent("COMMON");

	txtfile = NULL;

	last_track = 0;

	type = "gpstxt";
	logclass = "text";

	// Find the file name
	if ((fname = ProcessConfigOpt()) == "" ||
		globalreg->fatal_condition) {
		return;
	}

	if ((txtfile = fopen(fname.c_str(), "w")) == NULL) {
		_MSG("Failed to open gpstxt log file '" + fname + "': " + strerror(errno),
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	fprintf(txtfile, "#device,dest,ts,ts_usec,lat,lon,spd,heading,alt,hdop,vdop,"
			"fix,sigtype,signal,noise,phy,packtype\n");

	_MSG("Opened gpstxt log file '" + fname + "'", MSGFLAG_INFO);

	globalreg->packetchain->RegisterHandler(&dumpfilegpstxt_chain_hook, this,
											CHAINPOS_LOGGING, -100);

	globalreg->RegisterDumpFile(this);
}

Dumpfile_Gpstxt::~Dumpfile_Gpstxt() {
	globalreg->packetchain->RemoveHandler(&dumpfilegpstxt_chain_hook,
										  CHAINPOS_LOGGING);

	// Close files
	if (txtfile != NULL) {
		Flush();
		fclose(txtfile);
	}

	txtfile = NULL;
}

int Dumpfile_Gpstxt::Flush() {
	if (txtfile == NULL)
		return 0;

	fflush(txtfile);

	return 1;
}

int Dumpfile_Gpstxt::chain_handler(kis_packet *in_pack) {
	kis_gps_packinfo *gpsinfo = NULL;
	kis_common_info *common = NULL;
	kis_layer1_packinfo *radio = NULL;
	Kis_Phy_Handler *phyh = NULL;

	if (in_pack->error)
		return 0;

	// No GPS info, no worky
	if ((gpsinfo = (kis_gps_packinfo *) 
		 in_pack->fetch(_PCM(PACK_COMP_GPS))) == NULL) {
		return 0;
	}

	// Obviously no point in logging when theres no valid lock
	if (gpsinfo->gps_fix < 2) {
		return 0;
	}

	// If all we're doing is logging the GPS info...
	if ((common = (kis_common_info *)
		 in_pack->fetch(pack_comp_common)) == NULL) {

		// If we're only logging GPS track data, only do it once a second
		// (plugins, specifically non-dot11 PHYs, may have GPS tagged packets
		// with no eight11 record)
		if (last_track == globalreg->timestamp.tv_sec)
			return 0;

		last_track = globalreg->timestamp.tv_sec;

		fprintf(txtfile, "00:00:00:00:00:00,00:00:00:00:00:00,"
				"%ld,%ld,%f,%f,%f,%f,%f,%f,%f,%d,0,0,0,GPS,GPS\n",
				(long int) in_pack->ts.tv_sec, (long int) in_pack->ts.tv_usec,
				gpsinfo->lat, gpsinfo->lon, gpsinfo->spd, gpsinfo->heading,
				gpsinfo->alt, gpsinfo->hdop, gpsinfo->vdop,
				gpsinfo->gps_fix);

		dumped_frames++;
		return 1;
	}

	// Don't log errored eight11 packets
	if (common->error)
		return 0;

	// Otherwise we want to try to log the signal levels too
	radio = (kis_layer1_packinfo *) in_pack->fetch(_PCM(PACK_COMP_RADIODATA));

	int rtype = 0, sig = 0, noise = 0;

	if (radio != NULL) {
		if (radio->signal_rssi != 0) {
			rtype = 1;
			sig = radio->signal_rssi;
			noise = radio->noise_rssi;
		} else {
			rtype = 2;
			sig = radio->signal_dbm;
			noise = radio->noise_dbm;
		}
	}

	string phyname;

	phyh = devicetracker->FetchPhyHandler(common->phyid);

	if (phyh == NULL) {
		phyname = "UNKNOWN";
	} else {
		phyname = phyh->FetchPhyName();
	}

	fprintf(txtfile, "%s,%s,%ld,%ld,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%s,%d\n",
			common->device.Mac2String().c_str(),
			common->dest.Mac2String().c_str(),
			(long int) in_pack->ts.tv_sec, (long int) in_pack->ts.tv_usec,
			gpsinfo->lat, gpsinfo->lon, gpsinfo->spd, gpsinfo->heading,
			gpsinfo->alt, gpsinfo->hdop, gpsinfo->vdop,
			gpsinfo->gps_fix, rtype, sig, noise, phyname.c_str(),
			common->type);

	dumped_frames++;

	return 1;
}

int gpstxt_unregister(GlobalRegistry *in_globalreg) {
	return 0;
}

int gpstxt_register(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	if (globalreg->kismet_instance != KISMET_INSTANCE_SERVER) {
		_MSG("Not initializing gpstxt, not running on a server.",
			 MSGFLAG_INFO);
		return 1;
	}

	new Dumpfile_Gpstxt(globalreg);

	return 1;
}

extern "C" {
	int kis_plugin_info(plugin_usrdata *data) {
		data->pl_name = "GPSTXT";
		data->pl_version = string(VERSION_MAJOR) + "-" + string(VERSION_MINOR) + "-" +
			string(VERSION_TINY);
		data->pl_description = "GPSTXT Plugin";
		data->pl_unloadable = 0; // We can't be unloaded because we defined a source
		data->plugin_register = gpstxt_register;
		data->plugin_unregister = gpstxt_unregister;

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

