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

#include <errno.h>

#include "globalregistry.h"
#include "gpsdclient.h"
#include "dumpfile_gpsxml.h"

#define GPS_VERSION		5
#define gps_track_bssid	"GP:SD:TR:AC:KL:OG"

int dumpfilegpsxml_chain_hook(CHAINCALL_PARMS) {
	Dumpfile_Gpsxml *auxptr = (Dumpfile_Gpsxml *) auxdata;
	return auxptr->chain_handler(in_pack);
}

Dumpfile_Gpsxml::Dumpfile_Gpsxml() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Gpsxml called with no globalreg\n");
	exit(1);
}

Dumpfile_Gpsxml::Dumpfile_Gpsxml(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {
	globalreg = in_globalreg;

	xmlfile = NULL;

	type = "gpsxml";

	if (globalreg->sourcetracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Sourcetracker missing before "
				"Dumpfile_Gpsxml\n");
		exit(1);
	}

	int ret = 0;

	if ((ret = ProcessRuntimeResume("gpsxml")) == -1) {
		if (globalreg->fatal_condition)
			return;

		// Find the file name
		if ((fname = ProcessConfigOpt("gpsxml")) == "" || 
			globalreg->fatal_condition) {
			return;
		}

		if ((xmlfile = fopen(fname.c_str(), "w")) == NULL) {
			_MSG("Failed to open gpsxml log file '" + fname + "': " + strerror(errno),
				 MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return;
		}

		_MSG("Opened gpsxml log file '" + fname + "'", MSGFLAG_INFO);

		// Write the XML headers
		fprintf(xmlfile, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n"
				"<!DOCTYPE gps-run SYSTEM \"http://kismetwireless.net/"
				"kismet-gps-2.9.1.dtd\">\n\n");

	} else if (ret == 1) {
		xmlfile = fopen(fname.c_str(), "a+");
		if (xmlfile == NULL) {
			_MSG("Failed to open XML file '" + fname + "' to resume logging: " +
				 string(strerror(errno)), MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
		}

		int found_end = 0;

		// Rewrind the file and look for an end of the GPS run.  '</gps-run>'
		// ought to be 10 bytes, so roll back 15 and read 2 lines
		fseek(xmlfile, -15, SEEK_END);

		char line[1024];
		while (!feof(xmlfile)) {
			fgets(line, 1024, xmlfile);

			if (feof(xmlfile)) break;

			if (strncmp(line, "</gps-run>\n", 1024) == 0) {
				found_end = 1;
				break;
			}
		}

		fseek(xmlfile, 0, SEEK_END);

		if (found_end == 0) {
			_MSG("Resuming from incomplete gpsxml file, properly closing previous "
				 "gps session", MSGFLAG_INFO);
			fprintf(xmlfile, "</gps-run>\n\n");
		} else {
			fprintf(xmlfile, "\n");
			_MSG("Resumed gpsxml file '" + fname + "'", MSGFLAG_INFO);
		}
	} else {
		_MSG("Gpsxml log file not enabled in runstate", MSGFLAG_INFO);
		return;
	}

	globalreg->packetchain->RegisterHandler(&dumpfilegpsxml_chain_hook, this,
											CHAINPOS_LOGGING, -100);

    fprintf(xmlfile, "<gps-run gps-version=\"%d\" start-time=\"%.24s\">\n\n",
            GPS_VERSION, ctime(&(globalreg->timestamp.tv_sec)));

	string netxmlname;
	if ((netxmlname = ProcessConfigOpt("netxml")) != "") {
		fprintf(xmlfile, "    <network-file>%s</network-file>\n\n", 
				netxmlname.c_str());
	} else if (globalreg->fatal_condition) {
		fclose(xmlfile);
		return;
	}

	globalreg->RegisterDumpFile(this);
}

Dumpfile_Gpsxml::~Dumpfile_Gpsxml() {
	globalreg->packetchain->RemoveHandler(&dumpfilegpsxml_chain_hook,
										  CHAINPOS_LOGGING);

	// Close files
	if (xmlfile != NULL) {
		fprintf(xmlfile, "</gps-run>\n");
		Flush();
		fclose(xmlfile);
		_MSG("Closed gpsxml log file '" + fname + "'", MSGFLAG_INFO);
	}

	xmlfile = NULL;
}

int Dumpfile_Gpsxml::Flush() {
	if (xmlfile == NULL)
		return 0;

	fflush(xmlfile);

	return 1;
}

int Dumpfile_Gpsxml::chain_handler(kis_packet *in_pack) {
	kis_gps_packinfo *gpsinfo = NULL;
	kis_ieee80211_packinfo *eight11 = NULL;
	kis_layer1_packinfo *radio = NULL;

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
	if ((eight11 = (kis_ieee80211_packinfo *)
		 in_pack->fetch(_PCM(PACK_COMP_80211))) == NULL) {
		fprintf(xmlfile, "    <gps-point bssid=\"%s\" time-sec=\"%ld\" "
				"time-usec=\"%ld\" lat=\"%f\" lon=\"%f\" alt=\"%f\" spd=\"%f\" "
				"heading=\"%f\" fix=\"%d\" />\n",
				gps_track_bssid,
				(long int) in_pack->ts.tv_sec, (long int) in_pack->ts.tv_usec,
				gpsinfo->lat, gpsinfo->lon, gpsinfo->alt, gpsinfo->spd,
				gpsinfo->heading, gpsinfo->gps_fix);
		dumped_frames++;
		return 1;
	}

	// Otherwise we want to try to log the signal levels too
	radio = (kis_layer1_packinfo *) in_pack->fetch(_PCM(PACK_COMP_RADIODATA));

    fprintf(xmlfile, "    <gps-point bssid=\"%s\" source=\"%s\" time-sec=\"%ld\" "
			"time-usec=\"%ld\" lat=\"%f\" lon=\"%f\" alt=\"%f\" spd=\"%f\" "
			"heading=\"%f\" fix=\"%d\" signal=\"%d\" noise=\"%d\"/>\n",
			eight11->bssid_mac.Mac2String().c_str(),
			eight11->source_mac.Mac2String().c_str(),
			(long int) in_pack->ts.tv_sec, (long int) in_pack->ts.tv_usec,
			gpsinfo->lat, gpsinfo->lon, gpsinfo->alt, gpsinfo->spd,
			gpsinfo->heading, gpsinfo->gps_fix,
			radio == NULL ? 0 : radio->signal,
			radio == NULL ? 0 : radio->noise);

	dumped_frames++;

	return 1;
}

