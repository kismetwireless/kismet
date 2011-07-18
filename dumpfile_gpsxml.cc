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
#include "gpscore.h"
#include "dumpfile_gpsxml.h"
#include "phy_80211.h"

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

	last_track = 0;

	type = "gpsxml";
	logclass = "gps";

	if (globalreg->sourcetracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Sourcetracker missing before "
				"Dumpfile_Gpsxml\n");
		exit(1);
	}

	// Find the file name
	if ((fname = ProcessConfigOpt()) == "" ||
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

	globalreg->packetchain->RegisterHandler(&dumpfilegpsxml_chain_hook, this,
											CHAINPOS_LOGGING, -100);

    fprintf(xmlfile, "<gps-run gps-version=\"%d\" start-time=\"%.24s\">\n\n",
            GPS_VERSION, ctime((const time_t *) &(globalreg->timestamp.tv_sec)));

	string netxmlname;
	Dumpfile *netxmldump = globalreg->FindDumpFileType("netxml");

	if (netxmldump == NULL) {
		netxmlname = "error-netxml-not-found";
	} else{
		netxmlname = netxmldump->FetchFileName();
	}

	fprintf(xmlfile, "    <network-file>%s</network-file>\n\n", 
			netxmlname.c_str());

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
	dot11_packinfo *eight11 = NULL;
	kis_layer1_packinfo *radio = NULL;

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
	if ((eight11 = (dot11_packinfo *)
		 in_pack->fetch(_PCM(PACK_COMP_80211))) == NULL) {

		// If we're only logging GPS track data, only do it once a second
		// (plugins, specifically non-dot11 PHYs, may have GPS tagged packets
		// with no eight11 record)
		if (last_track == globalreg->timestamp.tv_sec)
			return 0;

		last_track = globalreg->timestamp.tv_sec;

		fprintf(xmlfile, "    <gps-point bssid=\"%s\" time-sec=\"%ld\" "
				"time-usec=\"%ld\" lat=\"%f\" lon=\"%f\" spd=\"%f\" heading=\"%f\" "
				"fix=\"%d\"",
				gps_track_bssid,
				(long int) in_pack->ts.tv_sec, (long int) in_pack->ts.tv_usec,
				gpsinfo->lat, gpsinfo->lon, gpsinfo->spd, gpsinfo->heading,
				gpsinfo->gps_fix);
		if (gpsinfo->gps_fix >= 3)
			fprintf(xmlfile, " alt=\"%f\"", gpsinfo->alt);
		if (gpsinfo->hdop != 0 || gpsinfo->vdop != 0)
			fprintf(xmlfile, " hdop=\"%f\" vdop=\"%f\"",
					gpsinfo->hdop, gpsinfo->vdop);
		fprintf(xmlfile, "/>\n");

		dumped_frames++;
		return 1;
	}

	// Don't log errored eight11 packets
	if (eight11->corrupt || eight11->type == packet_unknown)
		return 0;

	// Otherwise we want to try to log the signal levels too
	radio = (kis_layer1_packinfo *) in_pack->fetch(_PCM(PACK_COMP_RADIODATA));

	fprintf(xmlfile, "    <gps-point bssid=\"%s\" source=\"%s\" time-sec=\"%ld\" "
			"time-usec=\"%ld\" lat=\"%f\" lon=\"%f\" spd=\"%f\" heading=\"%f\" "
			"fix=\"%d\"",
			eight11->bssid_mac.Mac2String().c_str(),
			eight11->source_mac.Mac2String().c_str(),
			(long int) in_pack->ts.tv_sec, (long int) in_pack->ts.tv_usec,
			gpsinfo->lat, gpsinfo->lon, gpsinfo->spd, gpsinfo->heading,
			gpsinfo->gps_fix);
	if (gpsinfo->gps_fix >= 3)
		fprintf(xmlfile, " alt=\"%f\"", gpsinfo->alt);
	if (gpsinfo->hdop != 0 || gpsinfo->vdop != 0)
		fprintf(xmlfile, " hdop=\"%f\" vdop=\"%f\"",
				gpsinfo->hdop, gpsinfo->vdop);
	if (radio != NULL) {
		if (radio->signal_rssi != 0) {
			fprintf(xmlfile, " signal_rssi=\"%d\" noise_rssi=\"%d\"",
					radio->signal_rssi, radio->noise_rssi);
		} 
		if (radio->signal_dbm != 0) {
			fprintf(xmlfile, " signal_dbm=\"%d\" noise_dbm=\"%d\"",
				radio->signal_dbm, radio->noise_dbm);
		}
	}
	fprintf(xmlfile, "/>\n");

	dumped_frames++;

	return 1;
}

