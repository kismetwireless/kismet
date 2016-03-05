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

#include "getopt.h"

#include "gpscore.h"
#include "gpsserial.h"
#include "gpsdclient.h"
#include "gpsfixed.h"
#include "gpswrapper.h"
#include "configfile.h"

void GpsWrapper::Usage(char *name) {
	printf(" *** Kismet GPS Options ***\n");
	printf("     --use-gpsd-gps (h:p)     Use GPSD-controlled GPS at host:port\n"
		   "                              (default: localhost:2947)\n"
		   "     --use-nmea-gps (dev)     Use local NMEA serial GPS on device\n"
		   "                              (default: /dev/ttyUSB0)\n"
		   "     --use-virtual-gps\n"
		   "                (lat,lon,alt) Use a virtual fixed-position gps record\n"
		   "     --gps-modelock <t:f>     Force broken GPS units to act as if they\n"
		   "                              have a valid signal (true/false)\n"
		   "     --gps-reconnect <t:f>    Reconnect if a GPS device fails\n"
		   "                              (true/false)\n");
}

GpsWrapper::GpsWrapper(GlobalRegistry *in_globalreg) {
	string gpsopt = "";
	string gpsparm = "";

	gps = NULL;

	globalreg = in_globalreg;

	int gpsdc = globalreg->getopt_long_num++;
	int nmeac = globalreg->getopt_long_num++;
	int modec = globalreg->getopt_long_num++;
	int recoc = globalreg->getopt_long_num++;
	int fixec = globalreg->getopt_long_num++;

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  GpsWrapper() called before kismet_config\n");
		exit(1);
	}

	globalreg->InsertGlobal("GPSWRAPPER", this);

	static struct option gpswrapper_long_options[] = {
		{ "use-gpsd-gps", optional_argument, 0, gpsdc },
		{ "use-nmea-gps", optional_argument, 0, nmeac },
		{ "use-virtual-gps", required_argument, 0, fixec },
		{ "gps-modelock", required_argument, 0, modec },
		{ "gps-reconnect", required_argument, 0, recoc },
		{ 0, 0, 0, 0 }
	};
	int option_idx = 0;

	optind = 0;

	while (1) {
		int r = getopt_long(globalreg->argc, globalreg->argv, 
							"-",
							gpswrapper_long_options, &option_idx);

		if (r < 0) break;

		if (r == gpsdc) {
			if (optarg != NULL)
				gpsparm = string(optarg);
			else
				gpsparm = "localhost:2947";

			_MSG("Using GPSD connected GPS at " + gpsparm, MSGFLAG_INFO);

			globalreg->kismet_config->SetOpt("gps", "true", 1);
			globalreg->kismet_config->SetOpt("gpstype", "gpsd", 1);
			globalreg->kismet_config->SetOpt("gpshost", gpsparm, 1);
		}

		if (r == nmeac) {
			if (optarg != NULL)
				gpsparm = string(optarg);
			else
				gpsparm = "/dev/ttyUSB0";

			_MSG("Using NMEA serial connected GPS at " + gpsparm, MSGFLAG_INFO);

			globalreg->kismet_config->SetOpt("gps", "true", 1);
			globalreg->kismet_config->SetOpt("gpstype", "serial", 1);
			globalreg->kismet_config->SetOpt("gpsdevice", gpsparm, 1);
		}

		if (r == fixec) {
			float tlat, tlon, talt;
			int fnum;

			if ((fnum = sscanf(optarg, "%f,%f,%f", &tlat, &tlon, &talt)) < 2) {
				_MSG("Invalid use-virtual-gps, expected lat,lon,alt", MSGFLAG_ERROR);
				globalreg->kismet_config->SetOpt("gpsposition", "", 1);
			} else {
				globalreg->kismet_config->SetOpt("gps", "true", 1);
				globalreg->kismet_config->SetOpt("gpstype", "virtual", 1);
				globalreg->kismet_config->SetOpt("gpsposition", 
												 FloatToString(tlat) + "," + FloatToString(tlon), 1);
				if (fnum > 2)
					globalreg->kismet_config->SetOpt("gpsaltitude", FloatToString(talt), 1);
				else
					globalreg->kismet_config->SetOpt("gpsaltitude", "", 1);
			}
		}

		if (r == modec) {
			globalreg->kismet_config->SetOpt("gpsmodelock", optarg, 1);
		} 

		if (r == recoc) {
			globalreg->kismet_config->SetOpt("gpsreconnect", optarg, 1);
		}
	}

	// if (globalreg->kismet_config->FetchOpt("gps") != "true") {
	if (globalreg->kismet_config->FetchOptBoolean("gps", 0) != 1) {
		_MSG("GPS support disabled in kismet.conf", MSGFLAG_INFO);
		GPSNull *gn;
		gn = new GPSNull(globalreg);
		gps = gn;
		return;
	}

	gpsopt = globalreg->kismet_config->FetchOpt("gpstype");

	if (gpsopt == "serial") {
		GPSSerial *gs;
		gs = new GPSSerial(globalreg);
		gps = gs;
	} else if (gpsopt == "gpsd") {
		GPSDClient *gc;
		gc = new GPSDClient(globalreg);
		gps = gc;
	} else if (gpsopt == "virtual") {
		GPSFixed *gf = new GPSFixed(globalreg);
		gps = gf;
	} else if (gpsopt == "") {
		_MSG("GPS enabled but gpstype missing from kismet.conf", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
	} else {
		_MSG("GPS unknown gpstype " + gpsopt + ", continuing on blindly and hoping "
			 "we get something useful.  Unless you have loaded GPS plugins that "
			 "handle this GPS type, Kismet is not going to be able to use the GPS",
			 MSGFLAG_ERROR);
	}
}

