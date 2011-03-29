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

#include <globalregistry.h>
#include <manuf.h>

#include "dumpfile_btscantxt.h"

Dumpfile_Btscantxt::Dumpfile_Btscantxt() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Nettxt called with no globalreg\n");
	exit(1);
}

Dumpfile_Btscantxt::Dumpfile_Btscantxt(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {
	globalreg = in_globalreg;

	txtfile = NULL;

	tracker = NULL;

	type = "btscantxt";

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Config file missing before Dumpfile_Btscantxt\n");
		exit(1);
	}

	// Find the file name
	if ((fname = ProcessConfigOpt("btscantxt")) == "" || 
		globalreg->fatal_condition) {
		return;
	}

	if ((txtfile = fopen(fname.c_str(), "w")) == NULL) {
		_MSG("Failed to open btscantxt log file '" + fname + "': " + strerror(errno),
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	globalreg->RegisterDumpFile(this);

	_MSG("Opened btscantxt log file '" + fname + "'", MSGFLAG_INFO);
}

Dumpfile_Btscantxt::~Dumpfile_Btscantxt() {
	if (txtfile != NULL)
		Flush();

	txtfile = NULL;
}

int Dumpfile_Btscantxt::Flush() {
	if (tracker == NULL) {
		_MSG("Dumpfile_Btscantxt flush called when tracker was missing",
			 MSGFLAG_ERROR);
		return -1;
	}

	if (txtfile != NULL)
		fclose(txtfile);

	string tempname = fname + ".temp";
	if ((txtfile = fopen(tempname.c_str(), "w")) == NULL) {
		_MSG("Failed to open temporary btscantxt file for writing: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	fprintf(txtfile, "Kismet (http://www.kismetwireless.net) BTSCAN\n"
			"%.24s - Kismet %s.%s.%s BTSCAN %s.%s.%s\n"
			"-----------------\n\n",
			ctime(&(globalreg->start_time)),
			globalreg->version_major.c_str(),
			globalreg->version_minor.c_str(),
			globalreg->version_tiny.c_str(),
			globalreg->version_major.c_str(),
			globalreg->version_minor.c_str(),
			globalreg->version_tiny.c_str());

	int devnum = 1;

	for (map<mac_addr, btscan_network *>::iterator x = tracker->tracked_devs.begin();
		 x != tracker->tracked_devs.end(); ++x) {

		btscan_network *btnet = x->second;

		fprintf(txtfile, "BT Device %d: BDADDR %s\n",
				devnum, btnet->bd_addr.Mac2String().c_str());
		fprintf(txtfile, " Class      : %s\n", btnet->bd_class.c_str());
		fprintf(txtfile, " Name       : %s\n", btnet->bd_name.c_str());
		fprintf(txtfile, " Seen       : %d\n", btnet->packets);

		string manuf = "Unknown";
		if (globalreg->manufdb != NULL)
			manuf = globalreg->manufdb->LookupOUI(btnet->bd_addr);

		fprintf(txtfile, " Manuf      : %s\n", manuf.c_str());
		fprintf(txtfile, " First      : %.24s\n", ctime(&(btnet->first_time)));
		fprintf(txtfile, " Last       : %.24s\n", ctime(&(btnet->last_time)));

		if (btnet->gpsdata.gps_valid) {
			fprintf(txtfile, " Min Pos    : Lat %f Lon %f Alt %f Spd %f\n", 
					btnet->gpsdata.min_lat, btnet->gpsdata.min_lon,
					btnet->gpsdata.min_alt, btnet->gpsdata.min_spd);
			fprintf(txtfile, " Max Pos    : Lat %f Lon %f Alt %f Spd %f\n", 
					btnet->gpsdata.max_lat, btnet->gpsdata.max_lon,
					btnet->gpsdata.max_alt, btnet->gpsdata.max_spd);
			fprintf(txtfile, " Avg Pos    : AvgLat %f AvgLon %f AvgAlt %f\n",
					btnet->gpsdata.aggregate_lat, btnet->gpsdata.aggregate_lon,
					btnet->gpsdata.aggregate_alt);
		}

		fprintf(txtfile, "\n");
		devnum++;
	}

	fflush(txtfile);
	fclose(txtfile);

	txtfile = NULL;

	if (rename(tempname.c_str(), fname.c_str()) < 0) {
		_MSG("Failed to rename btscantxt temp file " + tempname + " to " + fname + 
			 ": " + string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	dumped_frames = devnum;

	return 1;
}


