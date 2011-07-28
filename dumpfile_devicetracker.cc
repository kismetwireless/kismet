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
#include "dumpfile_devicetracker.h"
#include "devicetracker.h"

Dumpfile_Devicetracker::Dumpfile_Devicetracker() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Devicetracker()\n");
	exit(1);
}

// Complex constructor for devicetracker to register its own global formats
Dumpfile_Devicetracker::Dumpfile_Devicetracker(GlobalRegistry *in_globalreg, 
	string in_type, string in_class) : Dumpfile(in_globalreg) {

	type = in_type;
	logclass = in_class;

	logfile = NULL;

	Devicetracker *tracker = (Devicetracker *) globalreg->FetchGlobal("DEVICE_TRACKER");
	
	if (tracker == NULL) {
		_MSG("Kismet phy-neutral devicetracker not present; did you disable it "
			 "in the config file?  Devicetracker depends on the new phy-neutral code.",
			 MSGFLAG_ERROR | MSGFLAG_PRINTERROR);
		return;
	}

	globalreg->InsertGlobal("DUMPFILE_" + in_type, this);

	if ((fname = ProcessConfigOpt()) == "" || globalreg->fatal_condition) {
		return;
	}

	if ((logfile = fopen(fname.c_str(), "w")) == NULL) {
		_MSG("Failed to open devicetracker " + type + " log file '" + 
			 fname + "': " + strerror(errno),
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	globalreg->RegisterDumpFile(this);

	_MSG("Opened Devicetracker " + logclass + " log file '" + fname + "'", 
		 MSGFLAG_INFO);
}

Dumpfile_Devicetracker::Dumpfile_Devicetracker(GlobalRegistry *in_globalreg) {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Devicetracker(globalreg)\n");
	exit(1);
}
		


Dumpfile_Devicetracker::~Dumpfile_Devicetracker() {
	if (logfile != NULL)
		Flush();

	logfile = NULL;

	if (export_filter != NULL)
		delete export_filter;
}

int Dumpfile_Devicetracker::Flush() {
	Devicetracker *tracker = (Devicetracker *) globalreg->FetchGlobal("DEVICE_TRACKER");
	
	if (tracker == NULL) {
		_MSG("Kismet phy-neutral devicetracker not present; did you disable it "
			 "in the config file?  Devicetracker depends on the new phy-neutral code.",
			 MSGFLAG_ERROR | MSGFLAG_PRINTERROR);
		return -1;
	}

	if (logfile != NULL)
		fclose(logfile);

	string tempname = fname + ".temp";
	if ((logfile = fopen(tempname.c_str(), "w")) == NULL) {
		_MSG("Failed to open temporary device " + logclass + " file for writing: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	// Kick the device_tracker logger
	int ret = tracker->LogDevices(logclass, type, logfile);

	fflush(logfile);
	fclose(logfile);

	logfile = NULL;

	if (rename(tempname.c_str(), fname.c_str()) < 0) {
		_MSG("Failed to rename device " + logclass + " file " + tempname + " to " + 
			 fname + ": " + string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	dumped_frames = tracker->FetchNumDevices(KIS_PHY_ANY);

	return ret;
}

