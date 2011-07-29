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
#include "gpscore.h"
#include "gpsserial.h"
#include "gpsdclient.h"

#ifndef __GPSWRAPPER_H__
#define __GPSWRAPPER_H__

// Simple wrapper class to parse the gps line and spawn the proper gps module
class GpsWrapper {
public:
	GpsWrapper() {
		fprintf(stderr, "FATAL OOPS:  GpsWrapper()\n");
		exit(1);
	}

	static void Usage(char *argv);

	GpsWrapper(GlobalRegistry *in_globalreg);

	~GpsWrapper() {
		globalreg->InsertGlobal("GPSWRAPPER", NULL);
	}

	string FetchType() { return gps->FetchType(); }
	string FetchDevice() { return gps->FetchDevice(); }

protected:
	GlobalRegistry *globalreg;

	GPSCore *gps;
};

// Empty GPS handler which inserts the network protocols but doesn't do anything
// else, so that clients don't get unhappy
class GPSNull : public GPSCore {
public:
	GPSNull() {
		fprintf(stderr, "FATAL OOPS:  GPSNull()\n");
		exit(1);
	}

	GPSNull(GlobalRegistry *in_globalreg) : GPSCore(in_globalreg) {
		// We don't parse our options
		RegisterComponents();
	}

	string FetchType() { return "none"; }

	string FetchDevice() { return "none"; }

	virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
		return in_max_fd;
	}

	virtual int Poll(fd_set &in_rset, fd_set& in_wset) {
		return 0;
	}

	virtual int ParseData() { 
		return 0;
	}

	virtual int KillConnection() {
		return 0;
	}

	virtual int Shutdown() {
		return 0;
	}

	virtual int InjectCommand() {
		return 1;
	}

	virtual int Reconnect() {
		return 0;
	}
protected:
};

#endif

