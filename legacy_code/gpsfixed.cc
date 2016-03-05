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

#ifndef HAVE_LIBGPS

#include "gpsfixed.h"
#include "configfile.h"
#include "soundcontrol.h"
#include "packetchain.h"
#include "kismet_json.h"

int GpsFixedEvent(Timetracker::timer_event *evt, void *parm, GlobalRegistry *globalreg) {
	GPSFixed *gps = (GPSFixed *) parm;

	return gps->Timer();
}

GPSFixed::GPSFixed() {
    fprintf(stderr, "FATAL OOPS: gpsfixed called with no globalreg\n");
	exit(-1);
}

void GPSFixed::ConnectCB(int status) {
	return;
}

GPSFixed::GPSFixed(GlobalRegistry *in_globalreg) : GPSCore(in_globalreg) {
	float tlat, tlon;

	if (sscanf(globalreg->kismet_config->FetchOpt("gpsposition").c_str(),
			   "%f,%f", &tlat, &tlon) != 2) {
		_MSG("Invalid gpsposition in config, expected latitude,longitude", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	lat = tlat;
	lon = tlon;
	mode = 3;

	if (sscanf(globalreg->kismet_config->FetchOpt("gpsaltitude").c_str(),
			   "%f", &tlat) != 1) {
		_MSG("Invalid or missing gpsaltitude=, emulating 2d fix", MSGFLAG_ERROR);
		mode = 2;
	} else {
		alt = tlat;
	}

	last_lat = lat;
	last_lon = lon;

	gps_ever_lock = 1;
	gps_connected = 1;

	gpseventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, 
											  &GpsFixedEvent, (void *) this);

	_MSG("Emulating GPS at fixed location " + FloatToString(lat) + "," + 
		 FloatToString(lon) + " altitude " + FloatToString(alt), MSGFLAG_INFO);

	ScanOptions();
	RegisterComponents();
}

GPSFixed::~GPSFixed() {
}

int GPSFixed::Shutdown() {
    return 1;
}

int GPSFixed::Timer() {
	GPSCore::Timer();

	return 1;
}

int GPSFixed::Reconnect() {
	return 1;
}

int GPSFixed::ParseData() {
	return 1;
}

#endif

