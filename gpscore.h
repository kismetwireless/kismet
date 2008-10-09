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

#ifndef __GPSCORE_H__
#define __GPSCORE_H__

#include "config.h"

#include "clinetframework.h"
#include "tcpclient.h"
#include "kis_netframe.h"
#include "packetchain.h"

// Options
#define GPSD_OPT_FORCEMODE    1

enum GPS_fields {
    GPS_lat, GPS_lon, GPS_alt, GPS_spd, GPS_heading, GPS_fix
};

struct GPS_data {
    string lat, lon, alt, spd, heading, mode;
};

int Protocol_GPS(PROTO_PARMS);

// GPS info linked into each packet
class kis_gps_packinfo : public packet_component {
public:
	kis_gps_packinfo() {
		self_destruct = 1; // Nothing special, just delete us
		lat = lon = alt = spd = heading = -1000;
		gps_fix = 0;
	}

    double lat;
    double lon;
    double alt;
    double spd;
    double heading;
    int gps_fix;
};

// Packetchain hook to add GPS data
int kis_gpspack_hook(CHAINCALL_PARMS);

class GPSCore : public ClientFramework {
public:
    GPSCore();
    GPSCore(GlobalRegistry *in_globalreg);
    virtual ~GPSCore();

	int Timer();

    void SetOptions(uint32_t in_opt) {
        gps_options = in_opt;
    }

    // Fetch a location
    int FetchLoc(double *in_lat, double *in_lon, double *in_alt, double *in_spd, 
				 double *in_hed, int *mode);

    // Fetch mode
    int FetchMode() { return mode; }

    // Various GPS transformations
    static double CalcHeading(double in_lat, double in_lon, 
							  double in_lat2, double in_lon2);
    static double CalcRad(double lat);
    static double Rad2Deg(double x);
    static double Deg2Rad(double x);
    static double EarthDistance(double in_lat, double in_lon, 
								double in_lat2, double in_lon2);

    virtual int Reconnect() = 0;

protected:
    uint32_t gps_options;

    int reconnect_attempt;
    time_t last_disconnect;

    double lat, lon, alt, spd, hed;
    int mode;

    // Last location used for softheading calcs
    double last_lat, last_lon, last_hed;

	// Scan options & register systems
	int ScanOptions();
	int RegisterComponents();

	// network proto ref
	int gps_proto_ref;

	int gpseventid;
    
    friend int GpsInjectEvent(TIMEEVENT_PARMS);
};

#endif

