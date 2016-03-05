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
    GPS_lat, GPS_lon, GPS_alt, GPS_spd, GPS_heading, GPS_fix, GPS_satinfo,
	GPS_hdop, GPS_vdop, GPS_connected,
	GPS_maxfield
};

struct GPS_data {
    string lat, lon, alt, spd, heading, mode, satinfo, hdop, vdop, connected;
};

int Protocol_GPS(PROTO_PARMS);

// GPS info linked into each packet
class kis_gps_packinfo : public packet_component {
public:
	kis_gps_packinfo() {
		self_destruct = 1; // Nothing special, just delete us
		lat = lon = alt = spd = heading = -1000;
		hdop = vdop = 0;
		gps_fix = 0;
	}

    double lat;
    double lon;
    double alt;
    double spd;
    double heading;
	double hdop, vdop;
    int gps_fix;
};

#define KIS_GPS_ALT_BOGUS_MAX 		100000
#define KIS_GPS_ALT_BOGUS_MIN 		-100000
#define KIS_GPS_SPD_BOGUS_MAX 		100000
#define KIS_GPS_SPD_BOGUS_MIN 		-100000

struct kis_gps_data {
	kis_gps_data() {
		gps_valid = 0;
		// Pick absurd initial values to be clearly out-of-bounds
		min_lat = 90;
		max_lat = -90;
		min_lon = 180;
		max_lon = -180;
		min_alt = KIS_GPS_ALT_BOGUS_MIN;
		max_alt = KIS_GPS_ALT_BOGUS_MAX;
		min_spd = KIS_GPS_SPD_BOGUS_MIN;
		max_spd = KIS_GPS_SPD_BOGUS_MAX;

		add_lat = add_lon = add_alt = 0;

		aggregate_lat = aggregate_lon = aggregate_alt = 0;
		aggregate_points = 0;
	}

	inline kis_gps_data& operator= (const kis_gps_data& in) {
		gps_valid = in.gps_valid;
		min_lat = in.min_lat;
		min_lon = in.min_lon;
		max_lat = in.max_lat;
		max_lon = in.max_lon;
		min_alt = in.min_alt;
		max_alt = in.max_alt;
		min_spd = in.min_spd;
		max_spd = in.max_spd;

		aggregate_lat = in.aggregate_lat;
		aggregate_lon = in.aggregate_lon;

		aggregate_points = in.aggregate_points;

		add_lat = in.add_lat;
		add_lon = in.add_lon;

		return *this;
	}

	inline kis_gps_data& operator+= (const kis_gps_packinfo *in) {
		if (in == NULL)
			return *this;

		if (in->gps_fix >= 2) {
			gps_valid = 1;

			if (in->lat < min_lat)
				min_lat = in->lat;
			if (in->lon < min_lon)
				min_lon = in->lon;
			if (in->alt < min_alt)
				min_alt = in->alt;
			if (in->spd < min_spd)
				min_spd = in->spd;

			if (in->lat > max_lat)
				max_lat = in->lat;
			if (in->lon > max_lon)
				max_lon = in->lon;
			if (in->alt > max_alt)
				max_alt = in->alt;
			if (in->spd > max_spd)
				max_spd = in->spd;

			// Add as fixed to prevent massive precision drift
			add_lat += double_to_fixed3_7(in->lat);
			add_lon += double_to_fixed3_7(in->lon);
			add_alt += double_to_fixed6_4(in->alt);

			aggregate_points++;

			aggregate_lat = fixed3_7_to_double(add_lat / aggregate_points);
			aggregate_lon = fixed3_7_to_double(add_lon / aggregate_points);
			aggregate_alt = fixed6_4_to_double(add_alt / aggregate_points);
		}

		return *this;
	}

	inline kis_gps_data& operator+= (const kis_gps_data& in) {
		if (in.gps_valid == 0)
			return *this;

		if (in.min_lat < min_lat)
			min_lat = in.min_lat;

		if (in.max_lat > max_lat)
			max_lat = in.max_lat;

		if (in.min_lon < min_lon)
			min_lon = in.min_lon;

		if (in.max_lon > max_lon)
			max_lon = in.max_lon;

		if (in.min_alt < min_alt)
			min_alt = in.min_alt;

		if (in.max_alt > max_alt)
			max_alt = in.max_alt;

		if (in.min_spd < min_spd)
			min_spd = in.min_spd;

		if (in.max_spd > max_spd)
			max_spd = in.max_spd;

		add_lat += in.add_lat;
		add_lon += in.add_lon;
		add_alt += in.add_alt;

		aggregate_points += in.aggregate_points;

		aggregate_lat = fixed3_7_to_double(add_lat / aggregate_points);
		aggregate_lon = fixed3_7_to_double(add_lon / aggregate_points);
		aggregate_alt = fixed6_4_to_double(add_alt / aggregate_points);

		return *this;
	}

	int gps_valid;
	double min_lat, min_lon, min_alt, min_spd;
	double max_lat, max_lon, max_alt, max_spd;
	// Aggregate/avg center position
	uint64_t add_lat, add_lon, add_alt;
	double aggregate_lat, aggregate_lon, aggregate_alt;
	unsigned long aggregate_points;
};

// Some nasty hacks for GPS automation in plugins w/out having to rewrite
// the same code a dozen times
#define GPS_COMMON_FIELDS(h)	\
	h ## _gpsfixed, \
	h ## _minlat, h ## _minlon, h ## _minalt, h ## _minspd, \
	h ## _maxlat, h ## _maxlon, h ## _maxalt, h ## _maxspd, \
	h ## _agglat, h ## _agglon, h ## _aggalt, h ## _aggpoints 

#define GPS_COMMON_FIELDS_TEXT 	\
	"gpsfixed", \
	"minlat", "minlon", "minalt", "minspd", \
	"maxlat", "maxlon", "maxalt", "maxspd", \
	"agglat", "agglon", "aggalt", "aggpoints" 

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

	// Fetch info about the gps
	virtual string FetchDevice() = 0;
	virtual string FetchType() = 0;

    // Fetch a location
    int FetchLoc(double *in_lat, double *in_lon, double *in_alt, double *in_spd, 
				 double *in_hed, int *mode);

    // Fetch mode
    int FetchMode() { return mode; }

	// Fetch connection
	int FetchConnected() { return (gps_connected == 1 && last_disconnect == 0); }

    // Various GPS transformations
    static double CalcHeading(double in_lat, double in_lon, 
							  double in_lat2, double in_lon2);
    static double CalcRad(double lat);
    static double Rad2Deg(double x);
    static double Deg2Rad(double x);
    static double EarthDistance(double in_lat, double in_lon, 
								double in_lat2, double in_lon2);

    virtual int Reconnect() = 0;

	struct sat_pos {
		int prn;
		int elevation;
		int azimuth;
		int snr;
	};

protected:
    uint32_t gps_options;

    int reconnect_attempt;
    time_t last_disconnect;

    double lat, lon, alt, spd, hed, hdop, vdop;
    int mode, gps_ever_lock;

	int gps_connected;

    // Last location used for softheading calcs
    double last_lat, last_lon, last_hed;

	// Satellite position info
	map<int, sat_pos> sat_pos_map;
	map<int, sat_pos> sat_pos_map_tmp;

	// Scan options & register systems
	int ScanOptions();
	int RegisterComponents();

	// network proto ref
	int gps_proto_ref;

	int gpseventid;
    
    friend int GpsInjectEvent(TIMEEVENT_PARMS);
};

#endif

