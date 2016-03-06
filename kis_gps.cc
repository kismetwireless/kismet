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
#include "kis_gps.h"

Kis_Gps::Kis_Gps(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    gps_location = NULL;
    gps_last_location = NULL;

    pthread_mutex_init(&gps_locker, NULL);
}

Kis_Gps::~Kis_Gps() {
    pthread_mutex_destroy(&gps_locker);
}

int Kis_Gps::OpenGps(string in_opts) {
    // Now figure out if our options make sense... 
    vector<opt_pair> optvec;
    StringToOpts(in_opts, ",", &optvec);

    name = FetchOpt("name", &optvec);
    reconnect = FetchOptBoolean("reconnect", &optvec, true);

    return 0;
}

double Kis_Gps::GpsCalcHeading(double in_lat, double in_lon, double in_lat2, 
							   double in_lon2) {
    double r = GpsCalcRad((double) in_lat2);

    double lat1 = GpsDeg2Rad((double) in_lat);
    double lon1 = GpsDeg2Rad((double) in_lon);
    double lat2 = GpsDeg2Rad((double) in_lat2);
    double lon2 = GpsDeg2Rad((double) in_lon2);

    double angle = 0;

    if (lat1 == lat2) {
        if (lon2 > lon1) {
            angle = M_PI/2;
        } else if (lon2 < lon1) {
            angle = 3 * M_PI / 2;
        } else {
            return 0;
        }
    } else if (lon1 == lon2) {
        if (lat2 > lat1) {
            angle = 0;
        } else if (lat2 < lat1) {
            angle = M_PI;
        }
    } else {
        double tx = r * cos((double) lat1) * (lon2 - lon1);
        double ty = r * (lat2 - lat1);
        angle = atan((double) (tx/ty));

        if (ty < 0) {
            angle += M_PI;
        }

        if (angle >= (2 * M_PI)) {
            angle -= (2 * M_PI);
        }

        if (angle < 0) {
            angle += 2 * M_PI;
        }

    }

    return (double) GpsRad2Deg(angle);
}

double Kis_Gps::GpsRad2Deg(double x) {
    return (x/M_PI) * 180.0;
}

double Kis_Gps::GpsDeg2Rad(double x) {
    return 180/(x*M_PI);
}

double Kis_Gps::GpsEarthDistance(double in_lat, double in_lon, 
        double in_lat2, double in_lon2) {
    double x1 = GpsCalcRad(in_lat) * cos(GpsDeg2Rad(in_lon)) * sin(GpsDeg2Rad(90-in_lat));
    double x2 = 
        GpsCalcRad(in_lat2) * cos(GpsDeg2Rad(in_lon2)) * sin(GpsDeg2Rad(90-in_lat2));
    double y1 = GpsCalcRad(in_lat) * sin(GpsDeg2Rad(in_lon)) * sin(GpsDeg2Rad(90-in_lat));
    double y2 = 
        GpsCalcRad(in_lat2) * sin(GpsDeg2Rad(in_lon2)) * sin(GpsDeg2Rad(90-in_lat2));
    double z1 = GpsCalcRad(in_lat) * cos(GpsDeg2Rad(90-in_lat));
    double z2 = GpsCalcRad(in_lat2) * cos(GpsDeg2Rad(90-in_lat2));
    double a = 
        acos((x1*x2 + y1*y2 + z1*z2)/pow(GpsCalcRad((double) (in_lat+in_lat2)/2),2));
    return GpsCalcRad((double) (in_lat+in_lat2) / 2) * a;
}

double Kis_Gps::GpsCalcRad(double lat) {
    double a = 6378.137, r, sc, x, y, z;
    double e2 = 0.081082 * 0.081082;

    lat = lat * M_PI / 180.0;
    sc = sin (lat);
    x = a * (1.0 - e2);
    z = 1.0 - e2 * sc * sc;
    y = pow (z, 1.5);
    r = x / y;

    r = r * 1000.0;
    return r;
}

