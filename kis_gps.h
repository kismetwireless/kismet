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

#ifndef __KIS_GPS_H__
#define __KIS_GPS_H__

#include "config.h"
#include "globalregistry.h"

class Kis_Gps_Location;
class kis_gps_packinfo;

/* Superclass for GPS support */
class Kis_Gps {
public:
    Kis_Gps(GlobalRegistry *in_globalreg);
    virtual ~Kis_Gps() { };

    // Create an GPS instance of the proper type
    virtual Kis_Gps *BuildGps(string in_opts) = 0;

    virtual int Open(string in_opts) = 0;

    // Descriptors for device and type
    virtual string FetchDevice() = 0;
    virtual string FetchType() = 0;

    // Fetch if we have a valid location anymore; per-gps-driver logic 
    // will determine if we consider a value to still be valid
    virtual bool FetchLocationValid() = 0;

    // Are we connected to our device?
    virtual bool FetchGpsConnected() = 0;

    // Fetch the last known location, and the time we knew it
    kis_gps_packinfo *FetchLocation() { return location; };

    // Various GPS transformation utility functions
    static double CalcHeading(double in_lat, double in_lon, 
							  double in_lat2, double in_lon2);
    static double CalcRad(double lat);
    static double Rad2Deg(double x);
    static double Deg2Rad(double x);
    static double EarthDistance(double in_lat, double in_lon, 
								double in_lat2, double in_lon2);

protected:
    kis_gps_packinfo *location;
    kis_gps_packinfo *last_location;

};

#endif

