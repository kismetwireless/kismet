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

#include "util.h"

#include <pthread.h>

#include "globalregistry.h"

class Kis_Gps_Location;
class kis_gps_packinfo;

// New-style superclass for GPS, all GPS devices are subclassed from this.
//
// GPS drivers are registered with the gps manager.  GPS instances are initiated
// with either a gps= config line or a runtime command.
//
// GPS options are passed as name=value,name2=value2 strings which are parsed by
// each driver, allowing for maximum flexibility in parsing parameters.
class Kis_Gps {
public:
    Kis_Gps(GlobalRegistry *in_globalreg);
    virtual ~Kis_Gps();

    // Create an GPS instance of the proper type & open it
    virtual Kis_Gps *BuildGps(string in_opts) = 0;

    virtual int OpenGps(string in_opts);

    // Human-readable description of device
    virtual string FetchGpsDescription() = 0;

    // Fetch if we have a valid location anymore; per-gps-driver logic 
    // will determine if we consider a value to still be valid
    virtual bool FetchGpsLocationValid() = 0;

    // Are we connected to our device?
    virtual bool FetchGpsConnected() = 0;

    virtual string FetchName() { 
        local_locker lock(&gps_locker);
        return name; 
    }

    // Fetch the last known location, and the time we knew it
    virtual kis_gps_packinfo *FetchGpsLocation() { 
        local_locker lock(&gps_locker);
        return gps_location; 
    };

    // Various GPS transformation utility functions
    static double GpsCalcHeading(double in_lat, double in_lon, 
            double in_lat2, double in_lon2);
    static double GpsCalcRad(double lat);
    static double GpsRad2Deg(double x);
    static double GpsDeg2Rad(double x);
    static double GpsEarthDistance(double in_lat, double in_lon, 
            double in_lat2, double in_lon2);

protected:
    GlobalRegistry *globalreg;

    kis_gps_packinfo *gps_location;
    kis_gps_packinfo *gps_last_location;

    string name;
    bool reconnect;

    pthread_mutex_t gps_locker;
};

#endif

