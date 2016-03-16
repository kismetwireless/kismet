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

#include "gpsfake.h"
#include "gps_manager.h"
#include "messagebus.h"

GPSFake::GPSFake(GlobalRegistry *in_globalreg) : Kis_Gps(in_globalreg) {
    globalreg = in_globalreg;
}

GPSFake::~GPSFake() {

}

Kis_Gps *GPSFake::BuildGps(string in_opts) {
    local_locker lock(&gps_locker);

    GPSFake *new_gps = new GPSFake(globalreg);

    if (new_gps->OpenGps(in_opts) < 0) {
        delete new_gps;
        return NULL;
    }

    return new_gps;
}

int GPSFake::OpenGps(string in_opts) {
    local_locker lock(&gps_locker);

    if (Kis_Gps::OpenGps(in_opts) < 0)
        return -1;

    // Now figure out if our options make sense... 
    vector<opt_pair> optvec;
    StringToOpts(in_opts, ",", &optvec);

    string proto_lat;
    string proto_lon;
    string proto_alt;

    proto_lat = FetchOpt("lat", &optvec);
    proto_lon = FetchOpt("lon", &optvec);
    proto_alt = FetchOpt("alt", &optvec);

    gps_location = new kis_gps_packinfo();

    if (proto_lat == "" || proto_lon == "") {
        _MSG("GPSVirtual expected lat= and lon= options.", MSGFLAG_ERROR);
        return -1;
    }

    if (sscanf(proto_lat.c_str(), "%lf", &(gps_location->lat)) != 1) {
        _MSG("GPSVirtual expected decimal coordinate in lat= option", MSGFLAG_ERROR);
        return -1;
    }

    if (sscanf(proto_lon.c_str(), "%lf", &(gps_location->lon)) != 1) {
        _MSG("GPSVirtual expected decimal coordinate in lon= option", MSGFLAG_ERROR);
        return -1;
    }

    gps_location->fix = 2;

    if (proto_alt != "") {
        if (sscanf(proto_alt.c_str(), "%lf", &(gps_location->alt)) != 1) {
            _MSG("GPSVirtual expected decimal altitude in alt= option", MSGFLAG_ERROR);
            return -1;
        }

        gps_location->fix = 3;
    }

    stringstream msg;
    msg << "GPSVirtual setting location to " << gps_location->lat << "," <<
        gps_location->lon << " @ " << gps_location->alt << "m";
    _MSG(msg.str(), MSGFLAG_INFO);

    return 1;
}

string GPSFake::FetchGpsDescription() {
    local_locker lock(&gps_locker);

    stringstream str;

    str << "Virtual GPS at " << gps_location->lat << "," <<
        gps_location->lon << " @ " << gps_location->alt << "m";

    return str.str();
}

bool GPSFake::FetchGpsLocationValid() {
    return true;
}

bool GPSFake::FetchGpsConnected() {
    return true;
}

kis_gps_packinfo *GPSFake::FetchGpsLocation() {
    local_locker lock(&gps_locker);

    if (gps_location != NULL)
        gps_location->time = globalreg->timestamp.tv_sec;

    return gps_location;
}

