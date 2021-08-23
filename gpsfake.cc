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

#include <time.h>
#include "gpsfake.h"
#include "gpstracker.h"
#include "messagebus.h"

kis_gps_fake::kis_gps_fake(shared_gps_builder in_builder) : 
    kis_gps(in_builder) { }

kis_gps_fake::~kis_gps_fake() { }

bool kis_gps_fake::open_gps(std::string in_opts) {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "kis_gps_fake open_gps");

    if (!kis_gps::open_gps(in_opts)) {
        return false;
    }

    std::string proto_lat;
    std::string proto_lon;
    std::string proto_alt;

    proto_lat = fetch_opt("lat", source_definition_opts);
    proto_lon = fetch_opt("lon", source_definition_opts);
    proto_alt = fetch_opt("alt", source_definition_opts);

    gps_location = packetchain->new_packet_component<kis_gps_packinfo>();

    if (proto_lat == "" || proto_lon == "") {
        _MSG("GPSVirtual expected lat= and lon= options.", MSGFLAG_ERROR);
        return false;
    }

    if (sscanf(proto_lat.c_str(), "%lf", &(gps_location->lat)) != 1) {
        _MSG("GPSVirtual expected decimal coordinate in lat= option", MSGFLAG_ERROR);
        return false;
    }

    if (sscanf(proto_lon.c_str(), "%lf", &(gps_location->lon)) != 1) {
        _MSG("GPSVirtual expected decimal coordinate in lon= option", MSGFLAG_ERROR);
        return false;
    }

    gps_location->fix = 2;

    if (proto_alt != "") {
        if (sscanf(proto_alt.c_str(), "%lf", &(gps_location->alt)) != 1) {
            _MSG("GPSVirtual expected decimal altitude in alt= option", MSGFLAG_ERROR);
            return false;
        }

        gps_location->fix = 3;
    }

    _MSG_INFO("GPSVirtual using location {},{} @ {}", gps_location->lat,
            gps_location->lon, gps_location->alt);

    std::stringstream msg;
    msg << "Virtual GPS at " << gps_location->lat << "," << 
        gps_location->lon << " @ " << gps_location->alt << "m";
    set_int_gps_description(msg.str());

    gps_location->gpsuuid = get_gps_uuid();
    gps_location->gpsname = get_gps_name();

    gps_last_location = gps_location;

    update_locations();

    return true;
}

std::shared_ptr<kis_gps_packinfo> kis_gps_fake::get_location() {
    auto upd_location = packetchain->new_packet_component<kis_gps_packinfo>();
    upd_location->set(gps_location);
    gettimeofday(&(upd_location->tv), NULL);
    gps_location = upd_location;
    return gps_location;
}

