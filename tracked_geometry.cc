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

#include "tracked_geometry.h"

kis_tracked_geom_point::kis_tracked_geom_point() : 
    tracker_component {0} {
    register_fields();
    reserve_fields(nullptr);
}

kis_tracked_geom_point::kis_tracked_geom_point(int id) :
    tracker_component {id} {
    register_fields();
    reserve_fields(nullptr);
}

kis_tracked_geom_point::kis_tracked_geom_point(int id, std::shared_ptr<TrackerElementMap> e) :
    tracker_component {id, e} {
    register_fields();
    reserve_fields(nullptr);
}

kis_tracked_geom_point::kis_tracked_geom_point(int id, double lat, double lon) :
    tracker_component {id} {
    register_fields();
    reserve_fields(nullptr);

    set_lat(lat);
    set_lon(lon);
}

kis_tracked_geom_point::kis_tracked_geom_point(int id, std::tuple<double, double> coord) :
    tracker_component {id} {
    register_fields();
    reserve_fields(nullptr);

    set_tuple(coord);
}

kis_tracked_geom_point::kis_tracked_geom_point(std::tuple<double, double> coord) :
    tracker_component {0} {
    register_fields();
    reserve_fields(nullptr);

    set_tuple(coord);
}

kis_tracked_geom_point::kis_tracked_geom_point(int id, kisgeometry::gps_point coord) :
    tracker_component {id} {
    register_fields();
    reserve_fields(nullptr);

    set_geom_tuple(coord);
}

kis_tracked_geom_point::kis_tracked_geom_point(kisgeometry::gps_point coord) :
    tracker_component {0} {
    register_fields();
    reserve_fields(nullptr);

    set_geom_tuple(coord);
}


void kis_tracked_geom_point::register_fields() {
    tracker_component::register_fields();
    RegisterField("kismet.common.point.lat", "latitude", &lat);
    RegisterField("kismet.common.point.lon", "longitude", &lon);
}

