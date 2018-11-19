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

#ifndef __TRACKED_GEOMETRY_H__
#define __TRACKED_GEOMETRY_H__

#include "config.h"

#include <string>

#include "kis_mutex.h"
#include "trackedelement.h"
#include "timetracker.h"
#include "kis_net_microhttpd.h"
#include "tracked_location.h"

#include "boost/geometry.hpp"
#include "boost/geometry/geometries/polygon.hpp"
#include "boost/geometry/geometries/adapted/boost_tuple.hpp"
#include "boost/geometry/algorithms/centroid.hpp"

BOOST_GEOMETRY_REGISTER_BOOST_TUPLE_CS(cs::cartesian)

namespace kisgeometry {
    using gps_point = boost::tuple<double, double>;
    using gps_poly = boost::geometry::model::polygon<gps_point>;
    using gps_multip = boost::geometry::model::multi_point<gps_point>;
};

// Single 2d point used by geometry
class kis_tracked_geom_point : public tracker_component {
public:
    kis_tracked_geom_point();
    kis_tracked_geom_point(int in_id);
    kis_tracked_geom_point(int in_id, std::shared_ptr<TrackerElementMap> e);
    kis_tracked_geom_point(int in_id, double lat, double lon);
    kis_tracked_geom_point(int in_id, std::tuple<double, double> coord);
    kis_tracked_geom_point(std::tuple<double, double> coord);
    kis_tracked_geom_point(int in_id, kisgeometry::gps_point point);
    kis_tracked_geom_point(kisgeometry::gps_point point);

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(lat, double, double, double, lat);
    __Proxy(lon, double, double, double, lon);

    template <typename T>
    void set_tuple(T t) {
        set_lat(std::get<0>(t));
        set_lon(std::get<1>(t));
    }

    void set_geom_tuple(kisgeometry::gps_point t) {
        set_lat(t.get<0>());
        set_lon(t.get<1>());
    }

protected:
    virtual void register_fields() override;

    std::shared_ptr<TrackerElementDouble> lat;
    std::shared_ptr<TrackerElementDouble> lon;
};

class kis_tracked_geom_polygon : public tracker_component {
public:
    kis_tracked_geom_polygon();
    kis_tracked_geom_polygon(int in_id);
    kis_tracked_geom_polygon(int in_id, std::shared_ptr<TrackerElementMap> e);
    kis_tracked_geom_polygon(int in_id, const kisgeometry::gps_poly& poly);
    kis_tracked_geom_polygon(const kisgeometry::gps_poly& poly);

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __ProxyTrackable(poly_points, TrackerElementVector, poly_points);

    void set_geom_poly(const kisgeometry::gps_poly& poly);

protected:
    virtual void register_fields() override;

    // Polygon is stored as a vector of points; each point is, itself, a doublevector
    std::shared_ptr<TrackerElementVector> poly_points;
};

#endif
