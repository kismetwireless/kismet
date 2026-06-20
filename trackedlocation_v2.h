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

#ifndef __TRACKED_LOCATION_V2_H__
#define __TRACKED_LOCATION_V2_H__

#include <string>

#include <stdint.h>

#include "json_adapter_v2.h"
#include "packet.h"
#include "packinfo_signal.h"

class kis_gps_packinfo;
class kis_tracked_location_full_v2;

using geopoint_t = std::pair<double, double>;

class kis_tracked_location_triplet_v2 : public json_adapter_v2::jsonable {
public:
    kis_tracked_location_triplet_v2() :
        geopoint_{0, 0},
        altitude_{0},
        fix_{0},
        time_sec_{0},
        time_usec_{0} { }

    void reset() {
        geopoint_ = {0, 0};
        altitude_ = 0;
        fix_ = 0;
        time_sec_ = 0;
        time_usec_ = 0;
    }

    constexpr17 auto lat() const { return std::get<1>(geopoint_); }
    void set_lat(double lat) { geopoint_.second = lat; }
    constexpr17 auto lon() const { return std::get<0>(geopoint_); }
    void set_lon(double lon) { geopoint_.first = lon; }
    constexpr17 auto& location() const { return geopoint_; }
    void set_location(double lat, double lon) { geopoint_ = std::make_pair(lon, lat); }
    void set_location(const geopoint_t& p) { geopoint_ = p; }
    void set_location(double lat, double lon, double altitude, uint8_t fix) {
        geopoint_ = std::make_pair(lon, lat);
        fix_ = fix;
        altitude_ = altitude;
    }
    void set_location(const geopoint_t& geopoint, double altitude, uint8_t fix) {
        geopoint_ = geopoint;
        fix_ = fix;
        altitude_ = altitude;
    }

    constexpr17 auto altitude() const { return altitude_; }
    void set_altitude(double alt) { altitude_ = alt; }

    void set_time(uint64_t time_s, uint64_t time_us) { time_sec_ = time_s; time_usec_ = time_us; }
    void set_time(std::pair<uint64_t, uint64_t> t) { time_sec_ = std::get<0>(t); time_usec_ = std::get<1>(t); }
    constexpr17 auto time() const { return std::make_pair(time_sec_, time_usec_); }

    constexpr17 bool get_valid() const { return fix_ >= 2; }
    constexpr17 uint8_t fix() const { return fix_; }
    void set_fix(uint8_t fix) { fix_ = fix; }

    virtual void set(const kis_tracked_location_triplet_v2& t);
    virtual void set(const kis_gps_packinfo *pi);

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    geopoint_t geopoint_;
    double altitude_;
    uint8_t fix_;
    uint64_t time_sec_, time_usec_;

    friend class kis_tracked_location_full_v2;
};

class kis_tracked_location_full_v2 : public kis_tracked_location_triplet_v2 {
public:
    kis_tracked_location_full_v2() :
        kis_tracked_location_triplet_v2{},
        speed_{0},
        heading_{0},
        magheading_{0} { }

    void reset() {
        kis_tracked_location_triplet_v2::reset();
        speed_ = 0;
        heading_ = 0;
        magheading_ = 0;
    }

    void set_speed(double s) { speed_ = s; }
    constexpr17 double speed() const { return speed_; }

    void set_heading(float h) { heading_ = h; }
    constexpr17 float heading() { return heading_; }

    void set_magheading(float m) { magheading_ = m; }
    constexpr17 float magheading() { return magheading_; }

    void set_location(const geopoint_t& geopoint, double altitude,
            uint8_t fix, double speed, float heading) {
        geopoint_ = geopoint;
        altitude_ = altitude;
        fix_ = fix;
        speed_ = speed;
        heading_ = heading;
        magheading_ = 0;
    }

    virtual void set(const kis_tracked_location_triplet_v2& t) override;
    virtual void set(const kis_tracked_location_full_v2& t);
    virtual void set(const kis_gps_packinfo *pi) override;

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    double speed_;
    float heading_;
    float magheading_;
};

// V2 instance of a full location record, which includes min/max/average location with
// running averages and previous location.
class kis_tracked_location_v2 : public json_adapter_v2::jsonable {
public:
    kis_tracked_location_v2() :
        json_adapter_v2::jsonable(),
        agg_x_{0},
        agg_y_{0},
        agg_z_{0},
        agg_a_{0},
        last_location_time_{0} { }

    void reset() {
        min_loc_.reset();
        max_loc_.reset();
        avg_loc_.reset();
        last_loc_.reset();
    }

    void add_loc(const kis_gps_packinfo* p);
    void add_loc_with_avg(const kis_gps_packinfo *p);

protected:
    kis_tracked_location_triplet_v2 min_loc_, max_loc_, avg_loc_, last_loc_;

    double agg_x_, agg_y_, agg_z_, agg_a_;
    uint64_t num_avg_, num_alt_avg_;

    time_t last_location_time_;
};

// V2 historic tracking used in runtime/history location display
class kis_historic_location_v2 : public json_adapter_v2::jsonable {
public:
    kis_historic_location_v2() :
        json_adapter_v2::jsonable{},
        geopoint_{0, 0},
        fix_{0},
        altitude_{0},
        speed_{0},
        heading_{0},
        magheading_{0},
        signal_{0},
        frequency_{0},
        time_sec_{0} { }

    constexpr17 auto lat() const { return std::get<1>(geopoint_); }
    void set_lat(double lat) { geopoint_.second = lat; }
    constexpr17 auto lon() const { return std::get<0>(geopoint_); }
    void set_lon(double lon) { geopoint_.first = lon; }
    constexpr17 auto& location() const { return geopoint_; }
    void set_location(double lat, double lon) { geopoint_ = std::make_pair(lon, lat); }
    void set_location(const geopoint_t& p) { geopoint_ = p; }
    void set_location(double lat, double lon, double altitude, uint8_t fix) {
        geopoint_ = std::make_pair(lon, lat);
        fix_ = fix;
        altitude_ = altitude;
    }
    void set_location(const geopoint_t& geopoint, double altitude, uint8_t fix) {
        geopoint_ = geopoint;
        fix_ = fix;
        altitude_ = altitude;
    }

    constexpr17 auto altitude() const { return altitude_; }
    void set_altitude(double alt) { altitude_ = alt; }

    void set_time(uint64_t time_s) { time_sec_ = time_s; }
    constexpr17 auto time() const { return time_sec_; }

    constexpr17 bool get_valid() const { return fix_ >= 2; }
    constexpr17 uint8_t fix() const { return fix_; }
    void set_fix(uint8_t fix) { fix_ = fix; }

    virtual void set(const kis_tracked_location_triplet_v2& t);
    virtual void set(const kis_gps_packinfo *pi);

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    geopoint_t geopoint_;
    uint8_t fix_;
    double altitude_;
    double speed_;

    float heading_;
    float magheading_;

    int32_t signal_;
    uint64_t frequency_;

    uint64_t time_sec_;
};

#endif /* __TRACKED_LOCATION_V2_H__ */
