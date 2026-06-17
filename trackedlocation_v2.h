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

class kis_tracked_location_triplet_v2 : public json_adapter_v2::jsonable {
public:
    kis_tracked_location_triplet_v2() :
        geopoint_{0, 0},
        altitude_{0},
        fix_{0},
        time_sec_{0},
        time_usec_{0} { }

    constexpr17 auto lat() const { return std::get<1>(geopoint_); }
    constexpr17 auto lon() const { return std::get<0>(geopoint_); }
    constexpr17 auto& location() const { return geopoint_; }
    void set_location(double lat, double lon) { geopoint_ = std::make_pair(lon, lat); }
    void set_location(double lat, double lon, double altitude, uint8_t fix) {
        geopoint_ = std::make_pair(lon, lat);
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

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    std::pair<double, double> geopoint_;
    double altitude_;
    uint8_t fix_;
    uint64_t time_sec_, time_usec_;
};

class kis_tracked_location_full_v2 : public kis_tracked_location_triplet_v2 {
public:
    kis_tracked_location_full_v2() :
        kis_tracked_location_triplet_v2{},
        speed_{0},
        heading_{0},
        magheading_{0} { }

    void set_speed(double s) { speed_ = s; }
    constexpr17 double speed() const { return speed_; }

    void set_heading(float h) { heading_ = h; }
    constexpr17 float heading() { return heading_; }

    void set_magheading(float m) { magheading_ = m; }
    constexpr17 float magheading() { return magheading_; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    double speed_;
    float heading_;
    float magheading_;
};

#endif /* __TRACKED_LOCATION_V2_H__ */
