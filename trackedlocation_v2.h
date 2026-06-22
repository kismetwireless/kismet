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
#include "kis_mutex.h"
#include "packet.h"
#include "packinfo_signal.h"

class kis_gps_packinfo;
class kis_tracked_location_full_v2;
class kis_historic_location_v2;

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
    friend class kis_historic_location_v2;
};

template<> struct json_adapter_v2::json_encode<kis_tracked_location_triplet_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_triplet_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_triplet_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_triplet_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_triplet_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
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

    friend class kis_historic_location_v2;
};

template<> struct json_adapter_v2::json_encode<kis_tracked_location_full_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_full_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_full_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_full_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_full_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
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

template<> struct json_adapter_v2::json_encode<kis_tracked_location_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_location_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
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

    kis_historic_location_v2(const kis_tracked_location_triplet_v2& t) { set(t); }
    kis_historic_location_v2(const kis_tracked_location_full_v2& t) { set(t); }
    kis_historic_location_v2(const kis_gps_packinfo *pi) { set(pi); }

    void reset() {
        geopoint_ = {0, 0};
        fix_ = 0;
        altitude_ = 0;
        speed_ = 0;
        heading_ = 0;
        magheading_ = 0;
        signal_ = 0;
        frequency_ = 0;
        time_sec_ = 0;
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

    constexpr17 auto time() const { return time_sec_; }
    void set_time(uint64_t time_s) { time_sec_ = time_s; }

    constexpr17 bool get_valid() const { return fix_ >= 2; }
    constexpr17 uint8_t fix() const { return fix_; }
    void set_fix(uint8_t fix) { fix_ = fix; }

    constexpr17 auto speed() const { return speed_; }
    void set_speed(double s) { speed_ = s; }

    constexpr17 auto heading() const { return heading_; }
    void set_heading(float h) { heading_ = h; }
    constexpr17 auto magheading() const { return magheading_; }
    void set_magheading(float h) { magheading_ = h; }

    constexpr17 int32_t signal() const { return signal_; }
    void set_signal(uint32_t s) { signal_ = s; }

    constexpr17 int32_t frequency() const { return frequency_; }
    void set_frequency(uint64_t f) { frequency_ = f; }

    void set(const kis_tracked_location_triplet_v2& t);
    void set(const kis_tracked_location_full_v2& t);
    void set(const kis_gps_packinfo *pi);

    template <typename It1, typename It2>
    void aggregate(size_t sz, It1 first, It2 last) {
        double avg_x = 0, avg_y = 0, avg_z = 0, avg_alt = 0;
        double heading = 0, magheading = 0, speed = 0, signal = 0, timesec = 0, frequency = 0;
        double num_signal = 0, num_alt = 0;

        for (; first != last; ++first) {
            double mod_lat = first->lat() * M_PI / 180;
            double mod_lon = first->lon() * M_PI / 180;

            avg_x += cos(mod_lat) * cos(mod_lon);
            avg_y += cos(mod_lat) * cos(mod_lon);
            avg_z = sin(mod_lat);

            if (first->fix() > 2) {
                avg_alt += first->altitude();
                num_alt++;
            }

            heading += first->heading();
            magheading += first->magheading();
            speed += first->speed();

            if (first->signal() != 0) {
                signal += first->signal();
                num_signal++;
            }

            timesec += first->time();
            frequency += first->frequency();
        }

        reset();

        double r_x = avg_x / sz;
        double r_y = avg_y / sz;
        double r_z = avg_z / sz;

        double central_lon = atan2(r_y, r_x);
        double central_sqr = sqrt(r_x * r_x + r_y * r_y);
        double central_lat = atan2(r_z, central_sqr);

        double r_alt = 0;
        if (num_alt > 0) {
            r_alt = avg_alt / num_alt;
        }

        set_location(central_lat * 180 / M_PI, central_lon * 180 / M_PI);
        set_fix(num_alt > 0);
        set_altitude(r_alt);
        set_heading(heading / sz);
        set_magheading(magheading / sz);
        set_speed(speed / sz);

        set_frequency(frequency / sz);
        set_signal(signal / num_signal);

        set_time(timesec / sz);
    }

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

template<> struct json_adapter_v2::json_encode<kis_historic_location_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_historic_location_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_historic_location_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_historic_location_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_historic_location_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

// V2 of a time-series RRD-like history track of decreasing precision over the number of
// samples collected
class kis_location_rrd_v2 : public json_adapter_v2::jsonable {
public:
    kis_location_rrd_v2() :
        json_adapter_v2::jsonable(),
        last_sample_ts_{0},
        samples_t1_pos_{0},
        samples_t2_pos_{0},
        samples_t3_pos_{0} { }

    void reset() {
        samples_tier1_ = {};
        samples_tier2_ = {};
        samples_tier3_ = {};
        last_sample_ts_ = 0;
        samples_t1_pos_ = 0;
        samples_t2_pos_ = 0;
        samples_t3_pos_ = 0;
    }

    void add_sample(const kis_tracked_location_triplet_v2& t) { return add_sample(kis_historic_location_v2{t}); };
    void add_sample(const kis_tracked_location_full_v2& t) { return add_sample(kis_historic_location_v2{t}); };
    void add_sample(const kis_gps_packinfo *pi) { return add_sample(kis_historic_location_v2{pi}); }
    void add_sample(const kis_historic_location_v2& h);

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    kis_shared_mutex mutex_;

    static const size_t samples_per_tier_ = 100;

    using sample_iter_ = std::array<kis_historic_location_v2, samples_per_tier_>::iterator;
    std::array<kis_historic_location_v2, samples_per_tier_> samples_tier1_;
    std::array<kis_historic_location_v2, samples_per_tier_> samples_tier2_;
    std::array<kis_historic_location_v2, samples_per_tier_> samples_tier3_;

    uint64_t last_sample_ts_;

    unsigned int samples_t1_pos_;
    unsigned int samples_t2_pos_;
    unsigned int samples_t3_pos_;
};

template<> struct json_adapter_v2::json_encode<kis_location_rrd_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_location_rrd_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_location_rrd_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_location_rrd_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_location_rrd_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

#endif /* __TRACKED_LOCATION_V2_H__ */
