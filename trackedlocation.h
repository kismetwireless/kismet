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

#ifndef __TRACKEDLOCATION_H__
#define __TRACKEDLOCATION_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "entrytracker.h"

class kis_gps_packinfo;

// Component-tracker common GPS element
class kis_tracked_location_triplet : public tracker_component {
public:
    kis_tracked_location_triplet();
    kis_tracked_location_triplet(int in_id);
    kis_tracked_location_triplet(int in_id, std::shared_ptr<tracker_element_map> e);

    kis_tracked_location_triplet(const kis_tracked_location_triplet *p);

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_tracked_location_triplet");
    }

    static uint32_t get_static_signature() {
        return adler32_checksum("kis_tracked_location_triplet");
    }

    // lat/lon are encoded in the geopoint
    double get_lat() const {
        return geopoint->at(1);
    }

    void set_lat(double lat) {
        geopoint->at(1) = lat;
    }

    double get_lon() const {
        return geopoint->at(0);
    }

    void set_lon(double lon) {
        geopoint->at(0) = lon;
    }

    __Proxy(alt, float, float, float, alt);

    __Proxy(fix, uint8_t, uint8_t, uint8_t, fix);
    __Proxy(time_sec, uint64_t, time_t, time_t, time_sec);
    __Proxy(time_usec, uint64_t, uint64_t, uint64_t, time_usec);

    /*
    __Proxy(error_x, double, double, double, error_x);
    __Proxy(error_y, double, double, double, error_y);
    __Proxy(error_v, double, double, double, error_v);
    */

    bool get_valid() const {
        return get_fix() >= 2;
    }

    void set(double in_lat, double in_lon, float in_alt, unsigned int in_fix);
    void set(double in_lat, double in_lon);
    void set(kis_gps_packinfo *in_packinfo);

	inline kis_tracked_location_triplet& operator= (const kis_tracked_location_triplet& in);

protected:
    virtual void register_fields() override;
    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override;

    std::shared_ptr<tracker_element_vector_double> geopoint;
    std::shared_ptr<tracker_element_float> alt;
    /*
    std::shared_ptr<tracker_element_double> error_x;
    std::shared_ptr<tracker_element_double> error_y;
    std::shared_ptr<tracker_element_double> error_v;
    */
    std::shared_ptr<tracker_element_uint8> fix;
    std::shared_ptr<tracker_element_uint64> time_sec;
    std::shared_ptr<tracker_element_uint64> time_usec;
};

class kis_tracked_location_full : public kis_tracked_location_triplet {
public:
    kis_tracked_location_full();
    kis_tracked_location_full(int in_id);
    kis_tracked_location_full(int in_id, std::shared_ptr<tracker_element_map> e);

    kis_tracked_location_full(const kis_tracked_location_full *p);

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_tracked_location_full");
    }

    static uint32_t get_static_signature() {
        return adler32_checksum("kis_tracked_location_full");
    }

    __Proxy(speed, float, float, float, spd);
    __Proxy(heading, float, float, float, heading);

    void set(kis_gps_packinfo *in_packinfo);

	inline kis_tracked_location_full& operator= (const kis_tracked_location_full& in);

protected:
    virtual void register_fields() override;
    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override;

    std::shared_ptr<tracker_element_float> spd;
    std::shared_ptr<tracker_element_float> heading;
};

// min/max/avg location
class kis_tracked_location : public tracker_component {
public:
    kis_tracked_location();
    kis_tracked_location(int in_id);
    kis_tracked_location(int in_id, std::shared_ptr<tracker_element_map> e);
    kis_tracked_location(const kis_tracked_location *p);

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
    }

    void add_loc(double in_lat, double in_lon, double in_alt, unsigned int fix,
            double in_speed, double in_heading);

    void add_loc_with_avg(double in_lat, double in_lon, double in_alt, unsigned int fix,
            double in_speed, double in_heading);

    __Proxy(fix, uint8_t, unsigned int, unsigned int, loc_fix);

    bool get_valid() const {
        return get_fix() >= 2;
    }

    std::shared_ptr<kis_tracked_location_triplet> get_min_loc() { return min_loc; }
    std::shared_ptr<kis_tracked_location_triplet> get_max_loc() { return max_loc; }
    std::shared_ptr<kis_tracked_location_triplet> get_avg_loc() { return avg_loc; }

    std::shared_ptr<kis_tracked_location_full> get_last_loc() { return last_loc; }

    time_t get_last_location_time() const {
        return last_location_time;
    }

    void set_last_location_time(time_t t) {
        last_location_time = t;
    }

protected:
    virtual void register_fields() override;

    // We save the IDs here because we dynamically generate them
    std::shared_ptr<kis_tracked_location_triplet> min_loc, max_loc, avg_loc;
    std::shared_ptr<kis_tracked_location_full> last_loc;

    int min_loc_id, max_loc_id, avg_loc_id, last_loc_id;

    std::shared_ptr<tracker_element_uint8> loc_fix;

    double agg_x, agg_y, agg_z, agg_a;
    uint64_t num_avg, num_alt_avg;

    time_t last_location_time;
};

#endif

