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

#include <math.h>
#include <cmath>

#include "trackedlocation.h"
#include "gpstracker.h"

kis_tracked_location_triplet::kis_tracked_location_triplet() :
    tracker_component() {

    register_fields();
    reserve_fields(NULL);
}

kis_tracked_location_triplet::kis_tracked_location_triplet(int in_id) :
    tracker_component(in_id) {

    register_fields();
    reserve_fields(NULL);
}

kis_tracked_location_triplet::kis_tracked_location_triplet(int in_id,
        std::shared_ptr<tracker_element_map> e) :
    tracker_component(in_id) {

    register_fields();
    reserve_fields(e);
}

kis_tracked_location_triplet::kis_tracked_location_triplet(const kis_tracked_location_triplet *p) :
    tracker_component(p) {

        __ImportField(geopoint, p);
        __ImportId(alt_id, p);
        __ImportId(fix_id, p);
        __ImportId(time_sec_id, p);
        __ImportId(time_usec_id, p);

        reserve_fields(nullptr);
}

void kis_tracked_location_triplet::set(double in_lat, double in_lon,
       float in_alt, unsigned int in_fix) {

    set_location(in_lat, in_lon);
    set_alt(in_alt);
    set_fix(in_fix);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    set_time_sec(tv.tv_sec);
    set_time_usec(tv.tv_usec);
}

void kis_tracked_location_triplet::set(double in_lat, double in_lon) {
    set_location(in_lat, in_lon);
    set_fix(2);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    set_time_sec(tv.tv_sec);
    set_time_usec(tv.tv_usec);
}

void kis_tracked_location_triplet::set(kis_gps_packinfo *in_packinfo) {
    if (in_packinfo == NULL)
        return;


    if (in_packinfo->lat != 0 && in_packinfo->lon != 0) {
        set_location(in_packinfo->lat, in_packinfo->lon);
    }

    set_alt(in_packinfo->alt);
    set_fix(in_packinfo->fix);
    set_time_sec(in_packinfo->tv.tv_sec);
    set_time_usec(in_packinfo->tv.tv_usec);
}

kis_tracked_location_triplet&
    kis_tracked_location_triplet::operator= (const kis_tracked_location_triplet& in) {
    set_location(in.get_lat(), in.get_lon());

    if (in.has_alt())
        set_alt(in.get_only_alt());
    else
        clear_alt();

    if (in.has_fix())
        set_fix(in.get_only_fix());
    else
        clear_fix();

    if (in.has_time_sec())
        set_time_sec(in.get_only_time_sec());
    else
        clear_time_sec();

    if (in.has_time_usec())
        set_time_usec(in.get_only_time_sec());
    else
        clear_time_usec();

    return *this;
}

void kis_tracked_location_triplet::register_fields() {
    tracker_component::register_fields();

    register_field("kismet.common.location.geopoint", "[lon, lat] point", &geopoint);
    alt_id =
        register_dynamic_field<tracker_element_float>("kismet.common.location.alt", "altitude (meters)");
    fix_id =
        register_dynamic_field<tracker_element_uint8>("kismet.common.location.fix", "gps fix");
    time_sec_id =
        register_dynamic_field<tracker_element_uint64>("kismet.common.location.time_sec", "timestamp (seconds)");
    time_usec_id =
        register_dynamic_field<tracker_element_uint64>("kismet.common.location.time_usec", "timestamp (usec)");
}

void kis_tracked_location_triplet::reserve_fields(std::shared_ptr<tracker_element_map> e) {
    tracker_component::reserve_fields(e);
    geopoint->set(0, 0);
}



kis_tracked_location_full::kis_tracked_location_full() :
    kis_tracked_location_triplet() {

    register_fields();
    reserve_fields(NULL);
}

kis_tracked_location_full::kis_tracked_location_full(int in_id) :
    kis_tracked_location_triplet(in_id) {

    register_fields();
    reserve_fields(NULL);
}

kis_tracked_location_full::kis_tracked_location_full(int in_id,
        std::shared_ptr<tracker_element_map> e) :
    kis_tracked_location_triplet(in_id, e) {

    register_fields();
    reserve_fields(e);
}

kis_tracked_location_full::kis_tracked_location_full(const kis_tracked_location_full *p) :
    kis_tracked_location_triplet(p) {

        __ImportId(spd_id, p);
        __ImportId(heading_id, p);
        __ImportId(magheading_id, p);

        reserve_fields(nullptr);
}

void kis_tracked_location_full::set(kis_gps_packinfo *in_packinfo) {
    if (in_packinfo == nullptr)
        return;

    if (in_packinfo->lat != 0 && in_packinfo->lon != 0) {
        set_location(in_packinfo->lat, in_packinfo->lon);
    }

    set_alt(in_packinfo->alt);
    set_fix(in_packinfo->fix);

    if (in_packinfo->speed != 0)
        set_speed(in_packinfo->speed);

    if (in_packinfo->heading != 0)
        set_heading(in_packinfo->heading);

    set_time_sec(in_packinfo->tv.tv_sec);
    set_time_usec(in_packinfo->tv.tv_usec);
}

kis_tracked_location_full& kis_tracked_location_full::operator= (const kis_tracked_location_full& in) {
    set_location(in.get_lat(), in.get_lon());

    if (in.has_alt())
        set_alt(in.get_only_alt());
    else
        clear_alt();

    if (in.has_fix())
        set_fix(in.get_only_fix());
    else
        clear_fix();

    if (in.has_time_sec())
        set_time_sec(in.get_only_time_sec());
    else
        clear_time_sec();

    if (in.has_time_usec())
        set_time_usec(in.get_only_time_sec());
    else
        clear_time_usec();

    if (in.has_speed())
        set_speed(in.get_only_speed());
    else
        clear_speed();

    if (in.has_heading())
        set_heading(in.get_only_heading());
    else
        clear_heading();

    if (in.has_magheading())
        set_magheading(in.get_only_magheading());
    else
        clear_magheading();

    return *this;
}

void kis_tracked_location_full::register_fields() {
    kis_tracked_location_triplet::register_fields();

    spd_id =
        register_dynamic_field<tracker_element_float>("kismet.common.location.speed", "speed (kph)");

    heading_id =
        register_dynamic_field<tracker_element_float>("kismet.common.location.heading", "heading (degrees)");

    magheading_id =
        register_dynamic_field<tracker_element_float>("kismet.common.location.magheading", "magnetic heading (degrees)");
}

void kis_tracked_location_full::reserve_fields(std::shared_ptr<tracker_element_map> e) {
    kis_tracked_location_triplet::reserve_fields(e);
}



kis_tracked_location::kis_tracked_location() :
    tracker_component(0) {
    agg_x = agg_y = agg_z = agg_a = 0;
    num_avg = num_alt_avg = 0;
    last_location_time = 0;

    register_fields();
    reserve_fields(NULL);
}

kis_tracked_location::kis_tracked_location(int in_id) :
    tracker_component(in_id) {

    agg_x = agg_y = agg_z = agg_a = 0;
    num_avg = num_alt_avg = 0;
    last_location_time = 0;

    register_fields();
    reserve_fields(NULL);
}

kis_tracked_location::kis_tracked_location(int in_id, std::shared_ptr<tracker_element_map> e) :
    tracker_component(in_id) {

    agg_x = agg_y = agg_z = agg_a = 0;
    num_avg = num_alt_avg = 0;
    last_location_time = 0;

    register_fields();
    reserve_fields(e);
}

kis_tracked_location::kis_tracked_location(const kis_tracked_location *p) :
    tracker_component(p) {

        __ImportId(min_loc_id, p);
        __ImportId(max_loc_id, p);
        __ImportId(avg_loc_id, p);
        __ImportId(last_loc_id, p);
        __ImportField(loc_fix, p);

        reserve_fields(nullptr);
}

void kis_tracked_location::add_loc_with_avg(double in_lat, double in_lon, double in_alt,
        unsigned int fix, double in_speed, double in_heading) {

    if (fix < 2) {
        return;
    }

    add_loc(in_lat, in_lon, in_alt, fix, in_speed, in_heading);

    if (avg_loc == nullptr) {
        // We probably have a last location; set the ID anyhow to make sure; if we don't,
        // this is just a new(nullptr) which is also fine
        avg_loc = Globalreg::globalreg->entrytracker->new_from_pool<kis_tracked_location_triplet>(last_loc.get());
        avg_loc->set_id(avg_loc_id);
        insert(avg_loc);
    }

    // Convert to vector for average
    double mod_lat = in_lat * M_PI / 180;
    double mod_lon = in_lon * M_PI / 180;

    agg_x += cos(mod_lat) * cos(mod_lon);
    agg_y += cos(mod_lat) * sin(mod_lon);
    agg_z += sin(mod_lat);

    num_avg += 1;

    if (fix > 2) {
        agg_a += in_alt;
        num_alt_avg += 1;
    }

    double r_x = agg_x / num_avg;
    double r_y = agg_y / num_avg;
    double r_z = agg_z / num_avg;

    double central_lon = atan2(r_y, r_x);
    double central_sqr = sqrt(r_x * r_x + r_y * r_y);
    double central_lat = atan2(r_z, central_sqr);

    double r_alt = 0;

    if (num_alt_avg > 0)
       r_alt =  agg_a / num_alt_avg;

    // Use the incoming if we're the first packet
    if (num_avg > 1)
        avg_loc->set(central_lat * 180 / M_PI, central_lon * 180 / M_PI,
                     r_alt, num_alt_avg > 0 ? 3 : 2);
    else
        avg_loc->set(in_lat, in_lon, in_alt, fix);
}

void kis_tracked_location::add_loc(double in_lat, double in_lon, double in_alt,
        unsigned int fix, double in_speed, double in_heading) {

    if (fix < 2) {
        return;
    }

    if (fix > get_fix()) {
        set_fix(fix);
    }

    if (min_loc == nullptr) {
        min_loc = Globalreg::globalreg->entrytracker->new_from_pool<kis_tracked_location_triplet>();
        min_loc->set_id(min_loc_id);
        insert(min_loc);
    }

    if (max_loc == nullptr) {
        max_loc = Globalreg::globalreg->entrytracker->new_from_pool<kis_tracked_location_triplet>();
        max_loc->set_id(max_loc_id);
        insert(max_loc);
    }

    if (last_loc == nullptr) {
        last_loc = Globalreg::globalreg->entrytracker->new_from_pool<kis_tracked_location_full>();
        last_loc->set_id(last_loc_id);
        insert(last_loc);
    }

    last_loc->set_location(in_lat, in_lon);
    last_loc->set_alt(in_alt);
    last_loc->set_fix(fix);
    last_loc->set_speed(in_speed);
    last_loc->set_heading(in_heading);

    double min_lat = min_loc->get_lat();
    double max_lat = max_loc->get_lat();
    double min_lon = min_loc->get_lon();
    double max_lon = max_loc->get_lon();

    if (in_lat < min_loc->get_lat() || min_loc->get_lat() == 0) {
        min_lat = in_lat;
    }

    if (in_lat > max_loc->get_lat() || max_loc->get_lat() == 0) {
        max_lat = in_lat;
    }

    if (in_lon < min_loc->get_lon() || min_loc->get_lon() == 0) {
        min_lon = in_lon;
    }

    if (in_lon > max_loc->get_lon() || max_loc->get_lon() == 0) {
        max_lon = in_lon;
    }

    min_loc->set_location(min_lat, min_lon);
    max_loc->set_location(max_lat, max_lon);

    if (fix > 2) {
        if (in_alt < min_loc->get_alt() || min_loc->get_alt() == 0) {
            min_loc->set_alt(in_alt);
        }

        if (in_alt > max_loc->get_alt() || max_loc->get_alt() == 0) {
            max_loc->set_alt(in_alt);
        }
    }
}

void kis_tracked_location::register_fields() {
    tracker_component::register_fields();

    register_field("kismet.common.location.loc_fix", "location fix precision (2d/3d)", &loc_fix);

    min_loc_id =
        register_dynamic_field("kismet.common.location.min_loc",
                "Minimum corner of bounding rectangle", &min_loc);
    max_loc_id =
        register_dynamic_field("kismet.common.location.max_loc",
                "Maximume corner of bounding rectangle", &max_loc);
    avg_loc_id =
        register_dynamic_field("kismet.common.location.avg_loc",
                "Average GPS center of all samples", &avg_loc);
    last_loc_id =
        register_dynamic_field("kismet.common.location.last",
                "Last location", &last_loc);
}

