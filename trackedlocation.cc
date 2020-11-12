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
    tracker_component(0) { 

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
    tracker_component{p} {

    __ImportField(geopoint, p);
    __ImportField(alt, p);
    __ImportField(spd, p);
    __ImportField(heading, p);
    /*
    __ImportField(error_x, p);
    __ImportField(error_y, p);
    __ImportField(error_v, p);
    */
    __ImportField(fix, p);
    __ImportField(time_sec, p);
    __ImportField(time_usec, p);

    reserve_fields(nullptr);
}

void kis_tracked_location_triplet::set(double in_lat, double in_lon, 
        double in_alt, unsigned int in_fix) {
    set_lat(in_lat);
    set_lon(in_lon);
    set_alt(in_alt);
    set_fix(in_fix);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    set_time_sec(tv.tv_sec);
    set_time_usec(tv.tv_usec);
}

void kis_tracked_location_triplet::set(double in_lat, double in_lon) {
    set_lat(in_lat);
    set_lon(in_lon);
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
        set_lat(in_packinfo->lat);
        set_lon(in_packinfo->lon);
    }

    set_alt(in_packinfo->alt);
    set_fix(in_packinfo->fix);
    set_speed(in_packinfo->speed);
    set_heading(in_packinfo->heading);
    set_time_sec(in_packinfo->tv.tv_sec);
    set_time_usec(in_packinfo->tv.tv_usec);
}

kis_tracked_location_triplet& 
    kis_tracked_location_triplet::operator= (const kis_tracked_location_triplet& in) {
    set_lat(in.get_lat());
    set_lon(in.get_lon());
    set_alt(in.get_alt());
    set_speed(in.get_speed());
    set_heading(in.get_heading());
    set_fix(in.get_fix());
    set_time_sec(in.get_time_sec());
    set_time_usec(in.get_time_usec());

    return *this;
}

void kis_tracked_location_triplet::register_fields() {
    tracker_component::register_fields();

    register_field("kismet.common.location.geopoint", "[lon, lat] point", &geopoint);
    register_field("kismet.common.location.alt", "altitude (meters)", &alt);
    register_field("kismet.common.location.speed", "speed (kph)", &spd);
    register_field("kismet.common.location.heading", "heading (degrees)", &heading);
    register_field("kismet.common.location.fix", "gps fix", &fix);
    register_field("kismet.common.location.time_sec", "timestamp (seconds)", &time_sec);
    register_field("kismet.common.location.time_usec", "timestamp (usec)", &time_usec);
    /*
    register_field("kismet.common.location.valid", "valid location", &valid);
    register_field("kismet.common.location.error_x", "location error (x)", &error_x);
    register_field("kismet.common.location.error_y", "location error (y)", &error_y);
    register_field("kismet.common.location.error_v", "location error (v)", &error_v);
    */
}

void kis_tracked_location_triplet::reserve_fields(std::shared_ptr<tracker_element_map> e) {
    tracker_component::reserve_fields(e);
    geopoint->set({0, 0});
}

kis_tracked_location::kis_tracked_location() :
    tracker_component(0) {
    register_fields();
    reserve_fields(NULL);
}

kis_tracked_location::kis_tracked_location(int in_id) :
    tracker_component(in_id) { 
    register_fields();
    reserve_fields(NULL);
}

kis_tracked_location::kis_tracked_location(int in_id, std::shared_ptr<tracker_element_map> e) : 
    tracker_component(in_id) {

    register_fields();
    reserve_fields(e);
}

kis_tracked_location::kis_tracked_location(const kis_tracked_location *p) :
    tracker_component{p} {

    __ImportId(min_loc_id, p);
    __ImportId(max_loc_id, p);
    __ImportId(avg_loc_id, p);
    __ImportId(last_loc_id, p);

    __ImportField(loc_valid, p);
    __ImportField(loc_fix, p);

    reserve_fields(nullptr);

    agg_x = p->agg_x;
    agg_y = p->agg_y;
    agg_z = p->agg_z;
    num_avg = p->num_avg;

    agg_a = p->agg_a;
    num_alt_avg = p->num_alt_avg;
}

void kis_tracked_location::add_loc_with_avg(double in_lat, double in_lon, double in_alt, 
        unsigned int fix, double in_speed, double in_heading) {
    add_loc(in_lat, in_lon, in_alt, fix, in_speed, in_heading);

    if (avg_loc == nullptr) {
        avg_loc = std::make_shared<kis_tracked_location_triplet>(avg_loc_id);
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

    avg_loc->set(central_lat * 180 / M_PI, central_lon * 180 / M_PI, r_alt, 3);
}

void kis_tracked_location::add_loc(double in_lat, double in_lon, double in_alt, 
        unsigned int fix, double in_speed, double in_heading) {

    if (fix > get_fix()) {
        set_fix(fix);
    }

    if (min_loc == nullptr) {
        min_loc = std::make_shared<kis_tracked_location_triplet>(min_loc_id);
        insert(min_loc);
    }

    if (max_loc == nullptr) {
        max_loc = std::make_shared<kis_tracked_location_triplet>(max_loc_id);
        insert(max_loc);
    }

    if (last_loc == nullptr) {
        last_loc = std::make_shared<kis_tracked_location_triplet>(last_loc_id);
        insert(last_loc);
    }

    last_loc->set_lat(in_lat);
    last_loc->set_lon(in_lon);
    last_loc->set_alt(in_alt);
    last_loc->set_fix(fix);
    last_loc->set_speed(in_speed);
    last_loc->set_heading(in_heading);

    if (in_lat < min_loc->get_lat() || min_loc->get_lat() == 0) {
        min_loc->set_lat(in_lat);
    }

    if (in_lat > max_loc->get_lat() || max_loc->get_lat() == 0) {
        max_loc->set_lat(in_lat);
    }

    if (in_lon < min_loc->get_lon() || min_loc->get_lon() == 0) {
        min_loc->set_lon(in_lon);
    }

    if (in_lon > max_loc->get_lon() || max_loc->get_lon() == 0) {
        max_loc->set_lon(in_lon);
    }

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

    agg_x = agg_y = agg_z = agg_a = 0;
    num_avg = num_alt_avg = 0;
    last_location_time = 0;

    register_field("kismet.common.location.loc_valid", "location data valid", &loc_valid);
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

kis_historic_location::kis_historic_location() :
    tracker_component(0) {
    register_fields();
    reserve_fields(NULL);
}

kis_historic_location::kis_historic_location(int in_id) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(NULL);
} 

kis_historic_location::kis_historic_location(int in_id, std::shared_ptr<tracker_element_map> e) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(e);
}

kis_historic_location::kis_historic_location(const kis_historic_location *p) :
    tracker_component{p} {

    __ImportField(geopoint, p);
    __ImportField(alt, p);
    __ImportField(heading, p);
    __ImportField(speed, p);
    __ImportField(signal, p);
    __ImportField(frequency, p);
    __ImportField(time_sec, p);

    reserve_fields(nullptr);
}

void kis_historic_location::register_fields() {
    tracker_component::register_fields();


    register_field("kismet.historic.location.geopoint", "[lon, lat] point", &geopoint);
    register_field("kismet.historic.location.alt", "altitude (m)", &alt);
    register_field("kismet.historic.location.speed", "speed (kph)", &speed);
    register_field("kismet.historic.location.heading", "heading (degrees)", &heading);
    register_field("kismet.historic.location.signal", "signal", &signal);
    register_field("kismet.historic.location.time_sec", "time (unix ts)", &time_sec);
    register_field("kismet.historic.location.frequency", "frequency (khz)", &frequency);
}

void kis_historic_location::reserve_fields(std::shared_ptr<tracker_element_map> e) {
    tracker_component::reserve_fields(e);
    geopoint->set({0, 0});
}

kis_location_history::kis_location_history() :
    tracker_component(0) {
    register_fields();
    reserve_fields(NULL);
    }

kis_location_history::kis_location_history(int in_id) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(NULL);
} 

kis_location_history::kis_location_history(int in_id, std::shared_ptr<tracker_element_map> e) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(e);
}

kis_location_history::kis_location_history(const kis_location_history *p) :
    tracker_component{p} {

    __ImportField(samples_100, p);
    __ImportField(samples_10k, p);
    __ImportField(samples_1m, p);
    __ImportField(last_sample_ts, p);


    reserve_fields(nullptr);
}

void kis_location_history::register_fields() {
    tracker_component::register_fields();

    register_field("kis.gps.rrd.samples_100", "last 100 historic GPS records", &samples_100);
    register_field("kis.gps.rrd.samples_10k", 
            "last 10,000 historic GPS records, as averages of 100", &samples_10k);
    register_field("kis.gps.rrd.samples_1m",
            "last 1,000,000 historic GPS records, as averages of 10,000", &samples_1m);
    register_field("kis.gps.rrd.last_sample_ts", "time (unix ts) of last sample", &last_sample_ts);
}

void kis_location_history::reserve_fields(std::shared_ptr<tracker_element_map> e) {
    tracker_component::reserve_fields(e);

    samples_100_cascade = 0;
    samples_10k_cascade = 0;
}

void kis_location_history::add_sample(std::shared_ptr<kis_historic_location> in_sample) {
    set_int_last_sample_ts(in_sample->get_time_sec());

    samples_100->push_back(in_sample);

    if (samples_100->size() > 100) 
        samples_100->erase(samples_100->begin());

    samples_100_cascade++;

    // We've gotten 100 samples, cascade up to our next bucket
    if (samples_100_cascade >= 100) {
        double avg_x = 0, avg_y = 0, avg_z = 0, avg_alt = 0;

        double heading, speed, signal, timesec, frequency;
        double num_signal, num_alt;

        heading = speed = signal = timesec = frequency = 0;
        num_signal = num_alt = 0;

        for (auto g : *samples_100) {
            std::shared_ptr<kis_historic_location> gl =
                std::static_pointer_cast<kis_historic_location>(g);

            // Convert to vector for average
            double mod_lat = gl->get_lat() * M_PI / 180;
            double mod_lon = gl->get_lon() * M_PI / 180;

            avg_x += cos(mod_lat) * cos(mod_lon);
            avg_y += cos(mod_lat) * sin(mod_lon);
            avg_z += sin(mod_lat);

            if (gl->get_alt()) {
                avg_alt += gl->get_alt();
                num_alt++;
            }

            heading += gl->get_heading();
            speed += gl->get_speed();

            if (gl->get_signal() != 0) {
                signal += gl->get_signal();
                num_signal++;
            }

            timesec += gl->get_time_sec();
            frequency += gl->get_frequency();
        }

        auto aggloc =
            std::make_shared<kis_historic_location>();

        double r_x = avg_x / samples_100->size();
        double r_y = avg_y / samples_100->size();
        double r_z = avg_z / samples_100->size();

        double central_lon = atan2(r_y, r_x);
        double central_sqr = sqrt(r_x * r_x + r_y * r_y);
        double central_lat = atan2(r_z, central_sqr);

        double r_alt = 0;

        if (num_alt > 0) 
            r_alt =  avg_alt / num_alt;

        aggloc->set_lat(central_lat * 180 / M_PI);
        aggloc->set_lon(central_lon * 180 / M_PI);
        aggloc->set_alt(r_alt);

        aggloc->set_heading(heading / samples_100->size());
        aggloc->set_speed(speed / samples_100->size());
        aggloc->set_signal(signal / num_signal);
        aggloc->set_time_sec(timesec / samples_100->size());
        aggloc->set_frequency(frequency / samples_100->size());

        samples_100_cascade = 0;

        samples_10k->push_back(aggloc);
        if (samples_10k->size() > 100)
            samples_10k->erase(samples_10k->begin());

        samples_10k_cascade++;

        if (samples_10k_cascade >= 100) {
            // If we've gotten 100 samples in the 10k bucket, cascade up again
            avg_x = avg_y = avg_z = avg_alt = heading = speed = signal = timesec = frequency = 0;
            num_alt = num_signal = 0;

            for (auto g : *samples_10k) {
                std::shared_ptr<kis_historic_location> gl =
                    std::static_pointer_cast<kis_historic_location>(g);

                // Convert to vector for average
                double mod_lat = gl->get_lat() * M_PI / 180;
                double mod_lon = gl->get_lon() * M_PI / 180;

                avg_x += cos(mod_lat) * cos(mod_lon);
                avg_y += cos(mod_lat) * sin(mod_lon);
                avg_z += sin(mod_lat);
                
                if (gl->get_alt()) {
                    avg_alt += gl->get_alt();
                    num_alt++;
                }

                heading += gl->get_heading();
                speed += gl->get_speed();

                if (gl->get_signal()) {
                    signal += gl->get_signal();
                    num_signal++;
                }

                timesec += gl->get_time_sec();
                frequency += gl->get_frequency();
            }

            auto aggloc10 =
                std::make_shared<kis_historic_location>();

            r_x = avg_x / samples_100->size();
            r_y = avg_y / samples_100->size();
            r_z = avg_z / samples_100->size();

            central_lon = atan2(r_y, r_x);
            central_sqr = sqrt(r_x * r_x + r_y * r_y);
            central_lat = atan2(r_z, central_sqr);

            r_alt = 0;

            if (num_alt > 0) 
                r_alt =  avg_alt / num_alt;

            aggloc10->set_lat(central_lat * 180 / M_PI);
            aggloc10->set_lon(central_lat * 180 / M_PI);
            aggloc10->set_alt(r_alt);

            aggloc10->set_heading(heading / samples_10k->size());
            aggloc10->set_speed(speed / samples_10k->size());
            aggloc10->set_signal(signal / num_signal);
            aggloc10->set_time_sec(timesec / samples_10k->size());
            aggloc10->set_frequency(timesec / samples_10k->size());

            samples_10k_cascade = 0;

            samples_1m->push_back(aggloc10);
            if (samples_1m->size() > 100)
                samples_1m->erase(samples_1m->begin());
        }
    }
}

