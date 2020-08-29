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

    geopoint = tracker_element_clone_adaptor(p->geopoint);
    alt = tracker_element_clone_adaptor(p->alt);
    spd = tracker_element_clone_adaptor(p->spd);
    heading = tracker_element_clone_adaptor(p->heading);
    error_x = tracker_element_clone_adaptor(p->error_x);
    error_y = tracker_element_clone_adaptor(p->error_y);
    error_v = tracker_element_clone_adaptor(p->error_v);
    fix = tracker_element_clone_adaptor(p->fix);
    valid = tracker_element_clone_adaptor(p->valid);
    time_sec = tracker_element_clone_adaptor(p->time_sec);
    time_usec = tracker_element_clone_adaptor(p->time_usec);

    reserve_fields(nullptr);
}

void kis_tracked_location_triplet::set(double in_lat, double in_lon, 
        double in_alt, unsigned int in_fix) {
    set_lat(in_lat);
    set_lon(in_lon);
    set_alt(in_alt);
    set_fix(in_fix);
    set_valid(1);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    set_time_sec(tv.tv_sec);
    set_time_usec(tv.tv_usec);
}

void kis_tracked_location_triplet::set(double in_lat, double in_lon) {
    set_lat(in_lat);
    set_lon(in_lon);
    set_fix(2);
    set_valid(1);

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
    set_valid(in_packinfo->fix >= 2);
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
    set_valid(in.get_valid());
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
    register_field("kismet.common.location.valid", "valid location", &valid);
    register_field("kismet.common.location.time_sec", "timestamp (seconds)", &time_sec);
    register_field("kismet.common.location.time_usec", "timestamp (usec)", &time_usec);
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

    min_loc_id = p->min_loc_id;
    max_loc_id = p->max_loc_id;
    avg_loc_id = p->avg_loc_id;
    last_loc_id = p->last_loc_id;

    loc_valid = tracker_element_clone_adaptor(p->loc_valid);
    loc_fix = tracker_element_clone_adaptor(p->loc_fix);

    avg_lat = tracker_element_clone_adaptor(p->avg_lat);
    avg_lon = tracker_element_clone_adaptor(p->avg_lon);
    avg_alt = tracker_element_clone_adaptor(p->avg_alt);
    num_avg = tracker_element_clone_adaptor(p->num_avg);
    num_alt_avg = tracker_element_clone_adaptor(p->num_alt_avg);

    reserve_fields(nullptr);
}

void kis_tracked_location::add_loc(double in_lat, double in_lon, double in_alt, 
        unsigned int fix, double in_speed, double in_heading) {
    set_valid(1);

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

    if (avg_loc == nullptr) {
        avg_loc = std::make_shared<kis_tracked_location_triplet>(avg_loc_id);
        insert(avg_loc);
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
    last_loc->set_valid(1);

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

    // Append to averaged location
    (*avg_lat) += (int64_t) (in_lat * precision_multiplier);
    (*avg_lon) += (int64_t) (in_lon * precision_multiplier);
    (*num_avg) += 1;

    if (fix > 2) {
        (*avg_alt) += (int64_t) (in_alt * precision_multiplier);
        (*num_alt_avg) += 1;
    }

    double calc_lat, calc_lon, calc_alt;

    calc_lat = (double) (get_tracker_value<int64_t>(avg_lat) / 
            get_tracker_value<int64_t>(num_avg)) / precision_multiplier;
    calc_lon = (double) (get_tracker_value<int64_t>(avg_lon) / 
            get_tracker_value<int64_t>(num_avg)) / precision_multiplier;
    if (get_tracker_value<int64_t>(num_alt_avg) != 0) {
        calc_alt = (double) (get_tracker_value<int64_t>(avg_alt) / 
                get_tracker_value<int64_t>(num_alt_avg)) / precision_multiplier;
    } else {
        calc_alt = 0;
    }
    avg_loc->set(calc_lat, calc_lon, calc_alt, 3);

    // Are we getting too close to the maximum size of any of our counters?
    // This would take a really long time but we might as well be safe.  We're
    // throwing away some of the highest ranges but it's a cheap compare.
    uint64_t max_size_mask = 0xF000000000000000LL;
    if ((get_tracker_value<int64_t>(avg_lat) & max_size_mask) ||
            (get_tracker_value<int64_t>(avg_lon) & max_size_mask) ||
            (get_tracker_value<int64_t>(avg_alt) & max_size_mask) ||
            (get_tracker_value<int64_t>(num_avg) & max_size_mask) ||
            (get_tracker_value<int64_t>(num_alt_avg) & max_size_mask)) {
        avg_lat->set((int64_t) (calc_lat * precision_multiplier));
        avg_lon->set((int64_t) (calc_lon * precision_multiplier));
        avg_alt->set((int64_t) (calc_alt * precision_multiplier));
        num_avg->set((int64_t) 1);
        num_alt_avg->set((int64_t) 1);
    }
}

void kis_tracked_location::register_fields() {
    tracker_component::register_fields();

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

    register_field("kismet.common.location.avg_lat", "run-time average latitude", &avg_lat);
    register_field("kismet.common.location.avg_lon", "run-time average longitude", &avg_lon);
    register_field("kismet.common.location.avg_alt", "run-time average altitude", &avg_alt);
    register_field("kismet.common.location.avg_num", "number of run-time average samples", &num_avg);
    register_field("kismet.common.location.avg_alt_num", 
            "number of run-time average samples (altitude)", &num_alt_avg);

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

    geopoint = tracker_element_clone_adaptor(p->geopoint);
    alt = tracker_element_clone_adaptor(p->alt);
    heading = tracker_element_clone_adaptor(p->heading);
    speed = tracker_element_clone_adaptor(p->speed);
    signal = tracker_element_clone_adaptor(p->signal);
    frequency = tracker_element_clone_adaptor(p->frequency);
    time_sec = tracker_element_clone_adaptor(p->time_sec);

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

    samples_100 = tracker_element_clone_adaptor(p->samples_100);
    samples_10k = tracker_element_clone_adaptor(p->samples_10k);
    samples_1m = tracker_element_clone_adaptor(p->samples_1m);
    last_sample_ts = tracker_element_clone_adaptor(p->last_sample_ts);


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
        double lat, lon, alt, heading, speed, signal, timesec, frequency;
        double num_signal, num_alt;

        lat = lon = alt = heading = speed = signal = timesec = frequency = 0;
        num_signal = num_alt = 0;

        for (auto g : *samples_100) {
            std::shared_ptr<kis_historic_location> gl =
                std::static_pointer_cast<kis_historic_location>(g);

            lat += gl->get_lat();
            lon += gl->get_lon();
            if (gl->get_alt()) {
                alt += gl->get_alt();
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

        aggloc->set_lat(lat / samples_100->size());
        aggloc->set_lon(lon / samples_100->size());
        if (!std::isnan(alt / num_alt))
            aggloc->set_alt(alt / num_alt);
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
            lat = lon = alt = heading = speed = signal = timesec = frequency = 0;
            num_alt = num_signal = 0;

            for (auto g : *samples_10k) {
                std::shared_ptr<kis_historic_location> gl =
                    std::static_pointer_cast<kis_historic_location>(g);

                lat += gl->get_lat();
                lon += gl->get_lon();
                
                if (gl->get_alt()) {
                    alt += gl->get_alt();
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

            aggloc10->set_lat(lat / samples_10k->size());
            aggloc10->set_lon(lon / samples_10k->size());
            if (!std::isnan(alt / num_alt))
                    aggloc10->set_alt(alt / num_alt);
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

