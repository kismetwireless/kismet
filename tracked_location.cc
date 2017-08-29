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

#include "tracked_location.h"

kis_tracked_location_triplet::kis_tracked_location_triplet(GlobalRegistry *in_globalreg, 
        int in_id) : tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(NULL);
} 

kis_tracked_location_triplet::kis_tracked_location_triplet(GlobalRegistry *in_globalreg, 
        int in_id, SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(e);
}

SharedTrackerElement kis_tracked_location_triplet::clone_type() {
    return SharedTrackerElement(new kis_tracked_location_triplet(globalreg, 
                get_id()));
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

    RegisterField("kismet.common.location.lat", TrackerDouble,
            "latitude", &lat);
    RegisterField("kismet.common.location.lon", TrackerDouble,
            "longitude", &lon);
    RegisterField("kismet.common.location.alt", TrackerDouble,
            "altitude", &alt);
    RegisterField("kismet.common.location.speed", TrackerDouble,
            "speed", &spd);
    RegisterField("kismet.common.location.heading", TrackerDouble,
            "heading", &heading);
    RegisterField("kismet.common.location.fix", TrackerUInt8,
            "gps fix", &fix);
    RegisterField("kismet.common.location.valid", TrackerUInt8,
            "valid location", &valid);
    RegisterField("kismet.common.location.time_sec", TrackerUInt64,
            "timestamp (seconds)", &time_sec);
    RegisterField("kismet.common.location.time_usec", TrackerUInt64,
            "timestamp (usec)", &time_usec);
}

kis_tracked_location::kis_tracked_location(GlobalRegistry *in_globalreg, int in_id) :
    tracker_component(in_globalreg, in_id) { 
    register_fields();
    reserve_fields(NULL);
}

kis_tracked_location::kis_tracked_location(GlobalRegistry *in_globalreg, int in_id, 
        SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {

    register_fields();
    reserve_fields(e);
}

SharedTrackerElement kis_tracked_location::clone_type() {
    return SharedTrackerElement(new kis_tracked_location(globalreg, get_id()));
}


void kis_tracked_location::add_loc(double in_lat, double in_lon, double in_alt, 
        unsigned int fix) {
    set_valid(1);

    if (fix > get_fix()) {
        set_fix(fix);
    }

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
    (*num_avg)++;

    if (fix > 2) {
        (*avg_alt) += (int64_t) (in_alt * precision_multiplier);
        (*num_alt_avg)++;
    }

    double calc_lat, calc_lon, calc_alt;

    calc_lat = (double) (GetTrackerValue<int64_t>(avg_lat) / 
            GetTrackerValue<int64_t>(num_avg)) / precision_multiplier;
    calc_lon = (double) (GetTrackerValue<int64_t>(avg_lon) / 
            GetTrackerValue<int64_t>(num_avg)) / precision_multiplier;
    if (GetTrackerValue<int64_t>(num_alt_avg) != 0) {
        calc_alt = (double) (GetTrackerValue<int64_t>(avg_alt) / 
                GetTrackerValue<int64_t>(num_alt_avg)) / precision_multiplier;
    } else {
        calc_alt = 0;
    }
    avg_loc->set(calc_lat, calc_lon, calc_alt, 3);

    // Are we getting too close to the maximum size of any of our counters?
    // This would take a really long time but we might as well be safe.  We're
    // throwing away some of the highest ranges but it's a cheap compare.
    uint64_t max_size_mask = 0xF000000000000000LL;
    if ((GetTrackerValue<int64_t>(avg_lat) & max_size_mask) ||
            (GetTrackerValue<int64_t>(avg_lon) & max_size_mask) ||
            (GetTrackerValue<int64_t>(avg_alt) & max_size_mask) ||
            (GetTrackerValue<int64_t>(num_avg) & max_size_mask) ||
            (GetTrackerValue<int64_t>(num_alt_avg) & max_size_mask)) {
        avg_lat->set((int64_t) (calc_lat * precision_multiplier));
        avg_lon->set((int64_t) (calc_lon * precision_multiplier));
        avg_alt->set((int64_t) (calc_alt * precision_multiplier));
        num_avg->set((int64_t) 1);
        num_alt_avg->set((int64_t) 1);
    }
}

void kis_tracked_location::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.common.location.loc_valid", TrackerUInt8,
            "location data valid", &loc_valid);

    RegisterField("kismet.common.location.loc_fix", TrackerUInt8,
            "location fix precision (2d/3d)", &loc_fix);

    shared_ptr<kis_tracked_location_triplet> 
        loc_builder(new kis_tracked_location_triplet(globalreg, 0));

    min_loc_id = 
        RegisterComplexField("kismet.common.location.min_loc", loc_builder, 
                "minimum corner of bounding rectangle");
    max_loc_id = 
        RegisterComplexField("kismet.common.location.max_loc", loc_builder,
                "maximum corner of bounding rectangle");
    avg_loc_id = 
        RegisterComplexField("kismet.common.location.avg_loc", loc_builder,
                "average corner of bounding rectangle");

    RegisterField("kismet.common.location.avg_lat", TrackerInt64,
            "run-time average latitude", &avg_lat);
    RegisterField("kismet.common.location.avg_lon", TrackerInt64,
            "run-time average longitude", &avg_lon);
    RegisterField("kismet.common.location.avg_alt", TrackerInt64,
            "run-time average altitude", &avg_alt);
    RegisterField("kismet.common.location.avg_num", TrackerInt64,
            "number of run-time average samples", &num_avg);
    RegisterField("kismet.common.location.avg_alt_num", 
            TrackerInt64,
            "number of run-time average samples (altitude)", &num_alt_avg);

}

void kis_tracked_location::reserve_fields(SharedTrackerElement e) {
    tracker_component::reserve_fields(e);

    if (e != NULL) {
        min_loc.reset(new kis_tracked_location_triplet(globalreg, min_loc_id, 
                    e->get_map_value(min_loc_id)));
        max_loc.reset(new kis_tracked_location_triplet(globalreg, max_loc_id, 
                    e->get_map_value(max_loc_id)));
        avg_loc.reset(new kis_tracked_location_triplet(globalreg, avg_loc_id, 
                    e->get_map_value(avg_loc_id)));
    } else {
        min_loc.reset(new kis_tracked_location_triplet(globalreg, min_loc_id));
        max_loc.reset(new kis_tracked_location_triplet(globalreg, max_loc_id));
        avg_loc.reset(new kis_tracked_location_triplet(globalreg, avg_loc_id));
    }

    add_map(avg_loc);
    add_map(min_loc);
    add_map(max_loc);

}

kis_historic_location::kis_historic_location(GlobalRegistry *in_globalreg, 
        int in_id) : tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(NULL);
} 

kis_historic_location::kis_historic_location(GlobalRegistry *in_globalreg, 
        int in_id, SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(e);
}

SharedTrackerElement kis_historic_location::clone_type() {
    return SharedTrackerElement(new kis_historic_location(globalreg, get_id()));
}


void kis_historic_location::register_fields() {
    tracker_component::register_fields();

    RegisterField("kis.historic.location.lat", TrackerDouble, "latitude", &lat);
    RegisterField("kis.historic.location.lon", TrackerDouble, "longitude", &lon);
    RegisterField("kis.historic.location.alt", TrackerDouble, "altitude (m)", &alt);
    RegisterField("kis.historic.location.speed", TrackerDouble, "speed (kph)", &speed);
    RegisterField("kis.historic.location.heading", TrackerDouble, 
            "heading (degrees)", &heading);
    RegisterField("kis.historic.location.signal", TrackerInt32, "signal", &signal);
    RegisterField("kis.historic.location.time_sec", TrackerUInt64, 
            "time (unix ts)", &time_sec);
    RegisterField("kis.historic.location.frequency", TrackerUInt64, 
            "frequency (khz)", &frequency);
}

kis_location_history::kis_location_history(GlobalRegistry *in_globalreg, 
        int in_id) : tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(NULL);
} 

kis_location_history::kis_location_history(GlobalRegistry *in_globalreg, 
        int in_id, SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(e);
}

SharedTrackerElement kis_location_history::clone_type() {
    return SharedTrackerElement(new kis_location_history(globalreg, get_id()));
}

void kis_location_history::register_fields() {
    tracker_component::register_fields();

    RegisterField("kis.gps.rrd.samples_100", TrackerVector,
            "last 100 historic GPS records", &samples_100);
    RegisterField("kis.gps.rrd.samples_10k", TrackerVector,
            "last 10,000 historic GPS records, as averages of 100", &samples_10k);
    RegisterField("kis.gps.rrd.samples_1m", TrackerVector,
            "last 1,000,000 historic GPS records, as averages of 10,000", &samples_1m);
    RegisterField("kis.gps.rrd.last_sample_ts", TrackerUInt64,
            "time (unix ts) of last sample", &last_sample_ts);
}

void kis_location_history::reserve_fields(SharedTrackerElement e) {
    tracker_component::reserve_fields(e);

    samples_100_vec = TrackerElementVector(samples_100);
    samples_10k_vec = TrackerElementVector(samples_10k);
    samples_1m_vec = TrackerElementVector(samples_1m);

    samples_100_cascade = 0;
    samples_10k_cascade = 0;
}

void kis_location_history::add_sample(shared_ptr<kis_historic_location> in_sample) {
    set_int_last_sample_ts(in_sample->get_time_sec());

    samples_100_vec.push_back(in_sample);

    if (samples_100_vec.size() > 100) 
        samples_100_vec.erase(samples_100_vec.begin());

    samples_100_cascade++;

    // We've gotten 100 samples, cascade up to our next bucket
    if (samples_100_cascade >= 100) {
        double lat, lon, alt, heading, speed, signal, timesec, frequency;
        double num_signal, num_alt;

        lat = lon = alt = heading = speed = signal = timesec = frequency = 0;
        num_signal = num_alt = 0;

        for (auto g : samples_100_vec) {
            shared_ptr<kis_historic_location> gl =
                static_pointer_cast<kis_historic_location>(g);

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

        shared_ptr<kis_historic_location> aggloc(new kis_historic_location(globalreg, 0));

        aggloc->set_lat(lat / samples_100_vec.size());
        aggloc->set_lon(lon / samples_100_vec.size());
        aggloc->set_alt(alt / num_alt);
        aggloc->set_heading(heading / samples_100_vec.size());
        aggloc->set_speed(speed / samples_100_vec.size());
        aggloc->set_signal(signal / num_signal);
        aggloc->set_time_sec(timesec / samples_100_vec.size());
        aggloc->set_frequency(frequency / samples_100_vec.size());

        samples_100_cascade = 0;

        samples_10k_vec.push_back(aggloc);
        if (samples_10k_vec.size() > 100)
            samples_10k_vec.erase(samples_10k_vec.begin());

        samples_10k_cascade++;

        if (samples_10k_cascade >= 100) {
            // If we've gotten 100 samples in the 10k bucket, cascade up again
            lat = lon = alt = heading = speed = signal = timesec = frequency = 0;
            num_alt = num_signal = 0;

            for (auto g : samples_10k_vec) {
                shared_ptr<kis_historic_location> gl =
                    static_pointer_cast<kis_historic_location>(g);

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

            shared_ptr<kis_historic_location> 
                aggloc10(new kis_historic_location(globalreg, 0));

            aggloc10->set_lat(lat / samples_10k_vec.size());
            aggloc10->set_lon(lon / samples_10k_vec.size());
            aggloc10->set_alt(alt / num_alt);
            aggloc10->set_heading(heading / samples_10k_vec.size());
            aggloc10->set_speed(speed / samples_10k_vec.size());
            aggloc10->set_signal(signal / num_signal);
            aggloc10->set_time_sec(timesec / samples_10k_vec.size());
            aggloc10->set_frequency(timesec / samples_10k_vec.size());

            samples_10k_cascade = 0;

            samples_1m_vec.push_back(aggloc10);
            if (samples_1m_vec.size() > 100)
                samples_1m_vec.erase(samples_1m_vec.begin());
        }
    }
}

