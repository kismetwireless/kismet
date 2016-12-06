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

#ifndef __TRACKERCOMPONENT_H__
#define __TRACKERCOMPONENT_H__

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
#include <pthread.h>

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "gps_manager.h"
#include "packet.h"
#include "uuid.h"
#include "packinfo_signal.h"

// Aggregator class used for RRD.  Performs functions like combining elements
// (for instance, adding to the existing element, or choosing to replace the
// element), and for averaging to higher buckets (for instance, performing a 
// raw average or taking absolutes)
class kis_tracked_rrd_default_aggregator {
public:
    // Performed when adding an element to the RRD.  By default, adds the new
    // value to the current value for aggregating multiple samples over time.
    static int64_t combine_element(const int64_t a, const int64_t b) {
        return a + b;
    }

    // Combine a vector for a higher-level record (seconds to minutes, minutes to 
    // hours, and so on).
    static int64_t combine_vector(TrackerElement *e) {
        TrackerElementVector v(e);

        int64_t avg = 0;
        for (TrackerElementVector::iterator i = v.begin(); i != v.end(); ++i) 
            avg += GetTrackerValue<int64_t>(*i);

        return avg / v.size();
    }

    // Default 'empty' value
    static int64_t default_val() {
        return (int64_t) 0;
    }
};

template <class Aggregator = kis_tracked_rrd_default_aggregator>
class kis_tracked_rrd : public tracker_component {
public:
    kis_tracked_rrd(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
        update_first = true;
    }

    kis_tracked_rrd(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
        update_first = true;
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_rrd<Aggregator>(globalreg, get_id());
    }

    // By default a RRD will fast forward to the current time before
    // transmission (this is desirable for RRD records that may not be
    // routinely updated, like records tracking activity on a specific 
    // device).  For records which are updated on a timer and the most
    // recently used value accessed (like devices per frequency) turning
    // this off may produce better results.
    void update_before_serialzie(bool in_upd) {
        update_first = in_upd;
    }

    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    // Add a sample.  Use combinator function 'c' to derive the new sample value
    void add_sample(int64_t in_s, time_t in_time) {
        Aggregator agg;

        int sec_bucket = in_time % 60;
        int min_bucket = (in_time / 60) % 60;
        int hour_bucket = (in_time / 3600) % 24;

        time_t ltime = get_last_time();

        // The second slot for the last time
        int last_sec_bucket = ltime % 60;
        // The minute of the hour the last known data would go in
        int last_min_bucket = (ltime / 60) % 60;
        // The hour of the day the last known data would go in
        int last_hour_bucket = (ltime / 3600) % 24;

        if (in_time < ltime) {
            // printf("debug - rrd - timewarp to the past?  discard\n");
            return;
        }
        
        TrackerElement *e;

        // If we haven't seen data in a day, we reset everything because
        // none of it is valid.  This is the simplest case.
        if (in_time - ltime > (60 * 60 * 24)) {
            // Directly fill in this second, clear rest of the minute
            TrackerElementVector mv(minute_vec);
            for (TrackerElementVector::iterator i = mv.begin(); i != mv.end(); ++i) {
                if (i - mv.begin() == sec_bucket)
                    (*i)->set(in_s);
                else
                    (*i)->set((int64_t) agg.default_val());
            }

            // Reset the last hour, setting it to a single sample
            // Get the combined value for the minute
            int64_t min_val = agg.combine_vector(minute_vec);
            TrackerElementVector hv = TrackerElementVector(hour_vec);
            for (TrackerElementVector::iterator i = hv.begin(); i != hv.end(); ++i) {
                if (i - hv.begin() == min_bucket)
                    (*i)->set(min_val);
                else
                    (*i)->set((int64_t) agg.default_val());
            }

            // Reset the last day, setting it to a single sample
            int64_t hr_val = agg.combine_vector(hour_vec);
            TrackerElementVector dv = TrackerElementVector(day_vec);
            for (TrackerElementVector::iterator i = dv.begin(); i != dv.end(); ++i) {
                if (i - dv.begin() == hour_bucket)
                    (*i)->set(hr_val);
                else
                    (*i)->set((int64_t) agg.default_val());
            }

            set_last_time(in_time);

            return;
        } else if (in_time - ltime > (60*60)) {
            // printf("debug - rrd - been an hour since last value\n");
            // If we haven't seen data in an hour but we're still w/in the day:
            //   - Average the seconds we know about & set the minute record
            //   - Clear seconds data & set our current value
            //   - Average the minutes we know about & set the hour record
            //
           
            int64_t sec_avg = 0, min_avg = 0;

            // We only have this entry in the minute, so set it and get the 
            // combined value
            
            TrackerElementVector mv(minute_vec);
            for (TrackerElementVector::iterator i = mv.begin(); i != mv.end(); ++i) {
                if (i - mv.begin() == sec_bucket)
                    (*i)->set(in_s);
                else
                    (*i)->set((int64_t) agg.default_val());
            }
            sec_avg = agg.combine_vector(minute_vec);

            // We haven't seen anything in this hour, so clear it, set the minute
            // and get the aggregate
            TrackerElementVector hv = TrackerElementVector(hour_vec);
            for (TrackerElementVector::iterator i = hv.begin(); i != hv.end(); ++i) {
                if (i - hv.begin() == min_bucket)
                    (*i)->set(sec_avg);
                else
                    (*i)->set((int64_t) agg.default_val());
            }
            min_avg = agg.combine_vector(hour_vec);

            // Fill the hours between the last time we saw data and now with
            // zeroes; fastforward time
            for (int h = 0; h < hours_different(last_hour_bucket + 1, hour_bucket); h++) {
                e = hour_vec->get_vector_value((last_hour_bucket + 1 + h) % 24);
                e->set((int64_t) agg.default_val());
            }

            e = day_vec->get_vector_value(hour_bucket);
            e->set(min_avg);

        } else if (in_time - ltime > 60) {
            // - Calculate the average seconds
            // - Wipe the seconds
            // - Set the new second value
            // - Update minutes
            // - Update hours
            // printf("debug - rrd - been over a minute since last value\n");

            int64_t sec_avg = 0, min_avg = 0;

            TrackerElementVector mv(minute_vec);
            for (TrackerElementVector::iterator i = mv.begin(); i != mv.end(); ++i) {
                if (i - mv.begin() == sec_bucket)
                    (*i)->set(in_s);
                else
                    (*i)->set((int64_t) agg.default_val());
            }
            sec_avg = agg.combine_vector(minute_vec);

            // Zero between last and current
            for (int m = 0; 
                    m < minutes_different(last_min_bucket + 1, min_bucket); m++) {
                e = hour_vec->get_vector_value((last_min_bucket + 1 + m) % 60);
                e->set((int64_t) agg.default_val());
            }

            // Set the updated value
            e = hour_vec->get_vector_value(min_bucket);
            e->set((int64_t) sec_avg);

            min_avg = agg.combine_vector(hour_vec);

            // Reset the hour
            e = day_vec->get_vector_value(hour_bucket);
            e->set(min_avg);

        } else {
            // printf("debug - rrd - w/in the last minute %d seconds\n", in_time - last_time);
            // If in_time == last_time then we're updating an existing record,
            // use the aggregator class to combine it
            
            // Otherwise, fast-forward seconds with zero data, then propagate the
            // changes up
            if (in_time == ltime) {
                e = minute_vec->get_vector_value(sec_bucket);
                e->set(agg.combine_element(GetTrackerValue<int64_t>(e), in_s));
            } else {
                for (int s = 0; 
                        s < minutes_different(last_sec_bucket + 1, sec_bucket); s++) {
                    e = minute_vec->get_vector_value((last_sec_bucket + 1 + s) % 60);
                    e->set((int64_t) agg.default_val());
                }

                e = minute_vec->get_vector_value(sec_bucket);
                e->set((int64_t) in_s);
            }

            // Update all the averages
            int64_t sec_avg = 0, min_avg = 0;

            sec_avg = agg.combine_vector(minute_vec);

            // Set the minute
            e = hour_vec->get_vector_value(min_bucket);
            e->set(sec_avg);

            min_avg = agg.combine_vector(hour_vec);

            // Set the hour
            e = day_vec->get_vector_value(hour_bucket);
            e->set(min_avg);
        }


        set_last_time(in_time);
    }

    virtual void pre_serialize() {
        tracker_component::pre_serialize();
        Aggregator agg;

        // printf("debug - rrd - preserialize\n");
        // Update the averages
        if (update_first) {
            add_sample(agg.default_val(), globalreg->timestamp.tv_sec);
        }
    }

protected:
    inline int minutes_different(int m1, int m2) const {
        if (m1 == m2) {
            return 0;
        } else if (m1 < m2) {
            return m2 - m1;
        } else {
            return 60 - m1 + m2;
        }
    }

    inline int hours_different(int h1, int h2) const {
        if (h1 == h2) {
            return 0;
        } else if (h1 < h2) {
            return h2 - h1;
        } else {
            return 24 - h1 + h2;
        }
    }

    inline int days_different(int d1, int d2) const {
        if (d1 == d2) {
            return 0;
        } else if (d1 < d2) {
            return d2 - d1;
        } else {
            return 7 - d1 + d2;
        }
    }

    virtual void register_fields() {
        tracker_component::register_fields();

        last_time_id =
            RegisterField("kismet.common.rrd.last_time", TrackerUInt64,
                    "last time udpated", (void **) &last_time);

        minute_vec_id = 
            RegisterField("kismet.common.rrd.minute_vec", TrackerVector,
                    "past minute values per second", (void **) &minute_vec);
        hour_vec_id = 
            RegisterField("kismet.common.rrd.hour_vec", TrackerVector,
                    "past hour values per minute", (void **) &hour_vec);
        day_vec_id = 
            RegisterField("kismet.common.rrd.day_vec", TrackerVector,
                    "past day values per hour", (void **) &day_vec);

        second_entry_id = 
            RegisterField("kismet.common.rrd.second", TrackerInt64, 
                    "second value", NULL);
        minute_entry_id = 
            RegisterField("kismet.common.rrd.minute", TrackerInt64, 
                    "minute value", NULL);
        hour_entry_id = 
            RegisterField("kismet.common.rrd.hour", TrackerInt64, 
                    "hour value", NULL);

    } 

    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        set_last_time(0);

        // Build slots for all the times
        int x;
        if ((x = minute_vec->get_vector()->size()) != 60) {
            for ( ; x < 60; x++) {
                TrackerElement *me =
                    new TrackerElement(TrackerInt64, second_entry_id);
                minute_vec->add_vector(me);
            }
        }

        if ((x = hour_vec->get_vector()->size()) != 60) {
            for ( ; x < 60; x++) {
                TrackerElement *he =
                    new TrackerElement(TrackerInt64, minute_entry_id);
                hour_vec->add_vector(he);
            }
        }

        if ((x = day_vec->get_vector()->size()) != 24) {
            for ( ; x < 24; x++) {
                TrackerElement *he =
                    new TrackerElement(TrackerInt64, hour_entry_id);
                day_vec->add_vector(he);
            }
        }
    }

    int last_time_id;
    TrackerElement *last_time;

    int minute_vec_id;
    TrackerElement *minute_vec;

    int hour_vec_id;
    TrackerElement *hour_vec;

    int day_vec_id;
    TrackerElement *day_vec;

    int second_entry_id;
    int minute_entry_id;
    int hour_entry_id;

    bool update_first;
};

// Easier to make this it's own class since for a single-minute RRD the logic is
// far simpler.  In a perfect would this would be derived from the common
// RRD (or the other way around) but until it becomes a problem that's a
// task for another day.
template <class Aggregator = kis_tracked_rrd_default_aggregator >
class kis_tracked_minute_rrd : public tracker_component {
public:
    kis_tracked_minute_rrd(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
        update_first = true;
    }

    kis_tracked_minute_rrd(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
        update_first = true;
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_minute_rrd<Aggregator>(globalreg, get_id());
    }

    // By default a RRD will fast forward to the current time before
    // transmission (this is desirable for RRD records that may not be
    // routinely updated, like records tracking activity on a specific 
    // device).  For records which are updated on a timer and the most
    // recently used value accessed (like devices per frequency) turning
    // this off may produce better results.
    void update_before_serialzie(bool in_upd) {
        update_first = in_upd;
    }

    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    void add_sample(int64_t in_s, time_t in_time) {
        Aggregator agg;

        int sec_bucket = in_time % 60;

        time_t ltime = get_last_time();

        // The second slot for the last time
        int last_sec_bucket = ltime % 60;

        if (in_time < ltime) {
            return;
        }
        
        TrackerElement *e;

        // If we haven't seen data in a minute, wipe
        if (in_time - ltime > 60) {
            for (int x = 0; x < 60; x++) {
                e = minute_vec->get_vector_value(x);
                e->set((int64_t) agg.default_val());
            }
        } else {
            // If in_time == last_time then we're updating an existing record, so
            // add that in.
            // Otherwise, fast-forward seconds with zero data, average the seconds,
            // and propagate the averages up
            if (in_time == ltime) {
                e = minute_vec->get_vector_value(sec_bucket);
                e->set(agg.combine_element(GetTrackerValue<int64_t>(e), in_s));
            } else {
                for (int s = 0; 
                        s < minutes_different(last_sec_bucket + 1, sec_bucket); s++) {
                    e = minute_vec->get_vector_value((last_sec_bucket + 1 + s) % 60);
                    e->set((int64_t) agg.default_val());
                }

                e = minute_vec->get_vector_value(sec_bucket);
                e->set((int64_t) in_s);
            }
        }


        set_last_time(in_time);
    }

    virtual void pre_serialize() {
        tracker_component::pre_serialize();
        Aggregator agg;

        if (update_first) {
            add_sample(agg.default_val(), globalreg->timestamp.tv_sec);
        }
    }

protected:
    inline int minutes_different(int m1, int m2) const {
        if (m1 == m2) {
            return 0;
        } else if (m1 < m2) {
            return m2 - m1;
        } else {
            return 60 - m1 + m2;
        }
    }

    virtual void register_fields() {
        tracker_component::register_fields();

        last_time_id =
            RegisterField("kismet.common.rrd.last_time", TrackerUInt64,
                    "last time udpated", (void **) &last_time);

        minute_vec_id = 
            RegisterField("kismet.common.rrd.minute_vec", TrackerVector,
                    "past minute values per second", (void **) &minute_vec);

        second_entry_id = 
            RegisterField("kismet.common.rrd.second", TrackerInt64, 
                    "second value", NULL);
    } 

    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        set_last_time(0);

        // Build slots for all the times
        int x;
        if ((x = minute_vec->get_vector()->size()) != 60) {
            for ( ; x < 60; x++) {
                TrackerElement *me =
                    new TrackerElement(TrackerInt64, second_entry_id);
                minute_vec->add_vector(me);
            }
        }
    }

    int last_time_id;
    TrackerElement *last_time;

    int minute_vec_id;
    TrackerElement *minute_vec;

    int second_entry_id;

    bool update_first;
};

// Signal level RRD, peak selector
class kis_tracked_rrd_peak_signal_aggregator {
public:
    // Select the stronger signal
    static int64_t combine_element(const int64_t a, const int64_t b) {
        if (a < b)
            return b;
        return a;
    }

    // Select the strongest signal of the bucket
    static int64_t combine_vector(TrackerElement *e) {
        TrackerElementVector v(e);

        int64_t max = 0;
        for (TrackerElementVector::iterator i = v.begin(); i != v.end(); ++i) {
            int64_t v = GetTrackerValue<int64_t>(*i);

            if (max == 0 || max < v)
                max = v;
        }

        return max;
    }

    // Default 'empty' value, no legit signal would be 0
    static int64_t default_val() {
        return (int64_t) 0;
    }
};

enum kis_ipdata_type {
	ipdata_unknown = 0,
	ipdata_factoryguess = 1,
	ipdata_udptcp = 2,
	ipdata_arp = 3,
	ipdata_dhcp = 4,
	ipdata_group = 5
};

// New component-based ip data
class kis_tracked_ip_data : public tracker_component {
public:
    // Since we're a subclass we're responsible for initializing our fields
    kis_tracked_ip_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    } 

    // Since we're a subclass, we're responsible for initializing our fields
    kis_tracked_ip_data(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_ip_data(globalreg, get_id());
    }

    __Proxy(ip_type, int32_t, kis_ipdata_type, kis_ipdata_type, ip_type);
    __Proxy(ip_addr, uint64_t, uint64_t, uint64_t, ip_addr_block);
    __Proxy(ip_netmask, uint64_t, uint64_t, uint64_t, ip_netmask);
    __Proxy(ip_gateway, uint64_t, uint64_t, uint64_t, ip_gateway);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        ip_type_id = 
            RegisterField("kismet.common.ipdata.type", TrackerInt32, 
                    "ipdata type enum", (void**) &ip_type);
        ip_addr_block_id = 
            RegisterField("kismet.common.ipdata.address", TrackerUInt64,
                    "ip address", (void**) &ip_addr_block);
        ip_netmask_id =
            RegisterField("kismet.common.ipdata.netmask", TrackerUInt64,
                    "ip netmask", (void**) &ip_netmask);
        ip_gateway_id =
            RegisterField("kismet.common.ipdata.gateway", TrackerUInt64,
                    "ip gateway", (void**) &ip_gateway);
    }

    int ip_type_id, ip_addr_block_id, ip_netmask_id, ip_gateway_id;

    TrackerElement *ip_type;
    TrackerElement *ip_addr_block;
    TrackerElement *ip_netmask;
    TrackerElement *ip_gateway;
};

// Component-tracker common GPS element
class kis_tracked_location_triplet : public tracker_component {
public:
    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    } 

    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, int in_id,
            TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_location_triplet(globalreg, get_id());
    }

    // Use proxy macro to define get/set
    __Proxy(lat, double, double, double, lat);
    __Proxy(lon, double, double, double, lon);
    __Proxy(alt, double, double, double, alt);
    __Proxy(speed, double, double, double, spd);
    __Proxy(fix, uint8_t, uint8_t, uint8_t, fix);
    __Proxy(valid, uint8_t, bool, bool, valid);

    void set(double in_lat, double in_lon, double in_alt, unsigned int in_fix) {
        set_lat(in_lat);
        set_lon(in_lon);
        set_alt(in_alt);
        set_fix(in_fix);
        set_valid(1);
    }

    void set(double in_lat, double in_lon) {
        set_lat(in_lat);
        set_lon(in_lon);
        set_fix(2);
        set_valid(1);
    }

	inline kis_tracked_location_triplet& operator= (const kis_tracked_location_triplet& in) {
        set_lat(in.get_lat());
        set_lon(in.get_lon());
        set_alt(in.get_alt());
        set_speed(in.get_speed());
        set_fix(in.get_fix());
        set_valid(in.get_valid());

        return *this;
    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        lat_id = 
            RegisterField("kismet.common.location.lat", TrackerDouble,
                    "latitude", (void **) &lat);
        lon_id = 
            RegisterField("kismet.common.location.lon", TrackerDouble,
                    "longitude", (void **) &lon);
        alt_id =
            RegisterField("kismet.common.location.alt", TrackerDouble,
                    "altitude", (void **) &alt);
        spd_id =
            RegisterField("kismet.common.location.speed", TrackerDouble,
                    "speed", (void **) &spd);
        fix_id =
            RegisterField("kismet.common.location.fix", TrackerUInt8,
                    "gps fix", (void **) &fix);
        valid_id =
            RegisterField("kismet.common.location.valid", TrackerUInt8,
                    "valid location", (void **) &valid);
    }

    int lat_id, lon_id, alt_id, spd_id, fix_id, valid_id;

    TrackerElement *lat, *lon, *alt, *spd, *fix, *valid;
};

// min/max/avg location
class kis_tracked_location : public tracker_component {
public:
    const static int precision_multiplier = 10000;

    kis_tracked_location(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) { 
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_location(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_location(globalreg, get_id());
    }


    void add_loc(double in_lat, double in_lon, double in_alt, unsigned int fix) {
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

    __Proxy(valid, uint8_t, bool, bool, loc_valid);
    __Proxy(fix, uint8_t, unsigned int, unsigned int, loc_fix);

    kis_tracked_location_triplet *get_min_loc() { return min_loc; }
    kis_tracked_location_triplet *get_max_loc() { return max_loc; }
    kis_tracked_location_triplet *get_avg_loc() { return avg_loc; }

    __Proxy(agg_lat, uint64_t, uint64_t, uint64_t, avg_lat);
    __Proxy(agg_lon, uint64_t, uint64_t, uint64_t, avg_lon);
    __Proxy(agg_alt, uint64_t, uint64_t, uint64_t, avg_alt);
    __Proxy(num_agg, int64_t, int64_t, int64_t, num_avg);
    __Proxy(num_alt_agg, int64_t, int64_t, int64_t, num_alt_avg);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        loc_valid_id = RegisterField("kismet.common.location.loc_valid", TrackerUInt8,
                "location data valid", (void **) &loc_valid);

        loc_fix_id = RegisterField("kismet.common.location.loc_fix", TrackerUInt8,
                "location fix precision (2d/3d)", (void **) &loc_fix);

        kis_tracked_location_triplet *loc_builder = 
            new kis_tracked_location_triplet(globalreg, 0);

        min_loc_id = RegisterComplexField("kismet.common.location.min_loc", loc_builder, 
                "minimum corner of bounding rectangle");
        max_loc_id = RegisterComplexField("kismet.common.location.max_loc", loc_builder,
                "maximum corner of bounding rectangle");
        avg_loc_id = RegisterComplexField("kismet.common.location.avg_loc", loc_builder,
                "average corner of bounding rectangle");

        delete(loc_builder);

        avg_lat_id = RegisterField("kismet.common.location.avg_lat", TrackerInt64,
                "run-time average latitude", (void **) &avg_lat);
        avg_lon_id = RegisterField("kismet.common.location.avg_lon", TrackerInt64,
                "run-time average longitude", (void **) &avg_lon);
        avg_alt_id = RegisterField("kismet.common.location.avg_alt", TrackerInt64,
                "run-time average altitude", (void **) &avg_alt);
        num_avg_id = RegisterField("kismet.common.location.avg_num", TrackerInt64,
                "number of run-time average samples", (void **) &num_avg);
        num_alt_avg_id = RegisterField("kismet.common.location.avg_alt_num", 
                TrackerInt64,
                "number of run-time average samples (altitude)", (void **) &num_alt_avg);

    }

    // We override this to nest our complex structures on top; we can be created
    // over a standard trackerelement map and inherit its sub-maps directly
    // into locations
    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            min_loc = new kis_tracked_location_triplet(globalreg, min_loc_id,
                    e->get_map_value(min_loc_id));
            max_loc = new kis_tracked_location_triplet(globalreg, max_loc_id,
                    e->get_map_value(max_loc_id));
            avg_loc = new kis_tracked_location_triplet(globalreg, avg_loc_id,
                    e->get_map_value(avg_loc_id));
        } else {
            min_loc = new kis_tracked_location_triplet(globalreg, min_loc_id);
            add_map(min_loc);

            max_loc = new kis_tracked_location_triplet(globalreg, max_loc_id);
            add_map(max_loc);

            avg_loc = new kis_tracked_location_triplet(globalreg, avg_loc_id);
            add_map(avg_loc);
        }
    }

    kis_tracked_location_triplet *min_loc, *max_loc, *avg_loc;
    int min_loc_id, max_loc_id, avg_loc_id;

    TrackerElement *avg_lat, *avg_lon, *avg_alt, *num_avg, *num_alt_avg;
    int avg_lat_id, avg_lon_id, avg_alt_id, num_avg_id, num_alt_avg_id;

    TrackerElement *loc_valid;
    int loc_valid_id;

    TrackerElement *loc_fix;
    int loc_fix_id;
};

// Component-tracker based signal data
// TODO operator overloading once rssi/dbm fixed upstream
class kis_tracked_signal_data : public tracker_component {
public:
    kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);      
    } 

    kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_signal_data(globalreg, get_id());
    }

    kis_tracked_signal_data& operator+= (const kis_layer1_packinfo& lay1) {
        if (lay1.signal_type == kis_l1_signal_type_dbm) {
            if (lay1.signal_dbm != 0) {

                last_signal_dbm->set((int32_t) lay1.signal_dbm);

                if ((*min_signal_dbm) == (int32_t) 0 ||
                        (*min_signal_dbm) > (int32_t) lay1.signal_dbm) {
                    min_signal_dbm->set((int32_t) lay1.signal_dbm);
                }

                if ((*max_signal_dbm) == (int32_t) 0 ||
                        (*max_signal_dbm) < (int32_t) lay1.signal_dbm) {
                    max_signal_dbm->set((int32_t) lay1.signal_dbm);
                }
            }

            if (lay1.noise_dbm != 0) {
                last_noise_dbm->set((int32_t) lay1.noise_dbm);

                if ((*min_noise_dbm) == (int32_t) 0 ||
                        (*min_noise_dbm) > (int32_t) lay1.noise_dbm) {
                    min_noise_dbm->set((int32_t) lay1.noise_dbm);
                }

                if ((*max_noise_dbm) == (int32_t) 0 ||
                        (*max_noise_dbm) < (int32_t) lay1.noise_dbm) {
                    max_noise_dbm->set((int32_t) lay1.noise_dbm);
                }
            }
        } else if (lay1.signal_type == kis_l1_signal_type_rssi) {
            if (lay1.signal_rssi != 0) {
                last_signal_rssi->set((int32_t) lay1.signal_rssi);

                if ((*min_signal_rssi) == (int32_t) 0 ||
                        (*min_signal_rssi) > (int32_t) lay1.signal_rssi) {
                    min_signal_dbm->set((int32_t) lay1.signal_rssi);
                }

                if ((*max_signal_rssi) == (int32_t) 0 ||
                        (*max_signal_rssi) < (int32_t) lay1.signal_rssi) {
                    max_signal_rssi->set((int32_t) lay1.signal_rssi);
                }
            }

            if (lay1.noise_rssi != 0) {
                last_noise_rssi->set((int32_t) lay1.noise_rssi);

                if ((*min_noise_rssi) == (int32_t) 0 ||
                        (*min_noise_rssi) > (int32_t) lay1.noise_rssi) {
                    min_noise_rssi->set((int32_t) lay1.noise_rssi);
                }

                if ((*max_noise_rssi) == (int32_t) 0 ||
                        (*max_noise_rssi) < (int32_t) lay1.noise_rssi) {
                    max_noise_rssi->set((int32_t) lay1.noise_rssi);
                }
            }

            (*carrierset) |= (uint64_t) lay1.carrier;
            (*encodingset) |= (uint64_t) lay1.encoding;

            if ((*maxseenrate) < (double) lay1.datarate) {
                maxseenrate->set((double) lay1.datarate);
            }
        }

        return *this;
    }

	kis_tracked_signal_data& operator+= (const Packinfo_Sig_Combo& in) {
        if (in.lay1 != NULL) {
            if (in.lay1->signal_type == kis_l1_signal_type_dbm) {
                if (in.lay1->signal_dbm != 0) {

                    last_signal_dbm->set((int32_t) in.lay1->signal_dbm);

                    if ((*min_signal_dbm) == (int32_t) 0 ||
                            (*min_signal_dbm) > (int32_t) in.lay1->signal_dbm) {
                        min_signal_dbm->set((int32_t) in.lay1->signal_dbm);
                    }

                    if ((*max_signal_dbm) == (int32_t) 0 ||
                            (*max_signal_dbm) < (int32_t) in.lay1->signal_dbm) {
                        max_signal_dbm->set((int32_t) in.lay1->signal_dbm);

                        if (in.gps != NULL) {
                            peak_loc->set(in.gps->lat, in.gps->lon, in.gps->alt, 
                                    in.gps->fix);
                        }
                    }

                    signal_min_rrd->add_sample(in.lay1->signal_dbm, 
                            globalreg->timestamp.tv_sec);
                }

                if (in.lay1->noise_dbm != 0) {
                    last_noise_dbm->set((int32_t) in.lay1->noise_dbm);

                    if ((*min_noise_dbm) == (int32_t) 0 ||
                            (*min_noise_dbm) > (int32_t) in.lay1->noise_dbm) {
                        min_noise_dbm->set((int32_t) in.lay1->noise_dbm);
                    }

                    if ((*max_noise_dbm) == (int32_t) 0 ||
                            (*max_noise_dbm) < (int32_t) in.lay1->noise_dbm) {
                        max_noise_dbm->set((int32_t) in.lay1->noise_dbm);
                    }
                }
            } else if (in.lay1->signal_type == kis_l1_signal_type_rssi) {
                if (in.lay1->signal_rssi != 0) {
                    last_signal_rssi->set((int32_t) in.lay1->signal_rssi);

                    if ((*min_signal_rssi) == (int32_t) 0 ||
                            (*min_signal_rssi) > (int32_t) in.lay1->signal_rssi) {
                        min_signal_dbm->set((int32_t) in.lay1->signal_rssi);
                    }

                    if ((*max_signal_rssi) == (int32_t) 0 ||
                            (*max_signal_rssi) < (int32_t) in.lay1->signal_rssi) {
                        max_signal_rssi->set((int32_t) in.lay1->signal_rssi);

                        if (in.gps != NULL) {
                            peak_loc->set(in.gps->lat, in.gps->lon, in.gps->alt, 
                                    in.gps->fix);
                        }
                    }

                    signal_min_rrd->add_sample(in.lay1->signal_rssi, 
                            globalreg->timestamp.tv_sec);
                }

                if (in.lay1->noise_rssi != 0) {
                    last_noise_rssi->set((int32_t) in.lay1->noise_rssi);

                    if ((*min_noise_rssi) == (int32_t) 0 ||
                            (*min_noise_rssi) > (int32_t) in.lay1->noise_rssi) {
                        min_noise_rssi->set((int32_t) in.lay1->noise_rssi);
                    }

                    if ((*max_noise_rssi) == (int32_t) 0 ||
                            (*max_noise_rssi) < (int32_t) in.lay1->noise_rssi) {
                        max_noise_rssi->set((int32_t) in.lay1->noise_rssi);
                    }
                }

            }

            (*carrierset) |= (uint64_t) in.lay1->carrier;
            (*encodingset) |= (uint64_t) in.lay1->encoding;

            if ((*maxseenrate) < (double) in.lay1->datarate) {
                maxseenrate->set((double) in.lay1->datarate);
            }
		}

		return *this;
	}

    __ProxyGet(last_signal_dbm, int32_t, int, last_signal_dbm);
    __ProxyGet(min_signal_dbm, int32_t, int, min_signal_dbm);
    __ProxyGet(max_signal_dbm, int32_t, int, max_signal_dbm);

    __ProxyGet(last_noise_dbm, int32_t, int, last_noise_dbm);
    __ProxyGet(min_noise_dbm, int32_t, int, min_noise_dbm);
    __ProxyGet(max_noise_dbm, int32_t, int, max_noise_dbm);

    __ProxyGet(last_signal_rssi, int32_t, int, last_signal_rssi);
    __ProxyGet(min_signal_rssi, int32_t, int, min_signal_rssi);
    __ProxyGet(max_signal_rssi, int32_t, int, max_signal_rssi);

    __ProxyGet(last_noise_rssi, int32_t, int, last_noise_rssi);
    __ProxyGet(min_noise_rssi, int32_t, int, min_noise_rssi);
    __ProxyGet(max_noise_rssi, int32_t, int, max_noise_rssi);

    __ProxyGet(maxseenrate, double, double, maxseenrate);
    __ProxyGet(encodingset, uint64_t, uint64_t, encodingset);
    __ProxyGet(carrierset, uint64_t, uint64_t, carrierset);

    typedef kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator> msig_rrd;
    __ProxyTrackable(signal_min_rrd, msig_rrd, signal_min_rrd);

    kis_tracked_location_triplet *get_peak_loc() { return peak_loc; }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        last_signal_dbm_id =
            RegisterField("kismet.common.signal.last_signal_dbm", TrackerInt32,
                    "most recent signal (dBm)", (void **) &last_signal_dbm);
        last_noise_dbm_id =
            RegisterField("kismet.common.signal.last_noise_dbm", TrackerInt32,
                    "most recent noise (dBm)", (void **) &last_noise_dbm);

        min_signal_dbm_id =
            RegisterField("kismet.common.signal.min_signal_dbm", TrackerInt32,
                    "minimum signal (dBm)", (void **) &min_signal_dbm);
        min_noise_dbm_id =
            RegisterField("kismet.common.signal.min_noise_dbm", TrackerInt32,
                    "minimum noise (dBm)", (void **) &min_noise_dbm);

        max_signal_dbm_id =
            RegisterField("kismet.common.signal.max_signal_dbm", TrackerInt32,
                    "maximum signal (dBm)", (void **) &max_signal_dbm);
        max_noise_dbm_id =
            RegisterField("kismet.common.signal.max_noise_dbm", TrackerInt32,
                    "maximum noise (dBm)", (void **) &max_noise_dbm);

        last_signal_rssi_id =
            RegisterField("kismet.common.signal.last_signal_rssi", TrackerInt32,
                    "most recent signal (RSSI)", (void**) &last_signal_rssi);
        last_noise_rssi_id =
            RegisterField("kismet.common.signal.last_noise_rssi", TrackerInt32,
                    "most recent noise (RSSI)", (void **) &last_noise_rssi);

        min_signal_rssi_id =
            RegisterField("kismet.common.signal.min_signal_rssi", TrackerInt32,
                    "minimum signal (rssi)", (void **) &min_signal_rssi);
        min_noise_rssi_id =
            RegisterField("kismet.common.signal.min_noise_rssi", TrackerInt32,
                    "minimum noise (RSSI)", (void **) &min_noise_rssi);

        max_signal_rssi_id =
            RegisterField("kismet.common.signal.max_signal_rssi", TrackerInt32,
                    "maximum signal (RSSI)", (void **) &max_signal_rssi);
        max_noise_rssi_id =
            RegisterField("kismet.common.signal.max_noise_rssi", TrackerInt32,
                    "maximum noise (RSSI)", (void **) &max_noise_rssi);


        kis_tracked_location_triplet *loc_builder = 
            new kis_tracked_location_triplet(globalreg, 0);
        peak_loc_id = 
            RegisterComplexField("kismet.common.signal.peak_loc", loc_builder,
                    "location of strongest signal");
        delete(loc_builder);

        maxseenrate_id =
            RegisterField("kismet.common.signal.maxseenrate", TrackerDouble,
                    "maximum observed data rate (phy dependent)", (void **) &maxseenrate);
        encodingset_id =
            RegisterField("kismet.common.signal.encodingset", TrackerUInt64,
                    "bitset of observed encodings", (void **) &encodingset);
        carrierset_id =
            RegisterField("kismet.common.signal.carrierset", TrackerUInt64,
                    "bitset of observed carrier types", (void **) &carrierset);

        kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator> 
            *signal_min_rrd_builder = new 
            kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator>(globalreg,
                    0);
        signal_min_rrd_id =
            RegisterComplexField("kismet.device.base.signal.rrd",
                    signal_min_rrd_builder, "signal data for past minute");
        delete(signal_min_rrd_builder);
    }

    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            peak_loc = new kis_tracked_location_triplet(globalreg, peak_loc_id,
                    e->get_map_value(peak_loc_id)); 
                signal_min_rrd = new 
                kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator>(globalreg,
                        signal_min_rrd_id, e->get_map_value(signal_min_rrd_id));
        } else {
            signal_min_rrd = new
                kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator>(globalreg,
                        signal_min_rrd_id);
            peak_loc = new kis_tracked_location_triplet(globalreg, peak_loc_id);
            add_map(peak_loc);

            signal_min_rrd = new 
                kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator>(globalreg, 
                            signal_min_rrd_id);
            add_map(signal_min_rrd);

        }
    }

    int last_signal_dbm_id, last_noise_dbm_id,
        min_signal_dbm_id, min_noise_dbm_id,
        max_signal_dbm_id, max_noise_dbm_id,

        last_signal_rssi_id, last_noise_rssi_id,
        min_signal_rssi_id, min_noise_rssi_id,
        max_signal_rssi_id, max_noise_rssi_id,

        peak_loc_id,
        maxseenrate_id, encodingset_id, carrierset_id;

    TrackerElement *last_signal_dbm, *last_noise_dbm;
    TrackerElement *min_signal_dbm, *min_noise_dbm;
    TrackerElement *max_signal_dbm, *max_noise_dbm;

    TrackerElement *last_signal_rssi, *last_noise_rssi;
    TrackerElement *min_signal_rssi, *min_noise_rssi;
    TrackerElement *max_signal_rssi, *max_noise_rssi;

    kis_tracked_location_triplet *peak_loc;

    TrackerElement *maxseenrate, *encodingset, *carrierset;

    // Signal record over the past minute, either rssi or dbm.  Devices
    // should not mix rssi and dbm signal reporting.
    int signal_min_rrd_id;
    kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator> *signal_min_rrd;
};

class kis_tracked_seenby_data : public tracker_component {
public:
    kis_tracked_seenby_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) { 
        register_fields();
        reserve_fields(NULL);
    } 

    kis_tracked_seenby_data(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_signal_data(globalreg, get_id());
    }

    __Proxy(src_uuid, uuid, uuid, uuid, src_uuid);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __Proxy(num_packets, uint64_t, uint64_t, uint64_t, num_packets);
    __ProxyIncDec(num_packets, uint64_t, uint64_t, num_packets);

    // Intmaps need special care by the caller
    TrackerElement *get_freq_khz_map() { return freq_khz_map; }

    void inc_frequency_count(int frequency) {
        TrackerElement::map_iterator i = freq_khz_map->find(frequency);

        if (i == freq_khz_map->end()) {
            TrackerElement *e = 
                globalreg->entrytracker->GetTrackedInstance(frequency_val_id);
            e->set((uint64_t) 1);
            freq_khz_map->add_intmap(frequency, e);
        } else {
            (*(i->second))++;
        }
    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        src_uuid_id =
            RegisterField("kismet.common.seenby.uuid", TrackerUuid,
                    "UUID of source", (void **) &src_uuid);
        first_time_id =
            RegisterField("kismet.common.seenby.first_time", TrackerUInt64,
                    "first time seen time_t", (void **) &first_time);
        last_time_id =
            RegisterField("kismet.common.seenby.last_time", TrackerUInt64,
                    "last time seen time_t", (void **) &last_time);
        num_packets_id =
            RegisterField("kismet.common.seenby.num_packets", TrackerUInt64,
                    "number of packets seen by this device", (void **) &num_packets);
        freq_khz_map_id =
            RegisterField("kismet.common.seenby.freq_khz_map", TrackerIntMap,
                    "packets seen per frequency (khz)", (void **) &freq_khz_map);
        frequency_val_id =
            globalreg->entrytracker->RegisterField("kismet.common.seenby.frequency.count",
                    TrackerUInt64, "frequency packet count");
    }

    TrackerElement *src_uuid;
    int src_uuid_id;

    TrackerElement *first_time; 
    int first_time_id;

    TrackerElement *last_time;
    int last_time_id;

    TrackerElement *num_packets;
    int num_packets_id;

    TrackerElement *freq_khz_map;
    int freq_khz_map_id;

    int frequency_val_id;
};

// Arbitrary tag data added to network
class kis_tracked_tag : public tracker_component {
public:
    kis_tracked_tag(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) { 
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_tag(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_tag(globalreg, get_id());
    }


    __Proxy(value, string, string, string, value);
    __Proxy(dirty, uint8_t, bool, bool, dirty);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        value_id =
            RegisterField("kismet.common.tag.value", TrackerString,
                    "arbitrary tag", (void **) &value);
        dirty_id =
            RegisterField("kismet.common.tag.dirty", TrackerUInt8,
                    "tag has been modified", (void **) &dirty);
    }

    int value_id, dirty_id;
    TrackerElement *value, *dirty;
};


#endif

