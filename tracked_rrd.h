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

#ifndef __TRACKED_RRD_H__
#define __TRACKED_RRD_H__

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

// Aggregator class used for RRD.  Performs functions like combining elements
// (for instance, adding to the existing element, or choosing to replace the
// element), and for averaging to higher buckets (for instance, performing a 
// raw average or taking absolutes)
//
// For aggregators which skip empty values, the 'default' value can be used as 
// the 'empty' value (for instance, when aggregating temperature, a default value
// could be -99999 and the average function would ignore it)
class kis_tracked_rrd_default_aggregator {
public:
    // Performed when adding an element to the RRD.  By default, adds the new
    // value to the current value for aggregating multiple samples over time.
    static int64_t combine_element(const int64_t a, const int64_t b) {
        return a + b;
    }

    // Combine a vector for a higher-level record (seconds to minutes, minutes to 
    // hours, and so on).
    static int64_t combine_vector(std::shared_ptr<TrackerElement> e) {
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

    static std::string name() {
        return "default";
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

    kis_tracked_rrd(GlobalRegistry *in_globalreg, int in_id, 
            std::shared_ptr<TrackerElement> e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
        update_first = true;

    }

    virtual std::shared_ptr<TrackerElement> clone_type() {
        return std::shared_ptr<TrackerElement>(new kis_tracked_rrd<Aggregator>(globalreg, 
                    get_id()));
    }

    // By default a RRD will fast forward to the current time before
    // transmission (this is desirable for RRD records that may not be
    // routinely updated, like records tracking activity on a specific 
    // device).  For records which are updated on a timer and the most
    // recently used value accessed (like devices per frequency) turning
    // this off may produce better results.
    void update_before_serialize(bool in_upd) {
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
        
        std::shared_ptr<TrackerElement> e;

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

        RegisterField("kismet.common.rrd.last_time", TrackerUInt64,
                "last time udpated", &last_time);

        RegisterField("kismet.common.rrd.minute_vec", TrackerVector,
                "past minute values per second", &minute_vec);
        RegisterField("kismet.common.rrd.hour_vec", TrackerVector,
                "past hour values per minute", &hour_vec);
        RegisterField("kismet.common.rrd.day_vec", TrackerVector,
                "past day values per hour", &day_vec);

        RegisterField("kismet.common.rrd.blank_val", TrackerInt64,
                "blank value", &blank_val);
        RegisterField("kismet.common.rrd.aggregator", TrackerString,
                "aggregator name", &aggregator_name);

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

    virtual void reserve_fields(std::shared_ptr<TrackerElement> e) {
        tracker_component::reserve_fields(e);

        // Build slots for all the times
        int x;
        if ((x = minute_vec->get_vector()->size()) != 60) {
            for ( ; x < 60; x++) {
                SharedTrackerElement me(new TrackerElement(TrackerInt64, 
                            second_entry_id));
                minute_vec->add_vector(me);
            }
        }

        if ((x = hour_vec->get_vector()->size()) != 60) {
            for ( ; x < 60; x++) {
                SharedTrackerElement he(new TrackerElement(TrackerInt64, 
                            minute_entry_id));
                hour_vec->add_vector(he);
            }
        }

        if ((x = day_vec->get_vector()->size()) != 24) {
            for ( ; x < 24; x++) {
                SharedTrackerElement he(new TrackerElement(TrackerInt64, hour_entry_id));
                day_vec->add_vector(he);
            }
        }

        Aggregator agg;
        (*blank_val).set(agg.default_val());
        (*aggregator_name).set(agg.name());

    }

    SharedTrackerElement last_time;
    SharedTrackerElement minute_vec;
    SharedTrackerElement hour_vec;
    SharedTrackerElement day_vec;
    SharedTrackerElement blank_val;
    SharedTrackerElement aggregator_name;

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

    kis_tracked_minute_rrd(GlobalRegistry *in_globalreg, int in_id, 
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
        update_first = true;
    }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new kis_tracked_minute_rrd<Aggregator>(globalreg, 
                    get_id()));
    }

    // By default a RRD will fast forward to the current time before
    // transmission (this is desirable for RRD records that may not be
    // routinely updated, like records tracking activity on a specific 
    // device).  For records which are updated on a timer and the most
    // recently used value accessed (like devices per frequency) turning
    // this off may produce better results.
    void update_before_serialize(bool in_upd) {
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
        
        SharedTrackerElement e;

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

        RegisterField("kismet.common.rrd.last_time", TrackerUInt64,
                "last time udpated", &last_time);

        RegisterField("kismet.common.rrd.minute_vec", TrackerVector,
                "past minute values per second", &minute_vec);

        second_entry_id = 
            RegisterField("kismet.common.rrd.second", TrackerInt64, 
                    "second value", NULL);

        RegisterField("kismet.common.rrd.blank_val", TrackerInt64,
                "blank value", &blank_val);
        RegisterField("kismet.common.rrd.aggregator", TrackerString,
                "aggregator name", &aggregator_name);
    } 

    virtual void reserve_fields(SharedTrackerElement e) {
        tracker_component::reserve_fields(e);

        set_last_time(0);

        // Build slots for all the times
        int x;
        if ((x = minute_vec->get_vector()->size()) != 60) {
            for ( ; x < 60; x++) {
                SharedTrackerElement me(new TrackerElement(TrackerInt64, 
                            second_entry_id));
                minute_vec->add_vector(me);
            }
        }

        Aggregator agg;
        (*blank_val).set(agg.default_val());
        (*aggregator_name).set(agg.name());
    }

    SharedTrackerElement last_time;
    SharedTrackerElement minute_vec;
    SharedTrackerElement blank_val;
    SharedTrackerElement aggregator_name;

    int second_entry_id;

    bool update_first;
};

// Signal level RRD, peak selector on overlap, averages signal but ignores
// empty slots
class kis_tracked_rrd_peak_signal_aggregator {
public:
    // Select the stronger signal
    static int64_t combine_element(const int64_t a, const int64_t b) {
        if (a < b)
            return b;
        return a;
    }

    // Select the strongest signal of the bucket
    static int64_t combine_vector(SharedTrackerElement e) {
        TrackerElementVector v(e);

        int64_t avg = 0, avgc = 0;

        for (TrackerElementVector::iterator i = v.begin(); i != v.end(); ++i) {
            int64_t v = GetTrackerValue<int64_t>(*i);

            if (v == 0)
                continue;

            avg += v;
            avgc++;
        }

        if (avgc == 0)
            return default_val();

        return avg / avgc;

#if 0
        int64_t max = 0;
        for (TrackerElementVector::iterator i = v.begin(); i != v.end(); ++i) {
            int64_t v = GetTrackerValue<int64_t>(*i);

            if (max == 0 || max < v)
                max = v;
        }

        return max;
#endif
    }

    // Default 'empty' value, no legit signal would be 0
    static int64_t default_val() {
        return (int64_t) 0;
    }

    static std::string name() {
        return "peak_signal";
    }
};

// Generic RRD, extreme selector.  If both values are > 0, selects the highest.
// If both values are below zero, selects the lowest.  If values are mixed,
// selects the lowest
class kis_tracked_rrd_extreme_aggregator {
public:
    // Select the most extreme value
    static int64_t combine_element(const int64_t a, const int64_t b) {
        if (a < 0 && b < 0) {
            if (a < b)
                return a;

            return b;
        } else if (a > 0 && b > 0) {
            if (a > b)
                return a;

            return b;
        } else if (a == 0) {
            return b;
        } else if (b == 0) {
            return a;
        } else if (a < b) {
            return a;
        }

        return b;
    }

    // Simple average
    static int64_t combine_vector(SharedTrackerElement e) {
        TrackerElementVector v(e);

        int64_t avg = 0;
        for (TrackerElementVector::iterator i = v.begin(); i != v.end(); ++i) 
            avg += GetTrackerValue<int64_t>(*i);

        return avg / v.size();
    }

    // Default 'empty' value, no legit signal would be 0
    static int64_t default_val() {
        return (int64_t) 0;
    }

    static std::string name() {
        return "extreme";
    }
};


#endif

