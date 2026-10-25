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
#include <array>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "entrytracker.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "trackedelement.h"
#include "trackedcomponent.h"

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
    static double combine_element(const int64_t a, const int64_t b) {
        return a + b;
    }

    // Combine a vector for a higher-level record (seconds to minutes, minutes to
    // hours, and so on).
    template<typename C>
    static double combine_vector(const C& v) {
        double avg = 0;
        for (const auto& i : v)
            avg += i;

        return avg / v.size();
    }

    // Default 'empty' value
    static double default_val() {
        return (double) 0;
    }

    static std::string name() {
        return "default";
    }
};

// Field ids of the RRD children
struct kis_tracked_rrd_field_ids {
    int last_time;
    int serial_time;
    int last_value;
    int last_value_n1;
    int minute_vec;
    int hour_vec;
    int day_vec;
    int blank_val;
};

// RRDs keep their samples inline and their scalar fields as embedded elements; the
// child map is only filled while serializing, and paths into the RRD are resolved by
// get_lazy_sub.  Vector children are built on demand and shared until released.
template <class M_Aggregator = kis_tracked_rrd_default_aggregator,
         class H_Aggregator = M_Aggregator, class D_Aggregator = M_Aggregator>
class kis_tracked_rrd : public tracker_component,
    public std::enable_shared_from_this<kis_tracked_rrd<M_Aggregator, H_Aggregator, D_Aggregator>> {
public:
    kis_tracked_rrd() :
        kis_tracked_rrd(0) { }

    kis_tracked_rrd(int in_id) :
        tracker_component(in_id),
        last_time{field_ids().last_time},
        serial_time{field_ids().serial_time},
        last_value{field_ids().last_value},
        last_value_n1{field_ids().last_value_n1},
        blank_val{field_ids().blank_val, static_cast<double>(M_Aggregator::default_val())},
        minute_vec{},
        hour_vec{},
        day_vec{},
        serialize_depth{0},
        update_first{true} {
        set_lazy_sub();
        mutex.set_name("kis_tracked_rrd");
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_tracked_rrd");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    // By default a RRD will fast forward to the current time before
    // transmission (this is desirable for RRD records that may not be
    // routinely updated, like records tracking activity on a specific
    // device).  For records which are updated on a timer and the most
    // recently used value accessed (like devices per frequency) turning
    // this Off may produce better results.
    void update_before_serialize(bool in_upd) {
        update_first = in_upd;
    }

    time_t get_last_time() const {
        return (time_t) last_time.get();
    }

    time_t get_serial_time() const {
        return (time_t) serial_time.get();
    }

    double get_last_value() const {
        return last_value.get();
    }

    double get_last_value_n1() const {
        return last_value_n1.get();
    }

    // Add a sample.  Use combinator function 'c' to derive the new sample value
    void add_sample(double in_s, time_t in_time) {
        kis_lock_guard<kis_mutex> lk(mutex, "kis_tracked_rrd add_sample");

        // A negative time would index outside the buckets
        if (in_time < 0)
            return;

        size_t sec_bucket = in_time % 60;
        size_t min_bucket = (in_time / 60) % 60;
        size_t hour_bucket = (in_time / 3600) % 24;

        time_t ltime = get_last_time();

        // The second slot for the last time
        size_t last_sec_bucket = ltime % 60;
        // The minute of the hour the last known data would go in
        size_t last_min_bucket = (ltime / 60) % 60;
        // The hour of the day the last known data would go in
        size_t last_hour_bucket = (ltime / 3600) % 24;

        if (in_time == ltime) {
            last_value_n1.set(last_value.get());
            last_value.set(m_agg.combine_element(last_value.get(), in_s));
        } else {
            last_value_n1.set(last_value.get());
            last_value.set(in_s);
        }

        // Allow backfilling w/in the past minute because packets might come out-of-order
        if (in_time < ltime) {
            if (ltime - in_time > 60)
                return;

            double v = minute_vec[sec_bucket];
            minute_vec[sec_bucket] = m_agg.combine_element(v, in_s);
        } else {
            // If we haven't seen data in a day, we reset everything because
            // none of it is valid.  This is the simplest case.
            if (in_time - ltime > (60 * 60 * 24)) {
                // Directly fill in this second, clear rest of the minute
                for (size_t i = 0; i < minute_vec.size(); i++) {
                    if (i == sec_bucket) {
                        minute_vec[i] = in_s;
                    } else {
                        minute_vec[i] = m_agg.default_val();
                    }

                }

                // Reset the last hour, setting it to a single sample
                // Get the combined value for the minute
                double min_val = h_agg.combine_vector(minute_vec);
                for (size_t i = 0; i < hour_vec.size(); i++) {
                    if (i == min_bucket) {
                        hour_vec[i] = min_val;
                    } else {
                        hour_vec[i] = h_agg.default_val();
                    }
                }

                // Reset the last day, setting it to a single sample
                double hr_val = d_agg.combine_vector(hour_vec);
                for (size_t i = 0; i < day_vec.size(); i++) {
                    if (i == hour_bucket) {
                        day_vec[i] = hr_val;
                    } else {
                        day_vec[i] = d_agg.default_val();
                    }
                }

                last_time.set(in_time);

                return;
            } else if (in_time - ltime > (60*60)) {
                // If we haven't seen data in an hour but we're still w/in the day:
                //   - Average the seconds we know about & set the minute record
                //   - Clear seconds data & set our current value
                //   - Average the minutes we know about & set the hour record
                //

                double sec_avg = 0, min_avg = 0;

                // We only have this entry in the minute, so set it and get the
                // combined value
                for (size_t i = 0; i < minute_vec.size(); i++) {
                    if (i == sec_bucket) {
                        minute_vec[i] = in_s;
                    } else {
                        minute_vec[i] = m_agg.default_val();
                    }
                }
                sec_avg = h_agg.combine_vector(minute_vec);

                // We haven't seen anything in this hour, so clear it, set the minute
                // and get the aggregate
                for (size_t i = 0; i < hour_vec.size(); i++) {
                    if (i == min_bucket) {
                        hour_vec[i] = sec_avg;
                    } else {
                        hour_vec[i] = h_agg.default_val();
                    }

                }
                min_avg = d_agg.combine_vector(hour_vec);

                // Fill the hours between the last time we saw data and now with
                // zeroes; fastforward time
                for (size_t h = 0; h < hours_different(last_hour_bucket + 1, hour_bucket); h++) {
                    day_vec[(last_hour_bucket + 1 + h) % 24] = d_agg.default_val();
                }

                day_vec[hour_bucket] = min_avg;

            } else if (in_time - ltime > 60) {
                // - Calculate the average seconds
                // - Wipe the seconds
                // - Set the new second value
                // - Update minutes
                // - Update hours

                double sec_avg = 0, min_avg = 0;

                for (size_t i = 0; i < minute_vec.size(); i++) {
                    if (i == sec_bucket) {
                        minute_vec[i] = in_s;
                    } else {
                        minute_vec[i] = m_agg.default_val();
                    }
                }
                sec_avg = h_agg.combine_vector(minute_vec);

                // Zero between last and current
                for (size_t m = 0; m < minutes_different(last_min_bucket + 1, min_bucket); m++) {
                    hour_vec[(last_min_bucket + 1 + m) % 60] = h_agg.default_val();
                }

                // Set the updated value
                hour_vec[min_bucket] = sec_avg;

                min_avg = d_agg.combine_vector(hour_vec);

                // Reset the hour
                day_vec[hour_bucket] = min_avg;
            } else {
                // If in_time == last_time then we're updating an existing record,
                // use the aggregator class to combine it

                // Otherwise, fast-forward seconds with zero data, then propagate the
                // changes up

                if (in_time == ltime) {
                    double v = minute_vec[sec_bucket];
                    minute_vec[sec_bucket] = m_agg.combine_element(v, in_s);
                } else {
                    for (size_t s = 0; s < minutes_different(last_sec_bucket + 1, sec_bucket); s++) {
                        minute_vec[(last_sec_bucket + 1 + s) % 60] = m_agg.default_val();
                    }

                    minute_vec[sec_bucket] = in_s;
                }

                // Update all the averages
                double sec_avg = 0, min_avg = 0;

                sec_avg = h_agg.combine_vector(minute_vec);
                hour_vec[min_bucket] = sec_avg;

                min_avg = d_agg.combine_vector(hour_vec);
                day_vec[hour_bucket] = min_avg;
            }
        }

        last_time.set(in_time);
    }

    virtual void pre_serialize() override {
        kis_lock_guard<kis_mutex> lk(mutex, kismet::retain_lock, "kis_tracked_rrd serialize");

        tracker_component::pre_serialize();

        uint64_t now = Globalreg::globalreg->last_tv_sec;
        serial_time.set(now);

        // Update the averages
        if (update_first) {
            add_sample(m_agg.default_val(), now);
        }

        if (serialize_depth++ == 0)
            fill_map();
    }

    virtual void post_serialize() override {
        kis_lock_guard<kis_mutex> lk(mutex, std::adopt_lock);
        release_map();
    }

    virtual void as_json(std::ostream& os, struct json_adapter::opts *opts = nullptr) override {
        kis_lock_guard<kis_mutex> lk(mutex, "kis_tracked_rrd as_json");

        if (serialize_depth++ == 0)
            fill_map();

        try {
            tracker_component::as_json(os, opts);
        } catch (...) {
            release_map();
            throw;
        }

        release_map();
    }

protected:
    struct vec_children {
        vec_children(const kis_tracked_rrd_field_ids& ids) :
            minute_vec{ids.minute_vec},
            hour_vec{ids.hour_vec},
            day_vec{ids.day_vec} { }

        tracker_element_vector_double minute_vec;
        tracker_element_vector_double hour_vec;
        tracker_element_vector_double day_vec;
    };

    static const kis_tracked_rrd_field_ids& field_ids() {
        static const kis_tracked_rrd_field_ids ids = register_field_ids();
        return ids;
    }

    static kis_tracked_rrd_field_ids register_field_ids() {
        auto& et = Globalreg::globalreg->entrytracker;
        kis_tracked_rrd_field_ids ids;

        ids.last_time = et->register_field("kismet.common.rrd.last_time",
                tracker_element_factory<tracker_element_uint64>(), "last time updated");
        ids.serial_time = et->register_field("kismet.common.rrd.serial_time",
                tracker_element_factory<tracker_element_uint64>(), "timestamp of serialization");

        ids.last_value = et->register_field("kismet.common.rrd.last_value",
                tracker_element_factory<tracker_element_double>(), "most recent value in rrd");
        ids.last_value_n1 = et->register_field("kismet.common.rrd.last_value_n1",
                tracker_element_factory<tracker_element_double>(), "most recent value - 1 in rrd");

        ids.minute_vec = et->register_field("kismet.common.rrd.minute_vec",
                tracker_element_factory<tracker_element_vector_double>(), "past minute values per second");
        ids.hour_vec = et->register_field("kismet.common.rrd.hour_vec",
                tracker_element_factory<tracker_element_vector_double>(), "past hour values per minute");
        ids.day_vec = et->register_field("kismet.common.rrd.day_vec",
                tracker_element_factory<tracker_element_vector_double>(), "past day values per hour");

        ids.blank_val = et->register_field("kismet.common.rrd.blank_val",
                tracker_element_factory<tracker_element_double>(), "blank value");

        et->register_field("kismet.common.rrd.second",
                tracker_element_factory<tracker_element_int64>(), "second value");
        et->register_field("kismet.common.rrd.minute",
                tracker_element_factory<tracker_element_int64>(), "minute value");
        et->register_field("kismet.common.rrd.hour",
                tracker_element_factory<tracker_element_int64>(), "hour value");

        return ids;
    }

    // Vector children, shared with anyone still holding them from a previous lookup; each
    // is refreshed from the samples when it is handed out.  Mutex must be held.
    std::shared_ptr<vec_children> get_vec_children() {
        auto v = vec_cache.lock();

        if (v == nullptr) {
            v = std::make_shared<vec_children>(field_ids());
            vec_cache = v;
        }

        return v;
    }

    virtual shared_tracker_element get_lazy_sub(int id) override {
        const auto& ids = field_ids();

        if (id == ids.minute_vec || id == ids.hour_vec || id == ids.day_vec) {
            kis_lock_guard<kis_mutex> lk(mutex, "kis_tracked_rrd get_sub");
            auto v = get_vec_children();

            if (id == ids.minute_vec) {
                v->minute_vec.get().assign(minute_vec.begin(), minute_vec.end());
                return shared_tracker_element(v, &v->minute_vec);
            }

            if (id == ids.hour_vec) {
                v->hour_vec.get().assign(hour_vec.begin(), hour_vec.end());
                return shared_tracker_element(v, &v->hour_vec);
            }

            v->day_vec.get().assign(day_vec.begin(), day_vec.end());
            return shared_tracker_element(v, &v->day_vec);
        }

        // Scalars are embedded, so share ownership with the RRD itself
        auto self = this->weak_from_this().lock();

        if (self == nullptr)
            return nullptr;

        if (id == ids.last_time)
            return shared_tracker_element(self, &last_time);
        if (id == ids.serial_time)
            return shared_tracker_element(self, &serial_time);
        if (id == ids.last_value)
            return shared_tracker_element(self, &last_value);
        if (id == ids.last_value_n1)
            return shared_tracker_element(self, &last_value_n1);
        if (id == ids.blank_val)
            return shared_tracker_element(self, &blank_val);

        return nullptr;
    }

    // Mutex must be held
    void fill_map() {
        auto self = this->weak_from_this().lock();

        if (self == nullptr)
            return;

        auto v = get_vec_children();
        v->minute_vec.get().assign(minute_vec.begin(), minute_vec.end());
        v->hour_vec.get().assign(hour_vec.begin(), hour_vec.end());
        v->day_vec.get().assign(day_vec.begin(), day_vec.end());

        map.reserve(8);
        insert(shared_tracker_element(self, &last_time));
        insert(shared_tracker_element(self, &serial_time));
        insert(shared_tracker_element(self, &last_value));
        insert(shared_tracker_element(self, &last_value_n1));
        insert(shared_tracker_element(v, &v->minute_vec));
        insert(shared_tracker_element(v, &v->hour_vec));
        insert(shared_tracker_element(v, &v->day_vec));
        insert(shared_tracker_element(self, &blank_val));
    }

    // Mutex must be held
    void release_map() {
        if (serialize_depth == 0 || --serialize_depth > 0)
            return;

        map.clear();
        map.shrink_to_fit();
    }

    constexpr size_t minutes_different(size_t m1, size_t m2) const {
        m1 = m1 % 60;
        m2 = m2 % 60;

        if (m1 == m2) {
            return 0;
        } else if (m1 < m2) {
            return m2 - m1;
        } else {
            return 60 - m1 + m2;
        }
    }

    constexpr size_t hours_different(size_t h1, size_t h2) const {
        h1 = h1 % 24;
        h2 = h2 % 24;

        if (h1 == h2) {
            return 0;
        } else if (h1 < h2) {
            return h2 - h1;
        } else {
            return 24 - h1 + h2;
        }
    }

    kis_mutex mutex;

    tracker_element_uint64 last_time;
    tracker_element_uint64 serial_time;

    tracker_element_double last_value;
    tracker_element_double last_value_n1;

    tracker_element_double blank_val;

    std::array<double, 60> minute_vec;
    std::array<double, 60> hour_vec;
    std::array<double, 24> day_vec;

    std::weak_ptr<vec_children> vec_cache;

    M_Aggregator m_agg;
    H_Aggregator h_agg;
    D_Aggregator d_agg;

    unsigned int serialize_depth;

    bool update_first;
};

// Easier to make this it's own class since for a single-minute RRD the logic is
// far simpler.  In a perfect would this would be derived from the common
// RRD (or the other way around) but until it becomes a problem that's a
// task for another day.
template <class Aggregator = kis_tracked_rrd_default_aggregator >
class kis_tracked_minute_rrd : public tracker_component,
    public std::enable_shared_from_this<kis_tracked_minute_rrd<Aggregator>> {
public:
    kis_tracked_minute_rrd() :
        kis_tracked_minute_rrd(0) { }

    kis_tracked_minute_rrd(int in_id) :
        tracker_component(in_id),
        last_time{field_ids().last_time},
        serial_time{field_ids().serial_time},
        last_value{field_ids().last_value},
        last_value_n1{field_ids().last_value_n1},
        blank_val{field_ids().blank_val, static_cast<double>(Aggregator::default_val())},
        minute_vec{},
        serialize_depth{0},
        update_first{true} {
        set_lazy_sub();
        mutex.set_name("kis_tracked_minute_rrd");
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_tracked_minute_rrd");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
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

    time_t get_last_time() const {
        return (time_t) last_time.get();
    }

    time_t get_serial_time() const {
        return (time_t) serial_time.get();
    }

    double get_last_value() const {
        return last_value.get();
    }

    double get_last_value_n1() const {
        return last_value_n1.get();
    }

    void add_sample(double in_s, time_t in_time) {
        kis_lock_guard<kis_mutex> lk(mutex, "kis_tracked_minute_rrd add_sample");

        // A negative time would index outside the buckets
        if (in_time < 0)
            return;

        size_t sec_bucket = in_time % 60;

        time_t ltime = get_last_time();

        // The second slot for the last time
        size_t last_sec_bucket = ltime % 60;

        if (in_time == ltime) {
            last_value_n1.set(last_value.get());
            last_value.set(agg.combine_element(last_value.get(), in_s));
        } else {
            last_value_n1.set(last_value.get());
            last_value.set(in_s);
        }

        // Allow backfilling w/in the past minute because packets might come out-of-order
        if (in_time < ltime) {
            if (ltime - in_time > 60)
                return;

            double v = minute_vec[sec_bucket];
            minute_vec[sec_bucket] = agg.combine_element(v, in_s);
        } else {
            // If we haven't seen data in a minute, wipe
            if (in_time - ltime > 60) {
                for (size_t x = 0; x < 60; x++) {
                    minute_vec[x] = agg.default_val();
                }
            } else {
                // If in_time == last_time then we're updating an existing record, so
                // add that in.
                // Otherwise, fast-forward seconds with zero data, average the seconds,
                // and propagate the averages up
                if (in_time == ltime) {
                    double v = minute_vec[sec_bucket];
                    minute_vec[sec_bucket] = agg.combine_element(v, in_s);
                } else {
                    for (size_t s = 0; s < minutes_different(last_sec_bucket + 1, sec_bucket); s++) {
                        minute_vec[(last_sec_bucket + 1 + s) % 60] = agg.default_val();
                    }

                    minute_vec[sec_bucket] = in_s;
                }
            }
        }

        last_time.set(in_time);
    }

    virtual void pre_serialize() override {
        kis_lock_guard<kis_mutex> lk(mutex, kismet::retain_lock, "kis_tracked_rrd serialize");

        tracker_component::pre_serialize();

        uint64_t now = Globalreg::globalreg->last_tv_sec;

        serial_time.set(now);

        if (update_first) {
            add_sample(agg.default_val(), now);
        }

        if (serialize_depth++ == 0)
            fill_map();
    }

    virtual void post_serialize() override {
        kis_lock_guard<kis_mutex> lk(mutex, std::adopt_lock);
        release_map();
    }

    virtual void as_json(std::ostream& os, struct json_adapter::opts *opts = nullptr) override {
        kis_lock_guard<kis_mutex> lk(mutex, "kis_tracked_minute_rrd as_json");

        if (serialize_depth++ == 0)
            fill_map();

        try {
            tracker_component::as_json(os, opts);
        } catch (...) {
            release_map();
            throw;
        }

        release_map();
    }

protected:
    static const kis_tracked_rrd_field_ids& field_ids() {
        static const kis_tracked_rrd_field_ids ids = register_field_ids();
        return ids;
    }

    static kis_tracked_rrd_field_ids register_field_ids() {
        auto& et = Globalreg::globalreg->entrytracker;
        kis_tracked_rrd_field_ids ids;

        ids.last_time = et->register_field("kismet.common.rrd.last_time",
                tracker_element_factory<tracker_element_uint64>(), "last time updated");
        ids.serial_time = et->register_field("kismet.common.rrd.serial_time",
                tracker_element_factory<tracker_element_uint64>(), "time of serialization");

        ids.last_value = et->register_field("kismet.common.rrd.last_value",
                tracker_element_factory<tracker_element_double>(), "last value of rrd");
        ids.last_value_n1 = et->register_field("kismet.common.rrd.last_value_n1",
                tracker_element_factory<tracker_element_double>(), "last value - 1 of rrd");

        ids.minute_vec = et->register_field("kismet.common.rrd.minute_vec",
                tracker_element_factory<tracker_element_vector_double>(), "past minute values per second");
        ids.hour_vec = -1;
        ids.day_vec = -1;

        et->register_field("kismet.common.rrd.second",
                tracker_element_factory<tracker_element_int64>(), "second value");

        ids.blank_val = et->register_field("kismet.common.rrd.blank_val",
                tracker_element_factory<tracker_element_double>(), "blank value");

        return ids;
    }

    // Mutex must be held
    std::shared_ptr<tracker_element_vector_double> get_vec_child() {
        auto v = vec_cache.lock();

        if (v == nullptr) {
            v = std::make_shared<tracker_element_vector_double>(field_ids().minute_vec);
            vec_cache = v;
        }

        v->get().assign(minute_vec.begin(), minute_vec.end());

        return v;
    }

    virtual shared_tracker_element get_lazy_sub(int id) override {
        const auto& ids = field_ids();

        if (id == ids.minute_vec) {
            kis_lock_guard<kis_mutex> lk(mutex, "kis_tracked_minute_rrd get_sub");
            return get_vec_child();
        }

        // Scalars are embedded, so share ownership with the RRD itself
        auto self = this->weak_from_this().lock();

        if (self == nullptr)
            return nullptr;

        if (id == ids.last_time)
            return shared_tracker_element(self, &last_time);
        if (id == ids.serial_time)
            return shared_tracker_element(self, &serial_time);
        if (id == ids.last_value)
            return shared_tracker_element(self, &last_value);
        if (id == ids.last_value_n1)
            return shared_tracker_element(self, &last_value_n1);
        if (id == ids.blank_val)
            return shared_tracker_element(self, &blank_val);

        return nullptr;
    }

    // Mutex must be held
    void fill_map() {
        auto self = this->weak_from_this().lock();

        if (self == nullptr)
            return;

        map.reserve(6);
        insert(shared_tracker_element(self, &last_time));
        insert(shared_tracker_element(self, &serial_time));
        insert(shared_tracker_element(self, &last_value));
        insert(shared_tracker_element(self, &last_value_n1));
        insert(get_vec_child());
        insert(shared_tracker_element(self, &blank_val));
    }

    // Mutex must be held
    void release_map() {
        if (serialize_depth == 0 || --serialize_depth > 0)
            return;

        map.clear();
        map.shrink_to_fit();
    }

    inline size_t minutes_different(int m1, int m2) const {
        // Sanity check
        m1 = m1 % 60;
        m2 = m2 % 60;

        if (m1 == m2) {
            return 0;
        } else if (m1 < m2) {
            return m2 - m1;
        } else {
            return 60 - m1 + m2;
        }
    }

    kis_mutex mutex;

    Aggregator agg;

    tracker_element_uint64 last_time;
    tracker_element_uint64 serial_time;
    tracker_element_double last_value;
    tracker_element_double last_value_n1;
    tracker_element_double blank_val;

    std::array<double, 60> minute_vec;

    std::weak_ptr<tracker_element_vector_double> vec_cache;

    unsigned int serialize_depth;

    bool update_first;
};

// Signal level RRD, peak selector on overlap, averages signal but ignores
// empty slots
class kis_tracked_rrd_peak_signal_aggregator {
public:
    // Select the stronger signal
    static double combine_element(const double a, const double b) {
        if (a == 0)
            return b;
        if (b == 0)
            return a;

        if (a < b)
            return b;

        return a;
    }

    // Average the non-empty signals of the bucket
    template<typename C>
    static double combine_vector(const C& e) {
        double avg = 0, avgc = 0;

        for (const auto& i : e) {
            double v = i;

            if (v == 0)
                continue;

            avg += v;
            avgc++;
        }

        if (avgc == 0)
            return default_val();

        return avg / avgc;
    }

    // Default 'empty' value, no legit signal would be 0
    static double default_val() {
        return (double) 0;
    }

    static std::string name() {
        return "peak_signal";
    }
};

// Signal level RRDs of the weakest or strongest reading.  Samples in the same slot,
// and the rollup of each level into the next, keep the weakest (or strongest) signal,
// skipping empty slots; the pair gives the range of signal heard in each second,
// minute, and hour.
template <bool Strongest>
class kis_tracked_rrd_signal_range_aggregator {
public:
    static double combine_element(const double a, const double b) {
        if (a == 0)
            return b;
        if (b == 0)
            return a;

        return Strongest ? std::max(a, b) : std::min(a, b);
    }

    template<typename C>
    static double combine_vector(const C& e) {
        double r = default_val();

        for (const auto& v : e)
            r = combine_element(r, v);

        return r;
    }

    // No legit signal would be 0
    static constexpr double default_val() {
        return 0;
    }

    static std::string name() {
        return Strongest ? "max_signal" : "min_signal";
    }
};

using kis_tracked_rrd_min_signal_aggregator = kis_tracked_rrd_signal_range_aggregator<false>;
using kis_tracked_rrd_max_signal_aggregator = kis_tracked_rrd_signal_range_aggregator<true>;

// Generic RRD, extreme selector.  If both values are > 0, selects the highest.
// If both values are below zero, selects the lowest.  If values are mixed,
// selects the lowest.  The same logic is applied when promoting to the next
// precision slot
class kis_tracked_rrd_extreme_aggregator {
public:
    // Select the most extreme value
    static double combine_element(const double a, const double b) {
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

    template<typename C>
    static double combine_vector(const C& e) {
        double extreme = 0;

        for (const auto& i : e) {
            extreme = combine_element(extreme, i);
        }

        return extreme;
    }

    // Default 'empty' value, no legit signal would be 0
    static double default_val() {
        return (double) 0;
    }

    static std::string name() {
        return "extreme";
    }
};

// Selects the most extreme value of the previous range; expects positive values
class kis_tracked_rrd_prev_pos_extreme_aggregator {
public:
    // Select the most extreme value
    static double combine_element(const double a, const double b) {
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

    // Largest value
    template<typename C>
    static double combine_vector(const C& e) {
        double most = 0;

        for (const auto& i : e) {
            if (i > most) {
                most = i;
            }
        }

        return most;
    }

    // Default 'empty' value, no legit signal would be 0
    static double default_val() {
        return (double) 0;
    }

    static std::string name() {
        return "prev_pos_extreme";
    }
};



#endif

