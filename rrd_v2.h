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


#ifndef __RRD_V2_H__
#define __RRD_V2_H__

#include <stdint.h>
#include <time.h>

#include <array>

#include "json_adapter_v2.h"
#include "kis_mutex.h"

class kis_rrd_v2_default_aggregator {
public:
    template<class InputIt>
    static double combine(InputIt first, InputIt last) {
        double avg = 0;
        double n = 0;
        for (; first != last; ++first) {
            avg += *first;
            n++;
        }

        return avg / n;
    }

    static double combine(double v, size_t sz) {
        return v / sz;
    }

    static double combine(double v1, double v2) {
        return (v1 + v2) / 2;
    }

    static double default_value() {
        return (double) 0;
    }

    static std::string name() {
        return "default";
    }
};

template <class M_Aggregator = kis_rrd_v2_default_aggregator,
         class H_Aggregator = M_Aggregator,
         class D_Aggregator = M_Aggregator>
class kis_rrd_v2 : public json_adapter_v2::jsonable {
public:
    kis_rrd_v2() :
        update_first{true},
        last_time{0},
        serial_time{0},
        last_value{M_Aggregator::default_value()},
        last_value_n1{M_Aggregator::default_value()} {
            m_array.fill(M_Aggregator::default_value());
            h_array.fill(M_Aggregator::default_value());
            d_array.fill(M_Aggregator::default_value());
        }

    kis_rrd_v2(kis_rrd_v2&& r) :
        update_first{r.update_first},
        last_time{r.last_time},
        serial_time{r.serial_time},
        last_value{r.last_value},
        last_value_n1{r.last_value_n1},
        m_array{std::move(r.m_array)},
        h_array{std::move(r.h_array)},
        d_array{std::move(r.d_array)} { }

    // Add a sample.  Use combinator function 'c' to derive the new sample value
    void add_sample(double in_s, time_t in_time) {
        kis_lock_guard<kis_mutex> lk(mutex, "kis_tracked_rrd add_sample");

        size_t sec_bucket = in_time % 60;
        size_t min_bucket = (in_time / 60) % 60;
        size_t hour_bucket = (in_time / 3600) % 24;

        time_t ltime = last_time;

        // The second slot for the last time
        const size_t last_sec_bucket = ltime % 60;
        // The minute of the hour the last known data would go in
        const size_t last_min_bucket = (ltime / 60) % 60;
        // The hour of the day the last known data would go in
        const size_t last_hour_bucket = (ltime / 3600) % 24;

        last_value_n1 = last_value;
        if (in_time == ltime) {
            last_value = M_Aggregator::combine(last_value, in_s);
        } else {
            last_value = in_s;
        }

        // Allow backfilling w/in the past minute because packets might come out-of-order
        if (in_time < ltime) {
            if (ltime - in_time > 60)
                return;

            double v = m_array[sec_bucket];
            m_array[sec_bucket] = M_Aggregator::combine(v, in_s);
        } else {
            // If we haven't seen data in a day, we reset everything because
            // none of it is valid.  This is the simplest case.
            if (in_time - ltime > (60 * 60 * 24)) {
                // Directly fill in this second, clear rest of the minute
                m_array.fill(M_Aggregator::default_value());
                m_array[sec_bucket] = in_s;

                // Reset the last hour, setting it to a single sample
                // Get the combined value for the minute
                // double min_val = H_Aggregator::combine(m_array.begin(), m_array.end());
                double min_val = H_Aggregator::combine(in_s, m_array.size());
                h_array.fill(M_Aggregator::default_value());
                h_array[min_bucket] = min_val;

                // Reset the last day, setting it to a single sample
                // double hr_val = D_Aggregator::combine(h_array.begin(), h_array.end());
                double hr_val = D_Aggregator::combine(min_val, h_array.size());
                d_array.fill(M_Aggregator::default_value());
                d_array[hour_bucket] = hr_val;

                last_time = in_time;

                return;
            } else if (in_time - ltime > (60*60)) {
                // printf("debug - rrd - been an hour since last value\n");
                // If we haven't seen data in an hour but we're still w/in the day:
                //   - Average the seconds we know about & set the minute record
                //   - Clear seconds data & set our current value
                //   - Average the minutes we know about & set the hour record
                //

                // We only have this entry in the minute, so set it and get the
                // combined value

                m_array.fill(M_Aggregator::default_value());
                m_array[sec_bucket] = in_s;

                double min_val = H_Aggregator::combine(in_s, m_array.size());
                h_array.fill(M_Aggregator::default_value());
                h_array[min_bucket] = min_val;

                // Fill the hours between the last time we saw data and now with
                // zeroes; fastforward time
                for (size_t h = 0; h < hours_different(last_hour_bucket + 1, hour_bucket); h++) {
                    d_array[(last_hour_bucket + 1 + h) % 24] = M_Aggregator::default_value();
                }

                d_array[hour_bucket] = min_val;
            } else if (in_time - ltime > 60) {
                // - Calculate the average seconds
                // - Wipe the seconds
                // - Set the new second value
                // - Update minutes
                // - Update hours
                // printf("debug - rrd - been over a minute since last value\n");


                m_array.fill(M_Aggregator::default_value());
                m_array[sec_bucket] = in_s;

                double min_val = M_Aggregator::combine(in_s, m_array.size());

                // Zero between last and current
                for (size_t m = 0; m < minutes_different(last_min_bucket + 1, min_bucket); m++) {
                    h_array[(last_min_bucket + 1 + m) % h_array.size()] = M_Aggregator::default_value();
                }

                h_array[min_bucket] = min_val;

                double hr_val = H_Aggregator::combine(h_array.begin(), h_array.end());
                d_array[hour_bucket] = hr_val;
            } else {
                if (in_time == ltime) {
                    double v = m_array[sec_bucket];
                    m_array[sec_bucket] = M_Aggregator::combine(v, in_s);
                } else {
                    for (size_t s = 0; s < minutes_different(last_sec_bucket + 1, sec_bucket); s++) {
                        m_array[(last_sec_bucket + 1 + s) % m_array.size()] = M_Aggregator::default_value();
                    }
                    m_array[sec_bucket] = in_s;
                }

                double min_val = M_Aggregator::combine(m_array.begin(), m_array.end());
                h_array[min_bucket] = min_val;

                double hr_val = H_Aggregator::combine(h_array.begin(), h_array.end());
                d_array[hour_bucket] = hr_val;
            }
        }

        last_time = in_time;
    }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override {
        // TODO handle field simplification, pretty printing

        auto lg = kis_lock_guard(mutex, __func__);

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        fmt::print(os, "{{");

        json_adapter_v2::encode_keyed(os, "kismet.common.rrd.last_time", opts, last_time);
        json_adapter_v2::encode_keyed(os, "kismet.common.rrd.serial_time", opts, serial_time);
        json_adapter_v2::encode_keyed(os, "kismet.common.rrd.last_value", opts, last_value);
        json_adapter_v2::encode_keyed(os, "kismet.common.rrd.last_value_n1", opts, last_value_n1);

        json_adapter_v2::encode_keyed(os, "kismet.common.rrd.minute_vec", opts, m_array.begin(), m_array.end());
        json_adapter_v2::encode_keyed(os, "kismet.common.rrd.hour_vec", opts, h_array.begin(), h_array.end());
        json_adapter_v2::encode_keyed(os, "kismet.common.rrd.day_vec", opts, d_array.begin(), d_array.end());

        json_adapter_v2::encode_keyed(os, "kismet.common.rrd.blank_val", opts, M_Aggregator::default_value());

        fmt::print(os, "}}");

        opts->next_key_comma = sv_comma;
    }

protected:
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

    constexpr size_t days_different(size_t d1, size_t d2) const {
        d1 = d1 % 7;
        d2 = d2 % 7;

        if (d1 == d2) {
            return 0;
        } else if (d1 < d2) {
            return d2 - d1;
        } else {
            return 7 - d1 + d2;
        }
    }

    kis_mutex mutex;

    M_Aggregator m_agg;
    H_Aggregator h_agg;
    D_Aggregator d_agg;

    bool update_first;

    time_t last_time, serial_time;

    double last_value;
    double last_value_n1;

    std::array<double, 60> m_array;
    std::array<double, 60> h_array;
    std::array<double, 24> d_array;
};

#endif /* __RRD_V2_H__ */
