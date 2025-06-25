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
    kis_tracked_location_triplet(const kis_tracked_location_triplet*);

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::globalreg->entrytracker->new_from_pool<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_tracked_location_triplet");
    }

    static uint32_t get_static_signature() {
        return adler32_checksum("kis_tracked_location_triplet");
    }

    // lat/lon are encoded in the geopoint
    double get_lat() const {
        return std::get<1>(geopoint->get());
    }

    double get_lon() const {
        return std::get<0>(geopoint->get());
    }

    void set_location(double lat, double lon) {
        geopoint->set(lon, lat);
    }

    __ProxyFullyDynamic(alt, float, float, float, tracker_element_float, alt_id);
    __ProxyFullyDynamic(fix, uint8_t, uint8_t, uint8_t, tracker_element_uint8, fix_id);
    __ProxyFullyDynamic(time_sec, uint64_t, time_t, time_t, tracker_element_uint64, time_sec_id);
    __ProxyFullyDynamic(time_usec, uint64_t, uint64_t, uint64_t, tracker_element_uint64, time_usec_id);

    bool get_valid() {
        if (has_fix())
            return get_fix() >= 2;
        return false;
    }

    void set(double in_lat, double in_lon, float in_alt, unsigned int in_fix);
    void set(double in_lat, double in_lon);
    virtual void set(kis_gps_packinfo *in_packinfo);

    virtual void set(std::shared_ptr<kis_gps_packinfo> in_pi) {
        set(in_pi.get());
    }

	inline kis_tracked_location_triplet& operator= (const kis_tracked_location_triplet& in);

    void reset() {
        geopoint->reset();
        clear_alt();
        clear_fix();
        clear_time_sec();
        clear_time_usec();
    }

protected:
    virtual void register_fields() override;
    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override;

    std::shared_ptr<tracker_element_pair_double> geopoint;

    uint16_t alt_id;
    uint16_t fix_id;
    uint16_t time_sec_id;
    uint16_t time_usec_id;
};

class kis_tracked_location_full : public kis_tracked_location_triplet {
public:
    kis_tracked_location_full();
    kis_tracked_location_full(int in_id);
    kis_tracked_location_full(int in_id, std::shared_ptr<tracker_element_map> e);
    kis_tracked_location_full(const kis_tracked_location_full *);

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::globalreg->entrytracker->new_from_pool<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_tracked_location_full");
    }

    static uint32_t get_static_signature() {
        return adler32_checksum("kis_tracked_location_full");
    }

    __ProxyFullyDynamic(speed, float, float, float, tracker_element_float, spd_id);
    __ProxyFullyDynamic(heading, float, float, float, tracker_element_float, heading_id);
    __ProxyFullyDynamic(magheading, float, float, float, tracker_element_float, magheading_id);

    virtual void set(kis_gps_packinfo *in_packinfo) override;

	inline kis_tracked_location_full& operator= (const kis_tracked_location_full& in);

    void reset() {
        kis_tracked_location_triplet::reset();
        clear_speed();
        clear_heading();
        clear_magheading();
    }

protected:
    virtual void register_fields() override;
    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override;

    uint16_t spd_id;
    uint16_t heading_id;
    uint16_t magheading_id;
};

class kis_tracked_location : public tracker_component {
public:
    kis_tracked_location();
    kis_tracked_location(int in_id);
    kis_tracked_location(int in_id, std::shared_ptr<tracker_element_map> e);
    kis_tracked_location(const kis_tracked_location *);

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    void add_loc(double in_lat, double in_lon, double in_alt, unsigned int fix,
            double in_speed, double in_heading);

    void add_loc_with_avg(double in_lat, double in_lon, double in_alt, unsigned int fix,
            double in_speed, double in_heading);

    __Proxy(fix, uint8_t, unsigned int, unsigned int, loc_fix);

    bool get_valid() const {
        return get_fix() >= 2;
    }

    bool has_min_loc() { return min_loc != nullptr; }
    std::shared_ptr<kis_tracked_location_triplet> get_min_loc() { return min_loc; }
    bool has_max_loc() { return max_loc != nullptr; }
    std::shared_ptr<kis_tracked_location_triplet> get_max_loc() { return max_loc; }
    bool has_avg_loc() { return avg_loc != nullptr; }
    std::shared_ptr<kis_tracked_location_triplet> get_avg_loc() { return avg_loc; }
    bool has_last_loc() { return last_loc != nullptr; }
    std::shared_ptr<kis_tracked_location_full> get_last_loc() { return last_loc; }

    time_t get_last_location_time() const {
        return last_location_time;
    }

    void set_last_location_time(time_t t) {
        last_location_time = t;
    }

    void reset() {
        if (min_loc)
            min_loc->reset();

        if (max_loc)
            max_loc->reset();

        if (avg_loc)
            avg_loc->reset();

        if (last_loc)
            last_loc->reset();

        agg_x = agg_y = agg_z = agg_a = 0;
        num_avg = num_alt_avg = 0;
        last_location_time = 0;
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

// Historic location track; used in the averaging / rrd historic location.
// Signal is tracked agnostically as whatever type of signal the owning device
// presents (dbm or rssi)
class kis_historic_location : public tracker_component {
public:
    kis_historic_location() :
        tracker_component(0) {
            register_fields();
            reserve_fields(NULL);
        }

    kis_historic_location(int in_id) : 
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        } 

    kis_historic_location(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    kis_historic_location(const kis_historic_location *p) :
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

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
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

    __Proxy(heading, double, double, double, heading);
    __Proxy(alt, double, double, double, alt);
    __Proxy(speed, double, double, double, speed);
    __Proxy(signal, int32_t, int32_t, int32_t, signal);
    __Proxy(time_sec, uint64_t, time_t, time_t, time_sec);
    __Proxy(frequency, uint64_t, uint64_t, uint64_t, frequency);

protected:
    void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.historic.location.geopoint", "[lon, lat] point", &geopoint);
        register_field("kismet.historic.location.alt", "altitude (m)", &alt);
        register_field("kismet.historic.location.speed", "speed (kph)", &speed);
        register_field("kismet.historic.location.heading", "heading (degrees)", &heading);
        register_field("kismet.historic.location.signal", "signal", &signal);
        register_field("kismet.historic.location.time_sec", "time (unix ts)", &time_sec);
        register_field("kismet.historic.location.frequency", "frequency (khz)", &frequency);
    }

    void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);
        geopoint->set({0, 0});
    }

    std::shared_ptr<tracker_element_vector_double> geopoint;
    std::shared_ptr<tracker_element_double> alt;
    std::shared_ptr<tracker_element_double> heading; 
    std::shared_ptr<tracker_element_double> speed;

    std::shared_ptr<tracker_element_int32> signal;
    std::shared_ptr<tracker_element_uint64> frequency;

    std::shared_ptr<tracker_element_uint64> time_sec;
};

// RRD-like history track
class kis_location_rrd : public tracker_component {
public:
    kis_location_rrd() :
        tracker_component{0} {
        register_fields();
        reserve_fields(nullptr);
        samples_10k_cascade = 0;
        samples_100_cascade = 0;
    }

    kis_location_rrd(int in_id) :
        tracker_component{in_id} {
        register_fields();
        reserve_fields(nullptr);
        samples_10k_cascade = 0;
        samples_100_cascade = 0;
    }

    kis_location_rrd(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
        samples_10k_cascade = 0;
        samples_100_cascade = 0;
    }

    kis_location_rrd(const kis_location_rrd* p) :
        tracker_component{p} {

            __ImportField(samples_100, p);
            __ImportField(samples_10k, p);
            __ImportField(samples_1m, p);
            __ImportField(last_sample_ts, p);

            __ImportField(historic_location_builder, p);

        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_location_rrd");
    }

    static uint32_t get_static_signature() {
        return adler32_checksum("kis_location_rrd");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::shared_ptr<this_t>(new this_t(this));
        dup->set_id(this->get_id());
        return dup;
    }

    void add_sample(std::shared_ptr<kis_historic_location> in_sample) {
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
                Globalreg::globalreg->entrytracker->new_from_pool<kis_historic_location>(historic_location_builder.get());

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
                    Globalreg::globalreg->entrytracker->new_from_pool<kis_historic_location>(historic_location_builder.get());

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

    __ProxyPrivSplit(last_sample_ts, uint64_t, time_t, time_t, last_sample_ts);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kis.gps.rrd.samples_100",
            "last 100 historic GPS records", &samples_100);
        register_field("kis.gps.rrd.samples_10k",
            "last 10,000 historic GPS records, as averages of 100",
            &samples_10k);
        register_field("kis.gps.rrd.samples_1m",
            "last 1,000,000 historic GPS records, as averages of 10,000",
            &samples_1m);
        register_field("kis.gps.rrd.last_sample_ts",
            "time (unix ts) of last sample", &last_sample_ts);

        historic_location_builder = 
            Globalreg::globalreg->entrytracker->new_from_pool<kis_historic_location>();
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        samples_100_cascade = 0;
        samples_10k_cascade = 0;
    }

    std::shared_ptr<tracker_element_vector> samples_100;
    std::shared_ptr<tracker_element_vector> samples_10k;
    std::shared_ptr<tracker_element_vector> samples_1m;
    
    std::shared_ptr<tracker_element_uint64> last_sample_ts;

    std::shared_ptr<kis_historic_location> historic_location_builder;

    unsigned int samples_100_cascade;
    unsigned int samples_10k_cascade;

};

#endif

