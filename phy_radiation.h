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

#ifndef __PHY_RADIATION_H__
#define __PHY_RADIATION_H__

#include "config.h"

#include <array>
#include <deque>

#include "configfile.h"
#include "globalregistry.h"
#include "kis_datasource.h"
#include "packet.h"
#include "phyhandler.h"

// One spectrum window, built on request for the spectrum endpoint and log
class radiation_spectrum : public tracker_component {
public:
    radiation_spectrum() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    radiation_spectrum(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    radiation_spectrum(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    radiation_spectrum(const radiation_spectrum *p) :
        tracker_component{p} {
        __ImportField(window, p);
        __ImportField(channels, p);
        __ImportField(calibration, p);
        __ImportField(start_time, p);
        __ImportField(end_time, p);
        __ImportField(duration, p);
        __ImportField(total, p);
        __ImportField(counts, p);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("radiation_spectrum");
    }

    virtual ~radiation_spectrum() { }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(window, std::string, std::string, std::string, window);
    __Proxy(channels, uint32_t, uint32_t, uint32_t, channels);
    __Proxy(start_time, uint64_t, uint64_t, uint64_t, start_time);
    __Proxy(end_time, uint64_t, uint64_t, uint64_t, end_time);
    __Proxy(duration, double, double, double, duration);
    __Proxy(total, uint64_t, uint64_t, uint64_t, total);

    std::shared_ptr<tracker_element_vector_double> get_calibration() { return calibration; }
    std::shared_ptr<tracker_element_vector_double> get_counts() { return counts; }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("radiation.spectrum.window", "Spectrum window (device, session, hour, minute)", &window);
        register_field("radiation.spectrum.channels", "Number of channels", &channels);
        register_field("radiation.spectrum.calibration",
                "Energy calibration a0, a1, a2; keV of channel n is a0 + a1*n + a2*n^2 (empty if unknown)",
                &calibration);
        register_field("radiation.spectrum.start_time", "Start of the window", &start_time);
        register_field("radiation.spectrum.end_time", "End of the window", &end_time);
        register_field("radiation.spectrum.duration", "Counting time in the window, seconds", &duration);
        register_field("radiation.spectrum.total", "Total counts in the window", &total);
        register_field("radiation.spectrum.counts", "Counts per channel", &counts);
    }

    std::shared_ptr<tracker_element_string> window;
    std::shared_ptr<tracker_element_uint32> channels;
    std::shared_ptr<tracker_element_vector_double> calibration;
    std::shared_ptr<tracker_element_uint64> start_time;
    std::shared_ptr<tracker_element_uint64> end_time;
    std::shared_ptr<tracker_element_double> duration;
    std::shared_ptr<tracker_element_uint64> total;
    std::shared_ptr<tracker_element_vector_double> counts;
};

// The spectrum windows of one sensor
class radiation_spectrum_report : public tracker_component {
public:
    radiation_spectrum_report() :
        tracker_component() {
        register_fields();
        reserve_fields(nullptr);
    }

    radiation_spectrum_report(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    radiation_spectrum_report(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    radiation_spectrum_report(const radiation_spectrum_report *p) :
        tracker_component{p} {
        __ImportField(sensor, p);
        __ImportId(device_id, p);
        __ImportId(session_id, p);
        __ImportId(hour_id, p);
        __ImportId(minutes_id, p);
        __ImportId(minute_entry_id, p);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("radiation_spectrum_report");
    }

    virtual ~radiation_spectrum_report() { }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(sensor, uuid, uuid, uuid, sensor);

    __ProxyDynamicTrackable(device, radiation_spectrum, device, device_id);
    __ProxyDynamicTrackable(session, radiation_spectrum, session, session_id);
    __ProxyDynamicTrackable(hour, radiation_spectrum, hour, hour_id);
    __ProxyDynamicTrackable(minutes, tracker_element_vector, minutes, minutes_id);

    std::shared_ptr<radiation_spectrum> make_minute() {
        return std::make_shared<radiation_spectrum>(minute_entry_id);
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("radiation.spectrum.sensor", "Sensor (datasource) UUID", &sensor);

        device_id = register_dynamic_field("radiation.spectrum.device",
                "Spectrum accumulated by the sensor itself", &device);
        session_id = register_dynamic_field("radiation.spectrum.session",
                "Spectrum counted since Kismet started tracking the sensor", &session);
        hour_id = register_dynamic_field("radiation.spectrum.hour",
                "Spectrum counted over the past hour", &hour);
        minutes_id = register_dynamic_field("radiation.spectrum.minutes",
                "Per-minute spectra over the past hour, oldest first", &minutes);
        minute_entry_id = register_field("radiation.spectrum.minute",
                tracker_element_factory<radiation_spectrum>(), "Spectrum for one minute");
    }

    std::shared_ptr<tracker_element_uuid> sensor;

    std::shared_ptr<radiation_spectrum> device;
    uint16_t device_id;
    std::shared_ptr<radiation_spectrum> session;
    uint16_t session_id;
    std::shared_ptr<radiation_spectrum> hour;
    uint16_t hour_id;
    std::shared_ptr<tracker_element_vector> minutes;
    uint16_t minutes_id;
    uint16_t minute_entry_id;
};

// Spectrum counts kept per sensor: the spectrum the sensor accumulates itself (when it
// keeps one), everything counted this session, and per-minute counts for the past hour.
// Kept out of the tracked fields so the sensor list and eventbus stay small; the
// spectrum endpoint builds radiation_spectrum records from it.
class radiation_spectrum_history {
public:
    static constexpr size_t max_bins = 4096;
    static constexpr size_t minute_slots = 60;

    // A spectrum the sensor accumulates; the change since the previous one is counted.
    // A sensor-side reset (counts or duration going down) counts the new spectrum whole.
    bool set_device(time_t ts, double duration, std::vector<uint64_t>&& counts,
            const std::array<double, 3>& calib);

    // Counts from one interval, for sensors that send each interval's counts
    bool add_interval(time_t ts, const std::vector<uint64_t>& counts);

    size_t channels() const { return n_channels; }
    time_t last_time() const { return session_end; }
    double session_duration() const { return session_dur; }
    uint64_t session_total() const { return session_sum; }

    void fill_device(const std::shared_ptr<radiation_spectrum>& out) const;
    void fill_session(const std::shared_ptr<radiation_spectrum>& out) const;
    // Sum of the per-minute counts within the hour before now
    bool fill_hour(const std::shared_ptr<radiation_spectrum>& out, time_t now) const;
    // One minute's counts, if that minute is still held
    bool fill_minute(const std::shared_ptr<radiation_spectrum>& out, int64_t minute) const;

    bool has_device() const { return have_device; }

    // Minutes are logged once, after they end
    int64_t last_logged_minute = -1;

protected:
    struct minute_slot {
        int64_t minute = -1;
        double duration = 0;
        std::vector<uint32_t> counts;
    };

    void reset(size_t n);
    void add_delta(time_t ts, double duration, const std::vector<uint64_t>& delta);
    void fill_common(const std::shared_ptr<radiation_spectrum>& out, const std::string& window) const;

    size_t n_channels = 0;

    bool have_calib = false;
    std::array<double, 3> calib{};

    bool have_device = false;
    time_t device_time = 0;
    double device_duration = 0;
    std::vector<uint64_t> device_counts;

    time_t session_start = 0;
    time_t session_end = 0;
    double session_dur = 0;
    uint64_t session_sum = 0;
    std::vector<uint64_t> session_counts;

    time_t last_interval = 0;

    std::array<minute_slot, minute_slots> minutes;
};

// Recent readings and per-minute count rate means, for the alerts and the dose track
class radiation_reading_history {
public:
    static constexpr size_t recent_slots = 16;
    static constexpr size_t minute_slots = 60;

    void add(time_t ts, double cps, double usv, bool has_usv);

    // Mean of the readings in the window of seconds before now; the number of readings
    size_t recent(time_t now, time_t window, double& cps, double& usv, bool& has_usv) const;

    // Mean count rate over the past hour, leaving out the current and previous minute
    // so a rise isn't counted as background straight away
    bool baseline(time_t now, double& cps, size_t& minutes) const;

    bool dose_alerted = false;
    bool rise_alerted = false;

protected:
    struct reading {
        time_t ts = 0;
        double cps = 0;
        double usv = 0;
        bool has_usv = false;
    };

    struct minute_mean {
        int64_t minute = -1;
        double sum = 0;
        uint32_t n = 0;
    };

    std::array<reading, recent_slots> readings;
    size_t next_reading = 0;
    std::array<minute_mean, minute_slots> minutes;
};

// Readings at a GPS location; readings within a few meters of the previous point are
// added to it
struct radiation_track_point {
    time_t first = 0;
    time_t last = 0;
    double lat = 0;
    double lon = 0;
    double cps_sum = 0;
    double usv_sum = 0;
    double usv_max = 0;
    uint32_t n = 0;
    bool has_usv = false;
};

class geiger_device : public tracker_component {
public:
    geiger_device() :
        tracker_component() {
            register_fields();
            reserve_fields(nullptr);
        }

    geiger_device(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(nullptr);
        }

    geiger_device(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    geiger_device(const geiger_device *p):
        tracker_component(p) {
            spectrum = p->spectrum;
            readings = p->readings;
            track = p->track;

            __ImportField(cps_rrd, p);
            __ImportField(usv_rrd, p);
            __ImportField(src_alias, p);
            __ImportField(cps_err, p);
            __ImportField(usv_err, p);
            __ImportField(dose_total, p);
            __ImportField(dose_total_duration, p);
            __ImportField(temperature, p);
            __ImportField(battery, p);
            __ImportField(last_status_time, p);
            __ImportField(spectrum_channels, p);
            __ImportField(spectrum_time, p);
            __ImportField(spectrum_session_duration, p);
            __ImportField(spectrum_session_total, p);

            cps_rrd->update_before_serialize(false);
            usv_rrd->update_before_serialize(false);
        }

    void insert_cps_usv(time_t ts, double cps, double usv) {
        cps_rrd->add_sample(cps, ts);
        usv_rrd->add_sample(usv, ts);
        readings.add(ts, cps, usv, true);
    }

    void set_errors(double cps_err_pct, double usv_err_pct) {
        cps_err->set(cps_err_pct);
        usv_err->set(usv_err_pct);
    }

    void set_status(time_t ts, double dose_usv, uint64_t dose_duration,
            double temperature_c, double battery_pct) {
        dose_total->set(dose_usv);
        dose_total_duration->set(dose_duration);
        temperature->set(temperature_c);
        battery->set(battery_pct);
        last_status_time->set(ts);
    }

    // CPS with the counts from that interval (Radview)
    void insert_cps_record(time_t ts, double cps, const std::vector<uint64_t>& interval_counts) {
        cps_rrd->add_sample(cps, ts);
        readings.add(ts, cps, 0, false);

        if (spectrum.add_interval(ts, interval_counts))
            update_spectrum_summary();
    }

    // Spectrum the sensor accumulates itself (Radiacode)
    void insert_device_spectrum(time_t ts, double duration, std::vector<uint64_t>&& counts,
            const std::array<double, 3>& calib) {
        if (spectrum.set_device(ts, duration, std::move(counts), calib))
            update_spectrum_summary();
    }

    radiation_spectrum_history& get_spectrum() { return spectrum; }
    radiation_reading_history& get_readings() { return readings; }
    std::deque<radiation_track_point>& get_track() { return track; }

    std::string sensor_name() {
        auto ds = std::static_pointer_cast<kis_datasource>(src_alias->get());
        if (ds != nullptr) {
            auto n = ds->get_source_name();
            if (n.length())
                return n;
        }
        return get_detector_type();
    }

    __Proxy(detector_type, std::string, std::string, std::string, detector_type);

    void set_src_alias(std::shared_ptr<kis_datasource> src) {
        src_alias->set(src);
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("radiation.sensor.cps_rrd", "Counts-per-second RRD", &cps_rrd);
        register_field("radiation.sensor.usv_rrd", "Dose rate RRD, uSv/h (if available)", &usv_rrd);
        register_field("radiation.sensor.cps_err", "Counts-per-second error, percent (if available)", &cps_err);
        register_field("radiation.sensor.usv_err", "Dose rate error, percent (if available)", &usv_err);
        register_field("radiation.sensor.dose_total", "Accumulated dose reported by the sensor, uSv", &dose_total);
        register_field("radiation.sensor.dose_total_duration",
                "Time the accumulated dose covers, seconds", &dose_total_duration);
        register_field("radiation.sensor.temperature", "Sensor temperature, C", &temperature);
        register_field("radiation.sensor.battery", "Sensor battery charge, percent", &battery);
        register_field("radiation.sensor.last_status_time",
                "Last sensor status report (dose, temperature, battery), 0 if none", &last_status_time);
        register_field("radiation.sensor.type", "Detector type/brand", &detector_type);

        register_field("radiation.sensor.spectrum_channels",
                "Spectrum channels, 0 if the sensor sends no spectrum", &spectrum_channels);
        register_field("radiation.sensor.spectrum_time", "Last spectrum update", &spectrum_time);
        register_field("radiation.sensor.spectrum_session_duration",
                "Counting time in the session spectrum, seconds", &spectrum_session_duration);
        register_field("radiation.sensor.spectrum_session_total",
                "Total counts in the session spectrum", &spectrum_session_total);

        register_field("radiation.sensor.datasource", "Datasource", &src_alias);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        cps_rrd->update_before_serialize(false);
        usv_rrd->update_before_serialize(false);
    }

    void update_spectrum_summary() {
        spectrum_channels->set(spectrum.channels());
        spectrum_time->set(spectrum.last_time());
        spectrum_session_duration->set(spectrum.session_duration());
        spectrum_session_total->set(spectrum.session_total());
    }

    std::shared_ptr<tracker_element_string> detector_type;
    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> cps_rrd;
    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> usv_rrd;

    std::shared_ptr<tracker_element_alias> src_alias;

    std::shared_ptr<tracker_element_double> cps_err;
    std::shared_ptr<tracker_element_double> usv_err;
    std::shared_ptr<tracker_element_double> dose_total;
    std::shared_ptr<tracker_element_uint64> dose_total_duration;
    std::shared_ptr<tracker_element_double> temperature;
    std::shared_ptr<tracker_element_double> battery;
    std::shared_ptr<tracker_element_uint64> last_status_time;

    std::shared_ptr<tracker_element_uint32> spectrum_channels;
    std::shared_ptr<tracker_element_uint64> spectrum_time;
    std::shared_ptr<tracker_element_double> spectrum_session_duration;
    std::shared_ptr<tracker_element_uint64> spectrum_session_total;

    radiation_spectrum_history spectrum;
    radiation_reading_history readings;
    std::deque<radiation_track_point> track;
};

class kis_radiation_phy : public kis_phy_handler {
public:
    virtual ~kis_radiation_phy();

    kis_radiation_phy() :
        kis_phy_handler() {
            indexed = false;
        };

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_radiation_phy(in_phyid);
    }

    kis_radiation_phy(int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

    std::shared_ptr<geiger_device> find_or_create_sensor(const uuid& src_uuid, const std::string& type);

    std::shared_ptr<radiation_spectrum_report> build_spectrum_report(const uuid& src_uuid,
            const std::shared_ptr<geiger_device>& sensor, bool with_minutes, time_t now);

    void log_spectrum_minutes(time_t now, const std::shared_ptr<kis_gps_packinfo>& loc);

    void check_alerts(time_t now);
    void update_track(time_t now, const std::shared_ptr<kis_gps_packinfo>& loc);
    std::shared_ptr<tracker_element> build_track(const std::shared_ptr<geiger_device>& sensor, time_t since);

    static std::string event_radiation() { return "RADIATION"; }

    // Readings are averaged over this many seconds for the alerts and the track
    static constexpr time_t alert_window = 10;
    static constexpr size_t alert_min_baseline = 10;
    static constexpr double alert_min_rise_ratio = 1.5;
    static constexpr double track_merge_meters = 10;
    static constexpr time_t track_merge_seconds = 60;
    static constexpr size_t track_max_points = 4000;
protected:
    kis_mutex rad_mutex;

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<datasource_tracker> datasourcetracker;
    std::shared_ptr<event_bus> eventbus;

    std::shared_ptr<tracker_element_uuid_map> geiger_counters;

    int pack_comp_json, pack_comp_meta, pack_comp_datasrc;

    uint16_t geiger_device_id;
    uint16_t spectrum_report_id;

    int event_timer;

    int alert_dose_ref, alert_rise_ref;
    double alert_dose_level;
    double alert_rise_sigma;
};


#endif

