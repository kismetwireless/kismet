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

#include <cmath>

#include "datasourcetracker.h"
#include "devicetracker.h"
#include "gpstracker.h"
#include "kis_databaselogfile.h"
#include "kis_httpd_registry.h"
#include "macaddr.h"
#include "phy_radiation.h"

void radiation_spectrum_history::reset(size_t n) {
    n_channels = n;

    have_device = false;
    device_time = 0;
    device_duration = 0;
    device_counts.clear();

    session_start = 0;
    session_end = 0;
    session_dur = 0;
    session_sum = 0;
    session_counts.assign(n, 0);

    last_interval = 0;

    for (auto& m : minutes) {
        m.minute = -1;
        m.duration = 0;
        m.counts.clear();
    }
}

void radiation_spectrum_history::add_delta(time_t ts, double duration,
        const std::vector<uint64_t>& delta) {
    if (ts < 0)
        return;

    if (session_start == 0)
        session_start = ts;

    if (ts > session_end)
        session_end = ts;

    session_dur += duration;

    int64_t minute = ts / 60;
    auto& slot = minutes[minute % minute_slots];

    if (slot.minute != minute) {
        slot.minute = minute;
        slot.duration = 0;
        slot.counts.assign(n_channels, 0);
    }

    slot.duration += duration;

    for (size_t i = 0; i < n_channels; i++) {
        session_counts[i] += delta[i];
        session_sum += delta[i];

        uint64_t m = (uint64_t) slot.counts[i] + delta[i];
        slot.counts[i] = m > UINT32_MAX ? UINT32_MAX : (uint32_t) m;
    }
}

bool radiation_spectrum_history::set_device(time_t ts, double duration,
        std::vector<uint64_t>&& counts, const std::array<double, 3>& in_calib) {
    if (counts.empty() || counts.size() > max_bins || !std::isfinite(duration) || duration < 0)
        return false;

    if (counts.size() != n_channels)
        reset(counts.size());

    have_calib = std::isfinite(in_calib[0]) && std::isfinite(in_calib[1]) &&
        std::isfinite(in_calib[2]);
    if (have_calib)
        calib = in_calib;

    if (have_device) {
        bool dev_reset = duration < device_duration;

        for (size_t i = 0; i < n_channels && !dev_reset; i++) {
            if (counts[i] < device_counts[i])
                dev_reset = true;
        }

        std::vector<uint64_t> delta(n_channels);

        for (size_t i = 0; i < n_channels; i++)
            delta[i] = dev_reset ? counts[i] : counts[i] - device_counts[i];

        add_delta(ts, dev_reset ? duration : duration - device_duration, delta);
    } else if (session_start == 0) {
        // The first spectrum only sets where the session starts counting
        session_start = ts;
        session_end = ts;
    }

    have_device = true;
    device_time = ts;
    device_duration = duration;
    device_counts = std::move(counts);

    return true;
}

bool radiation_spectrum_history::add_interval(time_t ts, const std::vector<uint64_t>& counts) {
    if (counts.empty() || counts.size() > max_bins)
        return false;

    if (counts.size() != n_channels)
        reset(counts.size());

    // Intervals are about a second; a long gap means samples were lost, not a long count
    double duration = 1;
    if (last_interval != 0 && ts > last_interval && ts - last_interval <= 60)
        duration = (double) (ts - last_interval);

    last_interval = ts;

    add_delta(ts, duration, counts);

    return true;
}

void radiation_spectrum_history::fill_common(const std::shared_ptr<radiation_spectrum>& out,
        const std::string& window) const {
    out->set_window(window);
    out->set_channels(n_channels);

    if (have_calib) {
        auto c = out->get_calibration();
        c->clear();
        for (auto v : calib)
            c->push_back(v);
    }
}

void radiation_spectrum_history::fill_device(const std::shared_ptr<radiation_spectrum>& out) const {
    fill_common(out, "device");

    out->set_start_time(device_duration < (double) device_time ?
            device_time - (time_t) device_duration : 0);
    out->set_end_time(device_time);
    out->set_duration(device_duration);

    auto c = out->get_counts();
    uint64_t sum = 0;
    c->reserve(device_counts.size());
    for (auto v : device_counts) {
        c->push_back((double) v);
        sum += v;
    }
    out->set_total(sum);
}

void radiation_spectrum_history::fill_session(const std::shared_ptr<radiation_spectrum>& out) const {
    fill_common(out, "session");

    out->set_start_time(session_start);
    out->set_end_time(session_end);
    out->set_duration(session_dur);
    out->set_total(session_sum);

    auto c = out->get_counts();
    c->reserve(session_counts.size());
    for (auto v : session_counts)
        c->push_back((double) v);
}

bool radiation_spectrum_history::fill_hour(const std::shared_ptr<radiation_spectrum>& out,
        time_t now) const {
    int64_t now_minute = now / 60;
    int64_t first = -1;
    double duration = 0;
    uint64_t sum = 0;
    std::vector<uint64_t> counts(n_channels, 0);

    for (const auto& m : minutes) {
        if (m.minute < 0 || m.minute > now_minute || m.minute <= now_minute - (int64_t) minute_slots)
            continue;

        if (first < 0 || m.minute < first)
            first = m.minute;

        duration += m.duration;

        for (size_t i = 0; i < n_channels && i < m.counts.size(); i++) {
            counts[i] += m.counts[i];
            sum += m.counts[i];
        }
    }

    if (first < 0)
        return false;

    fill_common(out, "hour");

    out->set_start_time(first * 60);
    out->set_end_time(session_end);
    out->set_duration(duration);
    out->set_total(sum);

    auto c = out->get_counts();
    c->reserve(n_channels);
    for (auto v : counts)
        c->push_back((double) v);

    return true;
}

bool radiation_spectrum_history::fill_minute(const std::shared_ptr<radiation_spectrum>& out,
        int64_t minute) const {
    if (minute < 0)
        return false;

    const auto& m = minutes[minute % minute_slots];

    if (m.minute != minute)
        return false;

    fill_common(out, "minute");

    out->set_start_time(minute * 60);
    out->set_end_time(minute * 60 + 59);
    out->set_duration(m.duration);

    auto c = out->get_counts();
    uint64_t sum = 0;
    c->reserve(m.counts.size());
    for (auto v : m.counts) {
        c->push_back((double) v);
        sum += v;
    }
    out->set_total(sum);

    return true;
}

kis_radiation_phy::kis_radiation_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("RADIATION");
    indexed = false;

    geiger_device_id = 
        Globalreg::globalreg->entrytracker->register_field("radiation.geiger",
                tracker_element_factory<geiger_device>(), "Geiger counter");

    spectrum_report_id =
        Globalreg::globalreg->entrytracker->register_field("radiation.spectrum_report",
                tracker_element_factory<radiation_spectrum_report>(), "Radiation sensor spectrum");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();
    datasourcetracker =
        Globalreg::fetch_mandatory_global_as<datasource_tracker>();
    eventbus = 
        Globalreg::fetch_mandatory_global_as<event_bus>();

    pack_comp_json =
        packetchain->register_packet_component("JSON");
    pack_comp_meta =
        packetchain->register_packet_component("METABLOB");
    pack_comp_datasrc =
        packetchain->register_packet_component("KISDATASRC");

	packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);

    geiger_counters = 
        std::make_shared<tracker_element_uuid_map>();

    auto httpd = 
        Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    auto httpregistry =
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_radiation", "js/kismet.ui.radiation.js");

    httpd->register_route("/radiation/sensors/all_sensors", {"GET", "POST"},
            httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(geiger_counters, rad_mutex));

    // Spectrum windows for one sensor; minutes=1 adds the per-minute spectra
    httpd->register_route("/radiation/sensors/by-uuid/:uuid/spectrum", {"GET", "POST"},
            httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto s_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (s_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto gk = geiger_counters->find(s_uuid);

                    if (gk == geiger_counters->end())
                        throw std::runtime_error("no such radiation sensor");

                    bool with_minutes = false;
                    auto mk = con->http_variables().find("minutes");
                    if (mk != con->http_variables().end())
                        with_minutes = mk->second == "1" || mk->second == "true";

                    return build_spectrum_report(s_uuid,
                            std::static_pointer_cast<geiger_device>(gk->second),
                            with_minutes, time(nullptr));
                }, rad_mutex));

    auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();
    event_timer =
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 3, nullptr, 1, 
                [this](int) -> int {
                    auto kismetdb = Globalreg::fetch_global_as<kis_database_logfile>();
                    auto lg = kis_lock_guard<kis_mutex>(rad_mutex);

                    // Nothing to report until a radiation sensor has sent something
                    if (geiger_counters->size() == 0)
                        return 1;

                    if (kismetdb != nullptr) {
                        struct timeval tv;
                        gettimeofday(&tv, nullptr);

                        auto gpstracker = Globalreg::fetch_global_as<gps_tracker>();
                        std::shared_ptr<kis_gps_packinfo> loc;
                        if (gpstracker != nullptr)
                            loc = gpstracker->get_best_location();

                        std::stringstream js;

                        Globalreg::globalreg->entrytracker->serialize("json", js, geiger_counters, NULL);

                        kismetdb->log_snapshot(loc, tv, "RADIATION", js.str());

                        log_spectrum_minutes(tv.tv_sec, loc);
                    }

                    auto evt = eventbus->get_eventbus_event(event_radiation());
                    evt->get_event_content()->insert(event_radiation(), geiger_counters);
                    eventbus->publish(evt);

                    return 1;

                });
}

kis_radiation_phy::~kis_radiation_phy() {
    packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

// Spectrum counts from JSON numbers; whole, non-negative, and within the bin limit
static bool spectrum_counts(const std::vector<double>& in, std::vector<uint64_t>& out) {
    // Largest integer a double holds exactly
    constexpr double max_count = 9007199254740992.0;

    if (in.empty() || in.size() > radiation_spectrum_history::max_bins)
        return false;

    out.clear();
    out.reserve(in.size());

    for (auto v : in) {
        if (!std::isfinite(v) || v < 0 || v > max_count)
            return false;

        out.push_back((uint64_t) std::llround(v));
    }

    return true;
}

// Caller holds rad_mutex
std::shared_ptr<geiger_device> kis_radiation_phy::find_or_create_sensor(const uuid& src_uuid,
        const std::string& type) {
    auto gk = geiger_counters->find(src_uuid);

    if (gk != geiger_counters->end())
        return std::static_pointer_cast<geiger_device>(gk->second);

    auto rv = std::make_shared<geiger_device>(geiger_device_id);

    // The packet source ref is a raw pointer, the alias needs the shared one from the DST
    rv->set_src_alias(datasourcetracker->find_datasource(src_uuid));
    rv->set_detector_type(type);
    geiger_counters->insert(src_uuid, rv);

    return rv;
}

// Caller holds rad_mutex
std::shared_ptr<radiation_spectrum_report> kis_radiation_phy::build_spectrum_report(const uuid& src_uuid,
        const std::shared_ptr<geiger_device>& sensor, bool with_minutes, time_t now) {
    auto report = std::make_shared<radiation_spectrum_report>(spectrum_report_id);
    auto& hist = sensor->get_spectrum();

    report->set_sensor(src_uuid);

    if (hist.channels() == 0)
        return report;

    if (hist.has_device())
        hist.fill_device(report->get_device());

    hist.fill_session(report->get_session());

    auto hour = report->make_minute();
    if (hist.fill_hour(hour, now))
        report->set_tracker_hour(hour);

    if (with_minutes) {
        auto mv = report->get_minutes();
        int64_t now_minute = now / 60;

        for (int64_t m = now_minute - (int64_t) radiation_spectrum_history::minute_slots + 1;
                m <= now_minute; m++) {
            auto ms = report->make_minute();
            if (hist.fill_minute(ms, m))
                mv->push_back(ms);
        }
    }

    return report;
}

// Log each finished minute's spectrum once; caller holds rad_mutex
void kis_radiation_phy::log_spectrum_minutes(time_t now, const std::shared_ptr<kis_gps_packinfo>& loc) {
    auto kismetdb = Globalreg::fetch_global_as<kis_database_logfile>();

    if (kismetdb == nullptr)
        return;

    int64_t done_minute = now / 60 - 1;

    for (const auto& gi : *geiger_counters) {
        auto sensor = std::static_pointer_cast<geiger_device>(gi.second);
        auto& hist = sensor->get_spectrum();

        if (hist.channels() == 0 || hist.last_logged_minute >= done_minute)
            continue;

        hist.last_logged_minute = done_minute;

        auto report = std::make_shared<radiation_spectrum_report>(spectrum_report_id);
        report->set_sensor(gi.first);

        auto ms = report->make_minute();
        if (!hist.fill_minute(ms, done_minute))
            continue;

        report->get_minutes()->push_back(ms);

        std::stringstream js;
        Globalreg::globalreg->entrytracker->serialize("json", js, report, NULL);

        struct timeval tv;
        tv.tv_sec = done_minute * 60 + 59;
        tv.tv_usec = 0;

        kismetdb->log_snapshot(loc, tv, "RADIATION_SPECTRUM", js.str());
    }
}

int kis_radiation_phy::packet_handler(CHAINCALL_PARMS) {
    kis_radiation_phy *radphy = (kis_radiation_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate) {
        return 0;
    }

    auto json = in_pack->fetch<kis_json_packinfo>(radphy->pack_comp_json);

    if (json == nullptr) {
        return 0;
    }

    auto datasrc = in_pack->fetch<packetchain_comp_datasource>(radphy->pack_comp_datasrc);

    if (datasrc == nullptr) {
        return 0;
    }

    // Radview arduino code emits the CPS and spectrum data
    if (json->type == "radview") {

        nlohmann::json json_;
        std::vector<double> spectrum;
        double cps;

        try {
            std::stringstream ss(json->json_string);
            ss >> json_;

            cps = json_["cps"].get<double>();
            spectrum = json_["spectrum"].get<std::vector<double>>();

        } catch (const std::exception& e) {
            _MSG_DEBUG("JSON parsing error: {}", e.what());
            return 0;
        }

        std::vector<uint64_t> counts;
        if (!spectrum_counts(spectrum, counts) || !std::isfinite(cps))
            return 0;

        auto lk = kis_lock_guard<kis_mutex>(radphy->rad_mutex, "radphy update");
        auto rv = radphy->find_or_create_sensor(datasrc->ref_source->get_source_uuid(), "Radview");

        rv->insert_cps_record(in_pack->ts.tv_sec, cps, counts);

        return 1;
    }

    // Radiacode sends real-time count and dose rate records, and less often a
    // status record with accumulated dose, temperature, and battery
    if (json->type == "radiacode") {
        nlohmann::json json_;

        try {
            std::stringstream ss(json->json_string);
            ss >> json_;
        } catch (const std::exception& e) {
            _MSG_DEBUG("JSON parsing error: {}", e.what());
            return 0;
        }

        if (!json_.is_object())
            return 0;

        auto num = [&json_](const char *key, double& out) -> bool {
            auto i = json_.find(key);

            if (i == json_.end() || !i->is_number())
                return false;

            out = i->get<double>();
            return std::isfinite(out);
        };

        double cps, sv, cps_err, sv_err;
        double dose, dose_duration, temp, charge;

        // Spectrum the device has accumulated, sent every few seconds
        auto spec_k = json_.find("spectrum");
        if (spec_k != json_.end()) {
            if (!spec_k->is_object())
                return 0;

            std::vector<uint64_t> counts;
            std::array<double, 3> calib;
            double duration;

            try {
                auto cal = spec_k->at("calibration").get<std::vector<double>>();
                if (cal.size() != calib.size())
                    return 0;
                std::copy(cal.begin(), cal.end(), calib.begin());

                duration = spec_k->at("duration").get<double>();

                if (!spectrum_counts(spec_k->at("counts").get<std::vector<double>>(), counts))
                    return 0;
            } catch (const std::exception& e) {
                _MSG_DEBUG("Radiacode spectrum JSON error: {}", e.what());
                return 0;
            }

            if (!std::isfinite(duration) || duration < 0 || duration > 4294967295.0)
                return 0;

            auto lk = kis_lock_guard<kis_mutex>(radphy->rad_mutex, "radphy spectrum");
            auto rv = radphy->find_or_create_sensor(datasrc->ref_source->get_source_uuid(), "Radiacode");

            rv->insert_device_spectrum(in_pack->ts.tv_sec, duration, std::move(counts), calib);

            return 1;
        }

        bool have_rt = num("cps", cps) && num("sv", sv);
        bool have_err = have_rt && num("cps_err", cps_err) && num("sv_err", sv_err);
        bool have_status = num("dose_total", dose) && num("dose_duration", dose_duration) &&
            num("temperature", temp) && num("charge", charge) &&
            dose_duration >= 0 && dose_duration <= 4294967295.0;

        if (!have_rt && !have_status)
            return 0;

        auto lk = kis_lock_guard<kis_mutex>(radphy->rad_mutex, "radphy update");
        auto rv = radphy->find_or_create_sensor(datasrc->ref_source->get_source_uuid(), "Radiacode");

        // Radiacode rates are in units of 10 mSv/h; x10000 gives uSv/h.  Errors
        // are percent x10.
        if (have_rt)
            rv->insert_cps_usv(in_pack->ts.tv_sec, cps, sv * 10000);

        if (have_err)
            rv->set_errors(cps_err / 10, sv_err / 10);

        // Accumulated dose uses the same x10000 scale, giving uSv.  Temperature
        // is C x100 offset by 2000, charge is percent x100.
        if (have_status)
            rv->set_status(in_pack->ts.tv_sec, dose * 10000, (uint64_t) dose_duration,
                    (temp - 2000) / 100, charge / 100);

        return 1;
    }

    return 1;
}
