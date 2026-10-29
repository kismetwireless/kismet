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

#include <algorithm>
#include <cctype>
#include <cmath>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "configfile.h"
#include "devicetracker.h"
#include "entrytracker.h"
#include "kis_datasource.h"
#include "messagebus.h"
#include "nlohmann/json.hpp"
#include "packetchain.h"
#include "range_tracker.h"
#include "timetracker.h"
#include "util.h"

namespace {
    constexpr double earth_m = 6371000;
    constexpr double deg_rad = M_PI / 180;
    constexpr double default_limit = 500000;
    constexpr double default_speed = 1500;      // m/s; faster jumps are bad decodes
    constexpr time_t max_gap = 300;             // s between positions that can still be compared
    constexpr size_t max_records = 128;
    constexpr size_t max_kind_len = 64;
    constexpr size_t max_save = 32 * 1024 * 1024;
    constexpr double max_dist = 2000000;
    constexpr int save_secs = 300;

    struct kind_default {
        const char *kind;
        double limit;       // m
        double speed;       // m/s
    };

    constexpr kind_default kind_defaults[] = {
        {"ADSB", 600000, 1500},
        {"AIS", 250000, 100},
        {"UAV", 25000, 150},
        {"Meshtastic", 400000, 1500},
        {"MeshCore", 400000, 1500},
    };

    double distance_m(double lat1, double lon1, double lat2, double lon2) {
        const double p1 = lat1 * deg_rad, p2 = lat2 * deg_rad;
        const double h = std::pow(std::sin((p2 - p1) / 2), 2) +
            std::cos(p1) * std::cos(p2) * std::pow(std::sin((lon2 - lon1) * deg_rad / 2), 2);
        return 2 * earth_m * std::asin(std::min(1.0, std::sqrt(h)));
    }

    double bearing_deg(double lat1, double lon1, double lat2, double lon2) {
        const double p1 = lat1 * deg_rad, p2 = lat2 * deg_rad, dl = (lon2 - lon1) * deg_rad;
        const double y = std::sin(dl) * std::cos(p2);
        const double x = std::cos(p1) * std::sin(p2) - std::sin(p1) * std::cos(p2) * std::cos(dl);
        return std::fmod(std::atan2(y, x) / deg_rad + 360, 360);
    }

    bool valid_kind(const std::string& k) {
        if (k.empty() || k.size() > max_kind_len)
            return false;
        for (auto c : k)
            if (!(isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_'))
                return false;
        return true;
    }

    bool read_file(const std::string& path, std::string& out, std::string& err, bool& missing) {
        missing = false;

        int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
            missing = errno == ENOENT;
            err = kis_strerror_r(errno);
            return false;
        }

        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            close(fd);
            err = "not a regular file";
            return false;
        }

        char buf[16384];
        ssize_t r;
        out.clear();
        while ((r = read(fd, buf, sizeof(buf))) > 0) {
            if (out.size() + r > max_save) {
                close(fd);
                err = "too large";
                return false;
            }
            out.append(buf, r);
        }

        int read_errno = errno;
        close(fd);

        if (r < 0) {
            err = kis_strerror_r(read_errno);
            return false;
        }

        return true;
    }

    // Arrays of numbers read back from a save, each checked
    template<typename T, size_t N>
    bool load_array(const nlohmann::json& j, const char *key, std::array<T, N>& out, double max,
            double min = 0) {
        auto ji = j.find(key);
        if (ji == j.end() || !ji->is_array() || ji->size() != N)
            return false;
        for (size_t i = 0; i < N; i++) {
            const auto& v = (*ji)[i];
            if (!v.is_number())
                return false;
            double d = v.get<double>();
            if (!std::isfinite(d) || d > max || d < min)
                return false;
            out[i] = static_cast<T>(d);
        }
        return true;
    }

    template<typename T, size_t N>
    nlohmann::json save_array(const std::array<T, N>& a) {
        auto r = nlohmann::json::array();
        for (const auto& v : a)
            r.push_back(std::is_floating_point<T>::value ? std::round(v * 10) / 10 : v);
        return r;
    }
}

range_tracker::range_tracker() :
    lifetime_global(),
    deferred_startup() {

    mutex.set_name("range_tracker");

    pack_comp_datasrc =
        Globalreg::fetch_mandatory_global_as<packet_chain>()->register_packet_component("KISDATASRC");

    auto conf = Globalreg::globalreg->kismet_config;
    enabled = conf->fetch_opt_bool("range_tracking", true);
    save_enabled = conf->fetch_opt_bool("range_save", true);
    save_file = conf->fetch_opt_path("range_file", "%h/.kismet/kismet_range.json");

    // range_max_km=KIND,km
    for (const auto& l : conf->fetch_opt_vec("range_max_km")) {
        auto c = l.find(',');
        if (c == std::string::npos) {
            _MSG_ERROR("Expected range_max_km=kind,km, got '{}'", l);
            continue;
        }
        auto kind = l.substr(0, c);
        double km = 0;
        try {
            km = std::stod(l.substr(c + 1));
        } catch (...) {
            km = 0;
        }
        if (!valid_kind(kind) || !std::isfinite(km) || km <= 0 || km * 1000 > max_dist) {
            _MSG_ERROR("Ignoring range_max_km={}; expected a kind and a distance up to {} km", l,
                    max_dist / 1000);
            continue;
        }
        limits[kind] = km * 1000;
    }

    auto et = Globalreg::globalreg->entrytracker;
    auto reg = [&et](const std::string& n, std::shared_ptr<tracker_element> b, const std::string& d) {
        return et->register_field(n, b, d);
    };

    f_records = reg("kismet.range.records", tracker_element_factory<tracker_element_vector>(),
            "receiver range records");
    f_kind = reg("kismet.range.kind", tracker_element_factory<tracker_element_string>(),
            "kind of device (phy name)");
    f_source = reg("kismet.range.source_uuid", tracker_element_factory<tracker_element_uuid>(),
            "data source UUID, or 0 for every source");
    f_source_name = reg("kismet.range.source_name", tracker_element_factory<tracker_element_string>(),
            "data source name");
    f_samples = reg("kismet.range.samples", tracker_element_factory<tracker_element_uint64>(),
            "positions counted");
    f_rejected = reg("kismet.range.rejected", tracker_element_factory<tracker_element_uint64>(),
            "positions rejected as bad decodes");
    f_first = reg("kismet.range.first_time", tracker_element_factory<tracker_element_uint64>(),
            "first position counted (unix ts)");
    f_last = reg("kismet.range.last_time", tracker_element_factory<tracker_element_uint64>(),
            "last position counted (unix ts)");
    f_center = reg("kismet.range.center", tracker_element_factory<tracker_element_pair_double>(),
            "average receiver location [lon, lat]");
    f_moved = reg("kismet.range.moved", tracker_element_factory<tracker_element_double>(),
            "furthest the receiver has been from its average location (m)");
    f_bin_deg = reg("kismet.range.bin_degrees", tracker_element_factory<tracker_element_double>(),
            "degrees of bearing in each bin; bin 0 starts at north");
    f_furthest = reg("kismet.range.furthest", tracker_element_factory<tracker_element_double>(),
            "furthest distance (m)");
    f_furthest_bearing = reg("kismet.range.furthest_bearing", tracker_element_factory<tracker_element_double>(),
            "bearing of the furthest distance (degrees)");
    f_dist = reg("kismet.range.distance", tracker_element_factory<tracker_element_vector_double>(),
            "furthest distance in each bin, all time (m)");
    f_alt = reg("kismet.range.altitude", tracker_element_factory<tracker_element_vector_double>(),
            "altitude of the furthest position in each bin (m)");
    f_time = reg("kismet.range.time", tracker_element_factory<tracker_element_vector_double>(),
            "time of the furthest position in each bin (unix ts)");
    f_signal = reg("kismet.range.signal", tracker_element_factory<tracker_element_vector_double>(),
            "signal of the furthest position in each bin (dBm, 0 if unknown)");
    f_day = reg("kismet.range.day_distance", tracker_element_factory<tracker_element_vector_double>(),
            "furthest distance in each bin over the last day (m)");
    f_bands = reg("kismet.range.bands", tracker_element_factory<tracker_element_vector>(),
            "furthest distance in each bin by altitude, all time");
    f_band_min = reg("kismet.range.band.min_alt", tracker_element_factory<tracker_element_double>(),
            "lowest altitude in the band (m)");
    f_band_max = reg("kismet.range.band.max_alt", tracker_element_factory<tracker_element_double>(),
            "highest altitude in the band (m), 0 for no limit");
    f_band_dist = reg("kismet.range.band.distance", tracker_element_factory<tracker_element_vector_double>(),
            "furthest distance in each bin for positions in the band (m)");
    f_hull = reg("kismet.range.hull", tracker_element_factory<tracker_element_vector>(),
            "convex hull, counterclockwise, of positions heard while the receiver location was unknown");
    f_hull_point = reg("kismet.range.hull.point", tracker_element_factory<tracker_element_pair_double>(),
            "hull corner [lon, lat]");
    f_hull_samples = reg("kismet.range.hull_samples", tracker_element_factory<tracker_element_uint64>(),
            "positions heard while the receiver location was unknown");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/range/all_ranges", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection>) {
                    return all_endpoint();
                }));

    httpd->register_route("/range/by-kind/:kind/range", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto r = kind_endpoint(con->uri_params()[":kind"], "");
                    if (r == nullptr) {
                        con->set_status(404);
                        return std::static_pointer_cast<tracker_element>(std::make_shared<tracker_element_map>());
                    }
                    return r;
                }));

    httpd->register_route("/range/by-kind/:kind/by-source/:uuid/range", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto u = string_to_n_dfl<uuid>(con->uri_params()[":uuid"], uuid());
                    if (u.error)
                        throw std::runtime_error("invalid UUID");
                    auto r = kind_endpoint(con->uri_params()[":kind"], u.as_string());
                    if (r == nullptr) {
                        con->set_status(404);
                        return std::static_pointer_cast<tracker_element>(std::make_shared<tracker_element_map>());
                    }
                    return r;
                }));

    httpd->register_route("/range/reset", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    reset_endpoint(con);
                }));
}

range_tracker::~range_tracker() {
    trigger_deferred_shutdown();
}

void range_tracker::trigger_deferred_startup() {
    if (!enabled)
        return;

    if (save_enabled)
        load();

    Globalreg::fetch_mandatory_global_as<device_tracker>()->set_range_tracker(this);

    timer_id =
        Globalreg::fetch_mandatory_global_as<time_tracker>()->register_timer(
                std::chrono::seconds(save_secs), true, [this](int) -> int {
                    if (!save_enabled)
                        return 1;
                    std::string err;
                    if (!save(err))
                        _MSG_ERROR("Could not save the receiver range to {}: {}", save_file, err);
                    return 1;
                });
}

void range_tracker::trigger_deferred_shutdown() {
    auto devicetracker = Globalreg::fetch_global_as<device_tracker>();
    if (devicetracker != nullptr)
        devicetracker->set_range_tracker(nullptr);

    if (timer_id >= 0) {
        auto timetracker = Globalreg::fetch_global_as<time_tracker>(time_tracker::global_name());
        if (timetracker != nullptr)
            timetracker->remove_timer(timer_id);
        timer_id = -1;

        if (save_enabled) {
            std::string err;
            if (!save(err))
                _MSG_ERROR("Could not save the receiver range to {}: {}", save_file, err);
        }
    }
}

double range_tracker::limit_for(const std::string& kind) const {
    auto li = limits.find(kind);
    if (li != limits.end())
        return li->second;
    for (const auto& d : kind_defaults)
        if (kind == d.kind)
            return d.limit;
    return default_limit;
}

double range_tracker::speed_for(const std::string& kind) const {
    for (const auto& d : kind_defaults)
        if (kind == d.kind)
            return d.speed;
    return default_speed;
}

range_tracker::range_record *range_tracker::record_for(const std::string& kind,
        const std::string& source_key, const uuid& source, const std::string& name) {
    auto key = record_key(kind, source_key);
    auto ri = records.find(key);
    if (ri != records.end()) {
        if (!name.empty() && ri->second->source_name != name)
            ri->second->source_name = name;
        return ri->second.get();
    }

    if (records.size() >= max_records || !valid_kind(kind))
        return nullptr;

    auto rec = std::make_unique<range_record>();
    rec->kind = kind;
    rec->source = source;
    rec->source_key = source_key;
    rec->source_name = name;
    auto r = rec.get();
    records.emplace(key, std::move(rec));
    return r;
}

void range_tracker::add(const std::string& kind, const std::shared_ptr<kis_packet>& in_pack,
        const kis_gps_packinfo& heard, const kis_gps_packinfo& reported,
        double prev_lat, double prev_lon, time_t prev_time) {
    if (!enabled || !reported.gps_info_ok || reported.fix < 2)
        return;

    if ((reported.lat == 0 && reported.lon == 0) || !std::isfinite(reported.lat) ||
            !std::isfinite(reported.lon) || std::fabs(reported.lat) > 90 || std::fabs(reported.lon) > 180)
        return;

    // Without Kismet's own location, the position only goes into the hull
    const bool located = heard.gps_info_ok && heard.fix >= 2 && !(heard.lat == 0 && heard.lon == 0) &&
        std::isfinite(heard.lat) && std::isfinite(heard.lon) &&
        std::fabs(heard.lat) <= 90 && std::fabs(heard.lon) <= 180;

    // The first position from a device, and repeats of the last one, can't be checked
    if (prev_time == 0 || (prev_lat == reported.lat && prev_lon == reported.lon))
        return;

    const time_t now = reported.tv.tv_sec != 0 ? reported.tv.tv_sec : in_pack->ts.tv_sec;
    const time_t dt = now - prev_time;
    if (dt < 0 || dt > max_gap)
        return;

    const double jump = distance_m(prev_lat, prev_lon, reported.lat, reported.lon);
    const bool plausible = jump <= speed_for(kind) * std::max<time_t>(dt, 1) + 1000;

    double dist = 0;
    bool in_range = true;
    size_t bin = 0;
    if (located) {
        dist = distance_m(heard.lat, heard.lon, reported.lat, reported.lon);
        in_range = std::isfinite(dist) && dist >= 1 && dist <= limit_for(kind);
        bin = static_cast<size_t>(bearing_deg(heard.lat, heard.lon, reported.lat, reported.lon)) % bins;
    }

    double sig = 0;
    if (in_pack->signal_info.data_ok && in_pack->signal_info.signal_type == kis_l1_signal_type_dbm)
        sig = in_pack->signal_info.signal_dbm;

    uuid src_uuid;
    std::string src_name;
    auto ds = in_pack->fetch<packetchain_comp_datasource>(pack_comp_datasrc);
    if (ds != nullptr && ds->ref_source != nullptr) {
        src_uuid = ds->ref_source->get_source_uuid();
        src_name = ds->ref_source->get_source_name();
    }
    const auto src_key = src_uuid.error ? std::string() : src_uuid.as_string();

    kis_lock_guard<kis_mutex> lk(mutex, "range_tracker add");

    for (auto rec : {record_for(kind, "", uuid(), ""),
            src_key.empty() ? nullptr : record_for(kind, src_key, src_uuid, src_name)}) {
        if (rec == nullptr)
            continue;
        if (!plausible || !in_range) {
            rec->rejected++;
            continue;
        }
        if (located)
            add_to(*rec, bin, dist, heard, reported, sig, now);
        else
            add_hull(*rec, reported.lat, reported.lon, now);
    }

    dirty = true;
}

void range_tracker::add_hull(range_record& rec, double lat, double lon, time_t now) {
    rec.hull_samples++;
    if (rec.first_time == 0)
        rec.first_time = now;
    rec.last_time = std::max(rec.last_time, now);

    auto& h = rec.hull;

    // Flat enough at these sizes: longitude is scaled at the first point's latitude and
    // taken relative to it, so a hull across the antimeridian stays whole
    const double ref_lat = h.empty() ? lat : h[0].first;
    const double ref_lon = h.empty() ? lon : h[0].second;
    const double k = std::cos(ref_lat * deg_rad);
    auto px = [&](const std::pair<double, double>& p) {
        return std::remainder(p.second - ref_lon, 360.0) * k;
    };
    auto cross = [&](const std::pair<double, double>& o, const std::pair<double, double>& a,
            const std::pair<double, double>& b) {
        return (px(a) - px(o)) * (b.first - o.first) - (a.first - o.first) * (px(b) - px(o));
    };

    const auto p = std::make_pair(lat, lon);

    // Inside (or on) a counterclockwise hull changes nothing
    if (h.size() >= 3) {
        bool inside = true;
        for (size_t i = 0; inside && i < h.size(); i++)
            if (cross(h[i], h[(i + 1) % h.size()], p) < 0)
                inside = false;
        if (inside)
            return;
    }

    for (const auto& q : h)
        if (q == p)
            return;

    // Rebuild from the old corners and the new point (monotone chain)
    auto pts = h;
    pts.push_back(p);
    std::sort(pts.begin(), pts.end(), [&](const auto& a, const auto& b) {
        const double ax = px(a), bx = px(b);
        return ax < bx || (ax == bx && a.first < b.first);
    });

    std::vector<std::pair<double, double>> out(2 * pts.size());
    size_t n = 0;
    for (const auto& q : pts) {
        while (n >= 2 && cross(out[n - 2], out[n - 1], q) <= 0)
            n--;
        out[n++] = q;
    }
    for (size_t i = pts.size() - 1, t = n + 1; i > 0; i--) {
        const auto& q = pts[i - 1];
        while (n >= t && cross(out[n - 2], out[n - 1], q) <= 0)
            n--;
        out[n++] = q;
    }
    out.resize(n > 1 ? n - 1 : n);

    if (out.size() > max_hull)
        return;

    h = std::move(out);
}

void range_tracker::add_to(range_record& rec, size_t bin, double dist, const kis_gps_packinfo& heard,
        const kis_gps_packinfo& reported, double sig, time_t now) {
    rec.samples++;
    if (rec.first_time == 0)
        rec.first_time = now;
    rec.last_time = std::max(rec.last_time, now);

    // A running mean is fine for a receiver that stays within a few km
    rec.center_n++;
    rec.center_lat += (heard.lat - rec.center_lat) / rec.center_n;
    rec.center_lon += (heard.lon - rec.center_lon) / rec.center_n;
    rec.moved = std::max(rec.moved, distance_m(rec.center_lat, rec.center_lon, heard.lat, heard.lon));

    const auto d = static_cast<float>(dist);

    if (d > rec.dist[bin]) {
        rec.dist[bin] = d;
        rec.alt[bin] = reported.fix >= 3 ? static_cast<float>(reported.alt) : 0;
        rec.time[bin] = now;
        rec.signal[bin] = static_cast<float>(sig);
    }

    const time_t hour = now / 3600;
    const size_t slot = static_cast<size_t>(hour % day_slots);
    if (rec.day_hour[slot] != hour) {
        rec.day_hour[slot] = hour;
        rec.day[slot].dist.fill(0);
    }
    rec.day[slot].dist[bin] = std::max(rec.day[slot].dist[bin], d);

    if (reported.fix >= 3) {
        size_t b = 0;
        while (b < band_tops.size() && reported.alt >= band_tops[b])
            b++;
        rec.band[b].dist[bin] = std::max(rec.band[b].dist[bin], d);
    }
}

std::shared_ptr<tracker_element> range_tracker::summary(const range_record& rec, time_t now) {
    auto et = Globalreg::globalreg->entrytracker;
    auto r = std::make_shared<tracker_element_map>();

    auto kind = et->get_shared_instance_as<tracker_element_string>(f_kind);
    kind->set(rec.kind);
    r->insert(kind);

    if (!rec.source_key.empty()) {
        auto src = et->get_shared_instance_as<tracker_element_uuid>(f_source);
        src->set(rec.source);
        r->insert(src);
    }

    auto srcname = et->get_shared_instance_as<tracker_element_string>(f_source_name);
    srcname->set(rec.source_name);
    r->insert(srcname);

    auto u64 = [&](int id, uint64_t v) {
        auto e = et->get_shared_instance_as<tracker_element_uint64>(id);
        e->set(v);
        r->insert(e);
    };
    auto dbl = [&](int id, double v) {
        auto e = et->get_shared_instance_as<tracker_element_double>(id);
        e->set(v);
        r->insert(e);
    };

    u64(f_samples, rec.samples);
    u64(f_hull_samples, rec.hull_samples);
    u64(f_rejected, rec.rejected);
    u64(f_first, rec.first_time);
    u64(f_last, rec.last_time);

    // Only once Kismet's own location has been known
    if (rec.center_n > 0) {
        auto center = et->get_shared_instance_as<tracker_element_pair_double>(f_center);
        center->set(rec.center_lon, rec.center_lat);
        r->insert(center);
    }

    dbl(f_moved, rec.moved);
    dbl(f_bin_deg, 360.0 / bins);

    size_t far = 0;
    for (size_t i = 1; i < bins; i++)
        if (rec.dist[i] > rec.dist[far])
            far = i;
    dbl(f_furthest, rec.dist[far]);
    dbl(f_furthest_bearing, rec.dist[far] > 0 ? (far + 0.5) * 360.0 / bins : 0);

    return r;
}

std::shared_ptr<tracker_element> range_tracker::detail(const range_record& rec, time_t now) {
    auto et = Globalreg::globalreg->entrytracker;
    auto r = std::static_pointer_cast<tracker_element_map>(summary(rec, now));

    auto vec = [&](int id, auto get) {
        auto e = et->get_shared_instance_as<tracker_element_vector_double>(id);
        e->reserve(bins);
        for (size_t i = 0; i < bins; i++)
            e->get().push_back(get(i));
        return e;
    };

    r->insert(vec(f_dist, [&](size_t i) { return rec.dist[i]; }));
    r->insert(vec(f_alt, [&](size_t i) { return rec.alt[i]; }));
    r->insert(vec(f_time, [&](size_t i) { return static_cast<double>(rec.time[i]); }));
    r->insert(vec(f_signal, [&](size_t i) { return rec.signal[i]; }));

    // The last day is every slot holding an hour from the last 24
    const time_t hour = now / 3600;
    r->insert(vec(f_day, [&](size_t i) {
        float m = 0;
        for (size_t s = 0; s < day_slots; s++)
            if (rec.day_hour[s] != 0 && hour - rec.day_hour[s] < static_cast<time_t>(day_slots))
                m = std::max(m, rec.day[s].dist[i]);
        return m;
    }));

    auto bandvec = et->get_shared_instance_as<tracker_element_vector>(f_bands);
    for (size_t b = 0; b < bands; b++) {
        auto bm = std::make_shared<tracker_element_map>();
        auto mn = et->get_shared_instance_as<tracker_element_double>(f_band_min);
        mn->set(b == 0 ? 0 : band_tops[b - 1]);
        bm->insert(mn);
        auto mx = et->get_shared_instance_as<tracker_element_double>(f_band_max);
        mx->set(b < band_tops.size() ? band_tops[b] : 0);
        bm->insert(mx);
        bm->insert(vec(f_band_dist, [&](size_t i) { return rec.band[b].dist[i]; }));
        bandvec->push_back(bm);
    }
    r->insert(bandvec);

    auto hull = et->get_shared_instance_as<tracker_element_vector>(f_hull);
    for (const auto& p : rec.hull) {
        auto pt = et->get_shared_instance_as<tracker_element_pair_double>(f_hull_point);
        pt->set(p.second, p.first);
        hull->push_back(pt);
    }
    r->insert(hull);

    return r;
}

std::shared_ptr<tracker_element> range_tracker::all_endpoint() {
    auto et = Globalreg::globalreg->entrytracker;
    auto ret = std::make_shared<tracker_element_map>();
    auto vec = et->get_shared_instance_as<tracker_element_vector>(f_records);
    ret->insert(vec);

    const time_t now = Globalreg::globalreg->last_tv_sec;

    kis_lock_guard<kis_mutex> lk(mutex, "range_tracker all");
    for (const auto& r : records)
        vec->push_back(summary(*r.second, now));

    return ret;
}

std::shared_ptr<tracker_element> range_tracker::kind_endpoint(const std::string& kind,
        const std::string& source_key) {
    const time_t now = Globalreg::globalreg->last_tv_sec;

    kis_lock_guard<kis_mutex> lk(mutex, "range_tracker kind");
    auto ri = records.find(record_key(kind, source_key));
    if (ri == records.end())
        return nullptr;
    return detail(*ri->second, now);
}

void range_tracker::reset_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());
    con->set_mime_type("application/json");

    std::string kind;
    std::string source;
    bool by_source = false;

    try {
        auto& j = con->json();
        if (j.contains("kind")) {
            if (!j["kind"].is_string())
                throw std::runtime_error("expected 'kind' to be a string");
            kind = j["kind"].get<std::string>();
            if (!valid_kind(kind))
                throw std::runtime_error("invalid kind");
        }
        if (j.contains("source")) {
            if (!j["source"].is_string())
                throw std::runtime_error("expected 'source' to be a UUID");
            auto u = string_to_n_dfl<uuid>(j["source"].get<std::string>(), uuid());
            if (u.error)
                throw std::runtime_error("invalid source UUID");
            source = u.as_string();
            by_source = true;
        }
    } catch (const std::exception& e) {
        con->set_status(400);
        stream << nlohmann::json{{"ok", false}, {"error", e.what()}}.dump();
        return;
    }

    size_t removed = 0;
    {
        kis_lock_guard<kis_mutex> lk(mutex, "range_tracker reset");
        for (auto i = records.begin(); i != records.end(); ) {
            const auto& rec = *i->second;
            // Clearing a kind clears every source's record of it too
            if ((kind.empty() || rec.kind == kind) && (!by_source || rec.source_key == source)) {
                i = records.erase(i);
                removed++;
            } else {
                ++i;
            }
        }
        dirty = true;
    }

    _MSG_INFO("Receiver range reset ({} record{})", removed, removed == 1 ? "" : "s");

    std::string err;
    if (save_enabled && !save(err))
        _MSG_ERROR("Could not save the receiver range to {}: {}", save_file, err);

    stream << nlohmann::json{{"ok", true}, {"removed", removed}}.dump();
}

bool range_tracker::save(std::string& err) {
    std::string text;
    {
        kis_lock_guard<kis_mutex> lk(mutex, "range_tracker save");
        if (!dirty)
            return true;

        nlohmann::json j;
        j["version"] = 1;
        auto recs = nlohmann::json::array();
        for (const auto& ri : records) {
            const auto& r = *ri.second;
            nlohmann::json o;
            o["kind"] = r.kind;
            o["source"] = r.source_key;
            o["source_name"] = r.source_name;
            o["samples"] = r.samples;
            o["rejected"] = r.rejected;
            o["first_time"] = r.first_time;
            o["last_time"] = r.last_time;
            o["center"] = {r.center_lat, r.center_lon, r.center_n};
            o["moved"] = r.moved;
            o["dist"] = save_array(r.dist);
            o["alt"] = save_array(r.alt);
            o["time"] = save_array(r.time);
            o["signal"] = save_array(r.signal);
            auto day = nlohmann::json::array();
            for (const auto& d : r.day)
                day.push_back(save_array(d.dist));
            o["day"] = day;
            o["day_hour"] = save_array(r.day_hour);
            auto band = nlohmann::json::array();
            for (const auto& b : r.band)
                band.push_back(save_array(b.dist));
            o["band"] = band;
            auto hull = nlohmann::json::array();
            for (const auto& p : r.hull)
                hull.push_back({p.first, p.second});
            o["hull"] = hull;
            o["hull_samples"] = r.hull_samples;
            recs.push_back(o);
        }
        j["records"] = recs;
        text = j.dump();
        dirty = false;
    }

    // Write beside the file and rename over it, so a crash never leaves half a file;
    // it holds where the receiver is, so only the user can read it
    auto tmp = save_file + ".tmp";

    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        err = kis_strerror_r(errno);
        return false;
    }

    auto fail = [&](int e) {
        err = kis_strerror_r(e);
        close(fd);
        unlink(tmp.c_str());
        return false;
    };

    if (fchmod(fd, 0600) != 0)
        return fail(errno);

    size_t off = 0;
    while (off < text.size()) {
        ssize_t w = write(fd, text.data() + off, text.size() - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return fail(errno);
        }
        off += w;
    }

    if (fsync(fd) != 0)
        return fail(errno);

    if (close(fd) != 0) {
        err = kis_strerror_r(errno);
        unlink(tmp.c_str());
        return false;
    }

    if (rename(tmp.c_str(), save_file.c_str()) != 0) {
        err = kis_strerror_r(errno);
        unlink(tmp.c_str());
        return false;
    }

    return true;
}

void range_tracker::load() {
    std::string text, err;
    bool missing;

    if (!read_file(save_file, text, err, missing)) {
        if (!missing)
            _MSG_ERROR("Could not read the saved receiver range from {}: {}", save_file, err);
        return;
    }

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(text);
    } catch (const std::exception& e) {
        _MSG_ERROR("Could not read the saved receiver range from {}: {}", save_file, e.what());
        return;
    }

    if (!j.is_object() || j.value("version", 0) != 1 || !j.contains("records") || !j["records"].is_array()) {
        _MSG_ERROR("Could not read the saved receiver range from {}: not a receiver range file", save_file);
        return;
    }

    size_t loaded = 0, bad = 0;

    kis_lock_guard<kis_mutex> lk(mutex, "range_tracker load");

    for (const auto& o : j["records"]) {
        if (records.size() >= max_records)
            break;

        auto rec = std::make_unique<range_record>();
        bool ok = o.is_object();

        try {
            if (ok) {
                rec->kind = o.at("kind").get<std::string>();
                rec->source_key = o.at("source").get<std::string>();
                if (!rec->source_key.empty()) {
                    rec->source = string_to_n_dfl<uuid>(rec->source_key, uuid());
                    rec->source_key = rec->source.as_string();
                }
                rec->source_name = o.at("source_name").get<std::string>().substr(0, 256);
                rec->samples = o.at("samples").get<uint64_t>();
                rec->rejected = o.at("rejected").get<uint64_t>();
                rec->first_time = o.at("first_time").get<time_t>();
                rec->last_time = o.at("last_time").get<time_t>();
                rec->moved = o.at("moved").get<double>();

                const auto& c = o.at("center");
                ok = c.is_array() && c.size() == 3 && c[0].is_number() && c[1].is_number() &&
                    c[2].is_number_unsigned();
                if (ok) {
                    rec->center_lat = c[0].get<double>();
                    rec->center_lon = c[1].get<double>();
                    rec->center_n = c[2].get<uint64_t>();
                }

                ok = ok && valid_kind(rec->kind) && (rec->source_key.empty() || !rec->source.error) &&
                    std::isfinite(rec->center_lat) && std::fabs(rec->center_lat) <= 90 &&
                    std::isfinite(rec->center_lon) && std::fabs(rec->center_lon) <= 180 &&
                    std::isfinite(rec->moved) && rec->moved >= 0 &&
                    load_array(o, "dist", rec->dist, max_dist) &&
                    load_array(o, "alt", rec->alt, 100000, -10000) &&
                    load_array(o, "time", rec->time, 1e12) &&
                    load_array(o, "signal", rec->signal, 1000, -1000) &&
                    load_array(o, "day_hour", rec->day_hour, 1e10);

                const auto& day = o.at("day");
                ok = ok && day.is_array() && day.size() == day_slots;
                for (size_t s = 0; ok && s < day_slots; s++)
                    ok = load_array(nlohmann::json{{"d", day[s]}}, "d", rec->day[s].dist, max_dist);

                const auto& band = o.at("band");
                ok = ok && band.is_array() && band.size() == bands;
                for (size_t b = 0; ok && b < bands; b++)
                    ok = load_array(nlohmann::json{{"d", band[b]}}, "d", rec->band[b].dist, max_dist);

                // Saves from before the hull have none
                if (ok && o.contains("hull")) {
                    const auto& hull = o.at("hull");
                    rec->hull_samples = o.at("hull_samples").get<uint64_t>();
                    ok = hull.is_array() && hull.size() <= max_hull;
                    for (size_t i = 0; ok && i < hull.size(); i++) {
                        const auto& p = hull[i];
                        ok = p.is_array() && p.size() == 2 && p[0].is_number() && p[1].is_number();
                        if (!ok)
                            break;
                        const double lat = p[0].get<double>(), lon = p[1].get<double>();
                        ok = std::isfinite(lat) && std::isfinite(lon) && std::fabs(lat) <= 90 && std::fabs(lon) <= 180;
                        if (ok)
                            rec->hull.emplace_back(lat, lon);
                    }
                }
            }
        } catch (const std::exception&) {
            ok = false;
        }

        if (!ok) {
            bad++;
            continue;
        }

        auto key = record_key(rec->kind, rec->source_key);
        records[key] = std::move(rec);
        loaded++;
    }

    if (bad)
        _MSG_ERROR("Skipped {} unreadable receiver range record{} in {}", bad, bad == 1 ? "" : "s", save_file);
    if (loaded)
        _MSG_INFO("Loaded the receiver range for {} kind{} of device and source from {}", loaded,
                loaded == 1 ? "" : "s", save_file);
}
