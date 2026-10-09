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
#include "kis_gps.h"

#include "messagebus.h"
#include "timetracker.h"
#include "gpstracker.h"

namespace {
    template<typename T>
    struct elem_tag {
        using type = T;
    };
}

kis_gps::kis_gps(shared_gps_builder in_builder, uint64_t in_id) :
    tracker_component() {

    register_fields();
    reserve_fields(NULL);

    packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    gpstracker = Globalreg::fetch_mandatory_global_as<gps_tracker>();

    gps_id = in_id;

    // Force the ID
    set_id(Globalreg::globalreg->entrytracker->register_field("kismet.gps.instance", 
            tracker_element_factory<tracker_element_map>(), "GPS"));

    // Link the builder
    gps_prototype = in_builder;
    insert(gps_prototype);

    gps_location = packetchain->new_packet_component<kis_gps_packinfo>();
    gps_last_location = packetchain->new_packet_component<kis_gps_packinfo>();
}

kis_gps::~kis_gps() {

}

bool kis_gps::open_gps(std::string in_definition) {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "kis_gps open_gps");

    set_int_device_connected(false);
    set_int_gps_definition(in_definition);

    // Source extraction modeled on datasource
    // We already had to extract the type= option in the gps tracker to get to
    // here but it's easier to just do it again and happens very very rarely

    // gps=type:name=whatever,etc=something
   
    size_t cpos = in_definition.find(":");

    // Turn the rest into an opt vector
    std::vector<opt_pair> options;

    std::string types;

    // If there's no ':' then there are no options
    if (cpos == std::string::npos) {
        types = in_definition;
    } else {
        types = in_definition.substr(0, cpos);

        // Blow up if we fail parsing
        if (string_to_opts(in_definition.substr(cpos + 1, 
                        in_definition.size() - cpos - 1), ",", &options) < 0) {
            return false;
        }

        for (auto i = options.begin(); i != options.end(); ++i) {
            source_definition_opts[str_lower((*i).opt)] = (*i).val;
        }
    }

    // A reconnect reopens with the same definition; keep the name instead of finding
    // our own name in use and picking a new one
    if (get_gps_name().empty()) {
        std::string sname = fetch_opt("name", source_definition_opts);
        if (sname != "") {
            set_int_gps_name(gpstracker->find_next_name(sname));
        } else {
            set_int_gps_name(gpstracker->find_next_name(gps_prototype->get_default_name()));
        }
    }

    std::string suuid = fetch_opt("uuid", source_definition_opts);
    if (suuid != "") {
        // Use the static UUID from the definition
        uuid u(suuid);

        if (u.error) {
            _MSG("Invalid UUID passed in GPS definition as uuid=... for " + 
                    get_gps_name(), MSGFLAG_FATAL);
            return false;
        }

        set_int_gps_uuid(u);
    } else {
        // Otherwise combine the server name and the definition, checksum it, and 
        // munge it into a UUID like we do for datasources
        std::string id = Globalreg::globalreg->servername + in_definition;
        char ubuf[40];

        snprintf(ubuf, 40, "%08X-0000-0000-0000-0000%08X",
                adler32_checksum("kismet_gps", strlen("kismet_gps")) & 0xFFFFFFFF,
                adler32_checksum(id.c_str(), id.length()) & 0xFFFFFFFF);
        uuid u(ubuf);

        set_int_gps_uuid(u);
    }

    std::string sprio = fetch_opt("priority", source_definition_opts);
    if (sprio != "") {
        int priority;

        if (sscanf(sprio.c_str(), "%d", &priority) != 1) {
            _MSG("Invalid priority passed in GPS definition as priority=... for " + 
                    get_gps_name(), MSGFLAG_FATAL);
            return false;
        }

        set_int_gps_priority(priority);
    } else {
        set_int_gps_priority(gps_prototype->get_gps_priority());
    }

    set_int_gps_data_only(fetch_opt_bool("dataonly", source_definition_opts, false));

    set_int_gps_reconnect(fetch_opt_bool("reconnect", source_definition_opts, true));

    set_int_device_connected(true);

    return true;
}

double kis_gps::gps_calc_heading(double in_lat, double in_lon, double in_lat2, 
							   double in_lon2) {
    double r = gps_calc_rad((double) in_lat2);

    double lat1 = gps_deg_to_rad((double) in_lat);
    double lon1 = gps_deg_to_rad((double) in_lon);
    double lat2 = gps_deg_to_rad((double) in_lat2);
    double lon2 = gps_deg_to_rad((double) in_lon2);

    double angle = 0;

    if (lat1 == lat2) {
        if (lon2 > lon1) {
            angle = M_PI/2;
        } else if (lon2 < lon1) {
            angle = 3 * M_PI / 2;
        } else {
            return 0;
        }
    } else if (lon1 == lon2) {
        if (lat2 > lat1) {
            angle = 0;
        } else if (lat2 < lat1) {
            angle = M_PI;
        }
    } else {
        double tx = r * cos((double) lat1) * (lon2 - lon1);
        double ty = r * (lat2 - lat1);
        angle = atan((double) (tx/ty));

        if (ty < 0) {
            angle += M_PI;
        }

        if (angle >= (2 * M_PI)) {
            angle -= (2 * M_PI);
        }

        if (angle < 0) {
            angle += 2 * M_PI;
        }

    }

    return (double) gps_rad_to_deg(angle);
}

double kis_gps::gps_rad_to_deg(double x) {
    return (x/M_PI) * 180.0;
}

double kis_gps::gps_deg_to_rad(double x) {
    return 180/(x*M_PI);
}

double kis_gps::gps_earth_distance(double in_lat, double in_lon, 
        double in_lat2, double in_lon2) {
    double x1 = gps_calc_rad(in_lat) * cos(gps_deg_to_rad(in_lon)) * sin(gps_deg_to_rad(90-in_lat));
    double x2 = 
        gps_calc_rad(in_lat2) * cos(gps_deg_to_rad(in_lon2)) * sin(gps_deg_to_rad(90-in_lat2));
    double y1 = gps_calc_rad(in_lat) * sin(gps_deg_to_rad(in_lon)) * sin(gps_deg_to_rad(90-in_lat));
    double y2 = 
        gps_calc_rad(in_lat2) * sin(gps_deg_to_rad(in_lon2)) * sin(gps_deg_to_rad(90-in_lat2));
    double z1 = gps_calc_rad(in_lat) * cos(gps_deg_to_rad(90-in_lat));
    double z2 = gps_calc_rad(in_lat2) * cos(gps_deg_to_rad(90-in_lat2));
    double a = 
        acos((x1*x2 + y1*y2 + z1*z2)/pow(gps_calc_rad((double) (in_lat+in_lat2)/2),2));
    return gps_calc_rad((double) (in_lat+in_lat2) / 2) * a;
}

double kis_gps::gps_calc_rad(double lat) {
    double a = 6378.137, r, sc, x, y, z;
    double e2 = 0.081082 * 0.081082;

    lat = lat * M_PI / 180.0;
    sc = sin (lat);
    x = a * (1.0 - e2);
    z = 1.0 - e2 * sc * sc;
    y = pow (z, 1.5);
    r = x / y;

    r = r * 1000.0;
    return r;
}

void kis_gps::apply_fix(const gps_fix_update& update) {
    if (update.empty()) {
        if (!update.quality.empty())
            apply_quality(update.quality);

        return;
    }

    auto loc = packetchain->new_packet_component<kis_gps_packinfo>();

    struct timeval now;
    gettimeofday(&now, nullptr);

    kis_lock_guard<kis_mutex> lk(data_mutex, "gps apply_fix");

    const auto prev = gps_location;

    merge_quality(update.quality, now.tv_sec);

    // A fix mode report which matches the current fix doesn't refresh the location, and a
    // no fix report before any location doesn't create one
    if (update.fix_reported && !update.has_position && !update.has_alt && !update.has_speed &&
            !update.has_heading && !update.has_magheading &&
            ((prev->gps_info_ok && prev->fix == update.fix) || (!prev->gps_info_ok && update.fix < 2))) {
        fix_reported_time = now.tv_sec;
        set_int_gps_data_time(now.tv_sec);
        publish_quality(now.tv_sec);
        return;
    }

    // Fields this report doesn't carry come from the previous report
    loc->set(prev);

    if (update.has_position) {
        loc->lat = update.lat;
        loc->lon = update.lon;
    }

    if (update.has_alt)
        loc->alt = update.alt;

    if (update.has_speed)
        loc->speed = update.speed;

    if (update.has_heading) {
        loc->heading = update.heading;
        fix_heading_time = now.tv_sec;
    }

    if (update.has_magheading) {
        loc->magheading = update.magheading;
        fix_heading_time = now.tv_sec;
    }

    if (update.has_fix && update.fix_reported) {
        loc->fix = update.fix;
        fix_reported_time = now.tv_sec;
    } else if (update.has_fix && now.tv_sec - fix_reported_time > fix_reported_stale) {
        // Keep a better fix from another sentence in this reporting cycle, but not a stale one
        const int64_t age_us = (static_cast<int64_t>(now.tv_sec) - prev->tv.tv_sec) * 1000000 +
            (now.tv_usec - prev->tv.tv_usec);

        const bool prev_recent = prev->gps_info_ok && age_us >= 0 && age_us < 1000000;
        loc->fix = std::max(update.fix, prev_recent ? prev->fix : 0);
    }

    if (update.has_position && !update.has_heading && prev->fix >= 2 &&
            now.tv_sec - fix_heading_time > 5) {
        loc->heading = gps_calc_heading(loc->lat, loc->lon, prev->lat, prev->lon);
        fix_heading_time = now.tv_sec;
    }

    loc->gps_info_ok = true;
    loc->tv = now;
    loc->gps_id = gps_id;

    bool reported;
    loc->precision = loc->fix >= 2 ? quality_precision(false, reported) : 0;

    gps_last_location = prev;
    gps_location = loc;

    update_locations();
    publish_quality(now.tv_sec);
}

void kis_gps::apply_quality(const gps_quality_update& update) {
    const time_t now = time(0);

    kis_lock_guard<kis_mutex> lk(data_mutex, "gps apply_quality");

    merge_quality(update, now);
    set_int_gps_data_time(now);
    publish_quality(now);
}

void kis_gps::clear_quality() {
    kis_lock_guard<kis_mutex> lk(data_mutex, "gps clear_quality");

    quality_state = {};

    for (auto id : {sats_used_id, sats_visible_id, hdop_id, vdop_id, precision_h_id,
            precision_v_id, precision_source_id, signal_cn0_id, signal_quality_id})
        clear_quality_field(id);
}

void kis_gps::merge_quality(const gps_quality_update& update, time_t now) {
    if (update.empty())
        return;

    expire_quality(now);

    auto merge = [&](bool has, quality_field f, double v) {
        if (!has)
            return;

        auto& q = quality_at(f);

        // A binary report outranks NMEA until it goes stale
        if (q.present && update.rank < q.rank)
            return;

        q.present = true;
        q.value = v;
        q.time = now;
        q.rank = update.rank;
    };

    merge(update.has_sats_used, quality_field::sats_used, update.sats_used);
    merge(update.has_sats_visible, quality_field::sats_visible, update.sats_visible);
    merge(update.has_hdop, quality_field::hdop, update.hdop);
    merge(update.has_vdop, quality_field::vdop, update.vdop);
    merge(update.has_error_h, quality_field::error_h, update.error_h);
    merge(update.has_error_v, quality_field::error_v, update.error_v);
    merge(update.has_cn0, quality_field::cn0, update.cn0);
}

void kis_gps::expire_quality(time_t now) {
    for (auto& q : quality_state) {
        if (q.present && (now - q.time > quality_expire || now < q.time))
            q = {};
    }
}

double kis_gps::quality_precision(bool vertical, bool& reported) {
    const auto& err = quality_at(vertical ? quality_field::error_v : quality_field::error_h);
    const auto& dop = quality_at(vertical ? quality_field::vdop : quality_field::hdop);

    if (err.present && err.value > 0) {
        reported = true;
        return err.value;
    }

    if (dop.present && dop.value > 0) {
        reported = false;
        return dop.value * estimated_uere;
    }

    return 0;
}

void kis_gps::publish_quality(time_t now) {
    expire_quality(now);

    const auto& used = quality_at(quality_field::sats_used);
    const auto& visible = quality_at(quality_field::sats_visible);
    const auto& hdop = quality_at(quality_field::hdop);
    const auto& vdop = quality_at(quality_field::vdop);
    const auto& cn0 = quality_at(quality_field::cn0);

    auto publish = [this](uint16_t id, const quality_value& q, auto as) {
        using T = typename decltype(as)::type;

        if (!q.present)
            clear_quality_field(id);
        else if constexpr (std::is_same<T, tracker_element_uint8>::value)
            set_quality_field<T>(id, static_cast<uint8_t>(std::min(q.value, 255.0)));
        else
            set_quality_field<T>(id, q.value);
    };

    publish(sats_used_id, used, elem_tag<tracker_element_uint8>{});
    publish(sats_visible_id, visible, elem_tag<tracker_element_uint8>{});
    publish(hdop_id, hdop, elem_tag<tracker_element_double>{});
    publish(vdop_id, vdop, elem_tag<tracker_element_double>{});
    publish(signal_cn0_id, cn0, elem_tag<tracker_element_double>{});

    // Same validity the drivers use for the location
    const bool recent = gps_location != nullptr && gps_location->gps_info_ok &&
        now - gps_location->tv.tv_sec <= 10;
    const int fix = recent ? gps_location->fix : 0;

    bool h_reported = false;
    bool v_reported = false;
    const double prec_h = fix >= 2 ? quality_precision(false, h_reported) : 0;
    const double prec_v = fix >= 3 ? quality_precision(true, v_reported) : 0;

    if (prec_h > 0)
        set_quality_field<tracker_element_double>(precision_h_id, prec_h);
    else
        clear_quality_field(precision_h_id);

    if (prec_v > 0)
        set_quality_field<tracker_element_double>(precision_v_id, prec_v);
    else
        clear_quality_field(precision_v_id);

    if (prec_h > 0 || prec_v > 0) {
        const bool all_reported = (prec_h <= 0 || h_reported) && (prec_v <= 0 || v_reported);
        const bool all_estimated = (prec_h <= 0 || !h_reported) && (prec_v <= 0 || !v_reported);

        set_quality_field<tracker_element_string>(precision_source_id,
                std::string(all_reported ? "reported" : all_estimated ? "estimated" : "mixed"));
    } else {
        clear_quality_field(precision_source_id);
    }

    // Known to be 0 while the GPS reports without a fix; unknown if it reports nothing
    const bool any = used.present || visible.present || hdop.present || cn0.present;
    const int score = gps_signal_quality_score(fix,
            cn0.present ? cn0.value : -1, hdop.present ? hdop.value : 0,
            used.present ? static_cast<int>(used.value) : -1);

    if (score >= 0 && (fix >= 2 || any || recent))
        set_quality_field<tracker_element_uint8>(signal_quality_id, static_cast<uint8_t>(score));
    else
        clear_quality_field(signal_quality_id);
}

void kis_gps::add_signal_report(tracker_component& report) {
    kis_lock_guard<kis_mutex> lk(data_mutex, "gps add_signal_report");

    publish_quality(time(0));

    auto copy = [this, &report](uint16_t id, auto as) {
        using T = typename decltype(as)::type;

        const auto ci = find(id);
        if (ci == end())
            return;

        auto e = Globalreg::globalreg->entrytracker->get_shared_instance_as<T>(id);
        e->set(std::static_pointer_cast<T>(ci->second)->get());
        report.insert(e);
    };

    copy(sats_used_id, elem_tag<tracker_element_uint8>{});
    copy(sats_visible_id, elem_tag<tracker_element_uint8>{});
    copy(hdop_id, elem_tag<tracker_element_double>{});
    copy(vdop_id, elem_tag<tracker_element_double>{});
    copy(precision_h_id, elem_tag<tracker_element_double>{});
    copy(precision_v_id, elem_tag<tracker_element_double>{});
    copy(precision_source_id, elem_tag<tracker_element_string>{});
    copy(signal_cn0_id, elem_tag<tracker_element_double>{});
    copy(signal_quality_id, elem_tag<tracker_element_uint8>{});
}

void kis_gps::update_locations() {
    kis_lock_guard<kis_mutex> lk(data_mutex);
    set_int_gps_data_time(time(0));
    set_int_gps_signal_time(time(0));

    tracked_last_location->set_location(gps_last_location->lat, gps_last_location->lon);
    tracked_last_location->set_alt(gps_last_location->alt);
    tracked_last_location->set_speed(gps_last_location->speed);
    tracked_last_location->set_heading(gps_last_location->heading);
    tracked_last_location->set_fix(gps_last_location->fix);
    tracked_last_location->set_time_sec(gps_last_location->tv.tv_sec);
    tracked_last_location->set_time_usec(gps_last_location->tv.tv_usec);

    tracked_location->set_location(gps_location->lat, gps_location->lon);
    tracked_location->set_alt(gps_location->alt);
    tracked_location->set_speed(gps_location->speed);
    tracked_location->set_heading(gps_location->heading);
    tracked_location->set_fix(gps_location->fix);
    tracked_location->set_time_sec(gps_location->tv.tv_sec);
    tracked_location->set_time_usec(gps_location->tv.tv_usec);
}

