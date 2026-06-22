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

#include "trackedlocation_v2.h"

#include "gpstracker.h"
#include "packet.h"

void kis_tracked_location_triplet_v2::set(const kis_tracked_location_triplet_v2& t) {
    geopoint_ = t.geopoint_;
    altitude_ = t.altitude_;
    fix_ = t.fix_;
    time_sec_ = t.time_sec_;
    time_usec_ = t.time_usec_;
}

void kis_tracked_location_triplet_v2::set(const kis_gps_packinfo *pi) {
    if (pi == nullptr) {
        return;
    }

    set_location(pi->lat, pi->lon, pi->alt, pi->fix);
    set_time(pi->tv.tv_sec, pi->tv.tv_usec);
}

void kis_tracked_location_triplet_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");
    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed_pair<double, double>{}(os, "kismet.common.location.geopoint", opts, geopoint_);
    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.common.location.alt", opts, altitude_);
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "kismet.common.location.fix", opts, fix_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.location.time_sec", opts, time_sec_);
    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.common.location.time_usec", opts, time_usec_);

    opts->next_key_comma = sv_comma;
    fmt::print(os, "}}");
}

void kis_tracked_location_triplet_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts,
        const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;
    fmt::print(os, "{{");

    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("kismet.common.location.geopoint"):
                json_adapter_v2::json_encode_keyed_pair<double, double>{}(os, f.second.rename, opts, geopoint_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.alt"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, altitude_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.fix"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, fix_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.time_sec"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, time_sec_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.time_usec"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, time_usec_);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

void kis_tracked_location_full_v2::set(const kis_tracked_location_triplet_v2& t) {
    geopoint_ = t.geopoint_;
    altitude_ = t.altitude_;
    fix_ = t.fix_;
    time_sec_ = t.time_sec_;
    time_usec_ = t.time_usec_;

    speed_ = 0;
    heading_ = 0;
    magheading_ = 0;
}

void kis_tracked_location_full_v2::set(const kis_tracked_location_full_v2& t) {
    geopoint_ = t.geopoint_;
    altitude_ = t.altitude_;
    fix_ = t.fix_;
    time_sec_ = t.time_sec_;
    time_usec_ = t.time_usec_;

    speed_ = t.speed_;
    heading_ = t.heading_;
    magheading_ = t.magheading_;
}

void kis_tracked_location_full_v2::set(const kis_gps_packinfo *pi) {
    if (pi == nullptr) {
        return;
    }

    geopoint_ = {pi->lon, pi->lat};
    time_sec_ = pi->tv.tv_sec;
    time_usec_ = pi->tv.tv_usec;
    altitude_ = pi->alt;
    fix_ = pi->fix;
    speed_ = pi->speed;
    heading_ = pi->heading;
    magheading_ = pi->magheading;
}

void kis_tracked_location_full_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");
    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed_pair<double, double>{}(os, "kismet.common.location.geopoint", opts, geopoint_);
    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.common.location.alt", opts, altitude_);
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "kismet.common.location.fix", opts, fix_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.location.time_sec", opts, time_sec_);
    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.common.location.time_usec", opts, time_usec_);

    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.common.location.speed", opts, speed_);
    json_adapter_v2::json_encode_keyed<float>{}(os, "kismet.common.location.heading", opts, heading_);
    json_adapter_v2::json_encode_keyed<float>{}(os, "kismet.common.location.magheading", opts, magheading_);

    opts->next_key_comma = sv_comma;
    fmt::print(os, "}}");
}

void kis_tracked_location_full_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts,
        const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;
    fmt::print(os, "{{");

    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("kismet.common.location.geopoint"):
                json_adapter_v2::json_encode_keyed_pair<double, double>{}(os, f.second.rename, opts, geopoint_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.alt"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, altitude_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.fix"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, fix_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.time_sec"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, time_sec_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.time_usec"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, time_usec_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.speed"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, speed_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.heading"):
                json_adapter_v2::json_encode_keyed<float>{}(os, f.second.rename, opts, heading_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.magheading"):
                json_adapter_v2::json_encode_keyed<float>{}(os, f.second.rename, opts, magheading_);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

void kis_tracked_location_v2::add_loc(const kis_gps_packinfo *p) {
    if (p->fix < 2) {
        return;
    }

    last_loc_.set(p);

    auto min_pair = min_loc_.location();
    auto max_pair = max_loc_.location();

    if (min_loc_.fix() < 2) {
        min_loc_.set(p);
    } else {
        if (min_pair.second > p->lat) {
            min_pair.second = p->lat;
        }

        if (min_pair.first > p->lon) {
            min_pair.first = p->lon;
        }

        if (p->fix >= 3) {
            if (min_loc_.altitude() > p->alt) {
                min_loc_.set_altitude(p->alt);
                min_loc_.set_fix(p->fix);
            }
        }

        min_loc_.set_location(min_pair);
    }

    if (max_loc_.fix() < 2) {
        max_loc_.set(p);
    } else {
        if (max_pair.second < p->lat) {
            max_pair.second = p->lat;
        }

        if (max_pair.first < p->lon) {
            max_pair.first = p->lon;
        }

        if (p->fix >= 3) {
            if (max_loc_.altitude() < p->alt) {
                max_loc_.set_altitude(p->alt);
                max_loc_.set_fix(p->fix);
            }
        }
    }
}

void kis_tracked_location_v2::add_loc_with_avg(const kis_gps_packinfo *p) {
    if (p->fix < 2) {
        return;
    }

    add_loc(p);

    double mod_lat = p->lat * M_PI / 180;
    double mod_lon = p->lon * M_PI / 180;

    agg_x_ += cos(mod_lat) * cos(mod_lon);
    agg_y_ += cos(mod_lat) * sin(mod_lon);
    agg_z_ += sin(mod_lat);

    num_avg_ += 1;

    if (p->fix > 2) {
        agg_a_ += p->alt;
        num_alt_avg_ += 1;
    }

    double r_x = agg_x_ / num_avg_;
    double r_y = agg_y_ / num_avg_;
    double r_z = agg_z_ / num_avg_;

    double central_lon = atan2(r_y, r_x);
    double central_sqr = sqrt(r_x * r_x + r_y * r_y);
    double central_lat = atan2(r_z, central_sqr);

    double r_alt = 0;

    if (num_alt_avg_ > 0)
       r_alt =  agg_a_ / num_alt_avg_;

    // Use the incoming if we're the first packet
    if (num_avg_ > 1) {
        avg_loc_.set_location(central_lat * 180 / M_PI, central_lon * 180 / M_PI,
                r_alt, num_alt_avg_ > 0 ? 3 : 2);
    } else {
        avg_loc_.set(p);
    }
}

void kis_historic_location_v2::set(const kis_tracked_location_triplet_v2& t) {
    geopoint_ = t.geopoint_;
    altitude_ = t.altitude_;
    fix_ = t.fix_;
    time_sec_ = t.time_sec_;

    speed_ = 0;
    heading_ = 0;
    magheading_ = 0;
}

void kis_historic_location_v2::set(const kis_tracked_location_full_v2& t) {
    geopoint_ = t.geopoint_;
    altitude_ = t.altitude_;
    fix_ = t.fix_;
    time_sec_ = t.time_sec_;

    speed_ = t.speed_;
    heading_ = t.heading_;
    magheading_ = t.magheading_;
}

void kis_historic_location_v2::set(const kis_gps_packinfo *pi) {
    if (pi == nullptr) {
        return;
    }

    geopoint_ = {pi->lon, pi->lat};
    time_sec_ = pi->tv.tv_sec;
    altitude_ = pi->alt;
    fix_ = pi->fix;
    speed_ = pi->speed;
    heading_ = pi->heading;
    magheading_ = pi->magheading;
}

void kis_historic_location_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");
    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed_pair<double, double>{}(os, "kismet.historic.location.geopoint", opts, geopoint_);
    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.historic.location.alt", opts, altitude_);
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "kismet.historic.location.fix", opts, fix_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.historic.location.time_sec", opts, time_sec_);

    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.historic.location.speed", opts, speed_);
    json_adapter_v2::json_encode_keyed<float>{}(os, "kismet.historic.location.heading", opts, heading_);
    json_adapter_v2::json_encode_keyed<float>{}(os, "kismet.historic.location.magheading", opts, magheading_);

    json_adapter_v2::json_encode_keyed<int32_t>{}(os, "kismet.historic.location.signal", opts, signal_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.historic.location.frequency", opts, frequency_);

    opts->next_key_comma = sv_comma;
    fmt::print(os, "}}");
}

void kis_historic_location_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts,
        const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;
    fmt::print(os, "{{");

    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("kismet.historic.location.geopoint"):
                json_adapter_v2::json_encode_keyed_pair<double, double>{}(os, f.second.rename, opts, geopoint_);
                break;
            case json_adapter_v2::consthash("kismet.historic.location.alt"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, altitude_);
                break;
            case json_adapter_v2::consthash("kismet.historic.location.fix"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, fix_);
                break;
            case json_adapter_v2::consthash("kismet.historic.location.time_sec"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, time_sec_);
                break;
            case json_adapter_v2::consthash("kismet.historic.location.speed"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, speed_);
                break;
            case json_adapter_v2::consthash("kismet.historic.location.heading"):
                json_adapter_v2::json_encode_keyed<float>{}(os, f.second.rename, opts, heading_);
                break;
            case json_adapter_v2::consthash("kismet.historic.location.magheading"):
                json_adapter_v2::json_encode_keyed<float>{}(os, f.second.rename, opts, magheading_);
                break;
            case json_adapter_v2::consthash("kismet.historic.location.signal"):
                json_adapter_v2::json_encode_keyed<int32_t>{}(os, f.second.rename, opts, signal_);
                break;
            case json_adapter_v2::consthash("kismet.historic.location.frequency"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, frequency_);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

void kis_location_rrd_v2::add_sample(const kis_historic_location_v2& l) {
    auto lg = kis_unique_lock{mutex_, __func__};

    last_sample_ts_ = l.time();

    samples_tier1_[samples_t1_pos_++ % samples_tier1_.size()] = l;

    if (samples_t1_pos_ % samples_tier1_.size()  == 0) {
        kis_historic_location_v2 aggloc;
        aggloc.aggregate(samples_tier1_.size(), samples_tier1_.begin(), samples_tier1_.end());

        samples_tier2_[samples_t2_pos_++ % samples_tier2_.size()] = aggloc;

        if (samples_t2_pos_ % samples_tier2_.size() == 0) {
            kis_historic_location_v2 aggloc_t2;
            aggloc_t2.aggregate(samples_tier2_.size(), samples_tier2_.begin(), samples_tier2_.end());

            samples_tier3_[samples_t3_pos_++ % samples_tier3_.size()] = aggloc_t2;
        }
    }
}

void kis_location_rrd_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    auto lg = kis_shared_lock{mutex_, __func__};

    fmt::print(os, "{{");
    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed_array<sample_iter_>{}(os, "kismet.gps.rrd.samples_100", opts,
            samples_tier1_.begin(), samples_tier1_.end());
    json_adapter_v2::json_encode_keyed_array<sample_iter_>{}(os, "kismet.gps.rrd.samples_10k", opts,
            samples_tier1_.begin(), samples_tier2_.end());
    json_adapter_v2::json_encode_keyed_array<sample_iter_>{}(os, "kismet.gps.rrd.samples_1m", opts,
            samples_tier1_.begin(), samples_tier3_.end());

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.gps.rrd.last_sample_ts", opts, last_sample_ts_);

    opts->next_key_comma = sv_comma;
    fmt::print(os, "}}");
}

void kis_location_rrd_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts,
        const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto lg = kis_shared_lock{mutex_, __func__};

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;
    fmt::print(os, "{{");

    json_adapter_v2::field_group_map subgroup;

    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("kismet.gps.rrd.samples_100"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_array<sample_iter_>{}(os, f.second.rename, opts,
                        samples_tier1_.begin(), samples_tier1_.end(), subgroup);
                break;
            case json_adapter_v2::consthash("kismet.gps.rrd.samples_10k"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_array<sample_iter_>{}(os, f.second.rename, opts,
                        samples_tier2_.begin(), samples_tier2_.end(), subgroup);
                break;
            case json_adapter_v2::consthash("kismet.gps.rrd.samples_1m"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_array<sample_iter_>{}(os, f.second.rename, opts,
                        samples_tier3_.begin(), samples_tier3_.end(), subgroup);
                break;
            case json_adapter_v2::consthash("kismet.gps.rrd.last_sample_ts"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, last_sample_ts_);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

