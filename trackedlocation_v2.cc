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

void kis_tracked_location_triplet_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");
    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::encode_keyed_pair<double, double>(os, "kismet.common.location.geopoint", opts, geopoint_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.alt", opts, altitude_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.fix", opts, fix_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.time_sec", opts, time_sec_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.time_usec", opts, time_usec_);

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
                json_adapter_v2::encode_keyed_pair<double, double>(os, f.second.rename, opts, geopoint_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.alt"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, altitude_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.fix"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, fix_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.time_sec"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, time_sec_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.time_usec"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, time_usec_);
                break;
            default:
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

void kis_tracked_location_full_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");
    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::encode_keyed_pair<double, double>(os, "kismet.common.location.geopoint", opts, geopoint_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.alt", opts, altitude_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.fix", opts, fix_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.time_sec", opts, time_sec_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.time_usec", opts, time_usec_);

    json_adapter_v2::encode_keyed(os, "kismet.common.location.speed", opts, speed_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.heading", opts, heading_);
    json_adapter_v2::encode_keyed(os, "kismet.common.location.magheading", opts, magheading_);

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
                json_adapter_v2::encode_keyed_pair<double, double>(os, f.second.rename, opts, geopoint_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.alt"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, altitude_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.fix"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, fix_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.time_sec"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, time_sec_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.time_usec"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, time_usec_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.speed"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, speed_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.heading"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, heading_);
                break;
            case json_adapter_v2::consthash("kismet.common.location.magheading"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, magheading_);
                break;
            default:
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}
