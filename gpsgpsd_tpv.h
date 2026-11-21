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

#ifndef __GPSGPSD_TPV_H__
#define __GPSGPSD_TPV_H__

#include <cmath>

#include "gps_bounds.h"
#include "nlohmann/json.hpp"

// Range-checked fields of a gpsd JSON TPV or ATT record.  gpsd is a network peer, so
// a field that is out of range or the wrong type is dropped rather than stored.
namespace gpsd_json {
    constexpr double ms_to_kph = 3.6;
    // 95% error estimates past this are not a fix
    constexpr double max_error_m = 1000000;
    // gpsd TPV mode: 0 unknown, 1 no fix, 2 2d, 3 3d
    constexpr int max_mode = 3;

    // A finite number, without throwing on a missing or mistyped field
    inline bool number(const nlohmann::json& j, const char *key, double& out) {
        const auto it = j.find(key);

        if (it == j.end() || !it->is_number())
            return false;

        out = it->get<double>();
        return std::isfinite(out);
    }

    inline bool present(const nlohmann::json& j, const char *key) {
        return j.find(key) != j.end();
    }

    using gps_bounds::lat_valid;
    using gps_bounds::lon_valid;
    using gps_bounds::alt_valid;
    using gps_bounds::speed_valid;
    constexpr bool heading_valid(double v) { return v >= 0 && v <= 360; }
    constexpr bool error_valid(double v) { return v >= 0 && v <= max_error_m; }

    // Altitude above mean sea level, as the NMEA drivers report it.  gpsd 3.20+ sends
    // altMSL and altHAE and deprecates alt; altHAE is corrected by geoidSep when it can be.
    inline bool msl_altitude(const nlohmann::json& j, double& out) {
        double v, sep;

        if (number(j, "altMSL", v) && alt_valid(v)) {
            out = v;
            return true;
        }

        if (number(j, "alt", v) && alt_valid(v)) {
            out = v;
            return true;
        }

        if (number(j, "altHAE", v)) {
            if (number(j, "geoidSep", sep))
                v -= sep;

            if (alt_valid(v)) {
                out = v;
                return true;
            }
        }

        return false;
    }

    struct tpv {
        bool has_fix = false;
        int fix = 0;

        bool has_alt = false;
        double alt = 0;

        bool has_position = false;
        double lat = 0;
        double lon = 0;

        bool has_heading = false;
        double heading = 0;

        bool has_magheading = false;
        double magheading = 0;

        bool has_speed = false;
        double speed_kph = 0;

        bool has_error_x = false;
        bool has_error_y = false;
        bool has_error_v = false;
        bool has_error_h = false;
        double error_x = 0;
        double error_y = 0;
        double error_v = 0;
        double error_h = 0;
    };

    // A missing field takes the value 0 (as gpsd's own clients read it); a present
    // field that is mistyped or out of range is not set.  An invalid mode drops the
    // whole fix, since the position fields are only meaningful under it; a 3d fix
    // without a usable altitude is reported as 2d.
    inline tpv parse_tpv(const nlohmann::json& j) {
        tpv r;
        double v;

        if (!present(j, "mode")) {
            r.has_fix = true;
        } else if (number(j, "mode", v) && v >= 0 && v <= max_mode && v == std::floor(v)) {
            r.has_fix = true;
            r.fix = static_cast<int>(v);
        }

        if (!r.has_fix)
            return r;

        if (r.fix > 2) {
            if (msl_altitude(j, v)) {
                r.has_alt = true;
                r.alt = v;
            } else {
                r.fix = 2;
            }
        }

        if (number(j, "epx", v) && error_valid(v)) {
            r.has_error_x = true;
            r.error_x = v;
        }

        if (number(j, "epy", v) && error_valid(v)) {
            r.has_error_y = true;
            r.error_y = v;
        }

        if (number(j, "epv", v) && error_valid(v)) {
            r.has_error_v = true;
            r.error_v = v;
        }

        if (number(j, "eph", v) && v > 0 && error_valid(v)) {
            r.has_error_h = true;
            r.error_h = v;
        }

        if (r.fix < 2)
            return r;

        double lat, lon;
        if (number(j, "lat", lat) && number(j, "lon", lon) && lat_valid(lat) && lon_valid(lon)) {
            r.has_position = true;
            r.lat = lat;
            r.lon = lon;
        }

        if (number(j, "track", v) && heading_valid(v)) {
            r.has_heading = true;
            r.heading = v;
        }

        if (number(j, "magtrack", v) && heading_valid(v)) {
            r.has_magheading = true;
            r.magheading = v;
        }

        if (number(j, "speed", v) && speed_valid(v * ms_to_kph)) {
            r.has_speed = true;
            r.speed_kph = v * ms_to_kph;
        }

        return r;
    }
}

#endif
