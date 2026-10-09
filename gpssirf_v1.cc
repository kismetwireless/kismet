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

#include <array>
#include <cmath>

#include "gpssirf_v1.h"

namespace {
    // SiRF is big endian
    uint16_t get_u16(const uint8_t *p) {
        return static_cast<uint16_t>((p[0] << 8) | p[1]);
    }

    int16_t get_i16(const uint8_t *p) {
        return static_cast<int16_t>(get_u16(p));
    }

    uint32_t get_u32(const uint8_t *p) {
        return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
            (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
    }

    int32_t get_i32(const uint8_t *p) {
        return static_cast<int32_t>(get_u32(p));
    }

    // Navigation type to a Kismet 2d/3d fix: Kalman fixes from 4 or more satellites and
    // 3d least squares fixes are 3d; fewer satellites, 2d least squares, and dead reckoning
    // are 2d
    constexpr int map_fix(uint16_t nav_type) {
        switch (nav_type & 0x07) {
            case 0:
                return 0;
            case 4:
            case 6:
                return 3;
            default:
                return 2;
        }
    }

    constexpr double pi = 3.14159265358979323846;

    // WGS-84
    constexpr double wgs84_a = 6378137.0;
    constexpr double wgs84_f = 1.0 / 298.257223563;
    constexpr double wgs84_b = wgs84_a * (1 - wgs84_f);
    constexpr double wgs84_e2 = wgs84_f * (2 - wgs84_f);
    constexpr double wgs84_ep2 = (wgs84_a * wgs84_a - wgs84_b * wgs84_b) / (wgs84_b * wgs84_b);

    // The receiver reported no usable fix, which invalidates the current location
    gps_sirf_decoder_v1::result no_fix(gps_fix_update& update) {
        update.has_fix = true;
        update.fix_reported = true;
        update.fix = 1;
        return gps_sirf_decoder_v1::result::update;
    }

    // Receivers report huge errors before the estimate settles
    constexpr uint32_t max_error_cm = 100000000;

    // HDOP * 5; 0 when unknown
    void set_hdop(uint8_t hdop5, gps_quality_update& q) {
        if (hdop5 == 0)
            return;

        q.has_hdop = true;
        q.hdop = hdop5 * 0.2;
    }

    double heading_deg(double east, double north) {
        double h = std::atan2(east, north) * 180.0 / pi;
        return h < 0 ? h + 360.0 : h;
    }
}

gps_sirf_decoder_v1::result gps_sirf_decoder_v1::decode(std::string_view frame, gps_fix_update& update) {
    update = gps_fix_update{};

    if (frame.size() < header_len + 1 + trailer_len)
        return result::malformed;

    const auto *f = reinterpret_cast<const uint8_t *>(frame.data());
    const size_t len = get_u16(f + 2) & 0x7FFF;

    if (frame.size() != header_len + len + trailer_len || len == 0)
        return result::malformed;

    const uint8_t *p = f + header_len;

    auto& q = update.quality;
    q.rank = gps_quality_update::source_rank::binary;

    switch (p[0]) {
        case mid_geodetic_nav: {
            if (len < 91)
                return result::malformed;

            have_geodetic = true;

            // Any invalid bit set means the fix isn't usable
            const int fix = map_fix(get_u16(p + 3));

            q.has_sats_used = true;
            q.sats_used = p[88];
            set_hdop(p[89], q);

            if (get_u16(p + 1) != 0 || fix < 2)
                return no_fix(update);

            const double lat = get_i32(p + 23) * 1e-7;
            const double lon = get_i32(p + 27) * 1e-7;

            if (lat < -90 || lat > 90 || lon < -180 || lon > 180)
                return result::malformed;

            update.has_position = true;
            update.lat = lat;
            update.lon = lon;

            update.has_fix = true;
            update.fix_reported = true;
            update.fix = fix;

            if (fix >= 3) {
                update.has_alt = true;
                update.alt = get_i32(p + 35) / 100.0;
            }

            // Estimated position errors, cm
            const uint32_t ehpe = get_u32(p + 50);
            const uint32_t evpe = get_u32(p + 54);

            if (ehpe > 0 && ehpe < max_error_cm) {
                q.has_error_h = true;
                q.error_h = ehpe / 100.0;
            }

            if (fix >= 3 && evpe > 0 && evpe < max_error_cm) {
                q.has_error_v = true;
                q.error_v = evpe / 100.0;
            }

            // m/s * 100, degrees * 100
            update.has_speed = true;
            update.speed = get_u16(p + 40) * 0.036;

            const double course = get_u16(p + 42) / 100.0;
            if (course <= 360) {
                update.has_heading = true;
                update.heading = course;
            }

            return result::update;
        }

        case mid_measured_nav: {
            if (len < 41)
                return result::malformed;

            if (have_geodetic)
                return result::ignored;

            const int fix = map_fix(p[19]);

            q.has_sats_used = true;
            q.sats_used = p[28];
            set_hdop(p[20], q);

            if (fix < 2)
                return no_fix(update);

            const double x = get_i32(p + 1);
            const double y = get_i32(p + 5);
            const double z = get_i32(p + 9);

            // Bowring's method; well under a centimeter at the surface
            const double r = std::sqrt(x * x + y * y);

            if (r < 1.0)
                return result::malformed;

            const double theta = std::atan2(z * wgs84_a, r * wgs84_b);
            const double st = std::sin(theta);
            const double ct = std::cos(theta);
            const double lat = std::atan2(z + wgs84_ep2 * wgs84_b * st * st * st,
                    r - wgs84_e2 * wgs84_a * ct * ct * ct);
            const double lon = std::atan2(y, x);
            const double sl = std::sin(lat);
            const double n = wgs84_a / std::sqrt(1 - wgs84_e2 * sl * sl);
            const double height = r / std::cos(lat) - n;

            update.has_position = true;
            update.lat = lat * 180.0 / pi;
            update.lon = lon * 180.0 / pi;

            update.has_fix = true;
            update.fix_reported = true;
            update.fix = fix;

            // Height above the ellipsoid; MID 2 has no geoid separation
            if (fix >= 3 && std::isfinite(height)) {
                update.has_alt = true;
                update.alt = height;
            }

            // m/s * 8, rotated from ECEF to east/north
            const double vx = get_i16(p + 13) / 8.0;
            const double vy = get_i16(p + 15) / 8.0;
            const double vz = get_i16(p + 17) / 8.0;
            const double clat = std::cos(lat);
            const double clon = std::cos(lon);
            const double slon = std::sin(lon);

            const double east = -slon * vx + clon * vy;
            const double north = -sl * clon * vx - sl * slon * vy + clat * vz;

            update.has_speed = true;
            update.speed = std::sqrt(east * east + north * north) * 3.6;

            update.has_heading = true;
            update.heading = heading_deg(east, north);

            return result::update;
        }

        case mid_tracker: {
            constexpr size_t chan_start = 8;
            constexpr size_t chan_len = 15;
            constexpr size_t cn0_samples = 10;

            if (len < chan_start || len < chan_start + chan_len * p[7])
                return result::malformed;

            std::array<double, 255> cn0;
            size_t ncn0 = 0;
            unsigned int visible = 0;

            for (size_t c = 0; c < p[7]; c++) {
                const auto *ch = p + chan_start + c * chan_len;

                if (ch[0] == 0)
                    continue;

                visible++;

                // Ten C/N0 samples, one per 100ms
                unsigned int sum = 0;
                unsigned int n = 0;
                for (size_t i = 0; i < cn0_samples; i++) {
                    if (ch[5 + i] > 0) {
                        sum += ch[5 + i];
                        n++;
                    }
                }

                if (n > 0)
                    cn0[ncn0++] = static_cast<double>(sum) / n;
            }

            q.has_sats_visible = true;
            q.sats_visible = visible;
            q.has_cn0 = gps_quality_update::strongest_cn0(cn0.data(), ncn0, q.cn0);

            return result::update;
        }

        default:
            return result::ignored;
    }
}
