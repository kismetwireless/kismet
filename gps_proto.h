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

#ifndef __GPS_PROTO_H__
#define __GPS_PROTO_H__

#include "config.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

enum class gps_constellation : uint8_t {
    unknown,
    gps,
    sbas,
    galileo,
    beidou,
    qzss,
    glonass,
    navic,
    imes,
};

constexpr const char *gps_constellation_name(gps_constellation c) {
    switch (c) {
        case gps_constellation::gps: return "GPS";
        case gps_constellation::sbas: return "SBAS";
        case gps_constellation::galileo: return "Galileo";
        case gps_constellation::beidou: return "BeiDou";
        case gps_constellation::qzss: return "QZSS";
        case gps_constellation::glonass: return "GLONASS";
        case gps_constellation::navic: return "NavIC";
        case gps_constellation::imes: return "IMES";
        default: return "Unknown";
    }
}

// The u-blox / gpsd GNSS id (gnssId, gnssid)
constexpr gps_constellation gps_constellation_from_gnss_id(unsigned int id) {
    switch (id) {
        case 0: return gps_constellation::gps;
        case 1: return gps_constellation::sbas;
        case 2: return gps_constellation::galileo;
        case 3: return gps_constellation::beidou;
        case 4: return gps_constellation::imes;
        case 5: return gps_constellation::qzss;
        case 6: return gps_constellation::glonass;
        case 7: return gps_constellation::navic;
        default: return gps_constellation::unknown;
    }
}

// A satellite numbered across all constellations, as NMEA 4.0, gpsd and older u-blox
// reports do; ranges per the gpsd and u-blox satellite numbering
constexpr gps_constellation gps_constellation_from_prn(unsigned int prn) {
    if (prn >= 1 && prn <= 32)
        return gps_constellation::gps;
    if (prn >= 33 && prn <= 64)
        return gps_constellation::sbas;
    if (prn >= 65 && prn <= 96)
        return gps_constellation::glonass;
    if (prn >= 120 && prn <= 158)
        return gps_constellation::sbas;
    if (prn >= 159 && prn <= 163)
        return gps_constellation::beidou;
    if (prn >= 193 && prn <= 202)
        return gps_constellation::qzss;
    if (prn >= 201 && prn <= 263)
        return gps_constellation::beidou;
    if (prn >= 301 && prn <= 336)
        return gps_constellation::galileo;
    if (prn >= 401 && prn <= 437)
        return gps_constellation::beidou;
    return gps_constellation::unknown;
}

// One satellite in view
struct gps_satellite {
    gps_constellation constellation = gps_constellation::unknown;
    // Satellite number, as the receiver reports it
    uint16_t id = 0;
    // Degrees; -1 when not known
    int16_t elevation = -1;
    int16_t azimuth = -1;
    // dB-Hz; 0 when not tracked
    double cn0 = 0;
    // In the fix: 1 yes, 0 no, -1 not known
    int8_t used = -1;
};

// Signal quality from one report; only the fields marked present are merged.  Binary
// protocols outrank NMEA, so a receiver sending both is reported from the binary values
// while they're current.
struct gps_quality_update {
    enum class source_rank : uint8_t {
        nmea = 1,
        binary = 2,
    };

    source_rank rank = source_rank::nmea;

    bool has_sats_used = false;
    unsigned int sats_used = 0;

    bool has_sats_visible = false;
    unsigned int sats_visible = 0;

    bool has_hdop = false;
    double hdop = 0;

    bool has_vdop = false;
    double vdop = 0;

    // The receiver's own position error estimate, meters
    bool has_error_h = false;
    double error_h = 0;

    bool has_error_v = false;
    double error_v = 0;

    // Average C/N0 of the strongest satellites, dB-Hz
    bool has_cn0 = false;
    double cn0 = 0;

    // Every satellite in view, when the report lists them
    bool has_satellites = false;
    std::vector<gps_satellite> satellites;

    bool empty() const {
        return !(has_sats_used || has_sats_visible || has_hdop || has_vdop || has_error_h ||
                has_error_v || has_cn0 || has_satellites);
    }

    // Satellites averaged for the C/N0
    static constexpr size_t cn0_strongest = 4;

    // Average of the strongest non-zero signals; values is reordered.  False when no
    // satellite has a signal.
    static bool strongest_cn0(double *values, size_t n, double& out) {
        const auto end = std::remove_if(values, values + n, [](double v) { return !(v > 0); });
        const size_t valid = static_cast<size_t>(end - values);

        if (valid == 0)
            return false;

        const size_t use = std::min(valid, cn0_strongest);
        std::partial_sort(values, values + use, end, [](double a, double b) { return a > b; });

        double sum = 0;
        for (size_t i = 0; i < use; i++)
            sum += values[i];

        out = sum / use;
        return true;
    }
};

// Estimated signal quality, 0-100, from whichever inputs are known (a negative value is
// unknown): the average C/N0 of the strongest satellites, the HDOP, and the satellites used
// in the fix.  Without a fix the quality is 0; a 2d fix is capped at 50.  -1 when a fix
// has none of the inputs.
constexpr int gps_signal_quality_score(int fix, double cn0, double hdop, int sats_used) {
    if (fix < 2)
        return 0;

    // 25 dB-Hz is barely tracking, 45 is a strong open sky signal
    constexpr double cn0_low = 25;
    constexpr double cn0_high = 45;
    // HDOP 1 is ideal geometry, 10 is poor
    constexpr double hdop_good = 1;
    constexpr double hdop_poor = 10;
    // 4 satellites is the minimum for a 3d fix
    constexpr double sats_low = 4;
    constexpr double sats_high = 10;

    constexpr double w_cn0 = 0.40;
    constexpr double w_hdop = 0.35;
    constexpr double w_sats = 0.25;

    double sum = 0;
    double weight = 0;

    if (cn0 >= 0) {
        sum += w_cn0 * std::clamp((cn0 - cn0_low) / (cn0_high - cn0_low), 0.0, 1.0);
        weight += w_cn0;
    }

    if (hdop > 0) {
        sum += w_hdop * std::clamp((hdop_poor - hdop) / (hdop_poor - hdop_good), 0.0, 1.0);
        weight += w_hdop;
    }

    if (sats_used >= 0) {
        sum += w_sats * std::clamp((sats_used - sats_low) / (sats_high - sats_low), 0.0, 1.0);
        weight += w_sats;
    }

    if (weight == 0)
        return -1;

    const int score = static_cast<int>(100 * sum / weight + 0.5);

    return fix == 2 ? std::min(score, 50) : score;
}

// One decoded report from a GPS protocol decoder; only the fields marked present are
// merged into the current location
struct gps_fix_update {
    bool has_position = false;
    double lat = 0;
    double lon = 0;

    // Meters above mean sea level
    bool has_alt = false;
    double alt = 0;

    // km/h
    bool has_speed = false;
    double speed = 0;

    // Degrees
    bool has_heading = false;
    double heading = 0;

    bool has_magheading = false;
    double magheading = 0;

    // Fix (1 for no fix, 2, or 3).  An implied fix is the minimum the report's fields allow,
    // and a recent better fix from another report in the same cycle is kept; a reported fix
    // is the receiver's own fix mode, replaces the current fix, and overrides implied fixes
    // while it is recent, so a reported no fix invalidates the location
    bool has_fix = false;
    bool fix_reported = false;
    int fix = 0;

    // Signal quality carried by the same report; it never creates a location on its own
    gps_quality_update quality;

    bool empty() const {
        return !(has_position || has_alt || has_speed || has_heading || has_magheading || has_fix);
    }
};

#endif
