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
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <time.h>

#include "gpsnmea_v3.h"
#include "gpstracker.h"
#include "messagebus.h"
#include "util.h"

namespace {
    constexpr size_t max_fields = 24;

    constexpr double knots_to_kph = 1.852;

    constexpr int hex_value(char c) {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        return -1;
    }

    constexpr bool is_digit(char c) {
        return c >= '0' && c <= '9';
    }

    // Whole field must be a finite number
    bool parse_double(std::string_view field, double& out) {
        char buf[32];

        if (field.empty() || field.size() >= sizeof(buf))
            return false;

        memcpy(buf, field.data(), field.size());
        buf[field.size()] = 0;

        char *end = nullptr;
        errno = 0;
        const double v = strtod(buf, &end);

        if (end != buf + field.size() || errno == ERANGE || !std::isfinite(v))
            return false;

        out = v;
        return true;
    }

    // ddmm.mmmm or dddmm.mmmm plus a hemisphere field
    bool parse_coord(std::string_view field, size_t deg_digits, std::string_view hemi,
            char pos_hemi, char neg_hemi, double max_deg, double& out) {
        if (field.size() <= deg_digits || hemi.size() != 1)
            return false;

        int deg = 0;
        for (size_t i = 0; i < deg_digits; i++) {
            if (!is_digit(field[i]))
                return false;
            deg = deg * 10 + (field[i] - '0');
        }

        double min;
        if (!parse_double(field.substr(deg_digits), min) || min < 0 || min >= 60)
            return false;

        double v = deg + (min / 60);
        if (v > max_deg)
            return false;

        if (hemi[0] == neg_hemi)
            v = -v;
        else if (hemi[0] != pos_hemi)
            return false;

        out = v;
        return true;
    }
}

bool gps_nmea::has_valid_checksum(std::string_view sentence) {
    while (!sentence.empty() && (sentence.back() == '\r' || sentence.back() == '\n'))
        sentence.remove_suffix(1);

    if (sentence.size() < 4 || (sentence[0] != '$' && sentence[0] != '!') ||
            sentence[sentence.size() - 3] != '*')
        return false;

    const int hi = hex_value(sentence[sentence.size() - 2]);
    const int lo = hex_value(sentence[sentence.size() - 1]);

    if (hi < 0 || lo < 0)
        return false;

    const auto body = sentence.substr(1, sentence.size() - 4);

    size_t addr_len = 0;
    while (addr_len < body.size() && body[addr_len] != ',') {
        const char c = body[addr_len];

        if (!((c >= 'A' && c <= 'Z') || is_digit(c)))
            return false;

        addr_len++;
    }

    if (addr_len < 3 || addr_len > 10)
        return false;

    unsigned int sum = 0;
    for (auto c : body)
        sum ^= static_cast<unsigned char>(c);

    return sum == static_cast<unsigned int>((hi << 4) | lo);
}

gps_nmea::result gps_nmea::parse(std::string_view sentence, gps_fix_update& update) {
    update = gps_fix_update{};

    while (!sentence.empty() && (sentence.back() == '\r' || sentence.back() == '\n'))
        sentence.remove_suffix(1);

    if (sentence.empty())
        return result::ignored;

    if (sentence.size() > max_sentence_len)
        return result::malformed;

    for (auto c : sentence) {
        if (c < 0x20 || c > 0x7E)
            return result::binary;
    }

    if (sentence[0] != '$' && sentence[0] != '!')
        return result::not_nmea;

    // Checksum is optional, but when present it covers everything between the $ and *
    auto body = sentence.substr(1);
    const auto star = body.find('*');

    if (star != std::string_view::npos) {
        if (body.size() - star != 3)
            return result::malformed;

        const int hi = hex_value(body[star + 1]);
        const int lo = hex_value(body[star + 2]);

        if (hi < 0 || lo < 0)
            return result::malformed;

        body = body.substr(0, star);

        unsigned int sum = 0;
        for (auto c : body)
            sum ^= static_cast<unsigned char>(c);

        if (sum != static_cast<unsigned int>((hi << 4) | lo))
            return result::bad_checksum;
    }

    std::array<std::string_view, max_fields> f;
    size_t nf = 0;
    size_t start = 0;

    while (true) {
        if (nf == max_fields)
            return result::malformed;

        const auto comma = body.find(',', start);

        if (comma == std::string_view::npos) {
            f[nf++] = body.substr(start);
            break;
        }

        f[nf++] = body.substr(start, comma - start);
        start = comma + 1;
    }

    // Talker (GP, GN, GL, ...) plus the 3 character sentence type
    if (f[0].size() != 5)
        return result::ignored;

    const auto type = f[0].substr(2);

    if (type == "GGA") {
        /*
            NMEA GGA standard referenced from https://gpsd.io/NMEA.html#_gga_global_positioning_system_fix_data
            Example:
            $GNGGA,001043.00,4404.14036,N,12118.85961,W,1,12,0.98,1113.0,M,-21.3,M*47
            $--GGA,hhmmss.ss,ddmm.mm,a,ddmm.mm,a,x,xx,x.x,x.x,M,x.x,M,x.x,xxxx*hh<CR><LF>
            Field Number:
                0.  Talker ID + GGA
                1.  UTC of this position report, hh is hours, mm is minutes, ss.ss is seconds.
                2.  Latitude, dd is degrees, mm.mm is minutes
                3.  N or S (North or South)
                4.  Longitude, dd is degrees, mm.mm is minutes
                5.  E or W (East or West)
                6.  GPS Quality Indicator (non null)
                    0 - fix not available,
                    1 - GPS fix,
                    2 - Differential GPS fix (values above 2 are 2.3 features)
                    3 = PPS fix
                    4 = Real Time Kinematic
                    5 = Float RTK
                    6 = estimated (dead reckoning)
                    7 = Manual input mode
                    8 = Simulation mode
                7.  Number of satellites in use, 00 - 12
                8.  Horizontal Dilution of precision (meters)
                9.  Antenna Altitude above/below mean-sea-level (geoid) (in meters)
                10. Units of antenna altitude, meters
                11. Geoidal separation, the difference between the WGS-84 earth ellipsoid and mean-sea-level (geoid), "-" means mean-sea-level below ellipsoid
                12. Units of geoidal separation, meters
                13. Age of differential GPS data, time in seconds since last SC104 type 1 or 9 update, null field when DGPS is not used
                14. Differential reference station ID, 0000-1023
                15. Checksum
                The number of digits past the decimal point for Time, Latitude and Longitude is model dependent.
        */
        if (nf < 10)
            return result::malformed;

        // Some receivers repeat their last position with no fix
        if (f[6] == "0")
            return result::ignored;

        double lat, lon, alt;

        if (!parse_coord(f[2], 2, f[3], 'N', 'S', 90, lat) ||
                !parse_coord(f[4], 3, f[5], 'E', 'W', 180, lon) ||
                !parse_double(f[9], alt))
            return result::ignored;

        update.has_position = true;
        update.lat = lat;
        update.lon = lon;

        update.has_alt = true;
        update.alt = alt;

        update.has_fix = true;
        update.fix = 3;

        return result::update;
    }

    if (type == "RMC") {
        /*
            NMEA RMC standard referenced from: https://gpsd.io/NMEA.html#_rmc_recommended_minimum_navigation_information
            Example: $GNRMC,001031.00,A,4404.13993,N,12118.86023,W,0.146,,100117,,,A*7B
            $--RMC,hhmmss.ss,A,ddmm.mm,a,dddmm.mm,a,x.x,x.x,xxxx,x.x,a*hh<CR><LF>
            NMEA 2.3:
            $--RMC,hhmmss.ss,A,ddmm.mm,a,dddmm.mm,a,x.x,x.x,xxxx,x.x,a,m*hh<CR><LF>
            NMEA 4.1:
            $--RMC,hhmmss.ss,A,ddmm.mm,a,dddmm.mm,a,x.x,x.x,xxxx,x.x,a,m,s*hh<CR><LF>
            Field Number:
                0.  Talker ID + RMC
                1.  UTC of position fix, hh is hours, mm is minutes, ss.ss is seconds.
                2.  Status, A = Valid, V = Warning
                3.  Latitude, dd is degrees. mm.mm is minutes.
                4.  N or S
                5.  Longitude, ddd is degrees. mm.mm is minutes.
                6.  E or W
                7.  Speed over ground, knots
                8.  Track made good, degrees true
                9.  Date, ddmmyy
                10. Magnetic Variation, degrees
                11. E or W
                12. FAA mode indicator (NMEA 2.3 and later)
                13. Nav Status (NMEA 4.1 and later) A=autonomous, D=differential, E=Estimated, M=Manual input mode N=not valid, S=Simulator, V = Valid
                14. Checksum
        */
        if (nf < 10)
            return result::malformed;

        if (f[2] != "A")
            return result::ignored;

        double lat, lon, knots;

        if (!parse_coord(f[3], 2, f[4], 'N', 'S', 90, lat) ||
                !parse_coord(f[5], 3, f[6], 'E', 'W', 180, lon) ||
                !parse_double(f[7], knots))
            return result::ignored;

        update.has_position = true;
        update.lat = lat;
        update.lon = lon;

        update.has_speed = true;
        update.speed = knots * knots_to_kph;

        // No altitude, so this only implies a 2d fix; a 3d fix from GGA in the same cycle is kept
        update.has_fix = true;
        update.fix = 2;

        return result::update;
    }

    if (type == "VTG") {
        /*
            NMEA VTG standard referenced from: https://gpsd.io/NMEA.html#_vtg_track_made_good_and_ground_speed
            Example: $GPVTG,220.86,T,,M,2.550,N,4.724,K,A*34
            $--VTG,x.x,T,x.x,M,x.x,N,x.x,K*hh<CR><LF>
            NMEA 2.3:
            $--VTG,x.x,T,x.x,M,x.x,N,x.x,K,m*hh<CR><LF>
            Field Number:
                0.  Talker ID + VTG
                1.  Course over ground, degrees True
                2.  T = True
                3.  Course over ground, degrees Magnetic
                4.  M = Magnetic
                5.  Speed over ground, knots
                6.  N = Knots
                7.  Speed over ground, km/hr
                8.  K = Kilometers Per Hour
                9.  FAA mode indicator (NMEA 2.3 and later)
                10. Checksum
        */
        if (nf < 9)
            return result::malformed;

        double v;

        if (parse_double(f[7], v) && v >= 0) {
            update.has_speed = true;
            update.speed = v;
        }

        if (parse_double(f[1], v) && v >= 0 && v <= 360) {
            update.has_heading = true;
            update.heading = v;
        }

        if (parse_double(f[3], v) && v >= 0 && v <= 360) {
            update.has_magheading = true;
            update.magheading = v;
        }

        return update.empty() ? result::ignored : result::update;
    }

    if (type == "GSA") {
        /*
            NMEA GSA standard referenced from: https://gpsd.io/NMEA.html#_gsa_gps_dop_and_active_satellites
            Example: $GPGSA,A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1*39
            $--GSA,a,a,x,x,x,x,x,x,x,x,x,x,x,x,x.x,x.x,x.x*hh<CR><LF>
            NMEA 4.1:
            $--GSA,a,a,x,x,x,x,x,x,x,x,x,x,x,x,x.x,x.x,x.x,s*hh<CR><LF>
            Field Number:
                0.  Talker ID + GSA
                1.  Selection mode: M=Manual, forced to operate in 2D or 3D, A=Automatic, 2D/3D
                2.  Mode (1 = no fix, 2 = 2D fix, 3 = 3D fix)
                3-14. ID of satellites used in the fix
                15. PDOP
                16. HDOP
                17. VDOP
                18. System ID (NMEA 4.1 and later)
                19. Checksum
            Multi-constellation receivers send one GSA per system, each with the same mode.
        */
        if (nf < 3)
            return result::malformed;

        // No fix overrides the fix implied by GGA and RMC
        if (f[2] != "1" && f[2] != "2" && f[2] != "3")
            return result::ignored;

        update.has_fix = true;
        update.fix_reported = true;
        update.fix = f[2][0] - '0';

        return result::update;
    }

    /*
        NMEA GSV standard referenced from: https://gpsd.io/NMEA.html#_gsv_satellites_in_view
        These sentences describe the sky position of a UPS satellite in view. Typically they’re shipped in a group of 2 or 3
        Example:
        $GPGSV,3,1,11,03,03,111,00,04,15,270,00,06,01,010,00,13,06,292,00*74
        $GPGSV,3,2,11,14,25,170,00,16,57,208,39,18,67,296,40,19,40,246,00*74
        $GPGSV,3,3,11,22,42,067,42,24,14,311,43,27,05,244,00,,,,*4D

        Not currently handled, in the future could be used for a graphical plot of
        the satellite position
    */

    return result::ignored;
}

void kis_gps_nmea_v3::start_read() {
    // Pass through to virtualized function to initiate read on socket/serial port/whatever
    start_read_impl();
}

void kis_gps_nmea_v3::handle_read(const boost::system::error_code& ec, std::size_t sz) {
    if (stopped)
        return;

    if (ec) {
        // Return from aborted errors cleanly
        if (ec.value() == boost::asio::error::operation_aborted)
            return;

        if (ec == boost::asio::error::not_found)
            _MSG_ERROR("(GPS) Error reading NMEA data from {}: no end of line in {} bytes; this "
                    "does not look like an NMEA GPS", get_gps_name(), max_line_buffer);
        else
            _MSG_ERROR("(GPS) Error reading NMEA data: {}", ec.message());

        close_impl();
        return;
    }

    if (in_buf.size() == 0) {
        _MSG_ERROR("(GPS) Error reading NMEA data: No data available");
        close_impl();
        return;
    }

    // Pull the line
    std::string line;
    std::istream is(&in_buf);
    std::getline(is, line);

    gps_fix_update update;

    switch (gps_nmea::parse(line, update)) {
        case gps_nmea::result::update:
            apply_fix(update);
            last_data_time = time(0);
            break;

        case gps_nmea::result::ignored:
            set_int_gps_data_time(time(0));
            last_data_time = time(0);
            break;

        case gps_nmea::result::binary:
            if (!warned_about_binary) {
                warned_about_binary = true;
                _MSG_ERROR("(GPS) NMEA GPS {} appears to be reporting binary data, not NMEA.  If this "
                        "is a binary-only GPS unit, you will need to use gpsd and configure Kismet "
                        "for gpsd mode.", get_gps_name());
            }
            break;

        default:
            break;
    }

    boost::asio::dispatch(strand_,
            [self = shared_from_this()]() {
                self->start_read();
            });
}
