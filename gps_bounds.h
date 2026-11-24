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

#ifndef __GPS_BOUNDS_H__
#define __GPS_BOUNDS_H__

/* Plausible ranges for a position from any source; NaN fails every comparison.  Also
 * included from C (capture_kismetdb), so the C helpers and the server share one copy. */
#define GPS_BOUNDS_MIN_LAT -90.0
#define GPS_BOUNDS_MAX_LAT 90.0
#define GPS_BOUNDS_MIN_LON -180.0
#define GPS_BOUNDS_MAX_LON 180.0
/* Meters */
#define GPS_BOUNDS_MIN_ALT_M -100000.0
#define GPS_BOUNDS_MAX_ALT_M 1000000.0

/* Kismet logs and sends 0,0 when it has no position.  Only both zero: the equator and the
 * prime meridian are real positions.  Arguments are evaluated twice. */
#define GPS_BOUNDS_NO_POSITION(lat, lon) ((lat) == 0 && (lon) == 0)

#ifdef __cplusplus
namespace gps_bounds {
    constexpr double min_lat = GPS_BOUNDS_MIN_LAT;
    constexpr double max_lat = GPS_BOUNDS_MAX_LAT;
    constexpr double min_lon = GPS_BOUNDS_MIN_LON;
    constexpr double max_lon = GPS_BOUNDS_MAX_LON;
    /* Meters */
    constexpr double min_alt = GPS_BOUNDS_MIN_ALT_M;
    constexpr double max_alt = GPS_BOUNDS_MAX_ALT_M;
    /* Km/h */
    constexpr double min_speed = 0;
    constexpr double max_speed = 1000000;

    constexpr bool lat_valid(double v) { return v >= min_lat && v <= max_lat; }
    constexpr bool lon_valid(double v) { return v >= min_lon && v <= max_lon; }
    constexpr bool alt_valid(double v) { return v >= min_alt && v <= max_alt; }
    constexpr bool speed_valid(double v) { return v >= min_speed && v <= max_speed; }

    constexpr bool no_position(double lat, double lon) { return GPS_BOUNDS_NO_POSITION(lat, lon); }
}
#endif

#endif
