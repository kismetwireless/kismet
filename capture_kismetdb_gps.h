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

#ifndef __CAPTURE_KISMETDB_GPS_H__
#define __CAPTURE_KISMETDB_GPS_H__

#include <math.h>

#include <sqlite3.h>

#include "capture_framework.h"
#include "gps_bounds.h"

/* A pre-v5 lat or lon column (stored as degrees * 100000) in degrees.  Text or a blob would
 * divide to 0.0, a real position, so it comes back NULL, which kismetdb_column_coord reads
 * as NaN. */
#define KISMETDB_V4_COORD_SQL(col) \
    "CASE WHEN typeof(" col ") IN ('integer', 'real') THEN " col " / 100000.0 END"

/* A lat or lon column.  sqlite stores NaN as NULL and reads NULL or text as 0, which is
 * now a real position (the equator or the prime meridian); anything but a number is NaN,
 * so kismetdb_row_gps drops it. */
static inline double kismetdb_column_coord(sqlite3_stmt *stmt, int col) {
    const int t = sqlite3_column_type(stmt, col);

    if (t != SQLITE_INTEGER && t != SQLITE_FLOAT)
        return NAN;

    return sqlite3_column_double(stmt, col);
}

/* The logged position of a row.  Kismet logs 0,0 when it had no GPS (GPS_BOUNDS_NO_POSITION,
 * the rule the device tracker and the wiglecsv log use), and a damaged or hostile log may
 * hold anything; both are sent as fix 0 at 0,0, which the server takes as "no position"
 * for this record.  Ranges are the server's (gps_bounds.h): a GPS block outside them would
 * be dropped whole there.  An unusable altitude alone makes it a 2d fix.  Altitude and
 * heading go out as floats, and a double outside float range can't be converted. */
static inline void kismetdb_row_gps(struct cf_params_gps *gps, double lat, double lon, double alt,
        double heading) {
    if (!isfinite(lat) || !isfinite(lon) || lat < GPS_BOUNDS_MIN_LAT || lat > GPS_BOUNDS_MAX_LAT ||
            lon < GPS_BOUNDS_MIN_LON || lon > GPS_BOUNDS_MAX_LON || GPS_BOUNDS_NO_POSITION(lat, lon)) {
        gps->lat = 0;
        gps->lon = 0;
        gps->alt = 0;
        gps->heading = 0;
        gps->fix = 0;
        return;
    }

    if (!isfinite(alt) || alt < GPS_BOUNDS_MIN_ALT_M || alt > GPS_BOUNDS_MAX_ALT_M)
        alt = 0;

    if (!isfinite(heading) || heading < 0 || heading > 360)
        heading = 0;

    gps->lat = lat;
    gps->lon = lon;
    gps->alt = alt;
    gps->heading = heading;
    gps->fix = alt != 0 ? 3 : 2;
}

#endif
