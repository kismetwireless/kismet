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

// Plausible ranges for a position from any source; NaN fails every comparison
namespace gps_bounds {
    constexpr double min_lat = -90;
    constexpr double max_lat = 90;
    constexpr double min_lon = -180;
    constexpr double max_lon = 180;
    // Meters
    constexpr double min_alt = -100000;
    constexpr double max_alt = 1000000;
    // Km/h
    constexpr double min_speed = 0;
    constexpr double max_speed = 1000000;

    constexpr bool lat_valid(double v) { return v >= min_lat && v <= max_lat; }
    constexpr bool lon_valid(double v) { return v >= min_lon && v <= max_lon; }
    constexpr bool alt_valid(double v) { return v >= min_alt && v <= max_alt; }
    constexpr bool speed_valid(double v) { return v >= min_speed && v <= max_speed; }
}

#endif
