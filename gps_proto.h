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

    bool empty() const {
        return !(has_position || has_alt || has_speed || has_heading || has_magheading || has_fix);
    }
};

#endif
