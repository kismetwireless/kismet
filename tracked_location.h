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

#ifndef __TRACKEDLOCATION_H__
#define __TRACKEDLOCATION_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"

// Component-tracker common GPS element
class kis_tracked_location_triplet : public tracker_component {
public:
    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, int in_id);

    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e);

    virtual SharedTrackerElement clone_type();

    // Use proxy macro to define get/set
    __Proxy(lat, double, double, double, lat);
    __Proxy(lon, double, double, double, lon);
    __Proxy(alt, double, double, double, alt);
    __Proxy(speed, double, double, double, spd);
    __Proxy(heading, double, double, double, heading);
    __Proxy(fix, uint8_t, uint8_t, uint8_t, fix);
    __Proxy(valid, uint8_t, bool, bool, valid);
    __Proxy(time_sec, uint64_t, time_t, time_t, time_sec);
    __Proxy(time_usec, uint64_t, uint64_t, uint64_t, time_usec);

    void set(double in_lat, double in_lon, double in_alt, unsigned int in_fix);

    void set(double in_lat, double in_lon);

	inline kis_tracked_location_triplet& operator= (const kis_tracked_location_triplet& in);

protected:
    virtual void register_fields();

    SharedTrackerElement lat, lon, alt, spd, fix, valid, time_sec, time_usec, heading;
};

// min/max/avg location
class kis_tracked_location : public tracker_component {
public:
    const static int precision_multiplier = 10000;

    kis_tracked_location(GlobalRegistry *in_globalreg, int in_id);

    kis_tracked_location(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e);

    virtual SharedTrackerElement clone_type();

    void add_loc(double in_lat, double in_lon, double in_alt, unsigned int fix);

    __Proxy(valid, uint8_t, bool, bool, loc_valid);
    __Proxy(fix, uint8_t, unsigned int, unsigned int, loc_fix);

    shared_ptr<kis_tracked_location_triplet> get_min_loc() { return min_loc; }
    shared_ptr<kis_tracked_location_triplet> get_max_loc() { return max_loc; }
    shared_ptr<kis_tracked_location_triplet> get_avg_loc() { return avg_loc; }

    __Proxy(agg_lat, uint64_t, uint64_t, uint64_t, avg_lat);
    __Proxy(agg_lon, uint64_t, uint64_t, uint64_t, avg_lon);
    __Proxy(agg_alt, uint64_t, uint64_t, uint64_t, avg_alt);
    __Proxy(num_agg, int64_t, int64_t, int64_t, num_avg);
    __Proxy(num_alt_agg, int64_t, int64_t, int64_t, num_alt_avg);

protected:
    virtual void register_fields();

    // We override this to nest our complex structures on top; we can be created
    // over a standard trackerelement map and inherit its sub-maps directly
    // into locations
    virtual void reserve_fields(SharedTrackerElement e);

    shared_ptr<kis_tracked_location_triplet> min_loc, max_loc, avg_loc;
    int min_loc_id, max_loc_id, avg_loc_id;

    SharedTrackerElement avg_lat, avg_lon, avg_alt, num_avg, num_alt_avg;

    SharedTrackerElement loc_valid;

    SharedTrackerElement loc_fix;
};

#endif

