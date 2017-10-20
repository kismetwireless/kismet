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

#ifndef __PHY_UAV_DRONE_H__
#define __PHY_UAV_DRONE_H__

#include "trackedelement.h"
#include "tracked_location.h"

/* An abstract model of a UAV (drone/quadcopter/plane) device.
 *
 * A UAV may have multiple communications protocols (bluetooth, wi-fi, RF)
 * which comprise the same device; references to the independent devices of
 * other phys are linked in the optional descriptors.
 *
 * A UAV is worthy of its own top-level device because it also introduces
 * independent tracking requirements; location history may be sources
 * from UAV telemetry independent of the devices/kismet sensor locations.
 *
 */

class uav_tracked_telemetry : public tracker_component {
public:
    uav_tracked_telemetry(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(NULL);
    }

    uav_tracked_telemetry(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual ~uav_tracked_telemetry() { }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();
    }

};

class uav_tracked_device : public tracker_component {
public:
    uav_tracked_device(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(NULL);
    }

    uav_tracked_device(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual ~uav_tracked_device() { }


protected:
    virtual void register_fields() {
        tracker_component::register_fields();

    }

    SharedTrackerElement uav_manufacturer;
    
    SharedTrackerElement uav_serialnumber;

};

#endif

