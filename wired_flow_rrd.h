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

#ifndef __WIRED_FLOW_RRD_H__
#define __WIRED_FLOW_RRD_H__

#include "config.h"

#include <ctime>
#include <memory>

#include "trackedelement.h"
#include "wired_flow_history.h"

// One series of a flow's history as a map shaped like a serialized kis_tracked_rrd, under the
// same kismet.common.rrd.* fields (registering them again returns the ids kis_tracked_rrd
// uses), so the UI reads both the same way.  last_value and last_value_n1 are left out.
class wired_flow_rrd {
public:
    wired_flow_rrd();

    std::shared_ptr<tracker_element_map> build(int id, const flow_history::rrd_vectors& v, time_t now) const;

private:
    int last_time_id, serial_time_id, minute_vec_id, hour_vec_id, day_vec_id, blank_val_id;
};

#endif
