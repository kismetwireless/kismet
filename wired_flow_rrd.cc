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

#include "wired_flow_rrd.h"

#include "entrytracker.h"
#include "globalregistry.h"

// Names, types and descriptions as kis_tracked_rrd registers them in trackedrrd.h
wired_flow_rrd::wired_flow_rrd() {
    auto& et = Globalreg::globalreg->entrytracker;

    last_time_id = et->register_field("kismet.common.rrd.last_time",
            tracker_element_factory<tracker_element_uint64>(), "last time updated");
    serial_time_id = et->register_field("kismet.common.rrd.serial_time",
            tracker_element_factory<tracker_element_uint64>(), "timestamp of serialization");
    minute_vec_id = et->register_field("kismet.common.rrd.minute_vec",
            tracker_element_factory<tracker_element_vector_double>(), "past minute values per second");
    hour_vec_id = et->register_field("kismet.common.rrd.hour_vec",
            tracker_element_factory<tracker_element_vector_double>(), "past hour values per minute");
    day_vec_id = et->register_field("kismet.common.rrd.day_vec",
            tracker_element_factory<tracker_element_vector_double>(), "past day values per hour");
    blank_val_id = et->register_field("kismet.common.rrd.blank_val",
            tracker_element_factory<tracker_element_double>(), "blank value");
}

std::shared_ptr<tracker_element_map>
    wired_flow_rrd::build(int id, const flow_history::rrd_vectors& v, time_t now) const {
    auto m = std::make_shared<tracker_element_map>(id);

    auto vec = [](int vid, const auto& a) {
        auto e = std::make_shared<tracker_element_vector_double>(vid);
        e->get().assign(a.begin(), a.end());
        return e;
    };

    m->insert(std::make_shared<tracker_element_uint64>(last_time_id, static_cast<uint64_t>(v.last_time)));
    m->insert(std::make_shared<tracker_element_uint64>(serial_time_id, static_cast<uint64_t>(now)));
    m->insert(vec(minute_vec_id, v.minute));
    m->insert(vec(hour_vec_id, v.hour));
    m->insert(vec(day_vec_id, v.day));
    m->insert(std::make_shared<tracker_element_double>(blank_val_id, 0.0));

    return m;
}
