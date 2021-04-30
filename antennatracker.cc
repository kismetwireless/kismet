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
#include "antennatracker.h"

antenna_tracker::antenna_tracker() {
    mutex.set_name("antennatracker");

    antenna_id_map = 
        std::make_shared<tracker_element_int_map>();

    auto httpd = Globalreg::fetch_global_as<kis_net_beast_httpd>();

    httpd->register_route("/antennas/antennas", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(antenna_id_map, mutex));

    next_ant_id = 1;
}

antenna_tracker::~antenna_tracker() {
    Globalreg::globalreg->remove_global("ANTENNATRACKER");
}

int antenna_tracker::add_antenna(uuid in_src, int in_srcnum, int in_adjustment) {
    kis_lock_guard<kis_mutex> lk(mutex, "antenna add_antenna");

    for (auto ai : *antenna_id_map) {
        auto a = std::static_pointer_cast<tracked_antenna>(ai.second);

        if (a->get_source_uuid() == in_src && a->get_source_antnum() == in_srcnum) { 
            return a->get_id();
        }
    }

    auto ant = std::make_shared<tracked_antenna>();

    uuid u;
    u.generate_random_time_uuid();
    
    ant->set_id(next_ant_id++);
    ant->set_source_uuid(in_src);
    ant->set_source_antnum(in_srcnum);
    ant->set_power_adjust(in_adjustment);

    ant->set_antenna_uuid(u);

    antenna_id_map->insert(ant->get_id(), ant);

    return ant->get_id();
}

int antenna_tracker::add_antenna(uuid in_src, int in_srcnum, int in_adjustment, uuid in_ant_uuid) {
    kis_lock_guard<kis_mutex> lk(mutex, "antennatracker add_antenna");

    for (auto ai : *antenna_id_map) {
        auto a = std::static_pointer_cast<tracked_antenna>(ai.second);

        if (a->get_source_uuid() == in_src && a->get_source_antnum() == in_srcnum) { 
            return a->get_id();
        }
    }

    auto ant = std::make_shared<tracked_antenna>();

    ant->set_id(next_ant_id++);
    ant->set_source_uuid(in_src);
    ant->set_source_antnum(in_srcnum);
    ant->set_power_adjust(in_adjustment);
    ant->set_antenna_uuid(in_ant_uuid);

    antenna_id_map->insert(ant->get_id(), ant);

    return ant->get_id();
}

int antenna_tracker::set_antenna_adjustment(int in_antnum, int in_adjustment) {
    kis_lock_guard<kis_mutex> lk(mutex, "antennatracker set_antenna_adjustment");

    auto ai = antenna_id_map->find(in_antnum);

    if (ai == antenna_id_map->end())
        return -1;

    auto a = std::static_pointer_cast<tracked_antenna>(ai->second);
    a->set_power_adjust(in_adjustment);

    return 1;
}

std::shared_ptr<tracked_antenna> antenna_tracker::get_antenna(int in_antnum) {
    kis_lock_guard<kis_mutex> lk(mutex, "antennatracker get_antenna");

    auto ai = antenna_id_map->find(in_antnum);

    if (ai == antenna_id_map->end())
        return nullptr;

    return std::static_pointer_cast<tracked_antenna>(ai->second);
}

