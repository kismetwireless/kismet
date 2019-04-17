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

Antennatracker::Antennatracker() {
    antenna_id_map = 
        std::make_shared<TrackerElementIntMap>();
    antenna_endp = 
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>("/antennas/antennas",
                antenna_id_map, &mutex);
    next_ant_id = 0;
}

Antennatracker::~Antennatracker() {
    Globalreg::globalreg->RemoveGlobal("ANTENNATRACKER");
}

int Antennatracker::add_antenna(uuid in_src, int in_srcnum, int in_adjustment) {
    local_locker l(&mutex);

    for (auto ai : *antenna_id_map) {
        auto a = std::static_pointer_cast<tracked_antenna>(ai.second);

        if (a->get_source_uuid() == in_src && a->get_source_antnum() == in_srcnum) { 
            return a->get_id();
        }
    }

    auto ant = std::make_shared<tracked_antenna>();

    uuid u;
    u.GenerateRandomTimeUUID();
    
    ant->set_id(next_ant_id++);
    ant->set_source_uuid(in_src);
    ant->set_source_antnum(in_srcnum);
    ant->set_power_adjust(in_adjustment);

    ant->set_antenna_uuid(u);

    antenna_id_map->insert(ant->get_id(), ant);

    return ant->get_id();
}

int Antennatracker::add_antenna(uuid in_src, int in_srcnum, int in_adjustment, uuid in_ant_uuid) {
    local_locker l(&mutex);

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

int Antennatracker::set_antenna_adjustment(int in_antnum, int in_adjustment) {
    local_locker l(&mutex);

    auto ai = antenna_id_map->find(in_antnum);

    if (ai == antenna_id_map->end())
        return -1;

    auto a = std::static_pointer_cast<tracked_antenna>(ai->second);
    a->set_power_adjust(in_adjustment);

    return 1;
}

std::shared_ptr<tracked_antenna> Antennatracker::get_antenna(int in_antnum) {
    local_locker l(&mutex);

    auto ai = antenna_id_map->find(in_antnum);

    if (ai == antenna_id_map->end())
        return nullptr;

    return std::static_pointer_cast<tracked_antenna>(ai->second);
}

