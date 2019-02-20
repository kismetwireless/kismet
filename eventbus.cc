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

#include "eventbus.h"

Eventbus::Eventbus() {
    next_cbl_id = 1;
}

unsigned long Eventbus::register_listener(const std::string& channel, cb_func cb) {
    local_locker l(&mutex);

    auto cbl = std::make_shared<callback_listener>(std::list<std::string>{channel}, cb, next_cbl_id++);

    callback_table[channel].push_back(cbl);
    callback_id_table[cbl->id] = cbl;

    return cbl->id;
}

unsigned long Eventbus::register_listener(const std::list<std::string>& channels, cb_func cb) {
    local_locker l(&mutex);

    auto cbl = std::make_shared<callback_listener>(channels, cb, next_cbl_id++);

    for (auto i : channels) {
        callback_table[i].push_back(cbl);
    }

    callback_id_table[cbl->id] = cbl;

    return cbl->id;
}

void Eventbus::remove_listener(unsigned long id) {
    local_locker l(&mutex);

    // Find matching cbl
    auto cbl = callback_id_table.find(id);
    if (cbl == callback_id_table.end())
        return;

    // Match all channels this cbl is subscribed to
    for (auto c : cbl->second->channels) {
        auto cb_list = callback_table[c];

        // remove from each chanel
        for (auto cbi = cb_list.begin(); cbi != cb_list.end(); ++cbi) {
            if ((*cbi)->id == id) {
                cb_list.erase(cbi);
                break;
            }
        }
    }

    // Remove from CBL ID table
    callback_id_table.erase(cbl);
}

void Eventbus::publish(std::shared_ptr<EventbusEvent> event) {
    local_locker l(&mutex);

    auto ch_listeners = callback_table.find(event->get_event());

    if (ch_listeners == callback_table.end())
        return;

    for (auto cbl : ch_listeners->second) {
        cbl->cb(event);
    }
}

