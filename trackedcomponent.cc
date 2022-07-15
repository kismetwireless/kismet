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

#include "trackedcomponent.h"

std::string tracker_component::get_name() {
    return Globalreg::globalreg->entrytracker->get_field_name(get_id());
}

std::string tracker_component::get_name(int in_id) {
    return Globalreg::globalreg->entrytracker->get_field_name(in_id);
}

int tracker_component::register_field(const std::string& in_name, 
        std::unique_ptr<tracker_element> in_builder,
        const std::string& in_desc, shared_tracker_element *in_dest) {

    int id = 
        Globalreg::globalreg->entrytracker->register_field(in_name, std::move(in_builder), in_desc);

    if (in_dest != NULL) {
        if (registered_fields == nullptr)
            registered_fields = new std::vector<std::unique_ptr<registered_field>>();

        auto rf = std::unique_ptr<registered_field>(new registered_field(id, in_dest));
        registered_fields->push_back(std::move(rf));
    }

    return id;
}

void tracker_component::reserve_fields(std::shared_ptr<tracker_element_map> e) {
    if (registered_fields == nullptr)
        return;

    for (auto& rf : *registered_fields) {
        if (rf->assign != nullptr) {
            // We use negative IDs to indicate dynamic to eke out 4 more bytes
            if (rf->id < 0) {
                // If the variable is dynamic set the assignment container to null so that
                // proxydynamictrackable can fill it in;
                *(rf->assign) = nullptr;
                insert(abs(rf->id), std::shared_ptr<tracker_element>());
            } else if (rf->assign != nullptr) {
                // otherwise generate a variable for the destination
                *(rf->assign) = import_or_new(e, rf->id);
            }
        }
    }

    // Remove all the registration records we've allocated
    delete registered_fields;
    registered_fields = nullptr;
}

shared_tracker_element tracker_component::import_or_new(std::shared_ptr<tracker_element_map> e, int i) {
    shared_tracker_element r;

    // Find the value of any known fields in the importer element; only try
    // if the imported element is a map
    if (e != nullptr && e->get_type() == tracker_type::tracker_map) {
        r = e->get_sub(i);

        if (r != nullptr) {
            // Added directly as a trackedelement of the right type and id
            
            insert(r);

            // Return existing item
            return r;
        }
    }

    // Look for the value in our own map already in case a parent instance
    // initialized it already
    auto existing = find(i);

    if (existing != end() && existing->second != nullptr)
        return existing->second;

    // Build it
    r = Globalreg::globalreg->entrytracker->get_shared_instance(i);

    // Add it to our tracked map object
    insert(r);

    return r;
}

shared_tracker_element tracker_component::get_child_path(const std::string& in_path) {
    std::vector<std::string> tok = str_tokenize(in_path, "/");
    return get_child_path(tok);
}

shared_tracker_element tracker_component::get_child_path(const std::vector<std::string>& in_path) {
    if (in_path.size() < 1)
        return nullptr;

    shared_tracker_element next_elem = nullptr;

    for (auto p : in_path) {
        // Skip empty path elements
        if (p.length() == 0)
            continue;

        int id = Globalreg::globalreg->entrytracker->get_field_id(p);

        if (id < 0) 
            return nullptr;

        if (next_elem == nullptr) {
            // If we're just starting, find the top element in this object
            next_elem = get_sub(id);
        } else if (next_elem->get_type() == tracker_type::tracker_map) {
            // Otherwise, find the next element of the path in the object in the chain
            // we're currently inspecting, assuming it's a map
            // next_elem = std::static_pointer_cast<tracker_element_map>(next_elem)->get_sub(id);
            next_elem = static_cast<tracker_element_map *>(next_elem.get())->get_sub(id);
        }

        // If we can't find it, bail
        if (next_elem == nullptr)
            return nullptr;
    }

    // We've drilled down to the end of the chain, return it
    return next_elem;
}

