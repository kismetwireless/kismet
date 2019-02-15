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
    return Globalreg::globalreg->entrytracker->GetFieldName(get_id());
}

std::string tracker_component::get_name(int in_id) {
    return Globalreg::globalreg->entrytracker->GetFieldName(in_id);
}

int tracker_component::RegisterField(const std::string& in_name, 
        std::unique_ptr<TrackerElement> in_builder,
        const std::string& in_desc, SharedTrackerElement *in_dest) {

    int id = 
        Globalreg::globalreg->entrytracker->RegisterField(in_name, std::move(in_builder), in_desc);

    if (in_dest != NULL) {
        auto rf = std::unique_ptr<registered_field>(new registered_field(id, in_dest));
        registered_fields.push_back(std::move(rf));
    }

    return id;
}

void tracker_component::reserve_fields(std::shared_ptr<TrackerElementMap> e) {
    for (unsigned int i = 0; i < registered_fields.size(); i++) {
        auto& rf = registered_fields[i];

        if (rf->assign != nullptr) {
            if (rf->dynamic) {
                // If the variable is dynamic set the assignment container to null so that
                // proxydynamictrackable can fill it in;
                *(rf->assign) = nullptr;
                insert(rf->id, std::shared_ptr<TrackerElement>());
            } else {
                // otherwise generate a variable for the destination
                *(rf->assign) = import_or_new(e, rf->id);
            }
        }
    }
}

SharedTrackerElement tracker_component::import_or_new(std::shared_ptr<TrackerElementMap> e, int i) {
    SharedTrackerElement r;

    // Find the value of any known fields in the importer element; only try
    // if the imported element is a map
    if (e != nullptr && e->get_type() == TrackerType::TrackerMap) {
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
    r = Globalreg::globalreg->entrytracker->GetSharedInstance(i);

    // Add it to our tracked map object
    insert(r);

    return r;
}

SharedTrackerElement tracker_component::get_child_path(const std::string& in_path) {
    std::vector<std::string> tok = StrTokenize(in_path, "/");
    return get_child_path(tok);
}

SharedTrackerElement tracker_component::get_child_path(const std::vector<std::string>& in_path) {
    if (in_path.size() < 1)
        return nullptr;

    SharedTrackerElement next_elem = nullptr;

    for (auto p : in_path) {
        // Skip empty path elements
        if (p.length() == 0)
            continue;

        int id = Globalreg::globalreg->entrytracker->GetFieldId(p);

        if (id < 0) 
            return nullptr;

        if (next_elem == nullptr) {
            // If we're just starting, find the top element in this object
            next_elem = get_sub(id);
        } else if (next_elem->get_type() == TrackerType::TrackerMap) {
            // Otherwise, find the next element of the path in the object in the chain
            // we're currently inspecting, assuming it's a map
            next_elem = std::static_pointer_cast<TrackerElementMap>(next_elem)->get_sub(id);
        }

        // If we can't find it, bail
        if (next_elem == nullptr)
            return nullptr;
    }

    // We've drilled down to the end of the chain, return it
    return next_elem;
}

