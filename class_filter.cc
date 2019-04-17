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

#include "fmt.h"
#include "class_filter.h"
#include "util.h"
#include "devicetracker.h"

Classfilter::Classfilter(const std::string& in_id, const std::string& in_description,
        const std::string& in_type) :
    tracker_component() {

    register_fields();
    reserve_fields(nullptr);

    set_filter_id(in_id);
    set_filter_description(in_description);
    set_filter_type(in_type);

    set_filter_default(false);

    base_uri = fmt::format("/filters/class/{}", in_id);

    auto url = fmt::format("{}/filter", base_uri);

    self_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>(
                url, 
                [this]() -> std::shared_ptr<TrackerElement> {
                    local_locker lock(&mutex);
                    return self_endp_handler();
                });

    auto posturl = fmt::format("{}/set_default", base_uri);
    default_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Post_Endpoint>(
                posturl, 
                [this](std::ostream& stream, const std::string& uri,
                    SharedStructured post_structured, 
                    Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) {
                    local_locker lock(&mutex);
                    return default_set_endp_handler(stream, post_structured);
                });
    
}

int Classfilter::default_set_endp_handler(std::ostream& stream, SharedStructured structured) {
    try {
        if (structured->hasKey("default")) {
            set_filter_default(filterstring_to_bool(structured->getKeyAsString("default")));
            stream << "Default filter: " << get_filter_default() << "\n";
            return 200;
        } else {
            throw std::runtime_error(std::string("Missing 'default' key in command dictionary."));
        }
    } catch (const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

void Classfilter::build_self_content(std::shared_ptr<TrackerElementMap> content) {
    content->insert(filter_id);
    content->insert(filter_description);
    content->insert(filter_type);
    content->insert(filter_default);
}

bool Classfilter::filterstring_to_bool(const std::string& str) {
    auto cstr = StrLower(str);

    if (cstr == "1")
        return true;

    if (cstr == "true")
        return true;

    if (cstr == "t")
        return true;

    if (cstr == "reject")
        return true;

    if (cstr == "deny")
        return true;

    if (cstr == "filter")
        return true;

    if (cstr == "block")
        return true;

    return false;
}

ClassfilterMacaddr::ClassfilterMacaddr(const std::string& in_id, const std::string& in_description) :
    Classfilter(in_id, in_description, "mac_addr") {

    register_fields();
    reserve_fields(nullptr);

	devicetracker = Globalreg::FetchMandatoryGlobalAs<Devicetracker>();

	eventbus = Globalreg::FetchMandatoryGlobalAs<Eventbus>();
	eb_id = 
		eventbus->register_listener("NEW_PHY",
				[this](std::shared_ptr<EventbusEvent> evt) {
					update_phy_map(evt);
				});

    // Set and clear endpoints
    macaddr_edit_endp =
        std::make_shared<Kis_Net_Httpd_Path_Post_Endpoint>(
                [this](const std::vector<std::string>& path, const std::string& uri) -> bool {
                    // /filters/class/[id]/[phyname]/set_filter
                    if (path.size() < 5)
                        return false;

                    if (path[0] != "filters")
                        return false;

                    if (path[1] != "class")
                        return false;

                    if (path[2] != get_filter_id())
                        return false;

                    if (path[4] == "set_filter")
                        return true;

                    return false;
                },
                [this](std::ostream& stream, const std::vector<std::string>& path, 
                        const std::string& uri, SharedStructured post_structured, 
                        Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return edit_endp_handler(stream, path, post_structured);
                }, &mutex);

    macaddr_remove_endp =
        std::make_shared<Kis_Net_Httpd_Path_Post_Endpoint>(
                [this](const std::vector<std::string>& path, const std::string& uri) -> bool {
                    // /filters/class/[id]/[phyname]/remove_filter
                    if (path.size() < 5)
                        return false;

                    if (path[0] != "filters")
                        return false;

                    if (path[1] != "class")
                        return false;

                    if (path[2] != get_filter_id())
                        return false;

                    if (path[4] != "remove_filter")
                        return false;

                    return false;
                },
                [this](std::ostream& stream, const std::vector<std::string>& path,
                        const std::string& uri, SharedStructured post_structured,
                        Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return remove_endp_handler(stream, path, post_structured);
                }, &mutex);
}

ClassfilterMacaddr::~ClassfilterMacaddr() {
    if (eventbus != nullptr) 
        eventbus->remove_listener(eb_id);
}

void ClassfilterMacaddr::set_filter(mac_addr in_mac, const std::string& in_phy, bool value) {
	local_locker l(&mutex);

	// Build the tracked version of the record, building any containers we need along the way, this
	// always gets built even for unknown phys
	auto tracked_phy_key = filter_phy_block->find(in_phy);
	std::shared_ptr<TrackerElementMacMap> tracked_mac_map;

	if (tracked_phy_key == filter_phy_block->end()) {
		tracked_mac_map = std::make_shared<TrackerElementMacMap>(filter_sub_mac_id);
		filter_phy_block->insert(in_phy, tracked_mac_map);
	} else {
		tracked_mac_map = TrackerElement::safe_cast_as<TrackerElementMacMap>(tracked_phy_key->second);
	}

	auto tracked_mac_key = tracked_mac_map->find(in_mac);
	if (tracked_mac_key == tracked_mac_map->end()) {
		auto tracked_value = std::make_shared<TrackerElementUInt8>(filter_sub_value_id);
		tracked_value->set(value);
		tracked_mac_map->insert(in_mac, tracked_value);
	} else {
		auto bool_value = TrackerElement::safe_cast_as<TrackerElementUInt8>(tracked_mac_key->second);
		bool_value->set(value);
	}

	// Try to build the id-based lookup table
	auto phy = devicetracker->FetchPhyHandlerByName(in_phy);

	// Cache unknown for future lookups
	if (phy == nullptr) {
		unknown_phy_mac_filter_map[in_phy][in_mac] = value;
		return;
	}

	// Set known phy types
	phy_mac_filter_map[phy->FetchPhyId()][in_mac] = value;
}

void ClassfilterMacaddr::remove_filter(mac_addr in_mac, const std::string& in_phy) {
	local_locker l(&mutex);

	// Remove it from the tracked version we display
	auto tracked_phy_key = filter_phy_block->find(in_phy);
	if (tracked_phy_key != filter_phy_block->end()) {
		auto tracked_mac_map = TrackerElement::safe_cast_as<TrackerElementMacMap>(tracked_phy_key->second);
		auto tracked_mac_key = tracked_mac_map->find(in_mac);

		if (tracked_mac_key != tracked_mac_map->end())
			tracked_mac_map->erase(tracked_mac_key);
	}

	// Remove it from the known and unknown internal tables
	auto phy = devicetracker->FetchPhyHandlerByName(in_phy);

	if (phy == nullptr) {
		auto unknown_phy = unknown_phy_mac_filter_map.find(in_phy);

		if (unknown_phy == unknown_phy_mac_filter_map.end())
			return;

		auto unknown_match = unknown_phy->second.find(in_mac);

		if (unknown_match != unknown_phy->second.end())
			unknown_phy->second.erase(unknown_match);

		return;
	}

	auto known_phy = phy_mac_filter_map.find(phy->FetchPhyId());

	if (known_phy == phy_mac_filter_map.end())
		return;

	auto known_match = known_phy->second.find(in_mac);

	if (known_match != known_phy->second.end())
		known_phy->second.erase(known_match);

}

void ClassfilterMacaddr::update_phy_map(std::shared_ptr<EventbusEvent> evt) {
	local_locker l(&mutex);

	if (unknown_phy_mac_filter_map.size() == 0)
		return;

	// Turn the generic event into the device event
	auto phy_evt = 
		std::static_pointer_cast<Devicetracker::EventNewPhy>(evt);

	// Do we have any pending filters that match this key?
	auto unknown_key = unknown_phy_mac_filter_map.find(phy_evt->phy->FetchPhyName());

	if (unknown_key == unknown_phy_mac_filter_map.end())
		return;

	// Copy the map over to the known key
	phy_mac_filter_map[phy_evt->phy->FetchPhyId()] = unknown_key->second;

	// Purge the unknown record
	unknown_phy_mac_filter_map.erase(unknown_key);
}

unsigned int ClassfilterMacaddr::edit_endp_handler(std::ostream& stream, 
        const std::vector<std::string>& path, SharedStructured structured) {
    try {
        if (!structured->hasKey("filter")) {
            stream << "Missing 'filter' object in request\n";
            return 500;
        }

        auto filter = structured->getStructuredByKey("filter");

        if (!filter->isDictionary()) {
            stream << "Expected dictionary 'filter' object\n";
            return 500;
        }


        for (auto i : filter->getStructuredStrMap()) {
            mac_addr m{i.first};
            bool v = i.second->getBool();

            if (m.error) 
                throw std::runtime_error(fmt::format("Invalid MAC address: '{}'",
                            kishttpd::EscapeHtml(i.first)));

			// /filters/class/[id]/[phyname]/cmd
			set_filter(m, path[3], v);
        }

    } catch (const std::exception& e) {
        stream << "Error handling request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

unsigned int ClassfilterMacaddr::remove_endp_handler(std::ostream& stream, 
        const std::vector<std::string>& path, SharedStructured structured) {
    try {
        if (!structured->hasKey("filter")) {
            stream << "Missing 'filter' object in request\n";
            return 500;
        }

        auto filter = structured->getStructuredByKey("filter");

        if (!filter->isArray()) {
            stream << "Expected dictionary 'filter' object\n";
            return 500;
        }

        for (auto i : filter->getStringVec()) {
            mac_addr m{i};

            if (m.error) 
                throw std::runtime_error(fmt::format("Invalid MAC address: '{}'",
                            kishttpd::EscapeHtml(i)));

			// /filters/class/[id]/[phyname]/cmd
			remove_filter(m, path[3]);
        }

    } catch (const std::exception& e) {
        stream << "Error handling request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

bool ClassfilterMacaddr::filter(mac_addr mac, unsigned int phy) {
	local_locker l(&mutex);

	auto pi = phy_mac_filter_map.find(phy);

	if (pi == phy_mac_filter_map.end())
		return get_filter_default();

	auto si = pi->second.find(mac);

	if (si == pi->second.end())
		return get_filter_default();

	return si->second;
}

std::shared_ptr<TrackerElementMap> ClassfilterMacaddr::self_endp_handler() {
    auto ret = std::make_shared<TrackerElementMap>();
    build_self_content(ret);
    return ret;
}

void ClassfilterMacaddr::build_self_content(std::shared_ptr<TrackerElementMap> content) { 
    Classfilter::build_self_content(content);

    content->insert(filter_phy_block);
}


