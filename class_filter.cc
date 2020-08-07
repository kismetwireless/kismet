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

class_filter::class_filter(const std::string& in_id, const std::string& in_description,
        const std::string& in_type) :
    tracker_component() {

    mutex.set_name("classfilter");

    register_fields();
    reserve_fields(nullptr);

    set_filter_id(in_id);
    set_filter_description(in_description);
    set_filter_type(in_type);

    set_filter_default(false);

    base_uri = fmt::format("/filters/class/{}", in_id);

    auto url = fmt::format("{}/filter", base_uri);

    self_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>(
                url, 
                [this]() -> std::shared_ptr<tracker_element> {
                    local_locker lock(&mutex);
                    return self_endp_handler();
                });

    auto posturl = fmt::format("{}/set_default", base_uri);
    default_endp =
        std::make_shared<kis_net_httpd_simple_post_endpoint>(
                posturl, 
                [this](std::ostream& stream, const std::string& uri,
                    const Json::Value& json,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) {
                    local_locker lock(&mutex);
                    return default_set_endp_handler(stream, json);
                });
    
}

int class_filter::default_set_endp_handler(std::ostream& stream, const Json::Value& json) {
    try {
        set_filter_default(filterstring_to_bool(json["default"].asString()));
        stream << "Default filter: " << get_filter_default() << "\n";
        return 200;
    } catch (const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

void class_filter::build_self_content(std::shared_ptr<tracker_element_map> content) {
    content->insert(filter_id);
    content->insert(filter_description);
    content->insert(filter_type);
    content->insert(filter_default);
}

bool class_filter::filterstring_to_bool(const std::string& str) {
    auto cstr = str_lower(str);

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

class_filter_mac_addr::class_filter_mac_addr(const std::string& in_id, const std::string& in_description) :
    class_filter(in_id, in_description, "mac_addr") {

        register_fields();
        reserve_fields(nullptr);

        devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

        eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();
        eb_id = 
            eventbus->register_listener(device_tracker::event_new_phy(),
                    [this](std::shared_ptr<eventbus_event> evt) {
                    update_phy_map(evt);
                    });

    // Set and clear endpoints
    macaddr_edit_endp =
        std::make_shared<kis_net_httpd_path_post_endpoint>(
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
                        const std::string& uri, const Json::Value& json, 
                        kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return edit_endp_handler(stream, path, json);
                }, &mutex);

    macaddr_remove_endp =
        std::make_shared<kis_net_httpd_path_post_endpoint>(
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
                        const std::string& uri, const Json::Value& json,
                        kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return remove_endp_handler(stream, path, json);
                }, &mutex);
}

class_filter_mac_addr::~class_filter_mac_addr() {
    if (eventbus != nullptr) 
        eventbus->remove_listener(eb_id);
}

void class_filter_mac_addr::set_filter(mac_addr in_mac, const std::string& in_phy, bool value) {
    local_locker l(&mutex);

    // Build the tracked version of the record, building any containers we need along the way, this
    // always gets built even for unknown phys
    auto tracked_phy_key = filter_phy_block->find(in_phy);
    std::shared_ptr<tracker_element_mac_map> tracked_mac_map;

    if (tracked_phy_key == filter_phy_block->end()) {
        tracked_mac_map = std::make_shared<tracker_element_mac_map>(filter_sub_mac_id);
        filter_phy_block->insert(in_phy, tracked_mac_map);
    } else {
        tracked_mac_map = tracker_element::safe_cast_as<tracker_element_mac_map>(tracked_phy_key->second);
    }

    auto tracked_mac_key = tracked_mac_map->find(in_mac);
    if (tracked_mac_key == tracked_mac_map->end()) {
        auto tracked_value = std::make_shared<tracker_element_uint8>(filter_sub_value_id);
        tracked_value->set(value);
        tracked_mac_map->insert(in_mac, tracked_value);
    } else {
        auto bool_value = tracker_element::safe_cast_as<tracker_element_uint8>(tracked_mac_key->second);
        bool_value->set(value);
    }

    // Try to build the id-based lookup table
    auto phy = devicetracker->fetch_phy_handler_by_name(in_phy);

    // Cache unknown for future lookups
    if (phy == nullptr) {
        unknown_phy_mac_filter_map[in_phy][in_mac] = value;
        return;
    }

    // Set known phy types
    phy_mac_filter_map[phy->fetch_phy_id()][in_mac] = value;
}

void class_filter_mac_addr::remove_filter(mac_addr in_mac, const std::string& in_phy) {
    local_locker l(&mutex);

    // Remove it from the tracked version we display
    auto tracked_phy_key = filter_phy_block->find(in_phy);
    if (tracked_phy_key != filter_phy_block->end()) {
        auto tracked_mac_map = tracker_element::safe_cast_as<tracker_element_mac_map>(tracked_phy_key->second);
        auto tracked_mac_key = tracked_mac_map->find(in_mac);

        if (tracked_mac_key != tracked_mac_map->end())
            tracked_mac_map->erase(tracked_mac_key);
    }

    // Remove it from the known and unknown internal tables
    auto phy = devicetracker->fetch_phy_handler_by_name(in_phy);

    if (phy == nullptr) {
        auto unknown_phy = unknown_phy_mac_filter_map.find(in_phy);

        if (unknown_phy == unknown_phy_mac_filter_map.end())
            return;

        auto unknown_match = unknown_phy->second.find(in_mac);

        if (unknown_match != unknown_phy->second.end())
            unknown_phy->second.erase(unknown_match);

        return;
    }

    auto known_phy = phy_mac_filter_map.find(phy->fetch_phy_id());

    if (known_phy == phy_mac_filter_map.end())
        return;

    auto known_match = known_phy->second.find(in_mac);

    if (known_match != known_phy->second.end())
        known_phy->second.erase(known_match);
}

void class_filter_mac_addr::update_phy_map(std::shared_ptr<eventbus_event> evt) {
    local_locker l(&mutex);

    if (unknown_phy_mac_filter_map.size() == 0)
        return;

    const auto phyname_k = 
        evt->get_event_content()->find(devicetracker->event_new_phy());

    if (phyname_k == evt->get_event_content()->end())
        return;

    auto phy = devicetracker->fetch_phy_handler_by_name(get_tracker_value<std::string>(phyname_k->second));

    if (phy == nullptr)
        return;

    // Do we have any pending filters that match this key?
    auto unknown_key = unknown_phy_mac_filter_map.find(phy->fetch_phy_name());

    if (unknown_key == unknown_phy_mac_filter_map.end())
        return;

    // Copy the map over to the known key
    phy_mac_filter_map[phy->fetch_phy_id()] = unknown_key->second;

    // Purge the unknown record
    unknown_phy_mac_filter_map.erase(unknown_key);
}

unsigned int class_filter_mac_addr::edit_endp_handler(std::ostream& stream, 
        const std::vector<std::string>& path, const Json::Value& json) {
    try {
        auto filter = json["filter"];

        if (!filter.isObject()) {
            stream << "Expected 'filter' as a dictionary\n";
            return 500;
        }

        for (const auto& i : filter.getMemberNames()) {
            mac_addr m(i);
            bool v = filter[i].asBool();

            if (m.state.error) 
                throw std::runtime_error(fmt::format("Invalid MAC address: '{}'",
                            kishttpd::escape_html(i)));

            // /filters/class/[id]/[phyname]/cmd
            set_filter(m, path[3], v);
        }

        stream << "Set filter\n";
        return 200;

    } catch (const std::exception& e) {
        stream << "Error handling request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

unsigned int class_filter_mac_addr::remove_endp_handler(std::ostream& stream, 
        const std::vector<std::string>& path, const Json::Value& json) {
    try {
        auto filter = json["filter"];

        if (!filter.isArray()) {
            stream << "Expected 'filter' as an array\n";
            return 500;
        }

        for (const auto& i : filter) {
            mac_addr m(i.asString());

            if (m.state.error) 
                throw std::runtime_error(fmt::format("Invalid MAC address: '{}'",
                            kishttpd::escape_html(i.asString())));

            // /filters/class/[id]/[phyname]/cmd
            remove_filter(m, path[3]);
        }

        stream << "Removed filter\n";
        return 200;

    } catch (const std::exception& e) {
        stream << "Error handling request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

bool class_filter_mac_addr::filter(mac_addr mac, unsigned int phy) {
    local_locker l(&mutex);

    auto pi = phy_mac_filter_map.find(phy);

    if (pi == phy_mac_filter_map.end())
        return get_filter_default();

    auto si = pi->second.find(mac);

    if (si == pi->second.end())
        return get_filter_default();

    return si->second;
}

std::shared_ptr<tracker_element_map> class_filter_mac_addr::self_endp_handler() {
    auto ret = std::make_shared<tracker_element_map>();
    build_self_content(ret);
    return ret;
}

void class_filter_mac_addr::build_self_content(std::shared_ptr<tracker_element_map> content) { 
    class_filter::build_self_content(content);

    content->insert(filter_phy_block);
}


