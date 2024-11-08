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

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route(url, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this, url](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return self_endp_handler();
                }, mutex));

    auto posturl = fmt::format("{}/set_default", base_uri);

    httpd->register_route(url, {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this, posturl](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return default_set_endp_handler(con);
                }, mutex));
}

void class_filter::default_set_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());

    try {
        set_filter_default(filterstring_to_bool(con->json()["default"]));
        stream << "Default filter: " << get_filter_default() << "\n";
        return;
    } catch (const std::exception& e) {
        con->set_status(500);
        stream << "Invalid request: " << e.what() << "\n";
        return;
    }

    con->set_status(500);
    stream << "Unhandled request\n";
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
    auto seturl = fmt::format("/filters/class/{}/:phyname/set_filter", get_filter_id());
    auto remurl = fmt::format("/filters/class/{}/:phyname/remove_filter", get_filter_id());

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route(seturl, {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this, seturl](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return edit_endp_handler(con);
                }, mutex));

    httpd->register_route(remurl, {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this, seturl](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return remove_endp_handler(con);
                }, mutex));
}

class_filter_mac_addr::~class_filter_mac_addr() {
    if (eventbus != nullptr) 
        eventbus->remove_listener(eb_id);
}

void class_filter_mac_addr::set_filter(mac_addr in_mac, const std::string& in_phy, bool value) {
    kis_lock_guard<kis_mutex> lk(mutex, "class_filter_mac_addr set_filter");

    // Build the tracked version of the record, building any containers we need along the way, this
    // always gets built even for unknown phys
    auto tracked_phy_key = filter_phy_block->find(in_phy);
    std::shared_ptr<tracker_element_macfilter_map> tracked_mac_map;

    if (tracked_phy_key == filter_phy_block->end()) {
        tracked_mac_map = std::make_shared<tracker_element_macfilter_map>(filter_sub_mac_id);
        filter_phy_block->insert(in_phy, tracked_mac_map);
    } else {
        tracked_mac_map = tracker_element::safe_cast_as<tracker_element_macfilter_map>(tracked_phy_key->second);
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
    kis_lock_guard<kis_mutex> lk(mutex, "class_filter_mac_addr remove_filter");

    // Remove it from the tracked version we display
    auto tracked_phy_key = filter_phy_block->find(in_phy);
    if (tracked_phy_key != filter_phy_block->end()) {
        auto tracked_mac_map = tracker_element::safe_cast_as<tracker_element_macfilter_map>(tracked_phy_key->second);
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
    kis_lock_guard<kis_mutex> lk(mutex, "class_filter_mac_addr update_phy_map");

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

void class_filter_mac_addr::edit_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());

    try {
        auto filter = con->json()["filter"];

        if (!filter.is_object()) {
            con->set_status(500);
            stream << "Expected 'filter' as a dictionary\n";
            return;
        }

        for (const auto& i : filter.items()) {
            mac_addr m(i.key());
            bool v = i.value();

            if (m.state.error) {
                const auto e = fmt::format("Invalid MAC address: '{}'", con->escape_html(i.key()));
                throw std::runtime_error(e);
            }

            auto phy_k = con->uri_params().find(":phyname");
            set_filter(m, phy_k->second, v);
        }

        stream << "Set filter\n";
        return;
    } catch (const std::exception& e) {
        con->set_status(500);
        stream << "Error handling request: " << e.what() << "\n";
        return;
    }

    con->set_status(500);
    stream << "Unhandled request\n";
}

void class_filter_mac_addr::remove_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());

    try {
        auto filter = con->json()["filter"];

        if (!filter.is_array()) {
            con->set_status(500);
            stream << "Expected 'filter' as an array\n";
            return;
        }

        for (const auto& i : filter) {
            mac_addr m(i.get<std::string>());

            if (m.state.error) {
                const auto e = fmt::format("Invalid MAC address: '{}'", con->escape_html(i));
                throw std::runtime_error(e);
            }

            auto phy_k = con->uri_params().find(":phyname");
            remove_filter(m, phy_k->second);
        }

        stream << "Removed filter\n";
        return;

    } catch (const std::exception& e) {
        con->set_status(500);
        stream << "Error handling request: " << e.what() << "\n";
        return;
    }

    con->set_status(500);
    stream << "Unhandled request\n";
}

bool class_filter_mac_addr::filter(mac_addr mac, unsigned int phy) {
    kis_lock_guard<kis_mutex> lk(mutex, "class_filter_mac_addr filter");

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


