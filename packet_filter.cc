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
#include "packet_filter.h"
#include "util.h"
#include "packet.h"
#include "packetchain.h"
#include "devicetracker.h"

packet_filter::packet_filter(const std::string& in_id, const std::string& in_description,
        const std::string& in_type) :
    tracker_component() {

    register_fields();
    reserve_fields(nullptr);

    set_filter_id(in_id);
    set_filter_description(in_description);
    set_filter_type(in_type);

    set_filter_default(false);

    base_uri = fmt::format("/filters/packet/{}", in_id);

    auto url = fmt::format("{}/filter", base_uri);

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route(url, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this, url](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    kis_lock_guard<kis_mutex> lk(mutex, url);
                    return self_endp_handler();
                }));

    auto posturl = fmt::format("{}/set_default", base_uri);

    httpd->register_route(url, {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this, posturl](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    kis_lock_guard<kis_mutex> lk(mutex, posturl);
                    return default_set_endp_handler(con);
                }));
}

void packet_filter::default_set_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
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

void packet_filter::build_self_content(std::shared_ptr<tracker_element_map> content) {
    content->insert(filter_id);
    content->insert(filter_description);
    content->insert(filter_type);
    content->insert(filter_default);
}

bool packet_filter::filterstring_to_bool(const std::string& str) {
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

packet_filter_mac_addr::packet_filter_mac_addr(const std::string& in_id, const std::string& in_description) :
    packet_filter(in_id, in_description, "mac_addr") {

        register_fields();
        reserve_fields(nullptr);

        devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

        eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();
        eb_id =
            eventbus->register_listener(device_tracker::event_new_phy(),
                    [this](std::shared_ptr<eventbus_event> evt) {
                    update_phy_map(evt);
                    });

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    // Set and clear endpoints
    auto seturl = fmt::format("/filters/packet/{}/:phyname/:block/set_filter", get_filter_id());
    auto remurl = fmt::format("/filters/packet/{}/:phyname/:block/remove_filter", get_filter_id());

    httpd->register_route(seturl, {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this, seturl](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    kis_lock_guard<kis_mutex> lk(mutex, seturl);
                    return edit_endp_handler(con);
                }));

    httpd->register_route(remurl, {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this, seturl](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    kis_lock_guard<kis_mutex> lk(mutex, seturl);
                    return remove_endp_handler(con);
                }));

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    pack_comp_common = packetchain->register_packet_component("COMMON");
}

packet_filter_mac_addr::~packet_filter_mac_addr() {
    if (eventbus != nullptr)
        eventbus->remove_listener(eb_id);
}

void packet_filter_mac_addr::update_phy_map(std::shared_ptr<eventbus_event> evt) {
    kis_lock_guard<kis_mutex> lk(mutex);

    if (unknown_phy_mac_filter_map.size() == 0)
        return;

    const auto phyname_k =
        evt->get_event_content()->find(device_tracker::event_new_phy());

    if (phyname_k == evt->get_event_content()->end())
        return;

    auto phy = devicetracker->fetch_phy_handler_by_name(get_tracker_value<std::string>(phyname_k->second));

    if (phy == nullptr)
        return;

    // Do we have any pending filters that match this key?
    auto unknown_key = unknown_phy_mac_filter_map.find(phy->fetch_phy_name());

    if (unknown_key == unknown_phy_mac_filter_map.end())
        return;

    // The tracked version already exists because that's always created, even
    // if we can't activate the filter b/c the phy is unknown

    // Copy the filter-engine code over to the new one
    phy_mac_filter_map[phy->fetch_phy_id()] = unknown_key->second;
    unknown_phy_mac_filter_map.erase(unknown_key);
}

void packet_filter_mac_addr::set_filter(mac_addr in_mac, const std::string& in_phy,
        const std::string& in_block, bool value) {
    kis_lock_guard<kis_mutex> lk(mutex);

	// Build the tracked version of the record, building any containers we need along the way, this
	// always gets built even for unknown phys
	auto tracked_phy_key = filter_phy_blocks->find(in_phy);

	std::shared_ptr<tracker_element_map> tracked_phy_map;
    std::shared_ptr<tracker_element_macfilter_map> target_block_map;
    int target_block_map_id;

    if (in_block == "source") {
        target_block_map_id = filter_source_id;
    } else if (in_block == "destination") {
        target_block_map_id = filter_dest_id;
    } else if (in_block == "network") {
        target_block_map_id = filter_network_id;
    } else if (in_block == "other") {
        target_block_map_id = filter_other_id;
    } else if (in_block == "any") {
        target_block_map_id = filter_any_id;
    } else {
        const auto e = fmt::format("Unknown target block '{}' in filter",
                kis_net_beast_httpd_connection::escape_html(in_block));
        throw std::runtime_error(e);
    }

    if (tracked_phy_key == filter_phy_blocks->end()) {
        // Generate all the required blocks
        tracked_phy_map = std::make_shared<tracker_element_map>();

        auto block_source = std::make_shared<tracker_element_macfilter_map>(filter_source_id);
        auto block_dest = std::make_shared<tracker_element_macfilter_map>(filter_dest_id);
        auto block_network = std::make_shared<tracker_element_macfilter_map>(filter_network_id);
        auto block_other = std::make_shared<tracker_element_macfilter_map>(filter_other_id);
        auto block_any = std::make_shared<tracker_element_macfilter_map>(filter_any_id);

        tracked_phy_map->insert(block_source);
        tracked_phy_map->insert(block_dest);
        tracked_phy_map->insert(block_network);
        tracked_phy_map->insert(block_other);
        tracked_phy_map->insert(block_any);

        filter_phy_blocks->insert(in_phy, tracked_phy_map);
	} else {
        tracked_phy_map = tracker_element::safe_cast_as<tracker_element_map>(tracked_phy_key->second);
	}

    // Find the target filter block
    target_block_map = tracked_phy_map->get_sub_as<tracker_element_macfilter_map>(target_block_map_id);

    // Find the actual filter
    auto tracked_mac_key = target_block_map->find(in_mac);
    if (tracked_mac_key == target_block_map->end()) {
        auto tracked_value = std::make_shared<tracker_element_uint8>(filter_sub_value_id);
        tracked_value->set(value);
        target_block_map->insert(in_mac, tracked_value);
    } else {
        auto bool_value = tracker_element::safe_cast_as<tracker_element_uint8>(tracked_mac_key->second);
        bool_value->set(value);
    }

	// Try to build the id-based lookup table
    auto phy = devicetracker->fetch_phy_handler_by_name(in_phy);

	// Cache unknown for future lookups
	if (phy == nullptr) {
        if (in_block == "source")
            unknown_phy_mac_filter_map[in_phy].filter_source[in_mac] = value;
        else if (in_block == "destination")
            unknown_phy_mac_filter_map[in_phy].filter_dest[in_mac] = value;
        else if (in_block == "network")
            unknown_phy_mac_filter_map[in_phy].filter_network[in_mac] = value;
        else if (in_block == "other")
            unknown_phy_mac_filter_map[in_phy].filter_other[in_mac] = value;
        else if (in_block == "any")
            unknown_phy_mac_filter_map[in_phy].filter_any[in_mac] = value;
        return;
	}

	// Set known phy types
    if (in_block == "source")
        phy_mac_filter_map[phy->fetch_phy_id()].filter_source[in_mac] = value;
    else if (in_block == "destination")
        phy_mac_filter_map[phy->fetch_phy_id()].filter_dest[in_mac] = value;
    else if (in_block == "network")
        phy_mac_filter_map[phy->fetch_phy_id()].filter_network[in_mac] = value;
    else if (in_block == "other")
        phy_mac_filter_map[phy->fetch_phy_id()].filter_other[in_mac] = value;
    else if (in_block == "any")
        phy_mac_filter_map[phy->fetch_phy_id()].filter_any[in_mac] = value;
}

void packet_filter_mac_addr::remove_filter(mac_addr in_mac, const std::string& in_phy,
        const std::string& in_block) {
    kis_lock_guard<kis_mutex> lk(mutex);

	// Build the tracked version of the record, building any containers we need along the way, this
	// always gets built even for unknown phys
	auto tracked_phy_key = filter_phy_blocks->find(in_phy);

	std::shared_ptr<tracker_element_map> tracked_phy_map;
    std::shared_ptr<tracker_element_macfilter_map> target_block_map;
    int target_block_map_id;

    if (in_block == "source") {
        target_block_map_id = filter_source_id;
    } else if (in_block == "destination") {
        target_block_map_id = filter_dest_id;
    } else if (in_block == "network") {
        target_block_map_id = filter_network_id;
    } else if (in_block == "other") {
        target_block_map_id = filter_other_id;
    } else if (in_block == "any") {
        target_block_map_id = filter_any_id;
    } else {
        const auto e = fmt::format("Unknown target block '{}' in filter",
                kis_net_beast_httpd_connection::escape_html(in_block));
        throw std::runtime_error(e);
    }

	if (tracked_phy_key == filter_phy_blocks->end()) {
        return;
	} else {
        tracked_phy_map = tracker_element::safe_cast_as<tracker_element_map>(tracked_phy_key->second);
	}

    // Find the target filter block
    target_block_map = tracked_phy_map->get_sub_as<tracker_element_macfilter_map>(target_block_map_id);

    // Find the actual filter
	auto tracked_mac_key = target_block_map->find(in_mac);
	if (tracked_mac_key != target_block_map->end()) {
        target_block_map->erase(tracked_mac_key);
	}

	// Try to build the id-based lookup table
	auto phy = devicetracker->fetch_phy_handler_by_name(in_phy);

	// Cache unknown for future lookups
	if (phy == nullptr) {
        if (in_block == "source") {
            auto k = unknown_phy_mac_filter_map[in_phy].filter_source.find(in_mac);
            if (k != unknown_phy_mac_filter_map[in_phy].filter_source.end())
                unknown_phy_mac_filter_map[in_phy].filter_source.erase(k);
        } else if (in_block == "destination") {
            auto k = unknown_phy_mac_filter_map[in_phy].filter_dest.find(in_mac);
            if (k != unknown_phy_mac_filter_map[in_phy].filter_dest.end())
                unknown_phy_mac_filter_map[in_phy].filter_dest.erase(k);
        } else if (in_block == "network") {
            auto k = unknown_phy_mac_filter_map[in_phy].filter_network.find(in_mac);
            if (k != unknown_phy_mac_filter_map[in_phy].filter_network.end())
                unknown_phy_mac_filter_map[in_phy].filter_network.erase(k);
        } else if (in_block == "other") {
            auto k = unknown_phy_mac_filter_map[in_phy].filter_other.find(in_mac);
            if (k != unknown_phy_mac_filter_map[in_phy].filter_other.end())
                unknown_phy_mac_filter_map[in_phy].filter_other.erase(k);
        } else if (in_block == "any") {
            auto k = unknown_phy_mac_filter_map[in_phy].filter_any.find(in_mac);
            if (k != unknown_phy_mac_filter_map[in_phy].filter_any.end())
                unknown_phy_mac_filter_map[in_phy].filter_any.erase(k);
        }
        return;
	}

    if (in_block == "source") {
        auto k = phy_mac_filter_map[phy->fetch_phy_id()].filter_source.find(in_mac);
        if (k != phy_mac_filter_map[phy->fetch_phy_id()].filter_source.end())
            phy_mac_filter_map[phy->fetch_phy_id()].filter_source.erase(k);
    } else if (in_block == "destination") {
        auto k = phy_mac_filter_map[phy->fetch_phy_id()].filter_dest.find(in_mac);
        if (k != phy_mac_filter_map[phy->fetch_phy_id()].filter_dest.end())
            phy_mac_filter_map[phy->fetch_phy_id()].filter_dest.erase(k);
    } else if (in_block == "network") {
        auto k = phy_mac_filter_map[phy->fetch_phy_id()].filter_network.find(in_mac);
        if (k != phy_mac_filter_map[phy->fetch_phy_id()].filter_network.end())
            phy_mac_filter_map[phy->fetch_phy_id()].filter_network.erase(k);
    } else if (in_block == "other") {
        auto k = phy_mac_filter_map[phy->fetch_phy_id()].filter_other.find(in_mac);
        if (k != phy_mac_filter_map[phy->fetch_phy_id()].filter_other.end())
            phy_mac_filter_map[phy->fetch_phy_id()].filter_other.erase(k);
    } else if (in_block == "any") {
        auto k = phy_mac_filter_map[phy->fetch_phy_id()].filter_any.find(in_mac);
        if (k != phy_mac_filter_map[phy->fetch_phy_id()].filter_any.end())
            phy_mac_filter_map[phy->fetch_phy_id()].filter_any.erase(k);
    }
}

void packet_filter_mac_addr::edit_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());

    auto filter = con->json()["filter"];

    if (!filter.is_object()) {
        con->set_status(500);
        stream << "Expected 'filter' to be a dictionary\n";
        return;
    }

    for (const auto& i : filter.items()) {
        mac_addr m(i.key());
        bool v = i.value();

        if (m.state.error) {
            const auto e = fmt::format("Invalid MAC address: '{}'", con->escape_html(i.key()));
            throw std::runtime_error(e);
        }

        set_filter(m, con->uri_params()[":phyname"], con->uri_params()[":block"], v);
    }

    stream << "set filter\n";
    return;
}

void packet_filter_mac_addr::remove_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());

    auto filter = con->json()["filter"];

    if (!filter.is_array()) {
        con->set_status(500);
        stream << "Expected 'filter' to be an array\n";
        return;
    }

    for (const auto& i : filter) {
        mac_addr m{i.get<std::string>()};

        if (m.state.error) {
            const auto e = fmt::format("Invalid MAC address: '{}'", con->escape_html(i));
            throw std::runtime_error(e);
        }

        remove_filter(m, con->uri_params()[":phyname"], con->uri_params()[":block"]);
    }

    stream << "Removed filter\n";
}

bool packet_filter_mac_addr::filter_packet(std::shared_ptr<kis_packet> packet) {
    auto common = packet->fetch<kis_common_info>(pack_comp_common);

    if (common == nullptr)
        return get_filter_default();

    auto phy_filter_group =
        phy_mac_filter_map.find(common->phyid);

    if (phy_filter_group == phy_mac_filter_map.end())
        return get_filter_default();

    auto si = phy_filter_group->second.filter_source.find(common->source);
    if (si != phy_filter_group->second.filter_source.end()) {
        return si->second;
    }

    auto di = phy_filter_group->second.filter_dest.find(common->dest);
    if (di != phy_filter_group->second.filter_dest.end()) {
        return di->second;
    }

    auto ni = phy_filter_group->second.filter_network.find(common->network);
    if (ni != phy_filter_group->second.filter_network.end()) {
        return ni->second;
    }

    auto oi = phy_filter_group->second.filter_other.find(common->transmitter);
    if (oi != phy_filter_group->second.filter_other.end()) {
        return oi->second;
    }

    auto ai = phy_filter_group->second.filter_any.find(common->source);

    if (ai == phy_filter_group->second.filter_any.end())
        ai = phy_filter_group->second.filter_any.find(common->dest);

    if (ai == phy_filter_group->second.filter_any.end())
        ai = phy_filter_group->second.filter_any.find(common->network);

    if (ai == phy_filter_group->second.filter_any.end())
        ai = phy_filter_group->second.filter_any.find(common->transmitter);

    if (ai == phy_filter_group->second.filter_any.end())
        ai = phy_filter_group->second.filter_any.find(common->dest);

    if (ai != phy_filter_group->second.filter_any.end())
        return ai->second;

    return get_filter_default();
}

std::shared_ptr<tracker_element_map> packet_filter_mac_addr::self_endp_handler() {
    auto ret = std::make_shared<tracker_element_map>();
    build_self_content(ret);
    return ret;
}

void packet_filter_mac_addr::build_self_content(std::shared_ptr<tracker_element_map> content) {
    packet_filter::build_self_content(content);

    content->insert(filter_phy_blocks);
}


