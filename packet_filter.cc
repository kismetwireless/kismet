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

Packetfilter::Packetfilter(const std::string& in_id, const std::string& in_description,
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

int Packetfilter::default_set_endp_handler(std::ostream& stream, SharedStructured structured) {
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

void Packetfilter::build_self_content(std::shared_ptr<TrackerElementMap> content) {
    content->insert(filter_id);
    content->insert(filter_description);
    content->insert(filter_type);
    content->insert(filter_default);
}

bool Packetfilter::filterstring_to_bool(const std::string& str) {
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

PacketfilterMacaddr::PacketfilterMacaddr(const std::string& in_id, const std::string& in_description) :
    Packetfilter(in_id, in_description, "mac_addr") {

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
                    // /filters/packet/[id]/[phyname]/[block]/set_filter
                    if (path.size() < 6)
                        return false;

                    if (path[0] != "filters")
                        return false;

                    if (path[1] != "packet")
                        return false;

                    if (path[2] != get_filter_id())
                        return false;

                    if (path[5] != "set_filter")
                        return false;

                    if (path[4] == "source")
                        return true;

                    if (path[4] == "destination")
                        return true;

                    if (path[4] == "network")
                        return true;

                    if (path[4] == "other")
                        return true;

                    if (path[4] == "any")
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
                    // /filters/packet/[id]/[phy]/[block]/remove_filter
                    if (path.size() < 6)
                        return false;

                    if (path[0] != "filters")
                        return false;

                    if (path[1] != "packet")
                        return false;

                    if (path[2] != get_filter_id())
                        return false;

                    if (path[5] != "remove_filter")
                        return false;

                    if (path[4] == "source")
                        return true;

                    if (path[4] == "destination")
                        return true;

                    if (path[4] == "network")
                        return true;

                    if (path[4] == "other")
                        return true;

                    if (path[4] == "any")
                        return true;

                    return false;
                },
                [this](std::ostream& stream, const std::vector<std::string>& path,
                        const std::string& uri, SharedStructured post_structured,
                        Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return remove_endp_handler(stream, path, post_structured);
                }, &mutex);

    auto packetchain = Globalreg::FetchMandatoryGlobalAs<Packetchain>();
    pack_comp_common = packetchain->RegisterPacketComponent("COMMON");
}

PacketfilterMacaddr::~PacketfilterMacaddr() {
    if (eventbus != nullptr)
        eventbus->remove_listener(eb_id);
}

void PacketfilterMacaddr::update_phy_map(std::shared_ptr<EventbusEvent> evt) {
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

    // The tracked version already exists because that's always created, even
    // if we can't activate the filter b/c the phy is unknown

    // Copy the filter-engine code over to the new one
	phy_mac_filter_map[phy_evt->phy->FetchPhyId()] = unknown_key->second;
	unknown_phy_mac_filter_map.erase(unknown_key);
}

void PacketfilterMacaddr::set_filter(mac_addr in_mac, const std::string& in_phy, const std::string& in_block, bool value) {
	local_locker l(&mutex);

	// Build the tracked version of the record, building any containers we need along the way, this
	// always gets built even for unknown phys
	auto tracked_phy_key = filter_phy_blocks->find(in_phy);

	std::shared_ptr<TrackerElementMap> tracked_phy_map;
    std::shared_ptr<TrackerElementMacMap> target_block_map;
    int target_block_map_id;

    if (in_block == "source")
        target_block_map_id = filter_source_id;
    else if (in_block == "destination")
        target_block_map_id = filter_dest_id;
    else if (in_block == "network")
        target_block_map_id = filter_network_id;
    else if (in_block == "other")
        target_block_map_id = filter_other_id;
    else if (in_block == "any")
        target_block_map_id = filter_any_id;
    else
        throw std::runtime_error(fmt::format("Unknown target block '{}' in filter", 
                    kishttpd::EscapeHtml(in_block)));

    if (tracked_phy_key == filter_phy_blocks->end()) {
        // Generate all the required blocks
        tracked_phy_map = std::make_shared<TrackerElementMap>();

        auto block_source = std::make_shared<TrackerElementMap>(filter_source_id);
        auto block_dest = std::make_shared<TrackerElementMap>(filter_dest_id);
        auto block_network = std::make_shared<TrackerElementMap>(filter_network_id);
        auto block_other = std::make_shared<TrackerElementMap>(filter_other_id);
        auto block_any = std::make_shared<TrackerElementMap>(filter_any_id);

        tracked_phy_map->insert(block_source);
        tracked_phy_map->insert(block_dest);
        tracked_phy_map->insert(block_network);
        tracked_phy_map->insert(block_other);
        tracked_phy_map->insert(block_any);

        filter_phy_blocks->insert(in_phy, tracked_phy_map);
	} else {
        tracked_phy_map = TrackerElement::safe_cast_as<TrackerElementMap>(tracked_phy_key->second);
	}

    // Find the target filter block
    target_block_map = tracked_phy_map->get_sub_as<TrackerElementMacMap>(target_block_map_id);

    // Find the actual filter
    auto tracked_mac_key = target_block_map->find(in_mac);
    if (tracked_mac_key == target_block_map->end()) {
        auto tracked_value = std::make_shared<TrackerElementUInt8>(filter_sub_value_id);
        tracked_value->set(value);
        target_block_map->insert(in_mac, tracked_value);
    } else {
        auto bool_value = TrackerElement::safe_cast_as<TrackerElementUInt8>(tracked_mac_key->second);
        bool_value->set(value);
    }

	// Try to build the id-based lookup table
    auto phy = devicetracker->FetchPhyHandlerByName(in_phy);

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
        phy_mac_filter_map[phy->FetchPhyId()].filter_source[in_mac] = value;
    else if (in_block == "destination")
        phy_mac_filter_map[phy->FetchPhyId()].filter_dest[in_mac] = value;
    else if (in_block == "network")
        phy_mac_filter_map[phy->FetchPhyId()].filter_network[in_mac] = value;
    else if (in_block == "other")
        phy_mac_filter_map[phy->FetchPhyId()].filter_other[in_mac] = value;
    else if (in_block == "any")
        phy_mac_filter_map[phy->FetchPhyId()].filter_any[in_mac] = value;
}

void PacketfilterMacaddr::remove_filter(mac_addr in_mac, const std::string& in_phy, const std::string& in_block) {
	local_locker l(&mutex);

	// Build the tracked version of the record, building any containers we need along the way, this
	// always gets built even for unknown phys
	auto tracked_phy_key = filter_phy_blocks->find(in_phy);

	std::shared_ptr<TrackerElementMap> tracked_phy_map;
    std::shared_ptr<TrackerElementMacMap> target_block_map;
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
        throw std::runtime_error(fmt::format("Unknown target block '{}' in filter", 
                    kishttpd::EscapeHtml(in_block)));
    }

	if (tracked_phy_key == filter_phy_blocks->end()) {
        return;
	} else {
        tracked_phy_map = TrackerElement::safe_cast_as<TrackerElementMap>(tracked_phy_key->second);
	}

    // Find the target filter block
    target_block_map = tracked_phy_map->get_sub_as<TrackerElementMacMap>(target_block_map_id);

    // Find the actual filter
	auto tracked_mac_key = target_block_map->find(in_mac);
	if (tracked_mac_key != target_block_map->end()) {
        target_block_map->erase(tracked_mac_key);
	}

	// Try to build the id-based lookup table
	auto phy = devicetracker->FetchPhyHandlerByName(in_phy);

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
        auto k = phy_mac_filter_map[phy->FetchPhyId()].filter_source.find(in_mac);
        if (k != phy_mac_filter_map[phy->FetchPhyId()].filter_source.end())
            phy_mac_filter_map[phy->FetchPhyId()].filter_source.erase(k);
    } else if (in_block == "destination") {
        auto k = phy_mac_filter_map[phy->FetchPhyId()].filter_dest.find(in_mac);
        if (k != phy_mac_filter_map[phy->FetchPhyId()].filter_dest.end())
            phy_mac_filter_map[phy->FetchPhyId()].filter_dest.erase(k);
    } else if (in_block == "network") {
        auto k = phy_mac_filter_map[phy->FetchPhyId()].filter_network.find(in_mac);
        if (k != phy_mac_filter_map[phy->FetchPhyId()].filter_network.end())
            phy_mac_filter_map[phy->FetchPhyId()].filter_network.erase(k);
    } else if (in_block == "other") {
        auto k = phy_mac_filter_map[phy->FetchPhyId()].filter_other.find(in_mac);
        if (k != phy_mac_filter_map[phy->FetchPhyId()].filter_other.end())
            phy_mac_filter_map[phy->FetchPhyId()].filter_other.erase(k);
    } else if (in_block == "any") {
        auto k = phy_mac_filter_map[phy->FetchPhyId()].filter_any.find(in_mac);
        if (k != phy_mac_filter_map[phy->FetchPhyId()].filter_any.end())
            phy_mac_filter_map[phy->FetchPhyId()].filter_any.erase(k);
    }
}

unsigned int PacketfilterMacaddr::edit_endp_handler(std::ostream& stream, 
        const std::vector<std::string>& path, SharedStructured structured) {
    // /filters/packet/[id]/[phy]/[block]/set_filter
    
    if (path.size() < 6) {
        stream << "Malformed request path\n";
        return 500;
    }

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

        // path[3] phy
        // path[4] block

        for (auto i : filter->getStructuredStrMap()) {
            mac_addr m{i.first};
            bool v = i.second->getBool();

            if (m.error) 
                throw std::runtime_error(fmt::format("Invalid MAC address: '{}'",
                            kishttpd::EscapeHtml(i.first)));

            set_filter(m, path[3], path[4], v);
        }

    } catch (const std::exception& e) {
        stream << "Error handling request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

unsigned int PacketfilterMacaddr::remove_endp_handler(std::ostream& stream, 
        const std::vector<std::string>& path, SharedStructured structured) {
    // /filters/packet/[id]/[phy]/[block]/remove_filter

    if (path.size() < 5) {
        stream << "Malformed request path\n";
        return 500;
    }

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

        // path[3] phy
        // path[4] block

        for (auto i : filter->getStringVec()) {
            mac_addr m{i};

            if (m.error) 
                throw std::runtime_error(fmt::format("Invalid MAC address: '{}'",
                            kishttpd::EscapeHtml(i)));

            remove_filter(m, path[3], path[4]);
        }

    } catch (const std::exception& e) {
        stream << "Error handling request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

bool PacketfilterMacaddr::filter_packet(kis_packet *packet) {
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

std::shared_ptr<TrackerElementMap> PacketfilterMacaddr::self_endp_handler() {
    auto ret = std::make_shared<TrackerElementMap>();
    build_self_content(ret);
    return ret;
}

void PacketfilterMacaddr::build_self_content(std::shared_ptr<TrackerElementMap> content) { 
    Packetfilter::build_self_content(content);

    content->insert(filter_phy_blocks);
}


