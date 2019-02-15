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
                url, false,
                [this]() -> std::shared_ptr<TrackerElement> {
                    local_locker lock(&mutex);
                    return self_endp_handler();
                });

    auto posturl = fmt::format("{}/set_default", base_uri);
    default_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Post_Endpoint>(
                posturl, true,
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

    // Set and clear endpoints
    macaddr_edit_endp =
        std::make_shared<Kis_Net_Httpd_Path_Post_Endpoint>(
                [this](const std::vector<std::string>& path, const std::string& uri) -> bool {
                    // /filters/packet/[id]/[block]/set_filter
                    if (path.size() < 5)
                        return false;

                    if (path[0] != "filters")
                        return false;

                    if (path[1] != "packet")
                        return false;

                    if (path[2] != get_filter_id())
                        return false;

                    if (path[4] != "set_filter")
                        return false;

                    if (path[3] == "source")
                        return true;

                    if (path[3] == "destination")
                        return true;

                    if (path[3] == "network")
                        return true;

                    if (path[3] == "other")
                        return true;

                    if (path[3] == "any")
                        return true;

                    return false;
                },
                true,
                [this](std::ostream& stream, const std::vector<std::string>& path, 
                        const std::string& uri, SharedStructured post_structured, 
                        Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return edit_endp_handler(stream, path, post_structured);
                }, &mutex);

    macaddr_remove_endp =
        std::make_shared<Kis_Net_Httpd_Path_Post_Endpoint>(
                [this](const std::vector<std::string>& path, const std::string& uri) -> bool {
                    // /filters/packet/[id]/[block]/remove_filter
                    if (path.size() < 5)
                        return false;

                    if (path[0] != "filters")
                        return false;

                    if (path[1] != "packet")
                        return false;

                    if (path[2] != get_filter_id())
                        return false;

                    if (path[4] != "remove_filter")
                        return false;

                    if (path[3] == "source")
                        return true;

                    if (path[3] == "destination")
                        return true;

                    if (path[3] == "network")
                        return true;

                    if (path[3] == "other")
                        return true;

                    if (path[3] == "any")
                        return true;

                    return false;
                },
                true,
                [this](std::ostream& stream, const std::vector<std::string>& path,
                        const std::string& uri, SharedStructured post_structured,
                        Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return remove_endp_handler(stream, path, post_structured);
                }, &mutex);

    auto packetchain = Globalreg::FetchMandatoryGlobalAs<Packetchain>();
    pack_comp_common = packetchain->RegisterPacketComponent("COMMON");
}

unsigned int PacketfilterMacaddr::edit_endp_handler(std::ostream& stream, 
        const std::vector<std::string>& path, SharedStructured structured) {

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

        if (!filter->isDictionary()) {
            stream << "Expected dictionary 'filter' object\n";
            return 500;
        }

        std::shared_ptr<TrackerElementMacMap> target;

        if (path[3] == "source")
            target = filter_source;

        if (path[3] == "destination")
            target = filter_dest;

        if (path[3] == "network")
            target = filter_network;

        if (path[3] == "other")
            target = filter_other;

        if (path[3] == "any")
            target = filter_any;

        if (target == nullptr) 
            throw std::runtime_error(fmt::format("Could not match target filter '{}'",
                        kishttpd::EscapeHtml(path[2])));

        for (auto i : filter->getStructuredStrMap()) {
            mac_addr m{i.first};
            bool v = i.second->getBool();

            if (m.error) 
                throw std::runtime_error(fmt::format("Invalid MAC address: '{}'",
                            kishttpd::EscapeHtml(i.first)));

            auto sv = std::make_shared<TrackerElementUInt8>(0, v);

            target->replace(m, sv);
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

        std::shared_ptr<TrackerElementMacMap> target;

        if (path[3] == "source")
            target = filter_source;

        if (path[3] == "destination")
            target = filter_dest;

        if (path[3] == "network")
            target = filter_network;

        if (path[3] == "other")
            target = filter_other;

        if (path[3] == "any")
            target = filter_any;

        if (target == nullptr) 
            throw std::runtime_error(fmt::format("Could not match target filter '{}'",
                        kishttpd::EscapeHtml(path[2])));

        for (auto i : filter->getStringVec()) {
            mac_addr m{i};

            if (m.error) 
                throw std::runtime_error(fmt::format("Invalid MAC address: '{}'",
                            kishttpd::EscapeHtml(i)));

            target->erase(m);
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

    auto si = filter_source->find(common->source);
    if (si != filter_source->end()) {
        auto v = std::static_pointer_cast<TrackerElementUInt8>(si->second);
        return v->get();
    }

    auto di = filter_dest->find(common->dest);
    if (di != filter_dest->end()) {
        auto v = std::static_pointer_cast<TrackerElementUInt8>(di->second);
        return v->get();
    }

    auto ni = filter_network->find(common->network);
    if (ni != filter_network->end()) {
        auto v = std::static_pointer_cast<TrackerElementUInt8>(ni->second);
        return v->get();
    }

    auto oi = filter_other->find(common->transmitter);
    if (oi != filter_other->end()) {
        auto v = std::static_pointer_cast<TrackerElementUInt8>(ni->second);
        return v->get();
    }

    auto ai = filter_any->find(common->source);

    if (ai == filter_any->end())
        ai = filter_any->find(common->dest);

    if (ai == filter_any->end())
        ai = filter_any->find(common->network);

    if (ai == filter_any->end())
        ai = filter_any->find(common->transmitter);

    if (ai != filter_any->end()) {
        auto v = std::static_pointer_cast<TrackerElementUInt8>(ai->second);
        return v->get();
    }

    return get_filter_default();
}

std::shared_ptr<TrackerElementMap> PacketfilterMacaddr::self_endp_handler() {
    auto ret = std::make_shared<TrackerElementMap>();
    build_self_content(ret);
    return ret;
}

void PacketfilterMacaddr::build_self_content(std::shared_ptr<TrackerElementMap> content) { 
    Packetfilter::build_self_content(content);

    content->insert(filter_source);
    content->insert(filter_dest);
    content->insert(filter_network);
    content->insert(filter_other);
    content->insert(filter_any);

}


