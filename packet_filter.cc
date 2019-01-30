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


Packetfilter::Packetfilter(const std::string& in_id, const std::string& in_description,
        const std::string& in_type) {

    set_filter_id(in_id);
    set_filter_description(in_description);
    set_filter_type(in_type);

    set_filter_default(false);

    auto url = fmt::format("/packetfilters/filters/{}/filter", in_id);

    self_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>(
                url, false,
                [this]() -> std::shared_ptr<TrackerElement> {
                    return self_endp_handler();
                }, mutex);

    auto posturl = fmt::format("{}/set_default", url);
    default_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Post_Endpoint>(
                url, true,
                [this](std::ostream& stream, const std::string& uri,
                    SharedStructured post_structured, 
                    Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) {
                    return handle_set_default_endp(stream, post_structured);
                }, mutex);
    
}

int Packetfilter::handle_set_default_endp(std::ostream& stream, SharedStructured structured) {
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

    if (cstr == "filter")
        return true;

    if (cstr == "block")
        return true;

    return false;
}

