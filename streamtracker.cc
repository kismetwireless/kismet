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

#include "streamtracker.h"
#include "entrytracker.h"

stream_tracker::stream_tracker() :
    lifetime_global() {

    mutex.set_name("stream_tracker");

    info_builder_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.stream.stream",
                tracker_element_factory<streaming_info_record>(),
                "Kismet data stream");

    tracked_stream_map = std::make_shared<tracker_element_double_map>();

    next_stream_id = 1;

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/streams/all_streams", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(tracked_stream_map, mutex));
    
    httpd->register_route("/streams/by-id/:id/stream_info", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto id = string_to_n<int>(con->uri_params()[":id"]);
                    auto s_k = tracked_stream_map->find(id);

                    if (s_k == tracked_stream_map->end())
                        throw std::runtime_error("invalid key");

                    return s_k->second;
                }, mutex));

    httpd->register_route("/streams/by-id/:id/close_stream", {"GET", "POST"}, httpd->LOGON_ROLE, {},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    std::ostream stream(&con->response_stream());

                    auto id = string_to_n<int>(con->uri_params()[":id"]);
                    auto s_k = tracked_stream_map->find(id);

                    if (s_k == tracked_stream_map->end())
                        throw std::runtime_error("invalid key");

                    auto ir = 
                        std::static_pointer_cast<streaming_info_record>(s_k->second);

                    ir->get_agent()->stop_stream("stream closed from web");

                    stream << "OK";
                }));
}

stream_tracker::~stream_tracker() {

}

void stream_tracker::cancel_streams() {
    kis_lock_guard<kis_mutex> lk(mutex, "stream_tracker cancel_streams");

    for (auto s_i : *tracked_stream_map) {
        auto s = std::static_pointer_cast<streaming_info_record>(s_i.second);
        s->get_agent()->stop_stream("closing all streams");
    }
}

double stream_tracker::register_streamer(std::shared_ptr<streaming_agent> in_agent,
        std::string in_name, std::string in_type, std::string in_path, std::string in_description) {

    kis_lock_guard<kis_mutex> lk(mutex, "stream_tracker register_streamer");

    auto streamrec =
        std::make_shared<streaming_info_record>(info_builder_id);

    streamrec->set_agent(in_agent);
    in_agent->set_stream_id(next_stream_id++);

    streamrec->set_log_name(in_name);
    streamrec->set_log_type(in_type);
    streamrec->set_log_path(in_path);
    streamrec->set_log_description(in_description);

    tracked_stream_map->insert(in_agent->get_stream_id(), streamrec);

    return in_agent->get_stream_id();
}

void stream_tracker::remove_streamer(double in_id) {
    kis_lock_guard<kis_mutex> lk(mutex, "stream_tracker remove_streamer");

    auto si = tracked_stream_map->find(in_id);

    if (si == tracked_stream_map->end())
        return;

    auto a = std::static_pointer_cast<streaming_info_record>(si->second);
    a->get_agent()->stop_stream("stream removed");

    tracked_stream_map->erase(si);
}

