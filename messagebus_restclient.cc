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

#include "messagebus.h"
#include "messagebus_restclient.h"

#include "json_adapter.h"

rest_message_client::rest_message_client() :
    lifetime_global() {

    eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();

    message_vec_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.messagebus.list",
                tracker_element_factory<tracker_element_vector>(),
                "list of messages");

    message_timestamp_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.messagebus.timestamp",
                tracker_element_factory<tracker_element_uint64>(),
                "message update timestamp");

    listener_id = 
        eventbus->register_listener(message_bus::event_message(), 
                [this](std::shared_ptr<eventbus_event> evt) {

                auto msg_k = evt->get_event_content()->find(message_bus::event_message());
                if (msg_k == evt->get_event_content()->end())
                    return;

                auto msg = std::static_pointer_cast<tracked_message>(msg_k->second);

                kis_lock_guard<kis_mutex> lk(msg_mutex, "rest_message_client message_event");
                message_list.push_back(msg);

                if (message_list.size() > 50)
                    message_list.pop_front();
                });

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/messagebus/last-time/:timestamp/messages", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto ts_k = con->uri_params().find(":timestamp");
                    auto ts = string_to_n<long>(ts_k->second);

                    kis_lock_guard<kis_mutex> lk(msg_mutex, "/messagebus/last-time/messages");
                    auto wrapper = std::make_shared<tracker_element_map>();
                    auto msgvec = std::make_shared<tracker_element_vector>(message_vec_id);

                    wrapper->insert(msgvec);
                    wrapper->insert(std::make_shared<tracker_element_uint64>(message_timestamp_id, time(0)));

                    for (auto i : message_list) 
                        if (ts < i->get_timestamp()) 
                            msgvec->push_back(i);

                    return wrapper;
                }));

    httpd->register_route("/messagebus/all_messages", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    kis_lock_guard<kis_mutex> lk(msg_mutex, "/messagebus/all_messages");

                    auto ret = std::make_shared<tracker_element_vector>();
                    for (auto i : message_list) 
                        ret->push_back(i);

                    return ret;
                }));

}

rest_message_client::~rest_message_client() {
    eventbus->remove_listener(listener_id);

    Globalreg::globalreg->remove_global("REST_MSG_CLIENT");

    message_list.clear();
}

