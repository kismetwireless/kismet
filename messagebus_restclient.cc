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

rest_message_client::rest_message_client(global_registry *in_globalreg, void *in_aux) :
    message_client(in_globalreg, in_aux),
    kis_net_httpd_cppstream_handler() {

    globalreg = in_globalreg;

    message_vec_id =
        globalreg->entrytracker->register_field("kismet.messagebus.list",
                tracker_element_factory<tracker_element_vector>(),
                "list of messages");

    message_timestamp_id =
        globalreg->entrytracker->register_field("kismet.messagebus.timestamp",
                tracker_element_factory<tracker_element_uint64>(),
                "message update timestamp");

    message_entry_id =
        globalreg->entrytracker->register_field("kismet.messagebus.message",
                tracker_element_factory<tracked_message>(),
                "Kismet message");

    Globalreg::globalreg->messagebus->register_client(this, MSGFLAG_ALL);

    bind_httpd_server();
}

rest_message_client::~rest_message_client() {
    local_eol_locker lock(&msg_mutex);

    globalreg->messagebus->remove_client(this);

    globalreg->remove_global("REST_MSG_CLIENT");

    message_list.clear();
}

void rest_message_client::process_message(std::string in_msg, int in_flags) {
    // Don't propagate LOCAL or DEBUG messages
    if ((in_flags & MSGFLAG_LOCAL) || (in_flags & MSGFLAG_DEBUG))
        return;

    auto msg =
        std::make_shared<tracked_message>(message_entry_id);

    msg->set_from_message(in_msg, in_flags);

    {
        local_locker lock(&msg_mutex);

        message_list.push_back(msg);

        // Hardcode a backlog count right now
        if (message_list.size() > 50) {
            message_list.pop_front();
        }
    }
}

bool rest_message_client::httpd_verify_path(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0) {
        return false;
    }

    // Split URL and process
    std::vector<std::string> tokenurl = str_tokenize(path, "/");
    if (tokenurl.size() < 3)
        return false;

    if (tokenurl[1] == "messagebus") {
        if (tokenurl[2] == "all_messages.json") {
            return true;
        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return false;

            if (tokenurl[4] == "messages.json")
                return true;
            else
                return false;
        }
    }

    return false;
}

void rest_message_client::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection __attribute__((unused)),
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    time_t since_time = 0;
    bool wrap = false;

    if (strcmp(method, "GET") != 0) {
        return;
    }

    // All paths end in final element
    if (!httpd_can_serialize(path))
        return;

    // Split URL and process
    std::vector<std::string> tokenurl = str_tokenize(path, "/");
    if (tokenurl.size() < 3)
        return;

    if (tokenurl[1] == "messagebus") {
        if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return;

            if (!httpd_can_serialize(tokenurl[4]))
                return;

            long lastts;
            if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1)
                return;

            wrap = true;

            since_time = lastts;

        } else if (httpd_strip_suffix(tokenurl[2]) != "all_messages") {
            return;
        }
    }

    {
        local_locker lock(&msg_mutex);

        std::shared_ptr<tracker_element> transmit;
        std::shared_ptr<tracker_element_map> wrapper;
        auto msgvec = std::make_shared<tracker_element_vector>(message_vec_id);
       
        // If we're doing a time-since, wrap the vector
        if (wrap) {
            wrapper =
                std::make_shared<tracker_element_map>();
            wrapper->insert(msgvec);

            auto ts =
                std::make_shared<tracker_element_uint64>(message_timestamp_id, time(0));
            wrapper->insert(ts);

            transmit = wrapper;
        } else {
            transmit = msgvec;
        }

        for (auto i : message_list) {
            if (since_time < i->get_timestamp())
                msgvec->push_back(i);
        }

        httpd_serialize(path, stream, transmit, nullptr, connection);
    }
}

