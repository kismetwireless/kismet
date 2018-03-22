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

RestMessageClient::RestMessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
    MessageClient(in_globalreg, in_aux),
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg) {

    globalreg = in_globalreg;

    message_vec_id =
        globalreg->entrytracker->RegisterField("kismet.messagebus.list",
                TrackerVector, "list of messages");

    message_timestamp_id =
        globalreg->entrytracker->RegisterField("kismet.messagebus.timestamp",
                TrackerUInt64, "message update timestamp");

    std::shared_ptr<tracked_message> msg_builder(new tracked_message(globalreg, 0));

    message_entry_id =
        globalreg->entrytracker->RegisterField("kismet.messagebus.message",
                msg_builder, "Kismet message");

	globalreg->messagebus->RegisterClient(this, MSGFLAG_ALL);
}

RestMessageClient::~RestMessageClient() {
    local_eol_locker lock(&msg_mutex);

    globalreg->messagebus->RemoveClient(this);

    globalreg->RemoveGlobal("REST_MSG_CLIENT");

    message_vec.clear();
}

void RestMessageClient::ProcessMessage(std::string in_msg, int in_flags) {
    // Don't propagate LOCAL messages
    if (in_flags & MSGFLAG_LOCAL)
        return;

    std::shared_ptr<tracked_message> msg = 
        std::static_pointer_cast<tracked_message>(globalreg->entrytracker->GetTrackedInstance(message_entry_id));

    msg->set_from_message(in_msg, in_flags);

    {
        local_locker lock(&msg_mutex);

        message_vec.push_back(msg);

        // Hardcode a backlog count right now
        if (message_vec.size() > 50) {
            message_vec.erase(message_vec.begin());
        }
    }
}

bool RestMessageClient::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0) {
        return false;
    }

    // Split URL and process
    std::vector<std::string> tokenurl = StrTokenize(path, "/");
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

void RestMessageClient::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection __attribute__((unused)),
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    time_t since_time = 0;
    bool wrap = false;

    if (strcmp(method, "GET") != 0) {
        return;
    }

    // All paths end in final element
    if (!Httpd_CanSerialize(path))
        return;

    // Split URL and process
    std::vector<std::string> tokenurl = StrTokenize(path, "/");
    if (tokenurl.size() < 3)
        return;

    if (tokenurl[1] == "messagebus") {
        if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return;

            if (!Httpd_CanSerialize(tokenurl[4]))
                return;

            long lastts;
            if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1)
                return;

            wrap = true;

            since_time = lastts;

        } else if (Httpd_StripSuffix(tokenurl[2]) != "all_messages") {
            return;
        }
    }

    {
        local_locker lock(&msg_mutex);

        SharedTrackerElement wrapper;
        SharedTrackerElement msgvec(globalreg->entrytracker->GetTrackedInstance(message_vec_id));
       
        // If we're doing a time-since, wrap the vector
        if (wrap) {
            wrapper.reset(new TrackerElement(TrackerMap));
            wrapper->add_map(msgvec);

            SharedTrackerElement ts =
                globalreg->entrytracker->GetTrackedInstance(message_timestamp_id);
            ts->set((uint64_t) globalreg->timestamp.tv_sec);
            wrapper->add_map(ts);
        } else {
            wrapper = msgvec;
        }

        for (std::vector<std::shared_ptr<tracked_message> >::iterator i = message_vec.begin();
                i != message_vec.end(); ++i) {
            if (since_time < (*i)->get_timestamp()) {
                msgvec->add_vector(*i);
            }
        }

        Httpd_Serialize(path, stream, wrapper);
    }
}

