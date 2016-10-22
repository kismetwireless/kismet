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

#include <pthread.h>

#include "messagebus.h"
#include "messagebus_restclient.h"

#include "json_adapter.h"
#include "msgpack_adapter.h"

RestMessageClient::RestMessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
    MessageClient(in_globalreg, in_aux),
    Kis_Net_Httpd_Stream_Handler(in_globalreg) {

    globalreg = in_globalreg;
    globalreg->InsertGlobal("REST_MSG_CLIENT", this);

    message_vec_id =
        globalreg->entrytracker->RegisterField("kismet.messagebus.list",
                TrackerVector, "list of messages");

    message_timestamp_id =
        globalreg->entrytracker->RegisterField("kismet.messagebus.timestamp",
                TrackerInt64, "message update timestamp");

    tracked_message *msg_builder =
        new tracked_message(globalreg, 0);

    message_entry_id =
        globalreg->entrytracker->RegisterField("kismet.messagebus.message",
                msg_builder, "Kismet message");
    
    delete(msg_builder);

    pthread_mutex_init(&msg_mutex, NULL);

	globalreg->messagebus->RegisterClient(this, MSGFLAG_ALL);
}

RestMessageClient::~RestMessageClient() {
    globalreg->messagebus->RemoveClient(this);

    globalreg->RemoveGlobal("REST_MSG_CLIENT");

    {
        local_locker lock(&msg_mutex);

        for (vector<tracked_message *>::iterator i = message_vec.begin();
                i != message_vec.end(); ++i) {
            (*i)->unlink();
        }
    }

    pthread_mutex_destroy(&msg_mutex);
}

void RestMessageClient::ProcessMessage(string in_msg, int in_flags) {
    tracked_message *msg = 
        (tracked_message *) globalreg->entrytracker->GetTrackedInstance(message_entry_id);

    msg->set_from_message(in_msg, in_flags);
    msg->link();

    {
        local_locker lock(&msg_mutex);

        message_vec.push_back(msg);

        // Hardcode a backlog count right now
        if (message_vec.size() > 50) {
            message_vec.front()->unlink();
            message_vec.erase(message_vec.begin());
        }
    }
}

bool RestMessageClient::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0) {
        return false;
    }

    // Split URL and process
    vector<string> tokenurl = StrTokenize(path, "/");
    if (tokenurl.size() < 3)
        return false;

    if (tokenurl[1] == "messagebus") {
        if (tokenurl[2] == "all_messages.msgpack") {
            return true;
        } else if (tokenurl[2] == "all_messages.json") {
            return true;
        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return false;

            if (tokenurl[4] == "messages.msgpack")
                return true;
            else if (tokenurl[4] == "messages.json")
                return true;
            else
                return false;
        }
    }

    return false;
}

void RestMessageClient::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        struct MHD_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    TrackerElementSerializer *serializer = NULL;
    time_t since_time = 0;
    bool wrap = false;

    if (strcmp(method, "GET") != 0) {
        return;
    }

    // Split URL and process
    vector<string> tokenurl = StrTokenize(path, "/");
    if (tokenurl.size() < 3)
        return;

    if (tokenurl[1] == "messagebus") {
        if (tokenurl[2] == "all_messages.msgpack") {
            serializer =
                new MsgpackAdapter::Serializer(globalreg, stream);
        } else if (tokenurl[2] == "all_messages.json") {
            serializer =
                new JsonAdapter::Serializer(globalreg, stream);
        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return;

            long lastts;
            if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1)
                return;

            wrap = true;

            since_time = lastts;

            if (tokenurl[4] == "messages.msgpack") {
                serializer =
                    new MsgpackAdapter::Serializer(globalreg, stream);
            } else if (tokenurl[4] == "messages.json") {
                serializer =
                    new JsonAdapter::Serializer(globalreg, stream);
            } else {
                return;
            }
        }
    }

    if (serializer == NULL)
        return;

    {
        local_locker lock(&msg_mutex);

        TrackerElement *wrapper;
        TrackerElement *msgvec = 
            globalreg->entrytracker->GetTrackedInstance(message_vec_id);
       
        // If we're doing a time-since, wrap the vector
        if (wrap) {
            wrapper = new TrackerElement(TrackerMap);
            wrapper->add_map(msgvec);

            TrackerElement *ts =
                globalreg->entrytracker->GetTrackedInstance(message_timestamp_id);
            ts->set((int64_t) since_time);
            wrapper->add_map(ts);
        } else {
            wrapper = msgvec;
        }

        for (vector<tracked_message *>::iterator i = message_vec.begin();
                i != message_vec.end(); ++i) {
            if (since_time < (*i)->get_timestamp()) {
                msgvec->add_vector(*i);
            }
        }

        serializer->serialize(wrapper);

        delete(wrapper);
        delete(serializer);
    }
}

