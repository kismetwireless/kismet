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
#include "entrytracker.h"

#include "util.h"

void StdoutMessageClient::ProcessMessage(std::string in_msg, int in_flags) {
    if (in_flags & (MSGFLAG_ERROR | MSGFLAG_FATAL))
        fprintf(stderr, "ERROR: %s\n", in_msg.c_str());
    else
        fprintf(stdout, "NOTICE: %s\n", in_msg.c_str());
    
    return;
}

MessageBus::MessageBus(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    shutdown = false;

    msg_cl.lock();

    msg_dispatch_t =
        std::thread([this]() {
                thread_set_process_name("msgbus");
                msg_queue_dispatcher();
            });
}

MessageBus::~MessageBus() {
    shutdown = true;
    msg_cl.unlock(0);
    msg_dispatch_t.join();

    globalreg->RemoveGlobal("MESSAGEBUS");
    globalreg->messagebus = NULL;
}

void MessageBus::InjectMessage(std::string in_msg, int in_flags) {
    local_locker lock(&msg_mutex);

    auto msg = std::make_shared<MessageBus::message>(in_msg, in_flags);

    msg_queue.push(msg);
    msg_cl.unlock(1);

    return;
}

void MessageBus::msg_queue_dispatcher() {
    local_demand_locker l(&msg_mutex);

    while (1) {
        if (shutdown)
            return;

        // Lock while we examine the queue
        l.lock();

        if (msg_queue.size() > 0) {
            auto e = msg_queue.front();
            msg_queue.pop();

            // Lock handlers and unlock message queue
            {
                l.unlock();
                local_shared_locker hl(&handler_mutex);

                for (auto sub : subscribers) {
                    if (sub->mask & e->flags) 
                        sub->client->ProcessMessage(e->msg, e->flags);
                }
            }

            // Loop for more events
            continue;
        }

        // Reset the lock
        msg_cl.lock();
      
        // Unlock our hold on the system
        l.unlock();

        // Wait until new events
        msg_cl.block_until();
    }
}

void MessageBus::RegisterClient(MessageClient *in_subscriber, int in_mask) {
    local_locker lock(&handler_mutex);

    busclient *bc = new busclient;

    bc->client = in_subscriber;
    bc->mask = in_mask;

    subscribers.push_back(bc);

    return;
}

void MessageBus::RemoveClient(MessageClient *in_unsubscriber) {
    local_locker lock(&handler_mutex);

    for (unsigned int x = 0; x < subscribers.size(); x++) {
        if (subscribers[x]->client == in_unsubscriber) {
            subscribers.erase(subscribers.begin() + x);
            return;
        }
    }    

    return;
}

