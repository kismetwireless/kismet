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

void StdoutMessageClient::ProcessMessage(string in_msg, int in_flags) {
    if (in_flags & (MSGFLAG_ERROR | MSGFLAG_FATAL))
        fprintf(stderr, "ERROR: %s\n", in_msg.c_str());
    else
        fprintf(stdout, "NOTICE: %s\n", in_msg.c_str());
    
    return;
}

void MessageBus::InjectMessage(string in_msg, int in_flags) {
    for (unsigned int x = 0; x < subscribers.size(); x++) {
        if (subscribers[x]->mask & in_flags)
            subscribers[x]->client->ProcessMessage(in_msg, in_flags);
    }

    return;
}

void MessageBus::RegisterClient(MessageClient *in_subscriber, int in_mask) {
    busclient *bc = new busclient;

    bc->client = in_subscriber;
    bc->mask = in_mask;

    subscribers.push_back(bc);

    return;
}

void MessageBus::RemoveClient(MessageClient *in_unsubscriber) {
    for (unsigned int x = 0; x < subscribers.size(); x++) {
        if (subscribers[x]->client == in_unsubscriber) {
            subscribers.erase(subscribers.begin() + x);
            return;
        }
    }    

    return;
}

