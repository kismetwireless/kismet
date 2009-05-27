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


#ifndef __MESSAGEBUS_H__
#define __MESSAGEBUS_H__

#include "config.h"

#include <string>
#include <vector>

#include "globalregistry.h"

// Message flags for queuing data
#define MSGFLAG_NONE    0
#define MSGFLAG_DEBUG   1
#define MSGFLAG_INFO    2
#define MSGFLAG_ERROR   4
#define MSGFLAG_ALERT   8
#define MSGFLAG_FATAL   16
// Don't propagate it past local display systems
#define MSGFLAG_LOCAL   32
// Force printing of the error in the shutdown messages, sort of a "fatal lite"
#define MSGFLAG_PRINT	64
#define MSGFLAG_ALL     (MSGFLAG_DEBUG | MSGFLAG_INFO | \
                         MSGFLAG_ERROR | MSGFLAG_ALERT | \
                         MSGFLAG_FATAL)
// Combine
#define MSGFLAG_PRINTERROR	(MSGFLAG_ERROR | MSGFLAG_PRINT)

// A subscriber to the message bus.  It subscribes with a mask of 
// what messages it wants to handle
class MessageClient {
public:
    MessageClient() {
        fprintf(stderr, "FATAL OOPS: MessageClient::MessageClient() called "
				"with no global registry\n");
		exit(1);
    }

    MessageClient(GlobalRegistry *in_globalreg, void *in_aux) {
        globalreg = in_globalreg;
		auxptr = in_aux;
    }

	virtual ~MessageClient() { }

    virtual void ProcessMessage(string in_msg, int in_flags) = 0;
protected:
    GlobalRegistry *globalreg;
	void *auxptr;
};

class StdoutMessageClient : public MessageClient {
public:
    StdoutMessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
        MessageClient(in_globalreg, in_aux) { }
	virtual ~StdoutMessageClient() { }
    void ProcessMessage(string in_msg, int in_flags);
};

class MessageBus {
public:
    // Inject a message into the bus
    void InjectMessage(string in_msg, int in_flags);

    // Link a meessage display system
    void RegisterClient(MessageClient *in_subcriber, int in_mask);
    void RemoveClient(MessageClient *in_unsubscriber);

protected:
    typedef struct {
        MessageClient *client;
        int mask;
    } busclient;

    vector<MessageBus::busclient *> subscribers;
};


#endif

