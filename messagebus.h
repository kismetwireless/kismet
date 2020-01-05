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

#include <queue>
#include <string>
#include <vector>

#include "globalregistry.h"
#include "kis_mutex.h"

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
class message_client {
public:
    message_client() {
        fprintf(stderr, "FATAL OOPS: message_client::message_client() called "
				"with no global registry\n");
		exit(1);
    }

    message_client(global_registry *in_globalreg, void *in_aux) {
        globalreg = in_globalreg;
		auxptr = in_aux;
    }

	virtual ~message_client() { }

    virtual void process_message(std::string in_msg, int in_flags) = 0;
protected:
    global_registry *globalreg;
	void *auxptr;
};

class stdout_message_client : public message_client {
public:
    stdout_message_client(global_registry *in_globalreg, void *in_aux) :
        message_client(in_globalreg, in_aux) { }
	virtual ~stdout_message_client() { }
    void process_message(std::string in_msg, int in_flags);
};

class message_bus : public lifetime_global {
public:
    static std::string global_name() { return "MESSAGEBUS"; }

    static std::shared_ptr<message_bus> create_messagebus(global_registry *in_globalreg) {
        std::shared_ptr<message_bus> mon(new message_bus(in_globalreg));
        in_globalreg->messagebus = mon.get();
        in_globalreg->register_lifetime_global(mon);
        in_globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    message_bus(global_registry *in_globalreg);

public:
    virtual ~message_bus();

    // Inject a message into the bus
    void inject_message(std::string in_msg, int in_flags);

    // Link a meessage display system
    void register_client(message_client *in_subcriber, int in_mask);
    void remove_client(message_client *in_unsubscriber);

protected:
    global_registry *globalreg;

    kis_recursive_timed_mutex handler_mutex;

    typedef struct {
        message_client *client;
        int mask;
    } busclient;

    std::vector<message_bus::busclient *> subscribers;

    class message {
    public:
        message(const std::string& in_msg, int in_flags) :
            msg {in_msg},
            flags {in_flags} { }

        std::string msg;
        int flags;
    }; 

    // Event pool and handler thread
    kis_recursive_timed_mutex msg_mutex;
    std::queue<std::shared_ptr<message>> msg_queue;
    std::thread msg_dispatch_t;
    conditional_locker<int> msg_cl;
    std::atomic<bool> shutdown;
    void msg_queue_dispatcher();
};


#endif

