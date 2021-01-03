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


#ifndef __MESSAGEBUS_REST_H__
#define __MESSAGEBUS_REST_H__

#include "config.h"

#include <string>
#include <vector>

#include "eventbus.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "messagebus.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "kis_net_beast_httpd.h"

class rest_message_client : public lifetime_global {
public:
    static std::shared_ptr<rest_message_client> 
        create_messageclient() {
        std::shared_ptr<rest_message_client> mon(new rest_message_client());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global("REST_MSG_CLIENT", mon);
        return mon;
    }

private:
    rest_message_client();

public:
	virtual ~rest_message_client();

protected:
    kis_mutex msg_mutex;

    std::shared_ptr<event_bus> eventbus;

    std::list<std::shared_ptr<tracked_message> > message_list;

    unsigned long listener_id;

    int message_vec_id, message_timestamp_id;
};


#endif

