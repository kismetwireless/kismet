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
#include <pthread.h>

#include "globalregistry.h"

#include "messagebus.h"
#include "trackedelement.h"
#include "kis_net_microhttpd.h"

class tracked_message : public tracker_component {
public:
    tracked_message(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_message(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
        }

    virtual TrackerElement *clone_type() {
        return new tracked_message(globalreg, get_id());
    }

    __Proxy(message, string, string, string, message);
    __Proxy(flags, int32_t, int32_t, int32_t, flags);
    __Proxy(timestamp, uint64_t, time_t, time_t, timestamp);

    void set_from_message(string in_msg, int in_flags) {
        set_message(in_msg);
        set_flags(in_flags);
        set_timestamp(globalreg->timestamp.tv_sec);
    }

    bool operator<(const tracked_message& comp) const {
        return get_timestamp() < comp.get_timestamp();
    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        message_id =
            RegisterField("kismet.messagebus.message_string", TrackerString,
                    "Message content", (void **) &message);
        flags_id =
            RegisterField("kismet.messagebus.message_flags", TrackerInt32,
                    "Message flags (per messagebus.h)", (void **) &flags);
        timestamp_id =
            RegisterField("kismet.messagebus.message_time", TrackerUInt64,
                    "Message time_t", (void **) &timestamp);
    }

    TrackerElement *message;
    int message_id;

    TrackerElement *flags;
    int flags_id;

    TrackerElement *timestamp;
    int timestamp_id;
};

class RestMessageClient : public MessageClient, public Kis_Net_Httpd_Stream_Handler,
    public LifetimeGlobal {
public:
    RestMessageClient(GlobalRegistry *in_globalreg, void *in_aux);
	virtual ~RestMessageClient();
    void ProcessMessage(string in_msg, int in_flags);

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

protected:
    pthread_mutex_t msg_mutex;

    std::vector<tracked_message *> message_vec;

    int message_vec_id, message_entry_id, message_timestamp_id;
};


#endif

