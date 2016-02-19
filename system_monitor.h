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

#ifndef __SYSTEM_MONITOR_H__
#define __SYSTEM_MONITOR_H__

#include "config.h"

#include <string>
#include "trackedelement.h"
#include "kis_net_microhttpd.h"

class Systemmonitor : public tracker_component, public Kis_Net_Httpd_Stream_Handler {
public:
    Systemmonitor(GlobalRegistry *in_globalreg);
    ~Systemmonitor();

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    __Proxy(battery_perc, int32_t, int32_t, int32_t, battery_perc);
    __Proxy(battery_charging, uint8_t, bool, bool, battery_charging);
    __Proxy(battery_ac, uint8_t, bool, bool, battery_ac);
    __Proxy(battery_remaining, uint32_t, uint32_t, uint32_t, battery_remaining);

protected:
    virtual void register_fields();

    int self_id;

    int battery_perc_id;
    TrackerElement *battery_perc;

    int battery_charging_id;
    TrackerElement *battery_charging;

    int battery_ac_id;
    TrackerElement *battery_ac;

    int battery_remaining_id;
    TrackerElement *battery_remaining;

};

#endif

