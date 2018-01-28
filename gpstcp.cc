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

#include <time.h>

#include "gpstcp.h"
#include "util.h"
#include "gpstracker.h"
#include "pollabletracker.h"

GPSTCP::GPSTCP(GlobalRegistry *in_globalreg, SharedGpsBuilder in_builder) : 
    GPSNMEA(in_globalreg, in_builder) {

    // Defer making buffers until open, because we might be used to make a 
    // builder instance
   
    tcpclient = NULL;

    ever_seen_gps = false;

    last_heading_time = time(0);

    pollabletracker =
        Globalreg::FetchGlobalAs<PollableTracker>(globalreg, "POLLABLETRACKER");

    auto timetracker = 
        Globalreg::FetchGlobalAs<Timetracker>(globalreg, "TIMETRACKER");
    error_reconnect_timer = 
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
                [this](int) -> int {
                    if (get_device_connected()) 
                        return 1;

                    open_gps(get_gps_definition());

                    return 1;
                });
}

GPSTCP::~GPSTCP() {
    local_eol_locker lock(&gps_mutex);

    pollabletracker->RemovePollable(tcpclient);

    shared_ptr<Timetracker> timetracker = 
        Globalreg::FetchGlobalAs<Timetracker>(globalreg, "TIMETRACKER");
    timetracker->RemoveTimer(error_reconnect_timer);
}

bool GPSTCP::open_gps(string in_opts) {
    local_locker lock(&gps_mutex);

    if (!KisGps::open_gps(in_opts))
        return false;

    set_int_device_connected(false);

    // Delete any existing serial interface before we parse options
    if (nmeahandler != NULL) {
        delete nmeahandler;
        nmeahandler = NULL;
    }

    if (tcpclient != NULL) {
        pollabletracker->RemovePollable(tcpclient);
        tcpclient.reset();
        nmeaclient.reset();
    }

    std::string proto_name;
    proto_name = FetchOpt("name", source_definition_opts);

    std::string proto_host;
    std::string proto_port_s;
    unsigned int proto_port;

    proto_host = FetchOpt("host", source_definition_opts);
    proto_port_s = FetchOpt("port", source_definition_opts);

    if (proto_host == "") {
        _MSG("GPSTCP expected host= option, none found.", MSGFLAG_ERROR);
        return -1;
    }

    if (proto_port_s != "") {
        if (sscanf(proto_port_s.c_str(), "%u", &proto_port) != 1) {
            _MSG("GPSTCP expected port in port= option.", MSGFLAG_ERROR);
            return -1;
        }
    } else {
        proto_port = 4352;
        _MSG("GPSTCP defaulting to port 4352, set the port= option if "
                "your NMEA server is on a different port", MSGFLAG_INFO);
    }


    // We never write to a serial gps so don't make a write buffer
    nmeahandler = new BufferHandler<RingbufV2>(2048, 0);
    // Set the read handler to us
    nmeahandler->SetReadBufferInterface(this);

    // Link to a tcp connection
    tcpclient.reset(new TcpClientV2(globalreg, nmeahandler));
    tcpclient->Connect(proto_host, proto_port);

    // Register a pollable event
    pollabletracker->RegisterPollable(static_pointer_cast<Pollable>(tcpclient));

    host = proto_host;
    port = proto_port;

    stringstream msg;
    msg << "GPSTCP connecting to GPS NMEA server on " << host << ":" << port;
    _MSG(msg.str(), MSGFLAG_INFO);

    set_int_device_connected(true);

    return 1;
}

bool GPSTCP::get_location_valid() {
    local_locker lock(&gps_mutex);

    if (gps_location == NULL) {
        return false;
    }

    if (gps_location->fix < 2) {
        return false;
    }

    time_t now = time(0);

    if (now - gps_location->tv.tv_sec > 10) {
        return false;
    }

    return true;
}

bool GPSTCP::get_device_connected() {
    local_locker lock(&gps_mutex);

    if (tcpclient == NULL)
        return false;

    return tcpclient->FetchConnected();
}

void GPSTCP::BufferError(string in_error) {
    local_locker lock(&gps_mutex);

    _MSG("GPS device '" + get_gps_name() + "' encountered a network error: " + in_error,
            MSGFLAG_ERROR);

    set_int_device_connected(false);
}

