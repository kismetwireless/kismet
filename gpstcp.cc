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

kis_gps_tcp::kis_gps_tcp(shared_gps_builder in_builder) : 
    kis_gps_nmea(in_builder) {

    // Defer making buffers until open, because we might be used to make a 
    // builder instance
   
    tcpclient = NULL;

    ever_seen_gps = false;

    last_heading_time = time(0);

    nmeainterface = buffer_interface_func(
            [this](size_t in_avail) {
                buffer_available(in_avail);
            },
            [this](std::string in_err) {
                buffer_error(in_err);
            });

    pollabletracker = Globalreg::fetch_mandatory_global_as<pollable_tracker>("POLLABLETRACKER");

    auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>("TIMETRACKER");
    error_reconnect_timer = 
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
                [this](int) -> int {
                    if (!get_gps_reconnect())
                        return 1;

                    if (get_device_connected()) 
                        return 1;

                    open_gps(get_gps_definition());

                    return 1;
                });
}

kis_gps_tcp::~kis_gps_tcp() {
    if (tcpclient != nullptr) {
        pollabletracker->remove_pollable(tcpclient);
    }

    if (nmeahandler != nullptr) {
        nmeahandler->remove_read_buffer_interface();
    }

    std::shared_ptr<time_tracker> timetracker = Globalreg::fetch_global_as<time_tracker>("TIMETRACKER");
    if (timetracker != nullptr)
        timetracker->remove_timer(error_reconnect_timer);
}

bool kis_gps_tcp::open_gps(std::string in_opts) {
    local_locker lock(gps_mutex);

    if (!kis_gps::open_gps(in_opts))
        return false;

    set_int_device_connected(false);

    if (tcpclient != nullptr) {
        tcpclient->disconnect();
    }

    if (nmeahandler != nullptr) {
        nmeahandler->clear_read_buffer();
        nmeahandler->clear_write_buffer();
    }

    std::string proto_name;
    proto_name = fetch_opt("name", source_definition_opts);

    std::string proto_host;
    std::string proto_port_s;
    unsigned int proto_port;

    proto_host = fetch_opt("host", source_definition_opts);
    proto_port_s = fetch_opt("port", source_definition_opts);

    if (proto_host == "") {
        _MSG("kis_gps_tcp expected host= option, none found.", MSGFLAG_ERROR);
        return -1;
    }

    if (proto_port_s != "") {
        if (sscanf(proto_port_s.c_str(), "%u", &proto_port) != 1) {
            _MSG("kis_gps_tcp expected port in port= option.", MSGFLAG_ERROR);
            return -1;
        }
    } else {
        proto_port = 4352;
        _MSG("kis_gps_tcp defaulting to port 4352, set the port= option if "
                "your NMEA server is on a different port", MSGFLAG_INFO);
    }


    if (nmeahandler == nullptr) {
        // We never write to a serial gps so don't make a write buffer
        nmeahandler =  std::make_shared<buffer_handler<ringbuf_v2>>(2048, 0, gps_mutex);
        nmeahandler->set_read_buffer_interface(&nmeainterface);
    }

    if (tcpclient == nullptr) {
        // Link to a tcp connection
        tcpclient = std::make_shared<tcp_client_v2>(Globalreg::globalreg, nmeahandler);
        pollabletracker->register_pollable(std::static_pointer_cast<kis_pollable>(tcpclient));
    }

    host = proto_host;
    port = proto_port;

    _MSG_INFO("kis_gps_tcp connecting to GPS NMEA server on {}:{}", host, port);

    tcpclient->connect(proto_host, proto_port);
    set_int_device_connected(true);

    return 1;
}

bool kis_gps_tcp::get_location_valid() {
    local_shared_locker lock(gps_mutex);

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

bool kis_gps_tcp::get_device_connected() {
    local_shared_locker lock(gps_mutex);

    if (tcpclient == NULL)
        return false;

    return tcpclient->get_connected();
}

void kis_gps_tcp::buffer_error(std::string in_error) {
    local_locker lock(gps_mutex);

    _MSG("GPS device '" + get_gps_name() + "' encountered a network error: " + in_error,
            MSGFLAG_ERROR);

    set_int_device_connected(false);
}

