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

#include "gpstcp_v2.h"
#include "gpstracker.h"
#include "messagebus.h"
#include "util.h"

#include <fmt_asio.h>

kis_gps_tcp_v2::kis_gps_tcp_v2(shared_gps_builder in_builder) : 
    kis_gps_nmea_v2{in_builder},
	resolver{Globalreg::globalreg->io},
	socket{Globalreg::globalreg->io} {

    // Defer making buffers until open, because we might be used to make a 
    // builder instance

    ever_seen_gps = false;
    last_heading_time = time(0);

    auto timetracker = 
        Globalreg::fetch_mandatory_global_as<time_tracker>("TIMETRACKER");

    error_reconnect_timer = 
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
                [this](int) -> int {
                    if (get_device_connected()) 
                        return 1;

                    open_gps(get_gps_definition());

                    return 1;
                });

    data_timeout_timer =
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
                [this](int) -> int {

                if (socket.is_open() && time(0) - last_data_time > 30) {
                    close();

                    if (get_gps_reconnect()) {
                        _MSG_ERROR("(GPS) No usable data from the TCP GPS {}:{} in over 30 seconds, reconnecting.",
								host, port);
                        open_gps(get_gps_definition());
                    } else {
                        _MSG_ERROR("(GPS) No usable data from the TCP GPS {}:{} in over 30 seconds, disconnecting.",
								host, port);
                    }
                }

                return 1;
                });
}

kis_gps_tcp_v2::~kis_gps_tcp_v2() {
    close_impl();

    auto timetracker = Globalreg::fetch_global_as<time_tracker>("TIMETRACKER");
    if (timetracker != nullptr) {
        timetracker->remove_timer(error_reconnect_timer);
        timetracker->remove_timer(data_timeout_timer);
    }
}

void kis_gps_tcp_v2::close() {
    kis_lock_guard<kis_mutex> lg(gps_mutex, "close");

    auto ft = boost::asio::post(strand_, 
            std::packaged_task<void()>([self = std::static_pointer_cast<kis_gps_tcp_v2>(shared_from_this())]() mutable {
                self->close_impl();
            }));

    ft.wait();
}
void kis_gps_tcp_v2::close_impl() {
    stopped = true;
    set_int_device_connected(false);

    if (socket.is_open()) {
        try {
            socket.cancel();
            socket.close();
        } catch (const std::exception& e) {
            // Ignore failures to close the socket, so long as its closed
            ;
        }
    }
}

void kis_gps_tcp_v2::start_read_impl() {
    boost::asio::async_read_until(socket, in_buf, '\n',
            boost::asio::bind_executor(strand_,
                [self = shared_from_this()](const boost::system::error_code& error, std::size_t t) {
                    self->handle_read(error, t);
                }));
}

void kis_gps_tcp_v2::start_connect(std::shared_ptr<kis_gps_tcp_v2> ref,
        const boost::system::error_code& error,
        const tcp::resolver::results_type& endpoints) {
    if (error) {
        _MSG_ERROR("(GPS) Could not resolve TCP GPS server address {}:{} - {}", host, port, error.message());
        stopped = true;
        set_int_device_connected(false);
    } else {
        boost::asio::async_connect(socket, endpoints,
                [this, ref](const boost::system::error_code& ec, tcp::endpoint endpoint) {
                    handle_connect(ref, ec, endpoint);
                });
    }
}

void kis_gps_tcp_v2::handle_connect(std::shared_ptr<kis_gps_tcp_v2> ref,
        const boost::system::error_code& error,
        tcp::endpoint endpoint) {
    if (stopped) {
        return;
    }

    if (error) {
        _MSG_ERROR("(GPS) Could not connect to TCP GPS {}:{} - {}", host, port, error.message());
        close_impl();
        return;
    }

    _MSG_INFO("(GPS) Connected to TCP GPS server {}:{}", endpoint.address().to_string(),
            endpoint.port());

    stopped = false;
    set_int_device_connected(true);

    start_read();
}

bool kis_gps_tcp_v2::open_gps(std::string in_opts) {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "gps_tcp_v2 open_gps");

    if (!kis_gps::open_gps(in_opts))
        return false;

    set_int_device_connected(false);

    if (socket.is_open()) {
        try {
            socket.cancel();
            socket.close();
        } catch (const std::exception& e) {
            ;
        }
    }

    std::string proto_host;
    std::string proto_port;

    proto_host = fetch_opt("host", source_definition_opts);
    proto_port = fetch_opt("port", source_definition_opts);

    if (proto_host == "") {
        _MSG("(GPS) Expected a host= option for TCP GPS, none found.", MSGFLAG_ERROR);
        return -1;
    }

    if (proto_port == "") {
        _MSG_INFO("(GPS) Expected a port= option for TCP GPS, none found.", MSGFLAG_ERROR);
        return -1;
    }

    host = proto_host;
    port = proto_port;

    // Reset the time counter
    last_data_time = time(0);

    // We're not stopped
    stopped = false;

    _MSG_INFO("(GPS) Connecting to TCP GPS on {}:{}", host, port);

    resolver.async_resolve(host, port,
            std::bind(&kis_gps_tcp_v2::start_connect, this,
                std::static_pointer_cast<kis_gps_tcp_v2>(shared_from_this()),
                boost::asio::placeholders::error,
                boost::asio::placeholders::results));

    return 1;
}

bool kis_gps_tcp_v2::get_location_valid() {
    kis_lock_guard<kis_mutex> lk(data_mutex, "gps_tcp_v2 get_location_valid");

    if (gps_location == nullptr) {
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

bool kis_gps_tcp_v2::get_device_connected() {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "gps_tcp_v2 get_device_connected");

    return socket.is_open();
}

