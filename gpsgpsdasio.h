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

#ifndef __GPSGPSD_ASIO_H__
#define __GPSGPSD_ASIO_H__

#include "config.h"

#include "kis_gps.h"
#include "timetracker.h"
#include "buffer_handler.h"
#include "ringbuf2.h"
#include "globalregistry.h"
#include "tcpclient2.h"
#include "pollabletracker.h"

#define ASIO_HAS_STD_CHRONO
#define ASIO_HAS_MOVE

#include "asio.hpp"
#include "asio/steady_timer.hpp"

using asio::ip::tcp;

class kis_gps_gpsd_asio : public kis_gps {
public:
    kis_gps_gpsd_asio(shared_gps_builder in_builder);
    virtual ~kis_gps_gpsd_asio();

    virtual bool open_gps(std::string in_definition);

    virtual bool get_location_valid();

protected:
    void start_connect(const std::error_code& error, tcp::resolver::iterator endpoint_iter);
    void handle_connect(const std::error_code& error, tcp::resolver::iterator endpoint);

    void start_read();
    void handle_read(const std::error_code& error, std::size_t sz);

    void write_gpsd(const std::string& data);

    void close();

    std::atomic<bool> stopped;

    tcp::resolver resolver;
    tcp::socket socket;

    asio::streambuf in_buf;

    std::string host, port;

    // Last time we got data, to allow us to reset the connection if we 
    // seem to stall
    time_t last_data_time;
    int data_timeout_timer;

    int error_reconnect_timer;

    // Last time we calculated the heading, don't do it more than once every 
    // few seconds or we get nasty noise
    time_t last_heading_time;

    // Decaying reconnection algorithm
    int reconnect_tid;
    int num_reconnects;
    static int time_event_reconnect(TIMEEVENT_PARMS);

    // pollable_poll mode (do we know we're JSON, etc
    int poll_mode;
    // Units - different gpsd variants return it different ways
    int si_units;
    // Do we run in raw mode?
    int si_raw;
};

class gps_gpsd_asio_builder : public kis_gps_builder {
public:
    gps_gpsd_asio_builder() : 
        kis_gps_builder() { 
        initialize();
    }

    virtual void initialize() {
        set_int_gps_class("gpsd");
        set_int_gps_class_description("networked GPSD server");
        set_int_gps_priority(-1000);
        set_int_singleton(false);
        set_int_default_name("gpsd");
    }

    virtual shared_gps build_gps(shared_gps_builder in_builder) {
        return shared_gps(new kis_gps_gpsd_asio(in_builder));
    }
};

#endif

