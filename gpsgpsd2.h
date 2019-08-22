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

#ifndef __GPSGPSD_V2_H__
#define __GPSGPSD_V2_H__

#include "config.h"

#include "kis_gps.h"
#include "timetracker.h"
#include "buffer_handler.h"
#include "ringbuf2.h"
#include "globalregistry.h"
#include "tcpclient2.h"
#include "pollabletracker.h"

// New GPSD interface
//
// This code uses the new buffer handler interface for communicating with a 
// gpsd host over TCP

class kis_gps_gpsd_v2 : public kis_gps {
public:
    kis_gps_gpsd_v2(shared_gps_builder in_builder);
    virtual ~kis_gps_gpsd_v2();

    virtual bool open_gps(std::string in_definition);

    virtual bool get_location_valid();

protected:
    std::shared_ptr<pollable_tracker> pollabletracker;

    std::shared_ptr<tcp_client_v2> tcpclient;
    std::shared_ptr<buffer_handler<ringbuf_v2>> tcphandler;
    buffer_interface_func tcpinterface;

    // Called by our tcpinterface 
    virtual void buffer_available(size_t in_amt);
    virtual void buffer_error(std::string in_err);

    // Device
    std::string host;
    unsigned int port;

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

class gps_gpsd_v2_builder : public kis_gps_builder {
public:
    gps_gpsd_v2_builder() : 
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
        return shared_gps(new kis_gps_gpsd_v2(in_builder));
    }
};

#endif

