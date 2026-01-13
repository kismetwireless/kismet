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

#include "globalregistry.h"
#include "kis_gps.h"
#include "timetracker.h"

#include "boost/asio.hpp"

using boost::asio::ip::tcp;

class kis_gps_gpsd_v3 : public kis_gps, public std::enable_shared_from_this<kis_gps_gpsd_v3> {
public:
    kis_gps_gpsd_v3(shared_gps_builder in_builder);
    virtual ~kis_gps_gpsd_v3();

    virtual bool open_gps(std::string in_definition);

    virtual bool get_location_valid();

    // Blocking public close that waits for the socket to close
    void close();

protected:
    void handle_error();

    void handle_open_gps();

    void start_connect(std::shared_ptr<kis_gps_gpsd_v3> ref,
            const boost::system::error_code& error,
            const tcp::resolver::results_type& endpoints);
    void handle_connect(std::shared_ptr<kis_gps_gpsd_v3> ref,
            const boost::system::error_code& error,
            tcp::endpoint endpoint);

    void start_read();
    void handle_read(const boost::system::error_code& error, std::size_t sz);

    std::queue<std::string, std::deque<std::string>> out_bufs;

    void write_gpsd(const std::string& data);
    void write_impl();

    // Internal closure that performs the closing; must be executed on the gps strand
    void close_impl();

    std::atomic<bool> stopped;

    tcp::resolver resolver;
    tcp::socket socket;

    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    boost::asio::streambuf in_buf{8192};

    std::string host, port;

    // Last time we got data, to allow us to reset the connection if we 
    // seem to stall
    std::atomic<time_t> last_data_time;
    int data_timeout_timer;

    std::atomic<int> error_reconnect_timer;

    // Last time we calculated the heading, don't do it more than once every 
    // few seconds or we get nasty noise
    time_t last_heading_time;

    // Last time we saw an ATT heading, and heading data
    time_t last_att_heading_time;
    double last_att_heading;


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

    std::shared_ptr<time_tracker> timetracker;
};

class gps_gpsd_v3_builder : public kis_gps_builder {
public:
    gps_gpsd_v3_builder() : 
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
        return shared_gps(new kis_gps_gpsd_v3(in_builder));
    }
};

#endif

