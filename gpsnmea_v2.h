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

#ifndef __GPSNMEA_V2_H__
#define __GPSNMEA_V2_H__

#include "config.h"

#include "kis_gps.h"
#include "timetracker.h"
#include "globalregistry.h"

#define ASIO_HAS_STD_CHRONO
#define ASIO_HAS_MOVE

#include "boost/asio.hpp"

// Generic NMEA parser for GPS

class kis_gps_nmea_v2 : public kis_gps, public std::enable_shared_from_this<kis_gps_nmea_v2> {
public:
    kis_gps_nmea_v2(shared_gps_builder in_builder) :
        kis_gps(in_builder),
        strand_{Globalreg::globalreg->io.get_executor()},
        last_heading_time(time(0)),
		last_data_time(time(0)) { }

    virtual ~kis_gps_nmea_v2() { };

    virtual void handle_read(const boost::system::error_code& error, std::size_t sz);

protected:
    virtual void close() = 0;
    virtual void close_impl() = 0;

    virtual void start_read();
    virtual void start_read_impl() = 0;

    boost::asio::streambuf in_buf;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    std::atomic<bool> stopped;

    bool warned_about_binary;

    // Have we ever seen data from the device?
    bool ever_seen_gps;

    // Last time we calculated the heading, don't do it more than once every 
    // few seconds or we get nasty noise
    time_t last_heading_time;
    time_t last_data_time;
};

#endif

