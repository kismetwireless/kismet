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

#ifndef __GPSSERIAL_V3_H__
#define __GPSSERIAL_V3_H__

#include "config.h"

#include "globalregistry.h"
#include "gpsnmea_v2.h"
#include "kis_gps.h"
#include "timetracker.h"

#define ASIO_HAS_STD_CHRONO
#define ASIO_HAS_MOVE

#include "boost/asio.hpp"

// NMEA serial-attached GPS
// Implemented using ASIO serial

class kis_gps_serial_v3 : public kis_gps_nmea_v2 {
public:
    kis_gps_serial_v3(shared_gps_builder in_builder);
    virtual ~kis_gps_serial_v3();

    virtual bool open_gps(std::string in_opts) override;
    virtual bool get_location_valid() override;
    virtual bool get_device_connected() override;

protected:
	virtual void start_read_impl() override;
	virtual void close() override;

    virtual void close_impl() override;

    boost::asio::serial_port serialport;

    // Device
    std::string serial_device;
    unsigned int baud;

    // Have we ever seen data from the device?
    bool ever_seen_gps;

    // Last time we calculated the heading, don't do it more than once every 
    // few seconds or we get nasty noise
    time_t last_heading_time;

    int data_timeout_timer;
    int error_reconnect_timer;
};

class gps_serial_v3_builder : public kis_gps_builder {
public:
    gps_serial_v3_builder() : 
        kis_gps_builder() { 
        initialize();
    }

    virtual void initialize() override {
        set_int_gps_class("serial");
        set_int_gps_class_description("serial-attached NMEA gps (includes USB GPS)");
        set_int_gps_priority(-1000);
        set_int_default_name("serial");
        set_int_singleton(false);
    }

    virtual shared_gps build_gps(shared_gps_builder in_builder) override {
        return shared_gps(new kis_gps_serial_v3(in_builder));
    }
};


#endif

