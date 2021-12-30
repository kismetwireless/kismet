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

#include "gpsserial_v3.h"
#include "gpstracker.h"
#include "messagebus.h"
#include "util.h"

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/serial/IOSerialKeys.h>
#include <IOKit/serial/ioss.h>
#include <IOKit/IOBSD.h>
#else
#include <sys/ioctl.h>
#endif

kis_gps_serial_v3::kis_gps_serial_v3(shared_gps_builder in_builder) : 
    kis_gps_nmea_v2{in_builder},
    serialport{Globalreg::globalreg->io} {

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

                if (serialport.is_open() && time(0) - last_data_time > 30) {
                    close();

                    if (get_gps_reconnect()) {
                        _MSG_ERROR("(GPS) No usable data from the serial GPS {} in over 30 seconds, check that "
                                "you are not running GPSD (it may have started automatically), the baud rate is "
                                "correct and the GPS outputs standard NMEA.",
                                serial_device);
                        open_gps(get_gps_definition());
                    } else {
                        _MSG_ERROR("(GPS) No usable data from the serial GPS {} in over 30 seconds, disconnecting. "
                                "Check that GPSD is not running (it may have started automatically), that the GPS "
                                "baud rate is correct, and that the GPS outputs standard NMEA.",
                                serial_device);
                    }
                }

                return 1;
                });
}

kis_gps_serial_v3::~kis_gps_serial_v3() {
    close_impl();

    auto timetracker = Globalreg::fetch_global_as<time_tracker>("TIMETRACKER");
    if (timetracker != nullptr) {
        timetracker->remove_timer(error_reconnect_timer);
        timetracker->remove_timer(data_timeout_timer);
    }
}

void kis_gps_serial_v3::close() {
    kis_lock_guard<kis_mutex> lg(gps_mutex);

    auto f =
        boost::asio::post(strand_,
                std::packaged_task<void()>(
                    [self = std::static_pointer_cast<kis_gps_serial_v3>(shared_from_this())]() {
                        self->close_impl();
                    }));

    f.get();
}

void kis_gps_serial_v3::close_impl() {
    stopped = true;
    set_int_device_connected(false);

    if (serialport.is_open()) {
        try {
            serialport.cancel();
            serialport.close();
        } catch (const std::exception& e) {
            // Ignore failures to close the socket, so long as its closed
            ;
        }
    }

    in_buf.consume(in_buf.size());
}

void kis_gps_serial_v3::start_read_impl() {
    if (stopped || !serialport.is_open())
        return;

    boost::asio::async_read_until(serialport, in_buf, '\n',
            boost::asio::bind_executor(strand_, 
                [self = shared_from_this()](const boost::system::error_code& error, std::size_t t) {
                    self->handle_read(error, t);
                }));

}

bool kis_gps_serial_v3::open_gps(std::string in_opts) {
    kis_unique_lock<kis_mutex> lk(gps_mutex, "gps_serial_v3 open_gps");

    if (!kis_gps::open_gps(in_opts))
        return false;

    close_impl();

    std::string proto_device;
    std::string proto_baud_s;
    std::string proto_name;
    unsigned int proto_baud;

    proto_device = fetch_opt("device", source_definition_opts);
    proto_baud_s = fetch_opt("baud", source_definition_opts);
    proto_name = fetch_opt("name", source_definition_opts);

    if (proto_device == "") {
        _MSG("(GPS) Serial GPS expected device= option, none found.", MSGFLAG_ERROR);
        return -1;
    }

    if (proto_baud_s != "") {
        if (sscanf(proto_baud_s.c_str(), "%u", &proto_baud) != 1) {
            _MSG("(GPS) Serial GPS expected baud rate in baud= option, but got something else.", MSGFLAG_ERROR);
            return -1;
        }
    } else {
        proto_baud = 4800;
        _MSG("(GPS) Serial defaulting to 4800 baud for GPS device, specify baud= option "
                "if your device uses a different speed.  Some newer GPS devices use 9600 or "
                "faster, check your GPS documentation.", MSGFLAG_INFO);
    }

    serial_device = proto_device;
    baud = proto_baud;

    try {
        serialport.open(serial_device);

#ifdef __APPLE__
        speed_t speed = static_cast<speed_t>(baud);
        auto fd = serialport.native_handle();
        if (ioctl(fd, IOSSIOSPEED, &speed)) {
            _MSG_ERROR("(GPS) Serial GPS failed to set baudrate on OSX: {}", kis_strerror_r(errno));
            return -1;
        }
#else
        boost::asio::serial_port_base::baud_rate baudrate(proto_baud);

        serialport.set_option(baudrate);
#endif
    } catch (const std::exception& e) {
        _MSG_ERROR("(GPS) Serial GPS could not open and configure {}: {}", serial_device, e.what());
        return -1;
    }

    stopped = false;
    set_int_device_connected(true);

    _MSG_INFO("(GPS) Opened serial port {}@{}", serial_device, baud);

    last_data_time = time(0);

    lk.unlock();

    boost::asio::post(strand_,
            [this]() {
                start_read();
            });

    return 1;
}

bool kis_gps_serial_v3::get_location_valid() {
    kis_lock_guard<kis_mutex> lk(data_mutex, "gps_serial_v3 get_location_valid");

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

bool kis_gps_serial_v3::get_device_connected() {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "gps_serial_v3 get_device_connected");

    return serialport.is_open();
}

