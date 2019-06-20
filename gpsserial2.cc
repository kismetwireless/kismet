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

#include "gpsserial2.h"
#include "util.h"
#include "gpstracker.h"
#include "pollabletracker.h"

GPSSerialV2::GPSSerialV2(SharedGpsBuilder in_builder) : 
    GPSNMEA(in_builder) {

    // Defer making buffers until open, because we might be used to make a 
    // builder instance

    ever_seen_gps = false;
    last_heading_time = time(0);

    nmeainterface = BufferInterfaceFunc(
            [this](size_t in_avail) {
                BufferAvailable(in_avail);
            },
            [this](std::string in_err) {
                BufferError(in_err);
            });

    pollabletracker =
        Globalreg::FetchMandatoryGlobalAs<PollableTracker>("POLLABLETRACKER");

    auto timetracker = 
        Globalreg::FetchMandatoryGlobalAs<Timetracker>("TIMETRACKER");

    error_reconnect_timer = 
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
                [this](int) -> int {
                    if (get_device_connected()) 
                        return 1;

                    open_gps(get_gps_definition());

                    return 1;
                });
}

GPSSerialV2::~GPSSerialV2() {
    if (serialclient != nullptr) {
        pollabletracker->RemovePollable(serialclient);
    }

    if (nmeahandler != nullptr) {
        nmeahandler->RemoveReadBufferInterface();
    }

    auto timetracker = Globalreg::FetchGlobalAs<Timetracker>();
    if (timetracker != nullptr)
        timetracker->RemoveTimer(error_reconnect_timer);
}

bool GPSSerialV2::open_gps(std::string in_opts) {
    local_locker lock(gps_mutex);

    if (!KisGps::open_gps(in_opts))
        return false;

    set_int_device_connected(false);

    if (serialclient != nullptr) {
        serialclient->Close();
    }

    if (nmeahandler != nullptr) {
        nmeahandler->ClearReadBuffer();
        nmeahandler->ClearWriteBuffer();
    }

    std::string proto_device;
    std::string proto_baud_s;
    std::string proto_name;
    unsigned int proto_baud;

    proto_device = FetchOpt("device", source_definition_opts);
    proto_baud_s = FetchOpt("baud", source_definition_opts);
    proto_name = FetchOpt("name", source_definition_opts);

    if (proto_device == "") {
        _MSG("GPSSerial expected device= option, none found.", MSGFLAG_ERROR);
        return -1;
    }

    if (proto_baud_s != "") {
        if (sscanf(proto_baud_s.c_str(), "%u", &proto_baud) != 1) {
            _MSG("GPSSerial expected baud rate in baud= option.", MSGFLAG_ERROR);
            return -1;
        }
    } else {
        proto_baud = 4800;
        _MSG("GPSSerial defaulting to 4800 baud for GPS device, specify baud= option "
                "if your device uses a different speed.", MSGFLAG_INFO);
    }

    // Initial setup as needed
    if (nmeahandler == nullptr) {
        // We never write to a serial gps so don't make a write buffer
        nmeahandler = std::make_shared<BufferHandler<RingbufV2>>(2048, 0);
        nmeahandler->SetMutex(gps_mutex);
        nmeahandler->SetReadBufferInterface(&nmeainterface);
    }

    if (serialclient == nullptr) {
        // Link it to a serial port
        serialclient = std::make_shared<SerialClientV2>(Globalreg::globalreg, nmeahandler);
        serialclient->SetMutex(gps_mutex);
        pollabletracker->RegisterPollable(serialclient);
    }

    serial_device = proto_device;
    baud = proto_baud;

    serialclient->OpenDevice(proto_device, proto_baud);
    set_int_device_connected(true);

    return 1;
}

bool GPSSerialV2::get_location_valid() {
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

bool GPSSerialV2::get_device_connected() {
    local_shared_locker lock(gps_mutex);

    if (serialclient == NULL)
        return false;

    return serialclient->FetchConnected();
}

void GPSSerialV2::BufferError(std::string in_error) {
    local_locker lock(gps_mutex);

    _MSG("GPS device '" + get_gps_name() + "' encountered a serial error: " + in_error,
            MSGFLAG_ERROR);

    set_int_device_connected(false);
}

