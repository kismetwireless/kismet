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

#ifndef __GPSNMEA_H__
#define __GPSNMEA_H__

#include "config.h"

#include "kis_gps.h"
#include "timetracker.h"
#include "buffer_handler.h"
#include "ringbuf2.h"
#include "globalregistry.h"
#include "serialclient2.h"
#include "pollabletracker.h"

// Generic NMEA parser for GPS

class GPSNMEA : public KisGps {
public:
    GPSNMEA(SharedGpsBuilder in_builder) :
        KisGps(in_builder),
        nmeahandler {nullptr},
        nmeainterface {nullptr, nullptr} { }

    virtual ~GPSNMEA() { };

protected:
    std::shared_ptr<BufferHandler<RingbufV2>> nmeahandler;
    BufferInterfaceFunc nmeainterface;

    // BufferInterface API
    virtual void BufferAvailable(size_t in_amt);
    virtual void BufferError(std::string in_err) = 0;

    // Have we ever seen data from the device?
    bool ever_seen_gps;

    // Last time we calculated the heading, don't do it more than once every 
    // few seconds or we get nasty noise
    time_t last_heading_time;
};

#endif

