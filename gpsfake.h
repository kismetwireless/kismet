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

#ifndef __GPSFAKE_V2_H__
#define __GPSFAKE_V2_H__

#include "config.h"

#include "kis_gps.h"
#include "timetracker.h"
#include "globalregistry.h"

// New fake GPS
//
// Always sets a fixed location and optional altitude.

class GPSFake : public KisGps {
public:
    GPSFake(SharedGpsBuilder in_builder);
    virtual ~GPSFake();

    virtual bool open_gps(std::string in_opts);

    virtual bool get_location_valid() { return true; };
    virtual bool get_device_connected() { return true; };

    virtual kis_gps_packinfo *get_location();
    virtual kis_gps_packinfo *get_last_location();
};

class GPSFakeBuilder : public KisGpsBuilder {
public:
    GPSFakeBuilder() : 
        KisGpsBuilder() { 
        initialize();
    }

    virtual void initialize() {
        set_int_gps_class("virtual");
        set_int_gps_class_description("Virtual fixed-location GPS");
        set_int_gps_priority(0);
        set_int_default_name("virtual");
        set_int_singleton(true);
    }

    virtual SharedGps build_gps(SharedGpsBuilder in_builder) {
        return SharedGps(new GPSFake(in_builder));
    }
};

#endif

