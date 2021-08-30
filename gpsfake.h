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

class kis_gps_fake : public kis_gps {
public:
    kis_gps_fake(shared_gps_builder in_builder);
    virtual ~kis_gps_fake();

    virtual bool open_gps(std::string in_opts) override;

    virtual bool get_location_valid() override  { return true; };
    virtual bool get_device_connected() override { return true; };

    virtual std::shared_ptr<kis_gps_packinfo> get_location() override;
};

class gps_fake_builder : public kis_gps_builder {
public:
    gps_fake_builder() : 
        kis_gps_builder() { 
        initialize();
    }

    virtual void initialize() {
        set_int_gps_class("virtual");
        set_int_gps_class_description("Virtual fixed-location GPS");
        set_int_gps_priority(0);
        set_int_default_name("virtual");
        set_int_singleton(true);
    }

    virtual shared_gps build_gps(shared_gps_builder in_builder) {
        return shared_gps(new kis_gps_fake(in_builder));
    }
};

#endif

