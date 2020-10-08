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

#ifndef __GPSWEB_H__
#define __GPSWEB_H__

#include "config.h"

#include "kis_gps.h"
#include "timetracker.h"
#include "globalregistry.h"
#include "kis_net_beast_httpd.h"

// GPS WEB
//
// Accept GPS location from HTTP POST, allows using a phone browser as a
// GPS source

class kis_gps_web : public kis_gps {
public:
    kis_gps_web(shared_gps_builder in_builder);
    virtual ~kis_gps_web();

    virtual bool open_gps(std::string in_opts);

    virtual bool get_location_valid();
    virtual bool get_device_connected();

protected:
    // Last time we calculated the heading, don't do it more than once every 
    // few seconds or we get nasty noise
    time_t last_heading_time;
};

class gps_web_builder : public kis_gps_builder {
public:
    gps_web_builder() : 
        kis_gps_builder() { 
        initialize();
    }

    virtual void initialize() override {
        set_int_gps_class("web");
        set_int_gps_class_description("Web-based GPS using client browser");
        set_int_gps_priority(0);
        set_int_default_name("web");
        set_int_singleton(true);
    }

    virtual shared_gps build_gps(shared_gps_builder in_builder) override {
        return shared_gps(new kis_gps_web(in_builder));
    }
};

#endif

