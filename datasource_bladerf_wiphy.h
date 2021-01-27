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

#ifndef __DATASOURCE_BLADERF_WIPHY_H__
#define __DATASOURCE_BLADERF_WIPHY_H__

#include "config.h"

#define HAVE_BLADERF_WIPHY_DATASOURCE

#include "kis_datasource.h"

class kis_datasource_bladerf_wiphy;
typedef std::shared_ptr<kis_datasource_bladerf_wiphy> shared_datasource_bladerf_wiphy;

class kis_datasource_bladerf_wiphy : public kis_datasource {
public:
    kis_datasource_bladerf_wiphy(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_bladerf_wiphy");
    }

    virtual ~kis_datasource_bladerf_wiphy() { };
};


class datasource_bladerf_wiphy_builder : public kis_datasource_builder {
public:
    datasource_bladerf_wiphy_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_bladerf_wiphy_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_bladerf_wiphy_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_bladerf_wiphy_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_bladerf_wiphy(new kis_datasource_bladerf_wiphy(in_sh_this));
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("bladerf-wiphy");
        set_source_description("Capture from bladeRF2 devices with Wiphy firmware");

        // We can probe an interface
        set_probe_capable(true);

        // We can list interfaces
        set_list_capable(true);

        // We're capable of opening a source
        set_local_capable(true);

        // We can do remote
        set_remote_capable(true);

        // We don't do passive packets over http
        set_passive_capable(false);

        // We allow tuning, sure
        set_tune_capable(true);

        set_hop_capable(true);
    }
};

#endif

