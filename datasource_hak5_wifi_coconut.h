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

#ifndef __DATASOURCE_HAK5_WIFI_COCONUT_H__
#define __DATASOURCE_HAK5_WIFI_COCONUT_H__

#include "config.h"

#define HAVE_HAK5_WIFI_COCONUT_DATASOURCE

#include "kis_datasource.h"

class kis_datasource_hak5_wifi_coconut;
typedef std::shared_ptr<kis_datasource_hak5_wifi_coconut> shared_datasource_hak5_wifi_coconut;

class kis_datasource_hak5_wifi_coconut : public kis_datasource {
public:
    kis_datasource_hak5_wifi_coconut(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_hak5_wifi_coconut");
    }

    virtual ~kis_datasource_hak5_wifi_coconut() { };

    // Almost all of the logic is implemented in the capture binary and derived
    // from our prototype; all the list, probe, etc functions proxy to our binary
    // and we communicate using only standard Kismet functions so we don't need
    // to do anything else
    
};


class datasource_hak5_wifi_coconut_builder : public kis_datasource_builder {
public:
    datasource_hak5_wifi_coconut_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_hak5_wifi_coconut_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_hak5_wifi_coconut_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_hak5_wifi_coconut_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_hak5_wifi_coconut(new kis_datasource_hak5_wifi_coconut(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("hak5wificoconut");
        set_source_description("Capture from the Hak5 WiFi Coconut radio cluster via "
				"userspace libusb drivers");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(false);
        set_hop_capable(false);
    }
};

#endif

