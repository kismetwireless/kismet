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

#ifndef __DATASOURCE_OSX_COREWLAN_WIFI_H__
#define __DATASOURCE_OSX_COREWLAN_WIFI_H__

#include "config.h"

#define HAVE_OSX_COREWLAN_WIFI_DATASOURCE

#include "kis_datasource.h"

class kis_datasource_osx_corewlan_wifi;
typedef std::shared_ptr<kis_datasource_osx_corewlan_wifi> shared_datasource_osx_corewlan_wifi;

class kis_datasource_osx_corewlan_wifi : public kis_datasource {
public:
    kis_datasource_osx_corewlan_wifi(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_osx_corewlan_wifi");
    }

    virtual ~kis_datasource_osx_corewlan_wifi() { };

    // Almost all of the logic is implemented in the capture binary and derived
    // from our prototype; all the list, probe, etc functions proxy to our binary
    // and we communicate using only standard Kismet functions so we don't need
    // to do anything else
    
};


class datasource_osx_corewlan_wifi_builder : public kis_datasource_builder {
public:
    datasource_osx_corewlan_wifi_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_osx_corewlan_wifi_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_osx_corewlan_wifi_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_osx_corewlan_wifi_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_osx_corewlan_wifi(new kis_datasource_osx_corewlan_wifi(in_sh_this));
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("osxcorewlanwifi");
        set_source_description("Capture from OSX Wi-Fi devices using the CoreWLAN framework "
                "(internal Apple Wi-Fi devices)");

#ifdef SYS_DARWIN
        // We can probe an interface
        set_probe_capable(true);

        // We can list interfaces
        set_list_capable(true);

        // We're capable of opening a source
        set_local_capable(true);
#else
        // Only remote on other platforms
        set_probe_capable(false);
        set_list_capable(false);
        set_local_capable(false);
#endif

        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
        set_hop_capable(true);
    }
};

#endif

