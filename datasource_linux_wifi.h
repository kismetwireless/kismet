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

#ifndef __DATASOURCE_LINUXWIFI_H__
#define __DATASOURCE_LINUXWIFI_H__

#include "config.h"

#define HAVE_LINUX_WIFI_DATASOURCE

#include "kis_datasource.h"

class KisDatasourceLinuxWifi;
typedef std::shared_ptr<KisDatasourceLinuxWifi> SharedDatasourceLinuxWifi;

class KisDatasourceLinuxWifi : public KisDatasource {
public:
    KisDatasourceLinuxWifi(SharedDatasourceBuilder in_builder) :
        KisDatasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_linux_wifi");
    }

    virtual ~KisDatasourceLinuxWifi() { };

    // Almost all of the logic is implemented in the capture binary and derived
    // from our prototype; all the list, probe, etc functions proxy to our binary
    // and we communicate using only standard Kismet functions so we don't need
    // to do anything else
    
};


class DatasourceLinuxWifiBuilder : public KisDatasourceBuilder {
public:
    DatasourceLinuxWifiBuilder(int in_id) :
        KisDatasourceBuilder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceLinuxWifiBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisDatasourceBuilder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    DatasourceLinuxWifiBuilder() :
        KisDatasourceBuilder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~DatasourceLinuxWifiBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) {
        return SharedDatasourceLinuxWifi(new KisDatasourceLinuxWifi(in_sh_this));
    }

    virtual void initialize() {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("linuxwifi");
        set_source_description("Capture from Linux Wi-Fi devices using (old) wireless "
                "extensions or (new) mac80211 controls");

#ifdef SYS_LINUX
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

        // We can do remote
        set_remote_capable(true);

        // We don't do passive packets over http
        set_passive_capable(false);

        // We allow tuning, sure
        set_tune_capable(true);
    }
};

#endif

