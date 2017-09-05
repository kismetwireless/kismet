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

#ifndef __DATASOURCE_LINUXBLUETOOTH_H__
#define __DATASOURCE_LINUXBLUETOOTH_H__

#include "config.h"

#if defined HAVE_DBUSGLIB && HAVE_GLIB2

#define HAVE_LINUX_BLUETOOTH_DATASOURCE

#include "kis_datasource.h"

class KisDatasourceLinuxBluetooth;
typedef shared_ptr<KisDatasourceLinuxBluetooth> SharedDatasourceLinuxBluetooth;

class KisDatasourceLinuxBluetooth : public KisDatasource {
public:
    KisDatasourceLinuxBluetooth(GlobalRegistry *in_globalreg, 
            SharedDatasourceBuilder in_builder) :
        KisDatasource(in_globalreg, in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_linux_bluetooth");
    }

    virtual ~KisDatasourceLinuxBluetooth() { };

protected:
    virtual void proto_dispatch_packet(string in_type, KVmap in_kvmap);
    
};


class DatasourceLinuxBluetoothBuilder : public KisDatasourceBuilder {
public:
    DatasourceLinuxBluetoothBuilder(GlobalRegistry *in_globalreg, int in_id) :
        KisDatasourceBuilder(in_globalreg, in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceLinuxBluetoothBuilder(GlobalRegistry *in_globalreg, int in_id,
        SharedTrackerElement e) :
        KisDatasourceBuilder(in_globalreg, in_id, e) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceLinuxBluetoothBuilder(GlobalRegistry *in_globalreg) :
        KisDatasourceBuilder(in_globalreg, 0) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~DatasourceLinuxBluetoothBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) {
        return SharedDatasourceLinuxBluetooth(new KisDatasourceLinuxBluetooth(globalreg, 
                    in_sh_this));
    }

    virtual void initialize() {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("linuxbluetooth");
        set_source_description("Capture from Linux Bluetooth devices using the Linux "
                "kernel drivers and Blue-Z");

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

        // Can't tune a BT
        set_tune_capable(false);
    }

};

#endif

#endif

