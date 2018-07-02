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

#define HAVE_LINUX_BLUETOOTH_DATASOURCE

#include "kis_datasource.h"

class KisDatasourceLinuxBluetooth;
typedef std::shared_ptr<KisDatasourceLinuxBluetooth> SharedDatasourceLinuxBluetooth;

class KisDatasourceLinuxBluetooth : public KisDatasource {
public:
    KisDatasourceLinuxBluetooth(SharedDatasourceBuilder in_builder);

    virtual ~KisDatasourceLinuxBluetooth() { };

protected:
    virtual bool dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c);
  
    virtual void handle_packet_linuxbtdevice(uint32_t in_seqno, std::string in_content);

    int pack_comp_btdevice;
};


class DatasourceLinuxBluetoothBuilder : public KisDatasourceBuilder {
public:
    DatasourceLinuxBluetoothBuilder() :
        KisDatasourceBuilder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceLinuxBluetoothBuilder(int in_id) :
        KisDatasourceBuilder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceLinuxBluetoothBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisDatasourceBuilder(in_id, e) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~DatasourceLinuxBluetoothBuilder() override { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) override {
        return std::make_shared<KisDatasourceLinuxBluetooth>(in_sh_this);
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("linuxbluetooth");
        set_source_description("Capture from Linux Bluetooth devices using the Linux "
                "kernel drivers and Blue-Z");

#ifdef SYS_LINUX
        // We can probe an interface
        set_probe_capable(true);

        // We can list interfaces
        set_list_capable(true);

        // We're capable of opening a source
        set_local_capable(true);
#else
        // Not local capable on non-linux systems
        set_probe_capable(false);
        set_list_capable(false);
        set_local_capable(false);

#endif

        // We can do remote
        set_remote_capable(true);

        // We don't do passive packets over http
        set_passive_capable(false);

        // Can't tune a BT
        set_tune_capable(false);
    }

};

#endif

