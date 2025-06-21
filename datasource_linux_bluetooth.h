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

class kis_datasource_linux_bluetooth;
typedef std::shared_ptr<kis_datasource_linux_bluetooth> shared_datasource_linux_bluetooth;

class kis_datasource_linux_bluetooth : public kis_datasource {
public:
    kis_datasource_linux_bluetooth(shared_datasource_builder in_builder);
    virtual ~kis_datasource_linux_bluetooth() { };

    protected:
#ifdef HAVE_PROTOBUF_CPP
    // legacy protobuf code
    virtual bool dispatch_rx_packet(const nonstd::string_view& command,
            uint32_t seqno, const nonstd::string_view& content) override;
    virtual void handle_packet_linuxbtdevice(uint32_t in_seqno,
            const nonstd::string_view& in_content);
#endif

    int pack_comp_btdevice, pack_comp_meta;
};

class datasource_linux_bluetooth_builder : public kis_datasource_builder {
public:
    datasource_linux_bluetooth_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_linux_bluetooth_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_linux_bluetooth_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_linux_bluetooth_builder() override { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return std::make_shared<kis_datasource_linux_bluetooth>(in_sh_this);
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

        set_hop_capable(false);
    }

};

#endif

