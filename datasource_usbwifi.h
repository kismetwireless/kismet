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

#ifndef __DATASOURCE_USBWIFI_H__
#define __DATASOURCE_USBWIFI_H__

#include "config.h"

#include "kis_datasource.h"

// USB Wi-Fi adapters driven by Linux drivers running in userspace on libusb.  All of the
// device handling is in kismet_cap_usbwifi; interfaces are named by driver and index,
// such as mt7921-0, and channels use the standard Kismet Wi-Fi channel names.

class kis_datasource_usbwifi;
typedef std::shared_ptr<kis_datasource_usbwifi> shared_datasource_usbwifi;

class kis_datasource_usbwifi : public kis_datasource {
public:
    kis_datasource_usbwifi(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {
        set_int_source_ipc_binary("kismet_cap_usbwifi");
    }

    virtual ~kis_datasource_usbwifi() { }
};

class datasource_usbwifi_builder : public kis_datasource_builder {
public:
    datasource_usbwifi_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(nullptr);
        initialize();
    }

    datasource_usbwifi_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_usbwifi_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(nullptr);
        initialize();
    }

    virtual ~datasource_usbwifi_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_usbwifi(new kis_datasource_usbwifi(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("usbwifi");
        set_source_description("Capture from USB Wi-Fi adapters using Linux drivers in userspace "
                "via libusb");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
        set_hop_capable(true);
    }
};

#endif
