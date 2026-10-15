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

#ifndef __DATASOURCE_MM8108_H__
#define __DATASOURCE_MM8108_H__

#include "config.h"

#include "kis_datasource.h"

// Morse Micro MM8108 USB 802.11ah (Wi-Fi HaLow) adapters, driven in userspace by
// kismet_cap_mm8108_halow.  Interfaces are named mm8108-0, mm8108-1, ... and channels are
// 802.11ah channel numbers such as 27ah.

class kis_datasource_mm8108;
typedef std::shared_ptr<kis_datasource_mm8108> shared_datasource_mm8108;

class kis_datasource_mm8108 : public kis_datasource {
public:
    kis_datasource_mm8108(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {
        set_int_source_ipc_binary("kismet_cap_mm8108_halow");
    }

    virtual ~kis_datasource_mm8108() { }
};

class datasource_mm8108_builder : public kis_datasource_builder {
public:
    datasource_mm8108_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(nullptr);
        initialize();
    }

    datasource_mm8108_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_mm8108_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(nullptr);
        initialize();
    }

    virtual ~datasource_mm8108_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_mm8108(new kis_datasource_mm8108(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("mm8108");
        set_source_description("Morse Micro MM8108 USB 802.11ah (Wi-Fi HaLow) adapters, using a "
                "userspace driver via libusb");

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
