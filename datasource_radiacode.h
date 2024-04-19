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

#ifndef __DATASOURCE_RADIACODE_H__
#define __DATASOURCE_RADIACODE_H__

#include "config.h"

#include "kis_datasource.h"

class kis_datasource_radiacode_usb : public kis_datasource {
public:
    kis_datasource_radiacode_usb(shared_datasource_builder in_builder) :
		kis_datasource(in_builder) {
		set_int_source_cap_interface("radiacode-usb");
        set_int_source_hardware("radiacode-usb");
        set_int_source_ipc_binary("kismet_cap_radiacode_usb");
    }

    virtual ~kis_datasource_radiacode_usb() { }

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override {
        kis_datasource::open_interface(in_definition, in_transaction, in_cb);
    }
};

class datasource_radiacode_usb_builder : public kis_datasource_builder {
public:
    datasource_radiacode_usb_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_radiacode_usb_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_radiacode_usb_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_radiacode_usb_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
		return std::make_shared<kis_datasource_radiacode_usb>(in_sh_this);
    }

    virtual void initialize() override {
        set_source_type("radiacode-usb");
        set_source_description("Radiacode geiger counter");

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


