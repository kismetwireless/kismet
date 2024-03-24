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

#ifndef __DATASOURCE_ADSBPROXY_H__
#define __DATASOURCE_ADSBPROXY_H__

#include "config.h"

#include "kis_datasource.h"
#include "datasource_virtual.h"

class kis_datasource_adsbproxy;
typedef std::shared_ptr<kis_datasource_adsbproxy> shared_datasource_adsbproxy;

class kis_datasource_adsbproxy : public kis_datasource {
public:
    kis_datasource_adsbproxy(shared_datasource_builder in_builder) :
		kis_datasource(in_builder) {
        set_int_source_hardware("adsbproxy");
        set_int_source_ipc_binary("kismet_cap_proxy_adsb");
        suppress_gps = true;
    }

    virtual ~kis_datasource_adsbproxy() { }

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override {
        kis_datasource::open_interface(in_definition, in_transaction, in_cb);
    }

};

class datasource_adsbproxy_builder : public kis_datasource_builder {
public:
    datasource_adsbproxy_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_adsbproxy_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_adsbproxy_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_adsbproxy_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_adsbproxy(new kis_datasource_adsbproxy(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("adsbproxy");
        set_source_description("adsb stream proxy");

        set_probe_capable(false);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(false);
        set_hop_capable(false);
    }
};

#endif


