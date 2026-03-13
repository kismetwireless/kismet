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

#ifndef __DATASOURCE_WCH_BLE_ANALYZER_PRO_H__
#define __DATASOURCE_WCH_BLE_ANALYZER_PRO_H__

#include "config.h"

#define HAVE_WCH_BLE_ANALYZER_PRO_DATASOURCE

#include "kis_datasource.h"
#include "dlttracker.h"

class kis_datasource_wch_ble_pro;
typedef std::shared_ptr<kis_datasource_wch_ble_pro> shared_datasource_wch_ble_pro;

class kis_datasource_wch_ble_pro : public kis_datasource {
public:
    kis_datasource_wch_ble_pro(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        set_int_source_ipc_binary("kismet_cap_wch_ble_analyzer_pro");
    }

    virtual ~kis_datasource_wch_ble_pro() { };

};


class datasource_wch_ble_pro_builder : public kis_datasource_builder {
public:
    datasource_wch_ble_pro_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_wch_ble_pro_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_wch_ble_pro_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_wch_ble_pro_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_wch_ble_pro(new kis_datasource_wch_ble_pro(in_sh_this));
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver

        set_source_type("wch-ble-pro");
        set_source_description("WCH BLE Analyzer Pro");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
        set_hop_capable(false);
    }
};

#endif

