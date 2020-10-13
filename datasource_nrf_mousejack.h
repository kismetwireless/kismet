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

#ifndef __DATASOURCE_NRF_MOUSEJACK_H__
#define __DATASOURCE_NRF_MOUSEJACK_H__

#include "config.h"

#define HAVE_NRF_MOUSEJACK_DATASOURCE

#include "kis_datasource.h"
#include "dlttracker.h"

class kis_datasource_nrf_mousejack;
typedef std::shared_ptr<kis_datasource_nrf_mousejack> shared_datasource_nrf_mousejack;

class kis_datasource_nrf_mousejack : public kis_datasource {
public:
    kis_datasource_nrf_mousejack(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_nrf_mousejack");

        // Get and register a DLT
        auto dltt = 
            Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");

        set_int_source_override_linktype(dltt->register_linktype("NRFMOUSEJACK"));
    }

    virtual ~kis_datasource_nrf_mousejack() { };
};


class datasource_nrf_mousejack_builder : public kis_datasource_builder {
public:
    datasource_nrf_mousejack_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_nrf_mousejack_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_nrf_mousejack_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_nrf_mousejack_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_nrf_mousejack(new kis_datasource_nrf_mousejack(in_sh_this));
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("nrfmousejack");
        set_source_description("NordicRF with Bastille Mousejack firmware");

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

