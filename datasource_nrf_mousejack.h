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

class KisDatasourceNrfMousejack;
typedef std::shared_ptr<KisDatasourceNrfMousejack> SharedDatasourceNrfMousejack;

class KisDatasourceNrfMousejack : public KisDatasource {
public:
    KisDatasourceNrfMousejack(SharedDatasourceBuilder in_builder) :
        KisDatasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_nrf_mousejack");

        // Get and register a DLT
        auto dltt = 
            Globalreg::FetchMandatoryGlobalAs<DltTracker>("DLTTRACKER");

        set_int_source_override_linktype(dltt->register_linktype("NRFMOUSEJACK"));
    }

    virtual ~KisDatasourceNrfMousejack() { };
};


class DatasourceNrfMousejackBuilder : public KisDatasourceBuilder {
public:
    DatasourceNrfMousejackBuilder(int in_id) :
        KisDatasourceBuilder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceNrfMousejackBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisDatasourceBuilder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    DatasourceNrfMousejackBuilder() :
        KisDatasourceBuilder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~DatasourceNrfMousejackBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) {
        return SharedDatasourceNrfMousejack(new KisDatasourceNrfMousejack(in_sh_this));
    }

    virtual void initialize() {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("nrfmousejack");
        set_source_description("NordicRF with Bastille Mousejack firmware");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
    }
};

#endif

