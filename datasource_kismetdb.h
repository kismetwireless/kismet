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

#ifndef __DATASOURCE_KISMETDB_H__
#define __DATASOURCE_KISMETDB_H__

#include "config.h"

#include "kis_datasource.h"

class KisDatasourceKismetdb;
typedef std::shared_ptr<KisDatasourceKismetdb> SharedDatasourceKismetdb;

class KisDatasourceKismetdb : public KisDatasource {
public:
    KisDatasourceKismetdb(SharedDatasourceBuilder in_builder) :
        KisDatasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_kismetdb");
    }

    virtual ~KisDatasourceKismetdb() { };

    // Almost all of the logic is implemented in the capture binary and derived
    // from our prototype; all the list, probe, etc functions proxy to our binary
    // and we communicate using only standard Kismet functions so we don't need
    // to do anything else
   
    // Override defaults for kismetdb - we don't want to reload a ksimetdb once
    // it finishes unless we're explicitly told to loop it
    virtual std::string override_default_option(std::string in_opt) {
        if (in_opt == "retry")
            return "false";

        return "";
    }
    
};


class DatasourceKismetdbBuilder : public KisDatasourceBuilder {
public:
    DatasourceKismetdbBuilder() :
        KisDatasourceBuilder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceKismetdbBuilder(int in_id) :
        KisDatasourceBuilder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceKismetdbBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisDatasourceBuilder(in_id, e) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~DatasourceKismetdbBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) {
        return SharedDatasourceKismetdb(new KisDatasourceKismetdb(in_sh_this));
    }

    virtual void initialize() {
        // Set up our basic parameters for the kismetdb driver
        
        set_source_type("kismetdb");
        set_source_description("Kismetdb unified log file");

        // We can probe an 'interface' and see if it's a local kismetdb file
        set_probe_capable(true);

        // We can't list interfaces - trying to list ksimetdb files doesn't make much sense
        set_list_capable(false);

        // We're capable of opening a source
        set_local_capable(true);

        // We can do remote kismetdb for testing
        set_remote_capable(true);

        // We don't accept packets over HTTP passively, though I guess we could
        set_passive_capable(false);

        // Can't change channel on a kismetdb
        set_tune_capable(false);
    }

};

#endif

