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

#ifndef __DATASOURCE_PCAPFILE_H__
#define __DATASOURCE_PCAPFILE_H__

#include "config.h"

#include "kis_datasource.h"

class KisDatasourcePcapfile;
typedef shared_ptr<KisDatasourcePcapfile> SharedDatasourcePcapfile;

class KisDatasourcePcapfile : public KisDatasource {
public:
    KisDatasourcePcapfile(GlobalRegistry *in_globalreg, 
            SharedDatasourceBuilder in_builder) :
        KisDatasource(in_globalreg, in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_pcapfile");
    }

    virtual ~KisDatasourcePcapfile() { };

    // Almost all of the logic is implemented in the capture binary and derived
    // from our prototype; all the list, probe, etc functions proxy to our binary
    // and we communicate using only standard Kismet functions so we don't need
    // to do anything else
    
};


class DatasourcePcapfileBuilder : public KisDatasourceBuilder {
public:
    DatasourcePcapfileBuilder(GlobalRegistry *in_globalreg, int in_id) :
        KisDatasourceBuilder(in_globalreg, in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourcePcapfileBuilder(GlobalRegistry *in_globalreg, int in_id,
        SharedTrackerElement e) :
        KisDatasourceBuilder(in_globalreg, in_id, e) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourcePcapfileBuilder(GlobalRegistry *in_globalreg) :
        KisDatasourceBuilder(in_globalreg, 0) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~DatasourcePcapfileBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) {
        return SharedDatasourcePcapfile(new KisDatasourcePcapfile(globalreg, 
                    in_sh_this));
    }

    virtual void initialize() {
        // Set up our basic parameters for the pcapfile driver
        
        set_source_type("pcapfile");
        set_source_description("Pre-recorded pcap or pcapng file");

        // We can probe an 'interface' and see if it's a local pcap file
        set_probe_capable(true);

        // We can't list interfaces - trying to list pcap files doesn't make much sense
        set_list_capable(false);

        // We're capable of opening a source
        set_local_capable(true);

        // We can't do remote pcapfile
        set_remote_capable(false);

        // We don't accept packets over HTTP passively, though I guess we could
        set_passive_capable(false);

        // Can't change channel on a pcapfile
        set_tune_capable(false);
    }

};

#endif

