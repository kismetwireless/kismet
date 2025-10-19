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

#ifndef __DATASOURCE_CATSNIFFER_ZIGBEE_H__
#define __DATASOURCE_CATSNIFFER_ZIGBEE_H__

#include "config.h"

#define HAVE_CATSNIFFER_ZIGBEE_DATASOURCE

#include "kis_datasource.h"
#include "dlttracker.h"
#include "tap_802_15_4.h"

class kis_datasource_catsniffer_zigbee;
typedef std::shared_ptr<kis_datasource_catsniffer_zigbee> shared_datasource_catsniffer_zigbee;

#ifndef KDLT_IEEE802_15_4_TAP
#define KDLT_IEEE802_15_4_TAP             283 
#endif

#ifndef KDLT_IEEE802_15_4_NOFCS
#define KDLT_IEEE802_15_4_NOFCS           230
#endif

class kis_datasource_catsniffer_zigbee : public kis_datasource {
public:
    kis_datasource_catsniffer_zigbee(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_catsniffer_zigbee");

        //set_int_source_dlt(KDLT_IEEE802_15_4_NOFCS);
        set_int_source_dlt(KDLT_IEEE802_15_4_TAP);

        pack_comp_decap = packetchain->register_packet_component("DECAP");
        pack_comp_radiodata = packetchain->register_packet_component("RADIODATA");

    };

    virtual ~kis_datasource_catsniffer_zigbee() { };

protected:
    virtual void handle_rx_datalayer(std::shared_ptr<kis_packet> packet, 
            const KismetDatasource::SubPacket& report) override;

    int pack_comp_decap, pack_comp_radiodata;
};


class datasource_catsniffer_zigbee_builder : public kis_datasource_builder {
public:
    datasource_catsniffer_zigbee_builder(int in_id) :
        kis_datasource_builder(in_id) {

        // Debugging: Indicate that the constructor with 'in_id' is being called
        fprintf(stderr, "Debug: datasource_catsniffer_zigbee_builder constructor with ID: %d called\n", in_id);

        register_fields();
        fprintf(stderr, "Debug: Fields registered in constructor with ID: %d\n", in_id);

        reserve_fields(NULL);
        fprintf(stderr, "Debug: Fields reserved (NULL) in constructor with ID: %d\n", in_id);

        initialize();
        fprintf(stderr, "Debug: Initialization completed in constructor with ID: %d\n", in_id);
    }

    datasource_catsniffer_zigbee_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        // Debugging: Indicate that the constructor with 'in_id' and tracker_element_map is being called
        fprintf(stderr, "Debug: datasource_catsniffer_zigbee_builder constructor with ID: %d and tracker_element_map called\n", in_id);

        register_fields();
        fprintf(stderr, "Debug: Fields registered in constructor with ID: %d\n", in_id);

        reserve_fields(e);
        fprintf(stderr, "Debug: Fields reserved with tracker_element_map in constructor with ID: %d\n", in_id);

        initialize();
        fprintf(stderr, "Debug: Initialization completed in constructor with ID: %d\n", in_id);
    }

    datasource_catsniffer_zigbee_builder() :
        kis_datasource_builder(0) {

        // Debugging: Indicate that the default constructor is being called
        fprintf(stderr, "Debug: Default datasource_catsniffer_zigbee_builder constructor called\n");

        register_fields();
        fprintf(stderr, "Debug: Fields registered in default constructor\n");

        reserve_fields(NULL);
        fprintf(stderr, "Debug: Fields reserved (NULL) in default constructor\n");

        initialize();
        fprintf(stderr, "Debug: Initialization completed in default constructor\n");
    }

    virtual ~datasource_catsniffer_zigbee_builder() { 
        // Debugging: Indicate that the destructor is being called
        fprintf(stderr, "Debug: datasource_catsniffer_zigbee_builder destructor called\n");
    }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        // Debugging: Log when the datasource is being built
        fprintf(stderr, "Debug: Building datasource for catsniffer_zigbee\n");

        return shared_datasource_catsniffer_zigbee(new kis_datasource_catsniffer_zigbee(in_sh_this));
    }

    virtual void initialize() override {
        // Debugging: Log when initialization functions are called
        fprintf(stderr, "Debug: Initializing datasource_catsniffer_zigbee_builder\n");

        set_source_type("catsniffer_zigbee");
        fprintf(stderr, "Debug: Source type set to catsniffer_zigbee\n");

        set_source_description("CatSniffer V3 with sniffer_fw_cc1252P_7 firmware");
        fprintf(stderr, "Debug: Source description set\n");

        set_probe_capable(true);
        fprintf(stderr, "Debug: Probe capability set to true\n");

        set_list_capable(false);
        fprintf(stderr, "Debug: List capability set to true\n");

        set_local_capable(true);
        fprintf(stderr, "Debug: Local capability set to true\n");

        set_remote_capable(true);
        fprintf(stderr, "Debug: Remote capability set to true\n");

        set_passive_capable(false);
        fprintf(stderr, "Debug: Passive capability set to false\n");

        set_tune_capable(true);
        fprintf(stderr, "Debug: Tune capability set to true\n");

        set_hop_capable(true);
        fprintf(stderr, "Debug: Hop capability set to true\n");
    }
};

#endif

