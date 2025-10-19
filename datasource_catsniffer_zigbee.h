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
    virtual int handle_rx_data_content(kis_packet *packet, kis_datachunk *datachunk,
            const uint8_t *content, size_t content_sz) override;

    int pack_comp_decap, pack_comp_radiodata;
};


class datasource_catsniffer_zigbee_builder : public kis_datasource_builder {
public:
    datasource_catsniffer_zigbee_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_catsniffer_zigbee_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_catsniffer_zigbee_builder() :
        kis_datasource_builder(0) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_catsniffer_zigbee_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_catsniffer_zigbee(new kis_datasource_catsniffer_zigbee(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("catsniffer_zigbee");
        set_source_description("CatSniffer V3 with sniffer_fw_cc1252P_7 firmware");
        set_probe_capable(true);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
        set_hop_capable(true);
    }
};

#endif

