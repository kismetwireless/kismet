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

#ifndef __DATASOURCE_TI_CC2540_H__
#define __DATASOURCE_TI_CC2540_H__

#include "config.h"

#define HAVE_TI_CC2540_DATASOURCE

#include "kis_datasource.h"
#include "dlttracker.h"

class kis_datasource_ticc2540;
typedef std::shared_ptr<kis_datasource_ticc2540> shared_datasource_ticc2540;

#ifndef KDLT_BLUETOOTH_LE_LL
#define KDLT_BLUETOOTH_LE_LL        251
#endif

#ifndef KDLT_BTLE_RADIO
#define KDLT_BTLE_RADIO             256
#endif

class kis_datasource_ticc2540 : public kis_datasource {
public:
    kis_datasource_ticc2540(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_ti_cc_2540");

        // We synthesize BTLE_LL_RADIO headers
        set_int_source_dlt(KDLT_BTLE_RADIO);

        pack_comp_decap =
            packetchain->register_packet_component("DECAP");
        pack_comp_radiodata =
            packetchain->register_packet_component("RADIODATA");
    }

    virtual ~kis_datasource_ticc2540() { };

protected:
    virtual int handle_rx_data_content(kis_packet *packet, kis_datachunk *datachunk,
            const uint8_t *content, size_t content_sz) override;

    int pack_comp_decap, pack_comp_radiodata;
};


class datasource_ticc2540_builder : public kis_datasource_builder {
public:
    datasource_ticc2540_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_ticc2540_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_ticc2540_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_ticc2540_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_ticc2540(new kis_datasource_ticc2540(in_sh_this));
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver

        set_source_type("ticc2540");
        set_source_description("TI CC2540 with sniffer firmware");

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

