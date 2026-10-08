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

#ifndef __DATASOURCE_LORAPIPE_H__
#define __DATASOURCE_LORAPIPE_H__

#include "config.h"

#define HAVE_LORAPIPE_DATASOURCE

#include "kis_datasource.h"
#include "dlttracker.h"

#include "kis_dlt_loratap.h"
#include "util.h"

class kis_datasource_lorapipe;
typedef std::shared_ptr<kis_datasource_lorapipe> shared_datasource_lorapipe;

// bridges a kismet capture based around the lorapipe firmware from
// https://github.com/krak3n77/lorapipe/tree/main with some extra fields
// prepended to the lorapipe fw output
//
// channel format is passed to the lorapipe fw, and is of the form
// frequency-bandwidth-spreading-coding-syncword
// ie
// 906.875-250-11-5-2b
//
// aliases can be added for different lora channel terms like
// US-Meshtastic-Longfast
// EU-Meshtastic-Longturbo
//
// to be determined: can we capture from all sync words, or does the lorapipe
// firmware/lora radio require a single sync word?

class kis_datasource_lorapipe : public kis_datasource {
public:
    kis_datasource_lorapipe(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        set_int_source_ipc_binary("kismet_cap_lorapipe");

        set_int_source_dlt(KDLT_LORATAP);

        // native link type is synthetic loratap
        pack_comp_decap = packetchain->register_packet_component("DECAP");

        auto dltt =
            Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");

        // decoded link type is based on the lora sync word; meshtastic supported
        // in this push with meshcore planned
        dlt_meshtastic = dltt->register_linktype("MESHTASTIC");
        dlt_meshcore = dltt->register_linktype("MESHCORE");
        dlt_lora_generic = dltt->register_linktype("LORA_GENERIC");
    }

    virtual ~kis_datasource_lorapipe() { }

protected:
    virtual int handle_rx_data_content(kis_packet *packet, kis_datachunk *datachunk,
            const uint8_t *content, size_t content_sz) override;

    int pack_comp_decap;
    int dlt_meshtastic, dlt_meshcore, dlt_lora_generic;
};

class datasource_lorapipe_builder : public kis_datasource_builder {
public:
    datasource_lorapipe_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_lorapipe_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_lorapipe_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_lorapipe_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_lorapipe(new kis_datasource_lorapipe(in_sh_this));
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver

        set_source_type("lorapipe");
        set_source_description("Lora microcontroller with LoraPipe sniffer-capable firmware");

        set_probe_capable(true);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);

        // debatable; experimentation needed
        set_tune_capable(true);
        set_hop_capable(true);

        // One hop every 30 seconds
        set_max_hop_rate(1.0 / 30);
    }
};


#endif /* __DATASOURCE_LORAPIPE_H__ */
