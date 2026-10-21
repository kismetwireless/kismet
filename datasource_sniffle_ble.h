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

// Datasource for a Sonoff ZBDongle-P (TI CC2652P) flashed with Sniffle
// (https://github.com/nccgroup/Sniffle) BLE 4.x/5 sniffer firmware.
//
// Mirrors datasource_nrf_51822.h/.cc closely: the capture binary
// (capture_sniffle_ble.c) forwards Sniffle's own raw message bytes largely
// untouched; this class does the actual pseudoheader construction,
// channel remapping, and CRC-flag propagation in handle_rx_data_content(),
// same split nrf51822 uses.

#ifndef __DATASOURCE_SNIFFLE_BLE_H__
#define __DATASOURCE_SNIFFLE_BLE_H__

#include "config.h"

#define HAVE_SNIFFLE_BLE_DATASOURCE

#include "kis_datasource.h"
#include "dlttracker.h"

class kis_datasource_sniffle_ble;
typedef std::shared_ptr<kis_datasource_sniffle_ble> shared_datasource_sniffle_ble;

#ifndef KDLT_BLUETOOTH_LE_LL
#define KDLT_BLUETOOTH_LE_LL        251
#endif

#ifndef KDLT_BTLE_RADIO
#define KDLT_BTLE_RADIO             256
#endif

class kis_datasource_sniffle_ble : public kis_datasource {
public:
    kis_datasource_sniffle_ble(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_sniffle_ble");

        // We synthesize BTLE_LL_RADIO headers, same as nrf51822/ubertooth/ti_cc_2540
        set_int_source_dlt(KDLT_BTLE_RADIO);

        pack_comp_decap =
            packetchain->register_packet_component("DECAP");
    }

    virtual ~kis_datasource_sniffle_ble() { };

protected:
    virtual rx_content handle_rx_data_content(kis_packet *packet, kis_datachunk *datachunk,
            const uint8_t *content, size_t content_sz) override;

    int pack_comp_decap;
};


class datasource_sniffle_ble_builder : public kis_datasource_builder {
public:
    datasource_sniffle_ble_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_sniffle_ble_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_sniffle_ble_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_sniffle_ble_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_sniffle_ble(new kis_datasource_sniffle_ble(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("sniffle_ble");
        set_source_description("Sonoff ZBDongle-P (CC2652P) with Sniffle BLE sniffer firmware");

        set_probe_capable(true);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(false);
        set_hop_capable(false);
    }
};

#endif
