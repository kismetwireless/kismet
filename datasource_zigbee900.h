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

/*
 * Datasource registration for legacy 900MHz IEEE 802.15.4 BPSK Zigbee,
 * received via an RTL-SDR. Pairs with capture_sdr_zigbee900/, which spawns
 * zigbee900_live_rx.py (a GNU Radio flowgraph + custom decode block) and
 * forwards decoded frames as DLT 195 (IEEE 802.15.4) packets.
 */

#ifndef __DATASOURCE_ZIGBEE900_H__
#define __DATASOURCE_ZIGBEE900_H__

#include "config.h"

#include <cmath>
#include <cstdio>

#include "kis_datasource.h"

class kis_datasource_zigbee900;
typedef std::shared_ptr<kis_datasource_zigbee900> shared_datasource_zigbee900;

class kis_datasource_zigbee900 : public kis_datasource {
public:
    kis_datasource_zigbee900(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        set_int_source_cap_interface("zigbee900sdr");
        set_int_source_hardware("rtlsdr");
        set_int_source_ipc_binary("kismet_cap_sdr_zigbee900");
    }

    virtual ~kis_datasource_zigbee900() { }

    // 802.15.4 sub-GHz channels 1-10 at 906 + 2 * (n - 1) MHz, taken in at 2.4 Msps
    virtual bool channel_span(const std::string& in_channel, double& low_khz,
            double& high_khz) override {
        constexpr double half_khz = 2400.0 / 2;
        unsigned int n;
        char extra;
        if (sscanf(in_channel.c_str(), "%u%c", &n, &extra) != 1 || n < 1 || n > 10)
            return false;
        auto f = 906000.0 + 2000.0 * (n - 1);
        low_khz = f - half_khz;
        high_khz = f + half_khz;
        return true;
    }

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override {
        kis_datasource::open_interface(in_definition, in_transaction, in_cb);
    }
};

class datasource_zigbee900_builder : public kis_datasource_builder {
public:
    datasource_zigbee900_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_zigbee900_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_zigbee900_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_zigbee900_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_zigbee900(new kis_datasource_zigbee900(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("zigbee900sdr");
        set_source_description("Legacy 900MHz IEEE 802.15.4 BPSK Zigbee via RTL-SDR");

        set_probe_capable(true);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);

        // Live channel hopping is supported (unlike rtl433/rtladsb, which
        // fix frequency at spawn time): zigbee900_live_rx.py retunes its
        // already-running osmosdr source on a "CHANNEL <n>" command
        set_tune_capable(true);
        set_hop_capable(true);
    }
};

#endif
