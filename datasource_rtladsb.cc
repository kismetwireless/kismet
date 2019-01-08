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

#include "config.h"
#include "kis_datasource.h"
#include "datasource_rtladsb.h"
#include "kismet_json.h"
#include "phy_rtladsb.h"

KisDatasourceRtladsb::KisDatasourceRtladsb(SharedDatasourceBuilder in_builder, bool in_mqtt) :
    KisDatasource(in_builder) {

    std::string devnum = MungeToPrintable(get_definition_opt("device"));
    if (devnum != "") {
        set_int_source_cap_interface("rtladsbusb#" + devnum);
    } else {
        set_int_source_cap_interface("rtladsbusb");
    }

    if (!in_mqtt) {
        set_int_source_hardware("rtlsdr");
        set_int_source_ipc_binary("kismet_cap_sdr_rtladsb");
    } else {
        set_int_source_hardware("rtlsdr-mqtt");
        set_int_source_ipc_binary("kismet_cap_sdr_rtladsb_mqtt");
    }

}

KisDatasourceRtladsb::~KisDatasourceRtladsb() {

}

void KisDatasourceRtladsb::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    KisDatasource::open_interface(in_definition, in_transaction, in_cb);

    if (get_source_interface().find("rtl-mqtt") == 0) {
        set_int_source_hopping(false);
    }

}

#if 0
int KisDatasourceRtladsb::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    std::string stripped = Httpd_StripSuffix(concls->url);
    std::vector<std::string> tokenurl = StrTokenize(stripped, "/");

    // Anything involving POST here requires a login
    if (!httpd->HasValidSession(concls, true)) {
        return 1;
    }

    if (tokenurl.size() < 5)
        return MHD_NO;

    if (tokenurl[1] != "datasource")
        return MHD_NO;

    if (tokenurl[2] != "by-uuid")
        return MHD_NO;

    if (tokenurl[3] != get_source_uuid().UUID2String())
        return MHD_NO;

    if (tokenurl[4] == "update") {

        packetchain_comp_datasource *datasrcinfo = new packetchain_comp_datasource();
        datasrcinfo->ref_source = this;
        packet->insert(pack_comp_datasrc, datasrcinfo);

        inc_source_num_packets(1);
        get_source_packet_rrd()->add_sample(1, time(0));

        packetchain->ProcessPacket(packet);
    }

    return MHD_NO;
}
#endif



