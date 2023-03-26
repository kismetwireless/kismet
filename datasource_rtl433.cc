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
#include "datasource_rtl433.h"

kis_datasource_rtl433::kis_datasource_rtl433(shared_datasource_builder in_builder) :
    kis_datasource(in_builder) {

    std::string devnum = munge_to_printable(get_definition_opt("device"));
    if (devnum != "") {
        set_int_source_cap_interface("rtl433usb#" + devnum);
    } else {
        set_int_source_cap_interface("rtl433usb");
    }

    set_int_source_hardware("rtlsdr");
    set_int_source_ipc_binary("kismet_cap_sdr_rtl433");
}

kis_datasource_rtl433::~kis_datasource_rtl433() {

}

void kis_datasource_rtl433::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    kis_datasource::open_interface(in_definition, in_transaction, in_cb);
}

#if 0
int kis_datasource_rtl433::httpd_post_complete(kis_net_httpd_connection *concls) {
    std::string stripped = httpd_strip_suffix(concls->url);
    std::vector<std::string> tokenurl = str_tokenize(stripped, "/");

    // Anything involving POST here requires a login
    if (!httpd->has_valid_session(concls, true)) {
        return 1;
    }

    if (tokenurl.size() < 5)
        return MHD_NO;

    if (tokenurl[1] != "datasource")
        return MHD_NO;

    if (tokenurl[2] != "by-uuid")
        return MHD_NO;

    if (tokenurl[3] != get_source_uuid().uuid_to_string())
        return MHD_NO;

    if (tokenurl[4] == "update") {

        packetchain_comp_datasource *datasrcinfo = new packetchain_comp_datasource();
        datasrcinfo->ref_source = this;
        packet->insert(pack_comp_datasrc, datasrcinfo);

        inc_source_num_packets(1);
        get_source_packet_rrd()->add_sample(1, time(0));

        packetchain->process_packet(packet);
    }

    return MHD_NO;
}
#endif



