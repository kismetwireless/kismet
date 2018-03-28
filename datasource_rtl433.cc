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
#include "kismet_json.h"
#include "phy_rtl433.h"
#include "protobuf_cpp/sdrrtl433.pb.h"

KisDatasourceRtl433::KisDatasourceRtl433(GlobalRegistry *in_globalreg,
        SharedDatasourceBuilder in_builder) :
    KisDatasource(in_globalreg, in_builder) {

    pack_comp_rtl433 = packetchain->RegisterPacketComponent("RTL433JSON");
    pack_comp_metablob = packetchain->RegisterPacketComponent("METABLOB");
    pack_comp_datasrc = packetchain->RegisterPacketComponent("KISDATASRC");

    std::string devnum = MungeToPrintable(get_definition_opt("device"));
    if (devnum != "") {
        set_int_source_cap_interface("rtl433usb#" + devnum);
    } else {
        set_int_source_cap_interface("rtl433usb");
    }

    set_int_source_hardware("rtlsdr");
    set_int_source_ipc_binary("kismet_cap_sdr_rtl433");
}

KisDatasourceRtl433::~KisDatasourceRtl433() {

}

void KisDatasourceRtl433::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    KisDatasource::open_interface(in_definition, in_transaction, in_cb);

    if (get_source_interface().find("rtl-mqtt") == 0) {
        set_int_source_hopping(false);
    }

}

bool KisDatasourceRtl433::dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) {
    if (KisDatasource::dispatch_rx_packet(c))
        return true;

    if (c->command() == "RTL433DATAREPORT") {
        handle_packet_rtl433device(c->seqno(), c->content());
        return true;
    }

    return false;
}

void KisDatasourceRtl433::handle_packet_rtl433device(uint32_t in_seqno, 
        std::string in_content) {

    // If we're paused, throw away this packet
    {
        local_locker lock(&ext_mutex);

        if (get_source_paused())
            return;
    }

    KismetSdrRtl433::SdrRtl433DataReport report;

    if (!report.ParseFromString(in_content)) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() + 
                std::string(" could not parse the data report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        trigger_error("Invalid RTL433DATAREPORT");
        return;
    }

    if (report.has_message()) 
        _MSG(report.message().msgtext(), report.message().msgtype());

    if (report.has_warning())
        set_int_source_warning(report.warning());

    kis_packet *packet = packetchain->GeneratePacket();

    kis_layer1_packinfo *siginfo = NULL;
    kis_gps_packinfo *gpsinfo = NULL;

    if (report.has_signal()) {
        siginfo = handle_sub_signal(report.signal());
        packet->insert(pack_comp_l1info, siginfo);
    }

    if (report.has_gps()) {
        gpsinfo = handle_sub_gps(report.gps());
        packet->insert(pack_comp_gps, gpsinfo);
    }


    if (clobber_timestamp && get_source_remote()) {
        gettimeofday(&(packet->ts), NULL);
    } else {
        packet->ts.tv_sec = report.time_sec();
        packet->ts.tv_usec = report.time_usec();
    }

    if (!process_rtl_json(packet, report.rtljson())) {
        packetchain->DestroyPacket(packet);
        packet = NULL;
        return;
    }
   
    packetchain_comp_datasource *datasrcinfo = new packetchain_comp_datasource();
    datasrcinfo->ref_source = this;

    packet->insert(pack_comp_datasrc, datasrcinfo);

    inc_source_num_packets(1);
    get_source_packet_rrd()->add_sample(1, time(0));

    // Inject the packet into the packetchain if we have one
    packetchain->ProcessPacket(packet);

}

bool KisDatasourceRtl433::process_rtl_json(kis_packet *packet, std::string in_json) {
    Json::Value device_json;
    Json::Value gps_json;
    Json::Value meta_json;

    try {
        std::stringstream ss;
        ss.str(in_json);
        ss >> device_json;
    } catch (std::exception& e) {
        trigger_error("Invalid JSON");
        return false;
    }

    // Put the parsed JSON in a rtl433
    packet_info_rtl433 *r433info = new packet_info_rtl433(device_json);
    packet->insert(pack_comp_rtl433, r433info);

    // Put the raw JSON in a metablob
    packet_metablob *metablob = new packet_metablob("RTL433", in_json);
    packet->insert(pack_comp_metablob, metablob);

    return true;
}

#if 0
int KisDatasourceRtl433::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
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



