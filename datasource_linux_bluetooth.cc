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

#include "datasource_linux_bluetooth.h"
#include "json_adapter.h"
#include "phy_bluetooth.h"
#include "messagebus.h"
#include "protobuf_cpp/linuxbluetooth.pb.h"

#ifdef HAVE_LINUX_BLUETOOTH_DATASOURCE

kis_datasource_linux_bluetooth::kis_datasource_linux_bluetooth(shared_datasource_builder in_builder) :
    kis_datasource(in_builder)  {
    // Set the capture binary
    set_int_source_ipc_binary("kismet_cap_linux_bluetooth");

    pack_comp_btdevice = packetchain->register_packet_component("BTDEVICE");
    pack_comp_meta = packetchain->register_packet_component("METABLOB");
}

bool kis_datasource_linux_bluetooth::dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) {
    if (kis_datasource::dispatch_rx_packet(c))
        return true;

    if (c->command() == "LBTDATAREPORT") {
        handle_packet_linuxbtdevice(c->seqno(), c->content());
        return true;
    }

    return false;
}

void kis_datasource_linux_bluetooth::handle_packet_linuxbtdevice(uint32_t in_seqno, 
        std::string in_content) {

    // If we're paused, throw away this packet
    {
        kis_lock_guard<kis_mutex> lk(ext_mutex, 
                "kis_datasource_linux_bluetooth handle_packet_linuxbtdevice");

        if (get_source_paused())
            return;
    }

    KismetLinuxBluetooth::LinuxBluetoothDataReport report;

    if (!report.ParseFromString(in_content)) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() + 
                std::string(" could not parse the data report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        trigger_error("Invalid LBTDATAREPORT");
        return;
    }

    if (report.has_message()) 
        _MSG(report.message().msgtext(), report.message().msgtype());

    if (report.has_warning())
        set_int_source_warning(report.warning());

    kis_packet *packet = packetchain->generate_packet();
    bluetooth_packinfo *bpi = new bluetooth_packinfo();

    packet->insert(pack_comp_btdevice, bpi);

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
        packet->ts.tv_sec = report.btdevice().time_sec();
        packet->ts.tv_usec = report.btdevice().time_usec();
    }

    bpi->address = mac_addr(report.btdevice().address());
    bpi->name = munge_to_printable(report.btdevice().name());
    bpi->txpower = report.btdevice().txpower();
    bpi->type = report.btdevice().type();

    for (auto u : report.btdevice().uuid_list()) 
        bpi->service_uuid_vec.push_back(uuid(u));

    // Forge a metablob until we transition the capture protocols
    std::stringstream fake_json;
    fake_json << "{";
    fake_json << "\"bt_address\":\"" << bpi->address << "\",";
    fake_json << "\"bt_name\":\"" << json_adapter::sanitize_string(bpi->name) << "\",";
    fake_json << "\"txpower\":" << bpi->txpower << ",";
    fake_json << "\"type\":" << bpi->type << ",";
    fake_json << "\"uuid_list\": [";

    bool need_comma = false;
    for (auto u : bpi->service_uuid_vec) {
        fake_json << "\"" << u << "\"";
        if (need_comma) 
            fake_json << ",";
        need_comma = true;
    }

    fake_json << "]";
    fake_json << "}";

    auto metablob = new packet_metablob("LINUXBLUETOOTH", fake_json.str());
    packet->insert(pack_comp_meta, metablob);

    packetchain_comp_datasource *datasrcinfo = new packetchain_comp_datasource();
    datasrcinfo->ref_source = this;

    packet->insert(pack_comp_datasrc, datasrcinfo);

    inc_source_num_packets(1);
    get_source_packet_rrd()->add_sample(1, time(0));

    // Inject the packet into the packetchain if we have one
    packetchain->process_packet(packet);

}

#endif
