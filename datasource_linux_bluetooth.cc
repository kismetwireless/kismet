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
#include "datasource_linux_bluetooth.h"
#include "phy_bluetooth.h"
#include "protobuf_cpp/linuxbluetooth.pb.h"

#ifdef HAVE_LINUX_BLUETOOTH_DATASOURCE

KisDatasourceLinuxBluetooth::KisDatasourceLinuxBluetooth(SharedDatasourceBuilder in_builder) : 
    KisDatasource(in_builder) {
    // Set the capture binary
    set_int_source_ipc_binary("kismet_cap_linux_bluetooth");

    pack_comp_btdevice = packetchain->RegisterPacketComponent("BTDEVICE");
}

bool KisDatasourceLinuxBluetooth::dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) {
    if (KisDatasource::dispatch_rx_packet(c))
        return true;

    if (c->command() == "LBTDATAREPORT") {
        handle_packet_linuxbtdevice(c->seqno(), c->content());
        return true;
    }

    return false;
}

void KisDatasourceLinuxBluetooth::handle_packet_linuxbtdevice(uint32_t in_seqno, 
        std::string in_content) {

    // If we're paused, throw away this packet
    {
        local_locker lock(ext_mutex);

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

    kis_packet *packet = packetchain->GeneratePacket();
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
    bpi->name = MungeToPrintable(report.btdevice().name());
    bpi->txpower = report.btdevice().txpower();
    bpi->type = report.btdevice().type();

    for (auto u : report.btdevice().uuid_list()) 
        bpi->service_uuid_vec.push_back(uuid(u));
   
    packetchain_comp_datasource *datasrcinfo = new packetchain_comp_datasource();
    datasrcinfo->ref_source = this;

    packet->insert(pack_comp_datasrc, datasrcinfo);

    inc_source_num_packets(1);
    get_source_packet_rrd()->add_sample(1, time(0));

    // Inject the packet into the packetchain if we have one
    packetchain->ProcessPacket(packet);

}

#endif
