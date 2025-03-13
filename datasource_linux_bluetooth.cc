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

#ifdef HAVE_PROTOBUF_CPP
#include "kis_gps.h"
#include "json_adapter.h"
#include "protobuf_cpp/linuxbluetooth.pb.h"
#endif

#ifdef HAVE_LINUX_BLUETOOTH_DATASOURCE

kis_datasource_linux_bluetooth::kis_datasource_linux_bluetooth(shared_datasource_builder in_builder) :
    kis_datasource(in_builder)  {
    // Set the capture binary
    set_int_source_ipc_binary("kismet_cap_linux_bluetooth");
}

#ifdef HAVE_PROTOBUF_CPP
bool kis_datasource_linux_bluetooth::dispatch_rx_packet(const nonstd::string_view& command,
        uint32_t seqno, const nonstd::string_view& content) {
    if (kis_datasource::dispatch_rx_packet(command, seqno, content))
        return true;

    if (command.compare("LBTDATAREPORT") == 0) {
        handle_packet_linuxbtdevice(seqno, content);
        return true;
    }

    return false;
}

void kis_datasource_linux_bluetooth::handle_packet_linuxbtdevice(uint32_t in_seqno,
        const nonstd::string_view& in_content) {

    // If we're paused, throw away this packet
    {
        kis_lock_guard<kis_mutex> lk(ext_mutex,
                "kis_datasource_linux_bluetooth handle_packet_linuxbtdevice");

        if (get_source_paused())
            return;
    }

    KismetLinuxBluetooth::LinuxBluetoothDataReport report;

    if (!report.ParseFromArray(in_content.data(), in_content.length())) {
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

    if (gpstracker == nullptr)
        gpstracker = Globalreg::fetch_mandatory_global_as<gps_tracker>();

    auto packet = packetchain->generate_packet();

    if (report.has_signal()) {
        auto siginfo = handle_sub_signal(report.signal());
        packet->insert(pack_comp_l1info, siginfo);
    }

    if (report.has_gps()) {
        auto gpsinfo = handle_sub_gps(report.gps());
        packet->insert(pack_comp_gps, gpsinfo);
    } else if (suppress_gps) {
        auto nogpsinfo = packetchain->new_packet_component<kis_no_gps_packinfo>();
        packet->insert(pack_comp_no_gps, nogpsinfo);
    } else if (device_gps != nullptr) {
        auto gpsinfo = device_gps->get_location();

        if (gpsinfo != nullptr)
            packet->insert(pack_comp_gps, gpsinfo);
    } else {
        auto gpsloc = gpstracker->get_best_location();

        if (gpsloc != nullptr) {
            packet->insert(pack_comp_gps, std::move(gpsloc));
        }
    }

    if (clobber_timestamp && get_source_remote()) {
        gettimeofday(&(packet->ts), NULL);
    } else {
        packet->ts.tv_sec = report.btdevice().time_sec();
        packet->ts.tv_usec = report.btdevice().time_usec();
    }

    std::stringstream fake_json;
    fake_json << "{";
    fake_json << "\"addr\": \"" << mac_addr(report.btdevice().address()) << "\",";
    fake_json << "\"name\": \"" << json_adapter::sanitize_string(report.btdevice().name()) << "\",";
    fake_json << "\"type\": " << report.btdevice().type();
    fake_json << "}";

    auto jsonblob = packetchain->new_packet_component<kis_json_packinfo>();
    jsonblob->type = "linuxbthci";
    jsonblob->json_string = fake_json.str();
    packet->insert(pack_comp_json, jsonblob);

    auto datasrcinfo = packetchain->new_packet_component<packetchain_comp_datasource>();
    datasrcinfo->ref_source = this;

    packet->insert(pack_comp_datasrc, datasrcinfo);

    inc_source_num_packets(1);
    get_source_packet_rrd()->add_sample(1, time(0));

    // Inject the packet into the packetchain if we have one
    packetchain->process_packet(packet);
}
#endif

#endif
