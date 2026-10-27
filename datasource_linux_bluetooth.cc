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

    // Base construction is complete, so insert() targets this source's own map
    auto et = Globalreg::globalreg->entrytracker;

    probe_mode = std::make_shared<tracker_element_string>(
            et->register_field("kismet.datasource.linuxbt.probe",
                tracker_element_factory<tracker_element_string>(),
                "active probing: off, name or info; empty until the helper reports"));
    insert(probe_mode);
    probe_interval = std::make_shared<tracker_element_uint32>(
            et->register_field("kismet.datasource.linuxbt.probe_interval",
                tracker_element_factory<tracker_element_uint32>(),
                "least time between probes of one device, seconds"));
    insert(probe_interval);
    probe_count = std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.linuxbt.probes",
                tracker_element_factory<tracker_element_uint64>(),
                "devices connected to and probed since the source opened"));
    insert(probe_count);
    probe_queued = std::make_shared<tracker_element_uint32>(
            et->register_field("kismet.datasource.linuxbt.probe_queue",
                tracker_element_factory<tracker_element_uint32>(),
                "devices waiting to be probed"));
    insert(probe_queued);
    probe_last = std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.linuxbt.probe_last",
                tracker_element_factory<tracker_element_uint64>(),
                "time the last probe ended"));
    insert(probe_last);
}

void kis_datasource_linux_bluetooth::apply_probe_status(const std::string& json_str) {
    auto j = nlohmann::json::parse(json_str, nullptr, false);

    if (j.is_discarded() || !j.is_object())
        return;

    kis_lock_guard<kis_mutex> lk(ext_mutex, "kis_datasource_linux_bluetooth apply_probe_status");

    auto mode = j.find("probe");
    if (mode != j.end() && mode->is_string()) {
        const auto& m = mode->get_ref<const std::string&>();
        if (m == "off" || m == "name" || m == "info")
            probe_mode->set(m);
    }

    auto iv = j.find("probe_interval");
    if (iv != j.end() && iv->is_number_unsigned())
        probe_interval->set(iv->get<uint32_t>());

    auto pc = j.find("probes");
    if (pc != j.end() && pc->is_number_unsigned())
        probe_count->set(pc->get<uint64_t>());

    auto q = j.find("queued");
    if (q != j.end() && q->is_number_unsigned())
        probe_queued->set(q->get<uint32_t>());

    auto lp = j.find("last_probe");
    if (lp != j.end() && lp->is_number_unsigned())
        probe_last->set(lp->get<uint64_t>());
}

void kis_datasource_linux_bluetooth::handle_rx_jsonlayer_v3(std::shared_ptr<kis_packet> packet,
        mpack_node_t& root, mpack_tree_t *tree) {
    if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK)) {
        auto jsonmap = mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK);

        if (mpack_tree_error(tree) == mpack_ok) {
            auto type_n = mpack_node_map_uint_optional(jsonmap,
                    KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TYPE);

            if (!mpack_node_is_missing(type_n) && mpack_node_type(type_n) == mpack_type_str &&
                    std::string_view(mpack_node_str(type_n), mpack_node_data_len(type_n)) ==
                    "linuxbtprobe") {
                auto json_n = mpack_node_map_uint_optional(jsonmap,
                        KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_JSON);
                if (!mpack_node_is_missing(json_n) && mpack_node_type(json_n) == mpack_type_str)
                    apply_probe_status(std::string(mpack_node_str(json_n),
                                mpack_node_data_len(json_n)));
                return;
            }
        }
    }

    kis_datasource::handle_rx_jsonlayer_v3(packet, root, tree);
}

#ifdef HAVE_PROTOBUF_CPP
bool kis_datasource_linux_bluetooth::dispatch_rx_packet(const std::string_view& command,
        uint32_t seqno, const std::string_view& content) {
    if (kis_datasource::dispatch_rx_packet(command, seqno, content))
        return true;

    if (command.compare("LBTDATAREPORT") == 0) {
        handle_packet_linuxbtdevice(seqno, content);
        return true;
    }

    return false;
}

void kis_datasource_linux_bluetooth::handle_packet_linuxbtdevice(uint32_t in_seqno,
        const std::string_view& in_content) {

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
        handle_sub_signal(report.signal(), packet->signal_info);
    }

    if (report.has_gps()) {
		handle_sub_gps(report.gps(), packet->gps_info);
    } else if (suppress_gps) {
		packet->suppress_gps = true;
    } else if (device_gps != nullptr) {
        auto gpsinfo = device_gps->get_location();

        if (gpsinfo != nullptr)
			packet->gps_info.set(gpsinfo);
    } else {
		gpstracker->get_best_location(packet->gps_info);
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

    get_source_packet_rrd()->add_sample(1, time(0));

    // Inject the packet into the packetchain if we have one
    packetchain->process_packet(packet);
}
#endif

#endif
