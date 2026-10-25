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

#include "datasourcetracker.h"
#include "datasource_virtual.h"
#include "datasource_scan.h"
#include "json_adapter.h"
#include "packet.h"

#include <cmath>

datasource_scan_source::datasource_scan_source(const std::string& uri, const std::string& source_type,
        const std::string& json_component_type) :
    endpoint_uri{uri},
    virtual_source_type{source_type},
    json_component_type{json_component_type} {

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    datasourcetracker = 
        Globalreg::fetch_mandatory_global_as<datasource_tracker>();

    pack_comp_json = 
        packetchain->register_packet_component("JSON");
    pack_comp_datasrc =
        packetchain->register_packet_component("KISDATASRC");
    pack_comp_devicetag =
        packetchain->register_packet_component("DEVICETAG");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route(endpoint_uri, {"POST"}, "scanreport", {},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return scan_result_endp_handler(con);
                }));
}

datasource_scan_source::~datasource_scan_source() {

}

void datasource_scan_source::scan_result_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());
    std::shared_ptr<kis_packet> packet;

    if (con->json() == nullptr) { 
        con->set_status(500);
        stream << "{\"status\": \"invalid or missing JSON\", \"success\": false}\n";
        return;
    }

    try {
        std::shared_ptr<kis_datasource> virtual_source;

        auto uuid_s = con->json()["source_uuid"].get<std::string>();
        uuid src_uuid{uuid_s};

        std::string name = con->json()["source_name"].get<std::string>();

        if (src_uuid.error) {
            con->set_status(500);
            stream << "{\"status\": \"invalid source uuid\", \"success\": false}\n";
            return;
        }

        auto reports_j = con->json()["reports"];

        if (!reports_j.is_array()) {
            con->set_status(500);
            stream << "{\"status\": \"expected 'reports' array\", \"success\": false}\n";
            return;
        }

        // Look up the source by either the uuid provided or the uuid we made based on the name
        virtual_source = datasourcetracker->find_datasource(src_uuid);

        if (virtual_source == nullptr) {
            auto virtual_builder = Globalreg::fetch_mandatory_global_as<datasource_virtual_builder>();

            virtual_source = virtual_builder->build_datasource(virtual_builder);

            auto vs_cast = std::static_pointer_cast<kis_datasource_virtual>(virtual_source);

            vs_cast->set_virtual_hardware(virtual_source_type);

            virtual_source->set_source_uuid(src_uuid);
            virtual_source->set_source_key(adler32_checksum(src_uuid.uuid_to_string()));
            virtual_source->set_source_name(name);

            datasourcetracker->merge_source(virtual_source);
        } else {
            // Update the name
            virtual_source->set_source_name(name);
        }

        for (auto r : reports_j) {
            if (!r.is_object() || !validate_report(r)) {
                virtual_source->inc_source_num_error_packets(1);
                throw std::runtime_error("invalid report");
            }

            // Numbers come from the client; range check before converting them
            auto get_num = [&r](const char *key, double min, double max) -> double {
                auto j = r.find(key);

                if (j == r.end() || j->is_null())
                    return 0;

                if (!j->is_number())
                    throw std::runtime_error(fmt::format("invalid '{}' in report", key));

                auto v = j->get<double>();

                if (!std::isfinite(v) || v < min || v > max)
                    throw std::runtime_error(fmt::format("invalid '{}' in report", key));

                return v;
            };

            // TS is optional
            uint64_t ts_s = static_cast<uint64_t>(get_num("timestamp", 0, 0xFFFFFFFFULL));

            packet = packetchain->generate_packet();

            // Timestamp based on packet data, or now
            if (ts_s != 0) {
                packet->ts.tv_sec = ts_s;
                packet->ts.tv_usec = 0;
            } else {
                gettimeofday(&packet->ts, nullptr);
            }

            // Re-pack the submitted record into json for this packet
            auto jsoninfo = std::make_shared<kis_json_packinfo>();
            jsoninfo->type = json_component_type;

            std::stringstream s;
            s << r;
            jsoninfo->json_string = s.str();

            packet->insert(pack_comp_json, jsoninfo);

            // Extract any tags
            auto tags_j = r["tags"];
            if (tags_j.is_object()) {
                auto tagsinfo = std::make_shared<kis_devicetag_packetinfo>();

                for (const auto& i : tags_j.items()) {
                    if (i.value().is_string())
                        tagsinfo->tagmap[i.key()] = i.value().get<std::string>();
                    else
                        tagsinfo->tagmap[i.key()] = i.value().dump();
                }

                packet->insert(pack_comp_devicetag, tagsinfo);
            }

            double lat = get_num("lat", -90, 90);
            double lon = get_num("lon", -180, 180);
            double alt = get_num("alt", -100000, 1000000);
            double speed = get_num("speed", 0, 1000000);

            if (lat != 0 && lon != 0) {
                packet->gps_info.gps_info_ok = true;

                packet->gps_info.lat = lat;
                packet->gps_info.lon = lon;

                if (alt != 0)
                    packet->gps_info.fix = 3;
                else
                    packet->gps_info.fix = 2;

                packet->gps_info.alt = alt;
                packet->gps_info.speed = speed;
            }

            // std::shared_ptr<kis_layer1_packinfo> l1info;

            if (!r["signal"].is_null()) {
                packet->signal_info.data_ok = true;
                packet->signal_info.signal_dbm = static_cast<int>(get_num("signal", -500, 500));
                packet->signal_info.signal_type = kis_l1_signal_type_dbm;
            }

            if (!r["freqkhz"].is_null()) {
                packet->signal_info.data_ok = true;
                packet->signal_info.freq_khz = get_num("freqkhz", 0, 1000000000);
            }

            if (!r["channel"].is_null()) {
                packet->signal_info.data_ok = true;
                packet->signal_info.channel = r["channel"];
            }

            auto srcinfo = std::make_shared<packetchain_comp_datasource>();
            srcinfo->ref_source = virtual_source.get();
            packet->insert(pack_comp_datasrc, srcinfo);

            packetchain->process_packet(packet);

            // Null out our local packet, it's destroyed by packetchain
            packet = nullptr;
        }

        stream << "{\"status\": \"Scan report accepted\", \"success\": true}\n";
        return;

    } catch (const std::exception& e) {
        con->set_status(500);
        stream << "{\"status\": \"" << e.what() << "\", \"success\": false}\n";
        return;
    }

    con->set_status(500);
    stream << "{\"status\": \"unhandled request\", \"success\": false}\n";
}

