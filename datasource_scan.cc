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
	pack_comp_common = 
		packetchain->register_packet_component("COMMON");
    pack_comp_datasrc =
        packetchain->register_packet_component("KISDATASRC");
    pack_comp_gps = 
        packetchain->register_packet_component("GPS");
    pack_comp_l1info = 
        packetchain->register_packet_component("RADIODATA");
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
            if (!validate_report(r)) {
                throw std::runtime_error("invalid report");
            }

            // TS is optional
            uint64_t ts_s = r.value("timestamp", 0);

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
            if (!tags_j.is_object()) {
                auto tagsinfo = std::make_shared<kis_devicetag_packetinfo>();

                for (const auto& i : tags_j.items()) {
                    tagsinfo->tagmap[i.key()] = i.value();
                }

                packet->insert(pack_comp_devicetag, tagsinfo);
            }

            double lat = r.value("lat", (double) 0);
            double lon = r.value("lon", (double) 0);
            double alt = r.value("alt", (double) 0);
            double speed = r.value("speed", (double) 0);

            if (lat != 0 && lon != 0) {
                auto gpsinfo = std::make_shared<kis_gps_packinfo>();

                gpsinfo->lat = lat;
                gpsinfo->lon = lon;
                
                if (alt != 0)
                    gpsinfo->fix = 3;
                else
                    gpsinfo->fix = 2;

                gpsinfo->alt = alt;
                gpsinfo->speed = speed;

                packet->insert(pack_comp_gps, gpsinfo);
            }

            std::shared_ptr<kis_layer1_packinfo> l1info;

            if (!r["signal"].is_null()) {
                if (l1info == nullptr)
                    l1info = std::make_shared<kis_layer1_packinfo>();

                l1info->signal_dbm = r["signal"];
                l1info->signal_type = kis_l1_signal_type_dbm;
            }

            if (!r["freqkhz"].is_null()) {
                if (l1info == nullptr)
                    l1info = std::make_shared<kis_layer1_packinfo>();

                l1info->freq_khz = r["freqkhz"];
            }

            if (!r["channel"].is_null()) {
                if (l1info == nullptr)
                    l1info = std::make_shared<kis_layer1_packinfo>();

                l1info->channel = r["channel"];
            }

            if (l1info != nullptr)
                packet->insert(pack_comp_l1info, l1info);

            auto srcinfo = std::make_shared<packetchain_comp_datasource>();
            srcinfo->ref_source = virtual_source.get();
            packet->insert(pack_comp_datasrc, srcinfo);

            packetchain->process_packet(packet);

            // Null out our local packet, it's destroyed by packetchain
            packet = nullptr;

            virtual_source->inc_source_num_packets(1);
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

