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
#include "dot11_scan_source.h"
#include "json_adapter.h"

dot11_scan_source::dot11_scan_source() :
    lifetime_global() {

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

    scan_result_endp =
        std::make_shared<kis_net_httpd_simple_post_endpoint>("/phy/phy80211/scan/scan_report",
                [this](std::ostream& stream, const std::string& uri, shared_structured post_structured,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                return scan_result_endp_handler(stream, uri, post_structured, variable_cache);
                });

}

dot11_scan_source::~dot11_scan_source() {
    Globalreg::globalreg->RemoveGlobal(global_name());
}

uuid dot11_scan_source::make_uuid(const std::string& in_name) {
    return uuid(fmt::format("{:8x}-0000-0000-0000-{:6x}",
            adler32_checksum("virtual_source_dot11_scan"),
            adler32_checksum(in_name)));
}

unsigned int dot11_scan_source::scan_result_endp_handler(std::ostream& stream,
        const std::string& uri, shared_structured structured,
        kis_net_httpd_connection::variable_cache_map& variable_cache) {

    kis_packet *packet = nullptr;

    try {
        std::shared_ptr<kis_datasource> virtual_source;

        std::string uuid_s;
        uuid src_uuid;
        std::string name;

        if (structured->has_key("source_uuid"))
            uuid_s = structured->key_as_string("source_uuid");

        if (structured->has_key("source_name"))
            name = structured->key_as_string("source_name");

        if (uuid_s == "" && name == "") {
            stream << "FATAL:  Requires source_uuid and/or source_name\n";
            return 500;
        }

        if (uuid_s != "") {
            src_uuid = uuid(uuid_s);

            if (src_uuid.error) {
                stream << "FATAL: Invalid source uuid\n";
                return 500;
            }
        } else {
            src_uuid = make_uuid(name);
        }

        if (!structured->has_key("reports")) {
            stream << "FATAL:  Expected 'reports'\n";
            return 500;
        }

        // Look up the source by either the uuid provided or the uuid we made based on the name
        virtual_source = datasourcetracker->find_datasource(src_uuid);

        if (virtual_source == nullptr) {
            auto virtual_builder = Globalreg::fetch_mandatory_global_as<datasource_virtual_builder>();

            virtual_source = virtual_builder->build_datasource(virtual_builder, nullptr);

            auto vs_cast = std::static_pointer_cast<kis_datasource_virtual>(virtual_source);

            vs_cast->set_virtual_hardware("IEEE80211 scan");

            virtual_source->set_source_uuid(src_uuid);
            virtual_source->set_source_name(name);
        }

        auto reports = structured->get_structured_by_key("reports")->as_vector();

        for (auto r : reports) {
            // Must have bssid, validate
            auto bssid_s = structured->key_as_string("bssid");

            // TS is optional
            uint64_t ts_s = 0;

            if (r->has_key("timestamp"))
                ts_s = r->key_as_number("timestamp");

            packet = packetchain->generate_packet();

            // Timestamp based on packet data, or now
            if (ts_s != 0) {
                packet->ts.tv_sec = ts_s;
                packet->ts.tv_usec = 0;
            } else {
                gettimeofday(&packet->ts, nullptr);
            }

            // Re-pack the submitted record into json for this packet
            auto jsoninfo = new kis_json_packinfo();
            jsoninfo->type = "DOT11SCAN";

            std::stringstream s;
            json_adapter::serialize_structured(r, s);
            jsoninfo->json_string = s.str();

            packet->insert(pack_comp_json, jsoninfo);

            double lat = 0, lon = 0, alt = 0, speed = 0;

            if (r->has_key("lat"))
                lat = r->key_as_number("lat");

            if (r->has_key("lon"))
                lon = r->key_as_number("lon");

            if (r->has_key("alt"))
                alt = r->key_as_number("alt");

            if (r->has_key("speed"))
                speed = r->key_as_number("speed");

            if (lat != 0 && lon != 0) {
                auto gpsinfo = new kis_gps_packinfo();

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

            double signal = 0;

            if (r->has_key("signal")) {
                signal = r->key_as_number("signal");

                auto l1info = new kis_layer1_packinfo();
                l1info->signal_dbm = signal;
                l1info->signal_type = kis_l1_signal_type_dbm;

                packet->insert(pack_comp_l1info, l1info);
            }

            auto srcinfo = new packetchain_comp_datasource();
            srcinfo->ref_source = virtual_source.get();
            packet->insert(pack_comp_datasrc, srcinfo);

            packetchain->process_packet(packet);

            // Null out our local packet, it's destroyed by packetchain
            packet = nullptr;
        }

    } catch (const std::exception& e) {
        // Free any half-made packets that didn't get injected because of parsing errors
        if (packet != nullptr) 
            packetchain->destroy_packet(packet);

        stream << "Error handling request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

