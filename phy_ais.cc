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

#include <atomic>
#include <cmath>
#include <optional>

#include "phy_ais.h"

#include "devicetracker.h"
#include "kis_httpd_registry.h"
#include "macaddr.h"
#include "manuf.h"
#include "messagebus.h"

uint32_t ais_bitreader::get_uint(size_t start, size_t len) const {
    uint32_t v = 0;

    for (size_t i = 0; i < len; i++) {
        size_t b = start + i;

        v <<= 1;

        if (b < size_bits() && ((uint8_t) data[b / 8] >> (7 - (b % 8))) & 0x01)
            v |= 1;
    }

    return v;
}

int32_t ais_bitreader::get_int(size_t start, size_t len) const {
    uint32_t v = get_uint(start, len);

    if (len > 0 && len < 32 && (v & (1U << (len - 1))))
        v |= ~((1U << len) - 1);

    return (int32_t) v;
}

std::string ais_bitreader::get_string(size_t start, size_t len) const {
    std::string r;

    for (size_t i = 0; i + 6 <= len && has(start + i, 6); i += 6) {
        auto v = get_uint(start + i, 6);

        // '@' (0) terminates the string
        if (v == 0)
            break;

        r += (char) (v < 32 ? v + 64 : v);
    }

    auto first = r.find_first_not_of(' ');
    if (first == std::string::npos)
        return "";

    auto last = r.find_last_not_of(' ');

    return r.substr(first, last - first + 1);
}

namespace {
    // Decoded fields of a single AIS message; only fields present in the
    // message (and not flagged as unavailable) are set
    struct ais_decoded {
        unsigned int msg_type = 0;
        uint32_t mmsi = 0;

        std::optional<std::string> station_class;

        std::optional<double> lat, lon;
        std::optional<double> sog, cog, heading, rot, altitude;

        std::optional<unsigned int> nav_status;
        std::optional<unsigned int> ship_type;
        std::optional<unsigned int> aton_type;
        std::optional<bool> aton_virtual, aton_off_position;

        std::optional<std::string> name, callsign, vendor, destination, eta, utc_time;
        std::optional<uint32_t> imo;
        std::optional<double> draught;

        bool has_dims = false;
        unsigned int dim_bow = 0, dim_stern = 0, dim_port = 0, dim_starboard = 0;
    };

    // Positions are in signed 1/divisor minutes; 181 / 91 degrees mean unavailable
    void ais_decode_position(const ais_bitreader& br, ais_decoded& d,
            size_t lon_off, size_t lon_len, size_t lat_off, size_t lat_len, double divisor) {
        if (!br.has(lat_off, lat_len))
            return;

        double lon = br.get_int(lon_off, lon_len) / divisor;
        double lat = br.get_int(lat_off, lat_len) / divisor;

        if (lon < -180 || lon > 180 || lat < -90 || lat > 90)
            return;

        if (lon == 0 && lat == 0)
            return;

        d.lat = lat;
        d.lon = lon;
    }

    // Speed in 1/10 knot, 1023 unavailable
    void ais_decode_sog(const ais_bitreader& br, ais_decoded& d, size_t off) {
        auto v = br.get_uint(off, 10);
        if (v != 1023 && br.has(off, 10))
            d.sog = v / 10.0;
    }

    // Course in 1/10 degree, 3600 unavailable
    void ais_decode_cog(const ais_bitreader& br, ais_decoded& d, size_t off) {
        auto v = br.get_uint(off, 12);
        if (v < 3600 && br.has(off, 12))
            d.cog = v / 10.0;
    }

    // Heading in degrees, 511 unavailable
    void ais_decode_heading(const ais_bitreader& br, ais_decoded& d, size_t off) {
        auto v = br.get_uint(off, 9);
        if (v < 360 && br.has(off, 9))
            d.heading = v;
    }

    void ais_decode_dims(const ais_bitreader& br, ais_decoded& d, size_t off) {
        if (!br.has(off, 30))
            return;

        d.dim_bow = br.get_uint(off, 9);
        d.dim_stern = br.get_uint(off + 9, 9);
        d.dim_port = br.get_uint(off + 18, 6);
        d.dim_starboard = br.get_uint(off + 24, 6);
        d.has_dims = true;
    }

    void ais_decode_string(const ais_bitreader& br, std::optional<std::string>& s,
            size_t off, size_t len) {
        if (!br.has(off, 6))
            return;

        auto v = br.get_string(off, len);

        if (v.length() > 0)
            s = v;
    }

    // Field offsets per ITU-R M.1371
    bool ais_decode_message(const std::string& payload, ais_decoded& d) {
        ais_bitreader br(payload);

        if (!br.has(0, 38))
            return false;

        d.msg_type = br.get_uint(0, 6);
        d.mmsi = br.get_uint(8, 30);

        if (d.mmsi == 0)
            return false;

        switch (d.msg_type) {
            case 1:
            case 2:
            case 3: {
                // Class A position report
                if (!br.has(0, 137))
                    return false;

                d.station_class = "Class A";
                d.nav_status = br.get_uint(38, 4);

                auto rot = br.get_int(42, 8);
                if (rot >= -126 && rot <= 126) {
                    double r = rot / 4.733;
                    d.rot = (rot < 0 ? -1 : 1) * r * r;
                }

                ais_decode_sog(br, d, 50);
                ais_decode_position(br, d, 61, 28, 89, 27, 600000.0);
                ais_decode_cog(br, d, 116);
                ais_decode_heading(br, d, 128);
                break;
            }

            case 4:
            case 11: {
                // Base station report / UTC response
                if (!br.has(0, 134))
                    return false;

                if (d.msg_type == 4)
                    d.station_class = "Base Station";

                auto year = br.get_uint(38, 14);
                auto month = br.get_uint(52, 4);
                auto day = br.get_uint(56, 5);
                auto hour = br.get_uint(61, 5);
                auto minute = br.get_uint(66, 6);
                auto second = br.get_uint(72, 6);

                if (year != 0 && month != 0 && day != 0 && hour < 24 && minute < 60 && second < 60)
                    d.utc_time = fmt::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
                            year, month, day, hour, minute, second);

                ais_decode_position(br, d, 79, 28, 107, 27, 600000.0);
                break;
            }

            case 5: {
                // Class A static and voyage data
                if (!br.has(0, 270))
                    return false;

                d.station_class = "Class A";

                auto imo = br.get_uint(40, 30);
                if (imo != 0)
                    d.imo = imo;

                ais_decode_string(br, d.callsign, 70, 42);
                ais_decode_string(br, d.name, 112, 120);
                d.ship_type = br.get_uint(232, 8);
                ais_decode_dims(br, d, 240);

                if (br.has(274, 20)) {
                    auto month = br.get_uint(274, 4);
                    auto day = br.get_uint(278, 5);
                    auto hour = br.get_uint(283, 5);
                    auto minute = br.get_uint(288, 6);

                    if (month != 0 && day != 0 && hour < 24 && minute < 60)
                        d.eta = fmt::format("{:02}-{:02} {:02}:{:02}", month, day, hour, minute);
                }

                if (br.has(294, 8)) {
                    auto draught = br.get_uint(294, 8);
                    if (draught != 0)
                        d.draught = draught / 10.0;
                }

                ais_decode_string(br, d.destination, 302, 120);
                break;
            }

            case 9: {
                // SAR aircraft position report
                if (!br.has(0, 128))
                    return false;

                d.station_class = "SAR Aircraft";

                auto alt = br.get_uint(38, 12);
                if (alt != 4095)
                    d.altitude = alt;

                // SAR aircraft report speed in whole knots
                auto sog = br.get_uint(50, 10);
                if (sog != 1023)
                    d.sog = sog;

                ais_decode_position(br, d, 61, 28, 89, 27, 600000.0);
                ais_decode_cog(br, d, 116);
                break;
            }

            case 18:
            case 19: {
                // Class B position report, and extended report
                if (!br.has(0, 133))
                    return false;

                d.station_class = "Class B";

                ais_decode_sog(br, d, 46);
                ais_decode_position(br, d, 57, 28, 85, 27, 600000.0);
                ais_decode_cog(br, d, 112);
                ais_decode_heading(br, d, 124);

                if (d.msg_type == 19 && br.has(0, 301)) {
                    ais_decode_string(br, d.name, 143, 120);
                    d.ship_type = br.get_uint(263, 8);
                    ais_decode_dims(br, d, 271);
                }

                break;
            }

            case 21: {
                // Aid to navigation report
                if (!br.has(0, 219))
                    return false;

                d.station_class = "AtoN";
                d.aton_type = br.get_uint(38, 5);

                std::optional<std::string> name;
                ais_decode_string(br, name, 43, 120);

                ais_decode_position(br, d, 164, 28, 192, 27, 600000.0);
                ais_decode_dims(br, d, 219);

                if (br.has(259, 1))
                    d.aton_off_position = br.get_uint(259, 1) != 0;

                if (br.has(269, 1))
                    d.aton_virtual = br.get_uint(269, 1) != 0;

                // Name extension of up to 14 more characters
                if (name.has_value() && name->length() == 20 && br.size_bits() > 272 + 6) {
                    std::optional<std::string> ext;
                    ais_decode_string(br, ext, 272, ((br.size_bits() - 272) / 6) * 6);

                    if (ext.has_value())
                        name = *name + *ext;
                }

                d.name = name;

                break;
            }

            case 24: {
                // Class B static data, in two parts
                if (!br.has(0, 40))
                    return false;

                d.station_class = "Class B";

                auto part = br.get_uint(38, 2);

                if (part == 0) {
                    ais_decode_string(br, d.name, 40, 120);
                } else if (part == 1) {
                    if (!br.has(0, 132))
                        return false;

                    d.ship_type = br.get_uint(40, 8);
                    ais_decode_string(br, d.vendor, 48, 18);
                    ais_decode_string(br, d.callsign, 90, 42);

                    // Auxiliary craft carry the mothership MMSI instead of dimensions
                    if (d.mmsi / 10000000 != 98)
                        ais_decode_dims(br, d, 132);
                }

                break;
            }

            case 27: {
                // Long range position report
                if (!br.has(0, 94))
                    return false;

                d.station_class = "Class A";
                d.nav_status = br.get_uint(40, 4);

                ais_decode_position(br, d, 44, 18, 62, 17, 600.0);

                auto sog = br.get_uint(79, 6);
                if (sog != 63)
                    d.sog = sog;

                auto cog = br.get_uint(85, 9);
                if (cog < 360)
                    d.cog = cog;

                break;
            }

            default:
                // Other message types identify the station but carry no
                // tracked data
                break;
        }

        // Emergency beacons transmit standard position reports from
        // distinct MMSI ranges
        switch (d.mmsi / 1000000) {
            case 970:
                d.station_class = "AIS-SART";
                break;
            case 972:
                d.station_class = "AIS-MOB";
                break;
            case 974:
                d.station_class = "AIS-EPIRB";
                break;
        }

        return true;
    }

    const char *ais_class_to_devicetype(const std::string& station_class) {
        if (station_class == "Base Station")
            return "AIS Base Station";
        if (station_class == "AtoN")
            return "AIS AtoN";
        if (station_class == "SAR Aircraft")
            return "SAR Aircraft";
        if (station_class == "AIS-SART")
            return "AIS SART";
        if (station_class == "AIS-MOB")
            return "AIS MOB";
        if (station_class == "AIS-EPIRB")
            return "AIS EPIRB";

        return "Vessel";
    }

    bool is_hex_string(const std::string& s) {
        if (s.length() == 0 || s.length() % 2 != 0)
            return false;

        for (auto c : s) {
            if (!std::isxdigit((unsigned char) c))
                return false;
        }

        return true;
    }
}

kis_ais_phy::kis_ais_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("AIS");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    pack_comp_json =
        packetchain->register_packet_component("JSON");
    pack_comp_meta =
        packetchain->register_packet_component("METABLOB");
    pack_comp_datasource =
        packetchain->register_packet_component("KISDATASRC");

    ais_vessel_id =
        Globalreg::globalreg->entrytracker->register_field("ais.device",
                tracker_element_factory<ais_tracked_vessel>(),
                "AIS station");

    map_min_lat_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.ais.map.min_lat",
                tracker_element_factory<tracker_element_double>(),
                "AIS map minimum latitude");
    map_max_lat_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.ais.map.max_lat",
                tracker_element_factory<tracker_element_double>(),
                "AIS map maximum latitude");
    map_min_lon_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.ais.map.min_lon",
                tracker_element_factory<tracker_element_double>(),
                "AIS map minimum longitude");
    map_max_lon_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.ais.map.max_lon",
                tracker_element_factory<tracker_element_double>(),
                "AIS map maximum longitude");
    map_recent_devs_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.ais.map.devices",
                tracker_element_factory<tracker_element_vector>(),
                "AIS map recent devices");

    ais_manuf = Globalreg::globalreg->manufdb->make_manuf("AIS");

    auto httpregistry =
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_ais", "js/kismet.ui.ais.js");

    packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/phy/AIS/map_data", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return ais_map_endp_handler(con);
                }));

    // NMEA AIVDM feeds, for OpenCPN and other AIS tools
    register_aivdm_websocket("/phy/AIS/raw", false);
    register_aivdm_websocket("/datasource/by-uuid/:uuid/ais_raw", true);
}

kis_ais_phy::~kis_ais_phy() {
    packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

void kis_ais_phy::register_aivdm_websocket(const std::string& uri, bool by_uuid) {
    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_websocket_route(uri, {httpd->RO_ROLE, "AIS"}, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this, by_uuid](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                uuid srcuuid;

                if (by_uuid) {
                    srcuuid = uuid(con->uri_params()[":uuid"]);

                    if (srcuuid.error)
                        throw std::runtime_error("invalid UUID");
                }

                auto ws =
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            std::shared_ptr<boost::asio::streambuf> buf, bool text) {
                            // Do nothing on input
                        });

                struct uptr_t {
                    std::shared_ptr<kis_net_web_websocket_endpoint> ws;
                    kis_ais_phy *ais;
                    bool by_uuid;
                    uuid srcuuid;
                    std::atomic<unsigned int> seq_id;
                };

                auto uptr = new uptr_t();

                uptr->ws = ws;
                uptr->ais = this;
                uptr->by_uuid = by_uuid;
                uptr->srcuuid = srcuuid;
                uptr->seq_id = 0;

                auto raw_handler_id =
                    packetchain->register_handler(
                            [](void *auxdata, const std::shared_ptr<kis_packet>& in_pack) -> int {
                            auto uptr = reinterpret_cast<struct uptr_t *>(auxdata);

                            if (in_pack->error || in_pack->filtered || in_pack->duplicate)
                                return 0;

                            auto json = in_pack->fetch<kis_json_packinfo>(uptr->ais->pack_comp_json);

                            if (json == nullptr || json->type != "ais")
                                return 0;

                            if (uptr->by_uuid) {
                                auto src =
                                    in_pack->fetch<packetchain_comp_datasource>(uptr->ais->pack_comp_datasource);

                                if (src == nullptr)
                                    return 0;

                                if (src->ref_source->get_source_uuid() != uptr->srcuuid)
                                    return 0;
                            }

                            try {
                                auto device_json = nlohmann::json::parse(json->json_string);

                                std::string payload;
                                char channel;

                                if (!uptr->ais->extract_ais_json(device_json, payload, channel))
                                    return 0;

                                auto sentences =
                                    payload_to_aivdm(payload, channel, uptr->seq_id++);

                                std::string out;
                                for (const auto& s : sentences) {
                                    out += s;
                                    out += "\r\n";
                                }

                                uptr->ws->write(out);
                            } catch (const std::exception& e) {
                                return 0;
                            }

                            return 1;
                    }, uptr, CHAINPOS_LOGGING, 1000);

                ws->text();

                try {
                    ws->handle_request(con);
                } catch (const std::exception& e) {
                    ;
                }

                packetchain->remove_handler(raw_handler_id, CHAINPOS_LOGGING);
                delete uptr;
            }));
}

mac_addr kis_ais_phy::mmsi_to_mac(uint32_t mmsi) {
    // Locally administered address with an AIS marker octet, followed by the
    // 30-bit MMSI; this keeps the MMSI readable in the device key
    uint8_t bytes[6];

    bytes[0] = 0x02;
    bytes[1] = 0xA1;
    bytes[2] = (mmsi >> 24) & 0xFF;
    bytes[3] = (mmsi >> 16) & 0xFF;
    bytes[4] = (mmsi >> 8) & 0xFF;
    bytes[5] = mmsi & 0xFF;

    return mac_addr(bytes, 6);
}

unsigned int kis_ais_phy::mmsi_to_mid(uint32_t mmsi) {
    // SAR aircraft: 111MIDxxx
    if (mmsi / 1000000 == 111)
        return (mmsi / 1000) % 1000;

    // Aids to navigation (99MIDxxxx) and auxiliary craft (98MIDxxxx)
    if (mmsi / 10000000 == 99 || mmsi / 10000000 == 98)
        return (mmsi / 10000) % 1000;

    // Coast stations: 00MIDxxxx
    if (mmsi < 10000000)
        return mmsi / 10000;

    // Group calls: 0MIDxxxxx
    if (mmsi < 100000000)
        return mmsi / 100000;

    // Ships: MIDxxxxxx
    return mmsi / 1000000;
}

bool kis_ais_phy::extract_ais_json(const nlohmann::json& json, std::string& payload, char& channel) {
    auto hex_j = json.find("ais");

    if (hex_j == json.end() || !hex_j->is_string())
        return false;

    auto hex = hex_j->get<std::string>();

    if (!is_hex_string(hex))
        return false;

    payload = hex_to_bytes(hex);

    // hex_to_bytes over-allocates by one byte
    payload.resize(hex.length() / 2);

    channel = 'A';

    auto chan_j = json.find("channel");
    if (chan_j != json.end() && chan_j->is_string()) {
        auto c = chan_j->get<std::string>();
        if (c.length() > 0 && (c[0] == 'A' || c[0] == 'B'))
            channel = c[0];
    }

    return true;
}

bool kis_ais_phy::process_ais_json(nlohmann::json& json, const std::shared_ptr<kis_packet>& packet) {
    std::string payload;
    char channel;

    if (!extract_ais_json(json, payload, channel))
        return false;

    ais_decoded d;

    if (!ais_decode_message(payload, d))
        return false;

    auto mac = mmsi_to_mac(d.mmsi);

    packet->common_info.common_info_ok = true;
    packet->common_info.type = packet_basic_data;
    packet->common_info.phyid = fetch_phy_id();
    packet->common_info.datasize = payload.length();

    if (channel == 'B') {
        packet->common_info.freq_khz = 162025;
        packet->common_info.channel = "162.025MHz";
    } else {
        packet->common_info.freq_khz = 161975;
        packet->common_info.channel = "161.975MHz";
    }

    packet->common_info.source = mac;
    packet->common_info.transmitter = mac;

    unsigned int flags = UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_SEENBY |
        UCD_UPDATE_SIGNAL;

    // AIS stations report their own location; use it as the device location
    if (d.lat.has_value() && d.lon.has_value()) {
        packet->gps_info.reset();
        packet->gps_info.gps_info_ok = true;
        packet->gps_info.lat = *d.lat;
        packet->gps_info.lon = *d.lon;

        if (d.sog.has_value())
            packet->gps_info.speed = *d.sog * 1.852;

        if (d.heading.has_value())
            packet->gps_info.heading = *d.heading;
        else if (d.cog.has_value())
            packet->gps_info.heading = *d.cog;

        if (d.altitude.has_value()) {
            packet->gps_info.alt = *d.altitude;
            packet->gps_info.fix = 3;
        } else {
            packet->gps_info.fix = 2;
        }

        packet->gps_info.tv = packet->ts;

        flags |= UCD_UPDATE_LOCATION;
    }

    bool new_device = false;

    auto basedev =
        devicetracker->update_common_device(mac, this, packet, flags, "AIS", new_device);

    if (basedev == nullptr)
        return false;

    kis_device_lock dlk(basedev, false);

    auto aisdev = basedev->get_sub_as<ais_tracked_vessel>(ais_vessel_id);

    if (aisdev == nullptr) {
        aisdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<ais_tracked_vessel>(ais_vessel_id);
        basedev->insert(aisdev);

        auto mid = mmsi_to_mid(d.mmsi);

        aisdev->set_mmsi(d.mmsi);
        aisdev->set_mid(mid);
        aisdev->set_country(mid_to_country(mid));
        aisdev->set_station_class("Unknown");

        basedev->set_manuf(ais_manuf);
        basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("AIS Station"));
    }

    aisdev->set_last_msg_type(d.msg_type);

    if (d.station_class.has_value() && aisdev->get_station_class() != *d.station_class) {
        aisdev->set_station_class(*d.station_class);
        basedev->set_tracker_type_string(
                devicetracker->get_cached_devicetype(ais_class_to_devicetype(*d.station_class)));
    }

    if (d.name.has_value())
        aisdev->set_shipname(*d.name);
    if (d.callsign.has_value())
        aisdev->set_callsign(*d.callsign);
    if (d.imo.has_value())
        aisdev->set_imo(*d.imo);
    if (d.vendor.has_value())
        aisdev->set_vendor(*d.vendor);
    if (d.destination.has_value())
        aisdev->set_destination(*d.destination);
    if (d.eta.has_value())
        aisdev->set_eta(*d.eta);
    if (d.draught.has_value())
        aisdev->set_draught(*d.draught);
    if (d.utc_time.has_value())
        aisdev->set_utc_time(*d.utc_time);

    if (d.ship_type.has_value()) {
        aisdev->set_ship_type(*d.ship_type);
        aisdev->set_ship_type_str(ship_type_to_string(*d.ship_type));
    }

    if (d.nav_status.has_value()) {
        aisdev->set_nav_status(*d.nav_status);
        aisdev->set_nav_status_str(nav_status_to_string(*d.nav_status));
    }

    if (d.aton_type.has_value()) {
        aisdev->set_aton_type(*d.aton_type);
        aisdev->set_aton_type_str(aton_type_to_string(*d.aton_type));
    }

    if (d.aton_virtual.has_value())
        aisdev->set_aton_virtual(*d.aton_virtual);
    if (d.aton_off_position.has_value())
        aisdev->set_aton_off_position(*d.aton_off_position);

    if (d.has_dims) {
        aisdev->set_dim_bow(d.dim_bow);
        aisdev->set_dim_stern(d.dim_stern);
        aisdev->set_dim_port(d.dim_port);
        aisdev->set_dim_starboard(d.dim_starboard);
    }

    if (d.sog.has_value())
        aisdev->set_sog(*d.sog);
    if (d.cog.has_value())
        aisdev->set_cog(*d.cog);
    if (d.heading.has_value())
        aisdev->set_heading(*d.heading);
    if (d.rot.has_value())
        aisdev->set_rot(*d.rot);
    if (d.altitude.has_value())
        aisdev->set_altitude(*d.altitude);

    if (aisdev->get_shipname().length() > 0)
        basedev->set_devicename(aisdev->get_shipname());
    else if (aisdev->get_callsign().length() > 0)
        basedev->set_devicename(aisdev->get_callsign());
    else
        basedev->set_devicename(fmt::format("AIS {}", d.mmsi));

    if (new_device) {
        _MSG_INFO("Detected new AIS station MMSI {} ({})", d.mmsi, aisdev->get_country());
    }

    return true;
}

int kis_ais_phy::packet_handler(CHAINCALL_PARMS) {
    kis_ais_phy *ais = (kis_ais_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto json = in_pack->fetch<kis_json_packinfo>(ais->pack_comp_json);
    if (json == nullptr)
        return 0;

    if (json->type != "ais")
        return 0;

    try {
        auto device_json = nlohmann::json::parse(json->json_string);

        if (ais->process_ais_json(device_json, in_pack)) {
            auto adata = in_pack->fetch_or_add<packet_metablob>(ais->pack_comp_meta);
            adata->set_data("AIS", json->json_string);
        }
    } catch (const std::exception& e) {
        _MSG_DEBUG("AIS - error processing json: {}", e.what());
        return 0;
    }

    return 1;
}

std::vector<std::string> kis_ais_phy::payload_to_aivdm(const std::string& payload,
        char channel, unsigned int seq_id) {
    std::vector<std::string> ret;
    ais_bitreader br(payload);

    auto nbits = br.size_bits();
    auto nchars = (nbits + 5) / 6;
    auto fill = (nchars * 6) - nbits;

    std::string armor;
    armor.reserve(nchars);

    // Reads past the end of the payload return zero fill bits
    for (size_t i = 0; i < nchars; i++) {
        auto v = br.get_uint(i * 6, 6);
        char c = (char) (v + 48);

        if (c > 87)
            c += 8;

        armor += c;
    }

    const size_t max_chars = 60;
    auto nsentences = armor.length() == 0 ? 1 : (armor.length() + max_chars - 1) / max_chars;
    std::string seq = nsentences > 1 ? fmt::format("{}", seq_id % 10) : "";

    for (size_t s = 0; s < nsentences; s++) {
        auto body = fmt::format("AIVDM,{},{},{},{},{},{}",
                nsentences, s + 1, seq, channel,
                armor.substr(s * max_chars, max_chars),
                s == nsentences - 1 ? fill : 0);

        uint8_t cs = 0;
        for (auto c : body)
            cs ^= (uint8_t) c;

        ret.push_back(fmt::format("!{}*{:02X}", body, cs));
    }

    return ret;
}

std::shared_ptr<tracker_element>
kis_ais_phy::ais_map_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    auto ret_map = std::make_shared<tracker_element_map>();
    auto ais_view = devicetracker->get_phy_view(phyid);

    if (ais_view == nullptr) {
        auto error =
            Globalreg::globalreg->entrytracker->register_and_get_field_as<tracker_element_string>(
                    "kismet.common.error",
                    tracker_element_factory<tracker_element_string>(),
                    "Device error");
        error->set("PHY view tracking disabled or no AIS devices seen");
        ret_map->insert(error);
        return ret_map;
    }

    auto min_lat = std::make_shared<tracker_element_double>(map_min_lat_id);
    auto min_lon = std::make_shared<tracker_element_double>(map_min_lon_id);
    auto max_lat = std::make_shared<tracker_element_double>(map_max_lat_id);
    auto max_lon = std::make_shared<tracker_element_double>(map_max_lon_id);

    ret_map->insert(min_lat);
    ret_map->insert(min_lon);
    ret_map->insert(max_lat);
    ret_map->insert(max_lon);

    auto recent_devs = std::make_shared<tracker_element_vector>(map_recent_devs_id);
    ret_map->insert(recent_devs);

    auto now = time(0);

    kis_mutex response_mutex;

    // Vessels report far less often than aircraft; class B static reports
    // can be 6 minutes apart and anchored vessels 3 minutes, so use a 30
    // minute window
    auto recent_worker =
        device_tracker_view_function_worker([this, now, recent_devs, min_lat,
                min_lon, max_lat, max_lon, &response_mutex](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
            auto aisdev =
                dev->get_sub_as<ais_tracked_vessel>(ais_vessel_id);

            if (aisdev == nullptr)
                return false;

            if (dev->get_last_time() < now - (60 * 30))
                return false;

            kis_lock_guard<kis_mutex> lk(response_mutex);

            recent_devs->push_back(dev);

            auto loc = dev->get_tracker_location();

            if (loc != nullptr) {
                auto last_loc = loc->get_last_loc();

                if (last_loc != nullptr && last_loc->get_lat() != 0 &&
                        last_loc->get_lon() != 0) {
                    if (last_loc->get_lat() < min_lat->get() || min_lat->get() == 0)
                        min_lat->set(last_loc->get_lat());
                    if (last_loc->get_lon() < min_lon->get() || min_lon->get() == 0)
                        min_lon->set(last_loc->get_lon());

                    if (last_loc->get_lat() > max_lat->get() || max_lat->get() == 0)
                        max_lat->set(last_loc->get_lat());
                    if (last_loc->get_lon() > max_lon->get() || max_lon->get() == 0)
                        max_lon->set(last_loc->get_lon());
                }
            }

            return false;
        });

    ais_view->do_readonly_device_work(recent_worker);

    return ret_map;
}

const char *kis_ais_phy::ship_type_to_string(unsigned int type) {
    if (type == 0)
        return "Not available";
    if (type >= 20 && type <= 29)
        return "Wing in ground";
    if (type >= 40 && type <= 49)
        return "High speed craft";
    if (type >= 60 && type <= 69)
        return "Passenger";
    if (type >= 70 && type <= 79)
        return "Cargo";
    if (type >= 80 && type <= 89)
        return "Tanker";
    if (type >= 90 && type <= 99)
        return "Other";

    switch (type) {
        case 30: return "Fishing";
        case 31: return "Towing";
        case 32: return "Towing (large)";
        case 33: return "Dredging or underwater operations";
        case 34: return "Diving operations";
        case 35: return "Military operations";
        case 36: return "Sailing";
        case 37: return "Pleasure craft";
        case 50: return "Pilot vessel";
        case 51: return "Search and rescue vessel";
        case 52: return "Tug";
        case 53: return "Port tender";
        case 54: return "Anti-pollution equipment";
        case 55: return "Law enforcement";
        case 56:
        case 57: return "Local vessel";
        case 58: return "Medical transport";
        case 59: return "Noncombatant ship";
    }

    return "Reserved";
}

const char *kis_ais_phy::nav_status_to_string(unsigned int status) {
    switch (status) {
        case 0: return "Under way using engine";
        case 1: return "At anchor";
        case 2: return "Not under command";
        case 3: return "Restricted manoeuverability";
        case 4: return "Constrained by draught";
        case 5: return "Moored";
        case 6: return "Aground";
        case 7: return "Engaged in fishing";
        case 8: return "Under way sailing";
        case 11: return "Towing astern";
        case 12: return "Pushing ahead or towing alongside";
        case 14: return "AIS-SART active";
        case 15: return "Not defined";
    }

    return "Reserved";
}

const char *kis_ais_phy::aton_type_to_string(unsigned int type) {
    static const char *aton_types[] = {
        "Not specified",
        "Reference point",
        "RACON",
        "Fixed offshore structure",
        "Spare",
        "Light, without sectors",
        "Light, with sectors",
        "Leading light front",
        "Leading light rear",
        "Beacon, cardinal N",
        "Beacon, cardinal E",
        "Beacon, cardinal S",
        "Beacon, cardinal W",
        "Beacon, port hand",
        "Beacon, starboard hand",
        "Beacon, preferred channel port hand",
        "Beacon, preferred channel starboard hand",
        "Beacon, isolated danger",
        "Beacon, safe water",
        "Beacon, special mark",
        "Cardinal mark N",
        "Cardinal mark E",
        "Cardinal mark S",
        "Cardinal mark W",
        "Port hand mark",
        "Starboard hand mark",
        "Preferred channel port hand",
        "Preferred channel starboard hand",
        "Isolated danger",
        "Safe water",
        "Special mark",
        "Light vessel / LANBY / rig",
    };

    if (type < sizeof(aton_types) / sizeof(char *))
        return aton_types[type];

    return "Unknown";
}

const char *kis_ais_phy::mid_to_country(unsigned int mid) {
    // ITU maritime identification digits
    static const std::unordered_map<unsigned int, const char *> mid_map = {
        {201, "Albania"}, {202, "Andorra"}, {203, "Austria"}, {204, "Azores"},
        {205, "Belgium"}, {206, "Belarus"}, {207, "Bulgaria"}, {208, "Vatican"},
        {209, "Cyprus"}, {210, "Cyprus"}, {211, "Germany"}, {212, "Cyprus"},
        {213, "Georgia"}, {214, "Moldova"}, {215, "Malta"}, {216, "Armenia"},
        {218, "Germany"}, {219, "Denmark"}, {220, "Denmark"}, {224, "Spain"},
        {225, "Spain"}, {226, "France"}, {227, "France"}, {228, "France"},
        {229, "Malta"}, {230, "Finland"}, {231, "Faroe Islands"}, {232, "United Kingdom"},
        {233, "United Kingdom"}, {234, "United Kingdom"}, {235, "United Kingdom"},
        {236, "Gibraltar"}, {237, "Greece"}, {238, "Croatia"}, {239, "Greece"},
        {240, "Greece"}, {241, "Greece"}, {242, "Morocco"}, {243, "Hungary"},
        {244, "Netherlands"}, {245, "Netherlands"}, {246, "Netherlands"}, {247, "Italy"},
        {248, "Malta"}, {249, "Malta"}, {250, "Ireland"}, {251, "Iceland"},
        {252, "Liechtenstein"}, {253, "Luxembourg"}, {254, "Monaco"}, {255, "Madeira"},
        {256, "Malta"}, {257, "Norway"}, {258, "Norway"}, {259, "Norway"},
        {261, "Poland"}, {262, "Montenegro"}, {263, "Portugal"}, {264, "Romania"},
        {265, "Sweden"}, {266, "Sweden"}, {267, "Slovakia"}, {268, "San Marino"},
        {269, "Switzerland"}, {270, "Czech Republic"}, {271, "Turkey"}, {272, "Ukraine"},
        {273, "Russia"}, {274, "North Macedonia"}, {275, "Latvia"}, {276, "Estonia"},
        {277, "Lithuania"}, {278, "Slovenia"}, {279, "Serbia"},

        {301, "Anguilla"}, {303, "Alaska (USA)"}, {304, "Antigua and Barbuda"},
        {305, "Antigua and Barbuda"}, {306, "Caribbean Netherlands"}, {307, "Aruba"},
        {308, "Bahamas"}, {309, "Bahamas"}, {310, "Bermuda"}, {311, "Bahamas"},
        {312, "Belize"}, {314, "Barbados"}, {316, "Canada"}, {319, "Cayman Islands"},
        {321, "Costa Rica"}, {323, "Cuba"}, {325, "Dominica"}, {327, "Dominican Republic"},
        {329, "Guadeloupe"}, {330, "Grenada"}, {331, "Greenland"}, {332, "Guatemala"},
        {334, "Honduras"}, {336, "Haiti"}, {338, "USA"}, {339, "Jamaica"},
        {341, "Saint Kitts and Nevis"}, {343, "Saint Lucia"}, {345, "Mexico"},
        {347, "Martinique"}, {348, "Montserrat"}, {350, "Nicaragua"}, {351, "Panama"},
        {352, "Panama"}, {353, "Panama"}, {354, "Panama"}, {355, "Panama"},
        {356, "Panama"}, {357, "Panama"}, {358, "Puerto Rico"}, {359, "El Salvador"},
        {361, "Saint Pierre and Miquelon"}, {362, "Trinidad and Tobago"},
        {364, "Turks and Caicos Islands"}, {366, "USA"}, {367, "USA"}, {368, "USA"},
        {369, "USA"}, {370, "Panama"}, {371, "Panama"}, {372, "Panama"}, {373, "Panama"},
        {374, "Panama"}, {375, "Saint Vincent and the Grenadines"},
        {376, "Saint Vincent and the Grenadines"}, {377, "Saint Vincent and the Grenadines"},
        {378, "British Virgin Islands"}, {379, "US Virgin Islands"},

        {401, "Afghanistan"}, {403, "Saudi Arabia"}, {405, "Bangladesh"}, {408, "Bahrain"},
        {410, "Bhutan"}, {412, "China"}, {413, "China"}, {414, "China"}, {416, "Taiwan"},
        {417, "Sri Lanka"}, {419, "India"}, {422, "Iran"}, {423, "Azerbaijan"},
        {425, "Iraq"}, {428, "Israel"}, {431, "Japan"}, {432, "Japan"},
        {434, "Turkmenistan"}, {436, "Kazakhstan"}, {437, "Uzbekistan"}, {438, "Jordan"},
        {440, "South Korea"}, {441, "South Korea"}, {443, "Palestine"},
        {445, "North Korea"}, {447, "Kuwait"}, {450, "Lebanon"}, {451, "Kyrgyzstan"},
        {453, "Macao"}, {455, "Maldives"}, {457, "Mongolia"}, {459, "Nepal"},
        {461, "Oman"}, {463, "Pakistan"}, {466, "Qatar"}, {468, "Syria"},
        {470, "United Arab Emirates"}, {471, "United Arab Emirates"}, {472, "Tajikistan"},
        {473, "Yemen"}, {475, "Yemen"}, {477, "Hong Kong"}, {478, "Bosnia and Herzegovina"},

        {501, "Adelie Land"}, {503, "Australia"}, {506, "Myanmar"}, {508, "Brunei"},
        {510, "Micronesia"}, {511, "Palau"}, {512, "New Zealand"}, {514, "Cambodia"},
        {515, "Cambodia"}, {516, "Christmas Island"}, {518, "Cook Islands"}, {520, "Fiji"},
        {523, "Cocos (Keeling) Islands"}, {525, "Indonesia"}, {529, "Kiribati"},
        {531, "Laos"}, {533, "Malaysia"}, {536, "Northern Mariana Islands"},
        {538, "Marshall Islands"}, {540, "New Caledonia"}, {542, "Niue"}, {544, "Nauru"},
        {546, "French Polynesia"}, {548, "Philippines"}, {550, "Timor-Leste"},
        {553, "Papua New Guinea"}, {555, "Pitcairn Island"}, {557, "Solomon Islands"},
        {559, "American Samoa"}, {561, "Samoa"}, {563, "Singapore"}, {564, "Singapore"},
        {565, "Singapore"}, {566, "Singapore"}, {567, "Thailand"}, {570, "Tonga"},
        {572, "Tuvalu"}, {574, "Vietnam"}, {576, "Vanuatu"}, {577, "Vanuatu"},
        {578, "Wallis and Futuna"},

        {601, "South Africa"}, {603, "Angola"}, {605, "Algeria"},
        {607, "Saint Paul and Amsterdam Islands"}, {608, "Ascension Island"},
        {609, "Burundi"}, {610, "Benin"}, {611, "Botswana"},
        {612, "Central African Republic"}, {613, "Cameroon"}, {615, "Congo"},
        {616, "Comoros"}, {617, "Cabo Verde"}, {618, "Crozet Archipelago"},
        {619, "Cote d'Ivoire"}, {620, "Comoros"}, {621, "Djibouti"}, {622, "Egypt"},
        {624, "Ethiopia"}, {625, "Eritrea"}, {626, "Gabon"}, {627, "Ghana"},
        {629, "Gambia"}, {630, "Guinea-Bissau"}, {631, "Equatorial Guinea"},
        {632, "Guinea"}, {633, "Burkina Faso"}, {634, "Kenya"}, {635, "Kerguelen Islands"},
        {636, "Liberia"}, {637, "Liberia"}, {638, "South Sudan"}, {642, "Libya"},
        {644, "Lesotho"}, {645, "Mauritius"}, {647, "Madagascar"}, {649, "Mali"},
        {650, "Mozambique"}, {654, "Mauritania"}, {655, "Malawi"}, {656, "Niger"},
        {657, "Nigeria"}, {659, "Namibia"}, {660, "Reunion"}, {661, "Rwanda"},
        {662, "Sudan"}, {663, "Senegal"}, {664, "Seychelles"}, {665, "Saint Helena"},
        {666, "Somalia"}, {667, "Sierra Leone"}, {668, "Sao Tome and Principe"},
        {669, "Eswatini"}, {670, "Chad"}, {671, "Togo"}, {672, "Tunisia"},
        {674, "Tanzania"}, {675, "Uganda"}, {676, "DR Congo"}, {677, "Tanzania"},
        {678, "Zambia"}, {679, "Zimbabwe"},

        {701, "Argentina"}, {710, "Brazil"}, {720, "Bolivia"}, {725, "Chile"},
        {730, "Colombia"}, {735, "Ecuador"}, {740, "Falkland Islands"},
        {745, "French Guiana"}, {750, "Guyana"}, {755, "Paraguay"}, {760, "Peru"},
        {765, "Suriname"}, {770, "Uruguay"}, {775, "Venezuela"},
    };

    auto k = mid_map.find(mid);

    if (k != mid_map.end())
        return k->second;

    return "Unknown";
}

