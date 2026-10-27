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

#include "btle_continuity.h"

#include <arpa/inet.h>
#include <sys/socket.h>

namespace btle_continuity {

namespace {

constexpr uint16_t apple_company_id = 0x004C;

constexpr uint8_t ibeacon_type = 0x02;
constexpr uint8_t proximity_pairing_type = 0x07;
constexpr uint8_t findmy_type = 0x12;

/* HomeKit types carry the length in the low 5 bits */
constexpr uint8_t hap_length_mask = 0x1F;

constexpr uint8_t nearby_status_primary = 0x01;
constexpr uint8_t nearby_status_airdrop = 0x04;
constexpr uint8_t nearby_data_airpods = 0x01;
constexpr uint8_t nearby_data_wifi = 0x04;

constexpr uint8_t action_flag_auth_tag = 0x80;
constexpr size_t action_auth_tag_len = 3;

constexpr uint8_t homekit_sf_unpaired = 0x01;

constexpr size_t homekit_min_len = 13;
constexpr size_t airplay_target_min_len = 6;
constexpr size_t airprint_min_len = 22;
constexpr size_t tethering_source_min_len = 6;

constexpr char hexdigits[] = "0123456789abcdef";

std::string to_hex(const uint8_t *data, size_t len) {
    std::string r;
    r.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        r.push_back(hexdigits[data[i] >> 4]);
        r.push_back(hexdigits[data[i] & 0x0F]);
    }
    return r;
}

std::string to_ipv4(const uint8_t *data) {
    std::string r;
    r.reserve(15);
    for (size_t i = 0; i < 4; i++) {
        if (i)
            r.push_back('.');
        r += std::to_string(data[i]);
    }
    return r;
}

std::string to_ipv6(const uint8_t *data) {
    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, data, buf, sizeof(buf)) == nullptr)
        return std::string();
    return std::string(buf);
}

constexpr bool is_hap_type(uint8_t type) {
    return type == static_cast<uint8_t>(msg_type::homekit) ||
        type == static_cast<uint8_t>(msg_type::homekit_encrypted);
}

/* Types which are only noted as present */
constexpr bool is_presence_type(uint8_t type) {
    switch (static_cast<msg_type>(type)) {
        case msg_type::observed_on_ios:
        case msg_type::airdrop:
        case msg_type::hey_siri:
        case msg_type::airplay_source:
        case msg_type::magic_switch:
        case msg_type::handoff:
        case msg_type::tethering_target:
        case msg_type::homekit_encrypted:
            return true;
        default:
            return false;
    }
}

bool decode_nearby_info(const uint8_t *v, size_t vlen, nearby_info& ni) {
    if (vlen < 1)
        return false;

    ni = nearby_info{};
    ni.present = true;
    ni.status_flags = v[0] >> 4;
    ni.activity = static_cast<activity_level>(v[0] & 0x0F);
    ni.primary_device = ni.status_flags & nearby_status_primary;
    ni.airdrop_receiving = ni.status_flags & nearby_status_airdrop;

    if (vlen >= 2) {
        ni.has_data_flags = true;
        ni.data_flags = v[1];
        ni.wifi_on = v[1] & nearby_data_wifi;
        ni.airpods_connected = v[1] & nearby_data_airpods;
    }

    return true;
}

bool decode_nearby_action(const uint8_t *v, size_t vlen, nearby_action& na) {
    if (vlen < 2)
        return false;

    na = nearby_action{};
    na.present = true;
    na.flags = v[0];
    na.type = static_cast<action_type>(v[1]);

    if (na.type == action_type::ios_setup) {
        size_t offt = 2;
        if (na.flags & action_flag_auth_tag)
            offt += action_auth_tag_len;
        if (offt < vlen)
            na.device_class = v[offt] >> 4;
    }

    return true;
}

bool decode_homekit(const uint8_t *v, size_t vlen, homekit& hk) {
    if (vlen < homekit_min_len)
        return false;

    hk = homekit{};
    hk.present = true;
    hk.status_flags = v[0];
    hk.paired = (v[0] & homekit_sf_unpaired) == 0;
    hk.device_id = to_hex(v + 1, 6);
    hk.category = static_cast<homekit_category>((uint16_t) v[7] | ((uint16_t) v[8] << 8));
    hk.global_state = (uint16_t) v[9] | ((uint16_t) v[10] << 8);
    hk.config_number = v[11];
    hk.compatible_version = v[12];

    return true;
}

bool decode_airplay_target(const uint8_t *v, size_t vlen, airplay_target& at) {
    if (vlen < airplay_target_min_len)
        return false;

    at = airplay_target{};
    at.present = true;
    at.flags = v[0];
    at.config_seed = v[1];
    at.ipv4 = to_ipv4(v + 2);

    return true;
}

bool decode_airprint(const uint8_t *v, size_t vlen, airprint& ap) {
    if (vlen < airprint_min_len)
        return false;

    ap = airprint{};
    ap.present = true;
    ap.address_type = v[0];
    ap.resource_path_type = v[1];
    ap.security_type = v[2];
    ap.address = to_ipv6(v + 5);

    return true;
}

bool decode_tethering_source(const uint8_t *v, size_t vlen, tethering_source& ts) {
    if (vlen < tethering_source_min_len)
        return false;

    ts = tethering_source{};
    ts.present = true;
    ts.version = v[0];
    ts.flags = v[1];

    /* Sources disagree on the width; a second byte other than 0 isn't a percent */
    const uint16_t battery = (uint16_t) v[2] | ((uint16_t) v[3] << 8);
    if (battery <= 100) {
        ts.battery_known = true;
        ts.battery = (uint8_t) battery;
    }

    ts.cell = static_cast<cell_service>(v[4]);
    ts.signal_bars = v[5];

    return true;
}

}

bool decode_manuf_data(const uint8_t *data, size_t len, info& out) {
    out = info{};

    if (data == nullptr || len < 4)
        return false;

    const uint16_t company = (uint16_t) data[0] | ((uint16_t) data[1] << 8);

    if (company != apple_company_id)
        return false;

    const uint8_t *p = data + 2;
    const size_t plen = len - 2;
    size_t offt = 0;

    while (plen - offt >= 2) {
        const uint8_t type = p[offt];
        uint8_t tlv_len = p[offt + 1];

        if (is_hap_type(type))
            tlv_len &= hap_length_mask;

        if (tlv_len > plen - offt - 2)
            break;

        const uint8_t *v = p + offt + 2;
        offt += 2 + (size_t) tlv_len;

        if (type == ibeacon_type || type == proximity_pairing_type || type == findmy_type)
            continue;

        bool ok = false;

        switch (static_cast<msg_type>(type)) {
            case msg_type::nearby_info:
                ok = decode_nearby_info(v, tlv_len, out.nearby_info);
                break;
            case msg_type::nearby_action:
                ok = decode_nearby_action(v, tlv_len, out.nearby_action);
                break;
            case msg_type::homekit:
                ok = decode_homekit(v, tlv_len, out.homekit);
                break;
            case msg_type::airplay_target:
                ok = decode_airplay_target(v, tlv_len, out.airplay_target);
                break;
            case msg_type::airprint:
                ok = decode_airprint(v, tlv_len, out.airprint);
                break;
            case msg_type::tethering_source:
                ok = decode_tethering_source(v, tlv_len, out.tethering_source);
                break;
            default:
                ok = is_presence_type(type);
                break;
        }

        if (ok && type < 32)
            out.seen_types |= (uint32_t) 1 << type;
    }

    return out.seen_types != 0;
}

const char *type_str(msg_type t) {
    switch (t) {
        case msg_type::observed_on_ios:
            return "observed_on_ios";
        case msg_type::airprint:
            return "airprint";
        case msg_type::airdrop:
            return "airdrop";
        case msg_type::homekit:
            return "homekit";
        case msg_type::hey_siri:
            return "hey_siri";
        case msg_type::airplay_target:
            return "airplay_target";
        case msg_type::airplay_source:
            return "airplay_source";
        case msg_type::magic_switch:
            return "magic_switch";
        case msg_type::handoff:
            return "handoff";
        case msg_type::tethering_target:
            return "tethering_target";
        case msg_type::tethering_source:
            return "tethering_source";
        case msg_type::nearby_action:
            return "nearby_action";
        case msg_type::nearby_info:
            return "nearby_info";
        case msg_type::homekit_encrypted:
            return "homekit_encrypted";
        default:
            return "unknown";
    }
}

const char *activity_str(activity_level a) {
    switch (a) {
        case activity_level::unknown:
            return "Activity level unknown";
        case activity_level::reporting_disabled:
            return "Activity reporting disabled";
        case activity_level::idle:
            return "User idle";
        case activity_level::audio_screen_off:
            return "Audio playing, screen off";
        case activity_level::screen_on:
            return "Screen on";
        case activity_level::screen_on_video:
            return "Screen on, video playing";
        case activity_level::watch_on_wrist_unlocked:
            return "Watch on wrist and unlocked";
        case activity_level::recent_interaction:
            return "Recent user interaction";
        case activity_level::driving:
            return "Driving";
        case activity_level::phone_call:
            return "Phone or FaceTime call";
        default:
            return "Unknown";
    }
}

const char *action_type_str(action_type a) {
    switch (a) {
        case action_type::apple_tv_setup:
            return "Apple TV tap to setup";
        case action_type::mobile_backup:
            return "Mobile backup";
        case action_type::watch_setup:
            return "Watch setup";
        case action_type::apple_tv_pair:
            return "Apple TV pair";
        case action_type::internet_relay:
            return "Internet relay";
        case action_type::wifi_password:
            return "Wi-Fi password";
        case action_type::ios_setup:
            return "iOS setup";
        case action_type::repair:
            return "Repair";
        case action_type::speaker_setup:
            return "Speaker setup";
        case action_type::apple_pay:
            return "Apple Pay";
        case action_type::whole_home_audio_setup:
            return "Whole home audio setup";
        case action_type::developer_tools_pairing:
            return "Developer tools pairing request";
        case action_type::answered_call:
            return "Answered call";
        case action_type::ended_call:
            return "Ended call";
        case action_type::dd_ping:
            return "DD ping";
        case action_type::dd_pong:
            return "DD pong";
        case action_type::remote_auto_fill:
            return "Remote auto fill";
        case action_type::companion_link_prox:
            return "Companion link proximity";
        case action_type::remote_management:
            return "Remote management";
        case action_type::remote_auto_fill_pong:
            return "Remote auto fill pong";
        case action_type::remote_display:
            return "Remote display";
        default:
            return "Unknown";
    }
}

const char *homekit_category_str(homekit_category c) {
    switch (c) {
        case homekit_category::other:
            return "Other";
        case homekit_category::bridge:
            return "Bridge";
        case homekit_category::fan:
            return "Fan";
        case homekit_category::garage_door_opener:
            return "Garage door opener";
        case homekit_category::lightbulb:
            return "Lightbulb";
        case homekit_category::door_lock:
            return "Door lock";
        case homekit_category::outlet:
            return "Outlet";
        case homekit_category::switch_:
            return "Switch";
        case homekit_category::thermostat:
            return "Thermostat";
        case homekit_category::sensor:
            return "Sensor";
        case homekit_category::security_system:
            return "Security system";
        case homekit_category::door:
            return "Door";
        case homekit_category::window:
            return "Window";
        case homekit_category::window_covering:
            return "Window covering";
        case homekit_category::programmable_switch:
            return "Programmable switch";
        case homekit_category::range_extender:
            return "Range extender";
        case homekit_category::ip_camera:
            return "IP camera";
        case homekit_category::video_doorbell:
            return "Video doorbell";
        case homekit_category::air_purifier:
            return "Air purifier";
        case homekit_category::heater:
            return "Heater";
        case homekit_category::air_conditioner:
            return "Air conditioner";
        case homekit_category::humidifier:
            return "Humidifier";
        case homekit_category::dehumidifier:
            return "Dehumidifier";
        case homekit_category::sprinklers:
            return "Sprinklers";
        case homekit_category::faucets:
            return "Faucets";
        case homekit_category::shower_systems:
            return "Shower systems";
        default:
            return "Unknown";
    }
}

const char *cell_service_str(cell_service c) {
    switch (c) {
        case cell_service::gsm_4g:
            return "4G (GSM)";
        case cell_service::rtt_1x:
            return "1xRTT";
        case cell_service::gprs:
            return "GPRS";
        case cell_service::edge:
            return "EDGE";
        case cell_service::evdo_3g:
            return "3G (EV-DO)";
        case cell_service::umts_3g:
            return "3G";
        case cell_service::g4:
            return "4G";
        case cell_service::lte:
            return "LTE";
        default:
            return "Unknown";
    }
}

const char *device_class_str(uint8_t c) {
    switch (c) {
        case 0x2:
            return "iPhone";
        case 0x4:
            return "iPod";
        case 0x6:
            return "iPad";
        case 0x8:
            return "Audio accessory";
        case 0xA:
            return "Mac";
        case 0xC:
            return "Apple TV";
        case 0xE:
            return "Watch";
        default:
            return "Unknown";
    }
}

std::string types_str(uint32_t mask) {
    std::string r;

    for (unsigned int i = 0; i < 32; i++) {
        if ((mask & ((uint32_t) 1 << i)) == 0)
            continue;

        const char *name = type_str(static_cast<msg_type>(i));

        if (!r.empty())
            r += ",";
        r += name;
    }

    return r;
}

}
