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

#include <cstring>

#include "opendroneid.h"

namespace odid {

namespace {

uint16_t le16(const uint8_t *p) {
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

uint32_t le32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
        ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

int32_t le32s(const uint8_t *p) {
    uint32_t v = le32(p);
    int32_t r;
    std::memcpy(&r, &v, sizeof(r));
    return r;
}

/* Fixed-width text field, trimmed at the first NUL */
std::string text_field(const uint8_t *p, size_t len) {
    size_t n = 0;
    while (n < len && p[n] != 0)
        n++;
    return std::string((const char *) p, n);
}

std::string hex_field(const uint8_t *p, size_t len) {
    static const char hexd[] = "0123456789abcdef";
    std::string r;
    r.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        r.push_back(hexd[p[i] >> 4]);
        r.push_back(hexd[p[i] & 0xF]);
    }
    return r;
}

/* Altitudes are 0.5m steps offset by -1000m; the encoded 0 (-1000m) means unknown */
bool decode_alt(const uint8_t *p, double& out) {
    uint16_t v = le16(p);
    out = (v * 0.5) - 1000.0;
    return v != 0;
}

/* Lat/lon are 1e-7 degree steps; 0,0 means unknown */
bool decode_latlon(const uint8_t *p, double& lat, double& lon) {
    int32_t ilat = le32s(p);
    int32_t ilon = le32s(p + 4);

    lat = ilat * 1e-7;
    lon = ilon * 1e-7;

    if (ilat == 0 && ilon == 0)
        return false;

    return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

void decode_basic_id(const uint8_t *m, basic_id_msg& b) {
    b.id_type = m[1] >> 4;
    b.ua_type = m[1] & 0xF;

    switch (static_cast<id_type>(b.id_type)) {
        case id_type::utm_uuid:
            b.uas_id = hex_field(m + 2, 16);
            break;
        case id_type::session_id:
            b.uas_id = hex_field(m + 2, 20);
            break;
        default:
            b.uas_id = text_field(m + 2, 20);
            break;
    }
}

void decode_location(const uint8_t *m, location_msg& l) {
    l.status = m[1] >> 4;
    l.height_type = (m[1] >> 2) & 0x1;

    bool ew = m[1] & 0x2;
    bool speed_mult = m[1] & 0x1;

    l.direction = m[2] + (ew ? 180 : 0);
    l.direction_valid = l.direction < 360;

    /* 255 with the multiplier set is the "unknown" speed */
    if (speed_mult) {
        l.speed_h = (m[3] * 0.75) + (255 * 0.25);
        l.speed_valid = m[3] != 255;
    } else {
        l.speed_h = m[3] * 0.25;
        l.speed_valid = true;
    }

    int8_t sv;
    std::memcpy(&sv, &m[4], 1);
    l.speed_v = sv * 0.5;
    l.speed_v_valid = sv >= -124 && sv <= 124;

    l.latlon_valid = decode_latlon(m + 5, l.lat, l.lon);
    l.alt_baro_valid = decode_alt(m + 13, l.alt_baro);
    l.alt_geo_valid = decode_alt(m + 15, l.alt_geo);
    l.height_valid = decode_alt(m + 17, l.height);

    l.horiz_accuracy = m[19] & 0xF;
    l.vert_accuracy = m[19] >> 4;
    l.speed_accuracy = m[20] & 0xF;
    l.baro_accuracy = m[20] >> 4;

    uint16_t ts = le16(m + 21);
    l.timestamp = ts / 10.0;
    l.timestamp_valid = ts <= 36000;

    l.ts_accuracy = m[23] & 0xF;
}

void decode_auth(const uint8_t *m, auth_msg& a) {
    a.auth_type = m[1] >> 4;
    a.page = m[1] & 0xF;

    if (a.page == 0) {
        a.last_page = m[2];
        a.length = m[3];
        a.timestamp = le32(m + 4);
        a.data = std::string((const char *) m + 8, 17);
    } else {
        a.data = std::string((const char *) m + 2, 23);
    }
}

void decode_self_id(const uint8_t *m, self_id_msg& s) {
    s.desc_type = m[1];
    s.desc = text_field(m + 2, 23);
}

void decode_system(const uint8_t *m, system_msg& s) {
    s.operator_location_type = m[1] & 0x3;
    s.classification_type = (m[1] >> 2) & 0x7;

    s.operator_latlon_valid = decode_latlon(m + 2, s.operator_lat, s.operator_lon);

    s.area_count = le16(m + 10);
    s.area_radius = m[12] * 10.0;
    s.area_ceiling_valid = decode_alt(m + 13, s.area_ceiling);
    s.area_floor_valid = decode_alt(m + 15, s.area_floor);

    s.eu_class = m[17] & 0xF;
    s.eu_category = m[17] >> 4;

    s.operator_alt_valid = decode_alt(m + 18, s.operator_alt_geo);

    uint32_t ts = le32(m + 20);
    s.timestamp = ts == 0 ? 0 : (uint64_t) ts + epoch_offset;
}

void decode_operator_id(const uint8_t *m, operator_id_msg& o) {
    o.id_type = m[1];
    o.operator_id = text_field(m + 2, 20);
}

/* Counter followed by a message or message pack, shared by every transport */
bool decode_service_info(const uint8_t *data, size_t len, uint8_t& counter,
        std::vector<message>& out) {
    if (len < 1 + message_len)
        return false;

    counter = data[0];
    return decode_messages(data + 1, len - 1, out);
}

}

bool decode_message(const uint8_t *data, size_t len, message& out) {
    if (data == nullptr || len < message_len)
        return false;

    out = message{};
    out.version = data[0] & 0xF;

    switch (static_cast<msg_type>(data[0] >> 4)) {
        case msg_type::basic_id:
            out.type = msg_type::basic_id;
            decode_basic_id(data, out.basic_id);
            return true;
        case msg_type::location:
            out.type = msg_type::location;
            decode_location(data, out.location);
            return true;
        case msg_type::auth:
            out.type = msg_type::auth;
            decode_auth(data, out.auth);
            return true;
        case msg_type::self_id:
            out.type = msg_type::self_id;
            decode_self_id(data, out.self_id);
            return true;
        case msg_type::system:
            out.type = msg_type::system;
            decode_system(data, out.system);
            return true;
        case msg_type::operator_id:
            out.type = msg_type::operator_id;
            decode_operator_id(data, out.operator_id);
            return true;
        default:
            return false;
    }
}

bool decode_messages(const uint8_t *data, size_t len, std::vector<message>& out) {
    if (data == nullptr || len < message_len)
        return false;

    if (static_cast<msg_type>(data[0] >> 4) != msg_type::pack) {
        message m;
        if (!decode_message(data, len, m))
            return false;
        out.push_back(m);
        return true;
    }

    /* Pack: header, message size, count, then count messages; packs don't nest */
    size_t msg_sz = data[1];
    size_t count = data[2];

    if (msg_sz != message_len || count == 0 || count > max_pack_messages)
        return false;

    if (len < 3 + (count * message_len))
        return false;

    bool any = false;

    for (size_t i = 0; i < count; i++) {
        message m;
        if (decode_message(data + 3 + (i * message_len), message_len, m)) {
            out.push_back(m);
            any = true;
        }
    }

    return any;
}

bool decode_ble_service_data(const uint8_t *data, size_t len, uint8_t& counter,
        std::vector<message>& out) {
    if (data == nullptr || len < 3)
        return false;

    if (le16(data) != ble_service_uuid || data[2] != app_code)
        return false;

    return decode_service_info(data + 3, len - 3, counter, out);
}

bool decode_wifi_vendor_ie(const uint8_t *data, size_t len, uint8_t& counter,
        std::vector<message>& out) {
    if (data == nullptr || len < 1 || data[0] != wifi_oui_type)
        return false;

    return decode_service_info(data + 1, len - 1, counter, out);
}

bool decode_nan_attributes(const uint8_t *data, size_t len, uint8_t& counter,
        std::vector<message>& out) {
    if (data == nullptr)
        return false;

    /* Attributes are id, 16 bit length, body */
    size_t pos = 0;
    while (pos + 3 <= len) {
        uint8_t attr_id = data[pos];
        size_t attr_len = le16(data + pos + 1);
        const uint8_t *attr = data + pos + 3;

        if (attr_len > len - pos - 3)
            return false;

        pos += 3 + attr_len;

        /* Service Descriptor Attribute */
        if (attr_id != 0x03 || attr_len < 9)
            continue;

        if (std::memcmp(attr, nan_service_id, sizeof(nan_service_id)) != 0)
            continue;

        /* Service ID, instance ID, requestor instance ID, service control */
        uint8_t control = attr[8];
        size_t off = 9;

        /* Optional fields in order: binding bitmap, matching filter, service
         * response filter, service info */
        if (control & 0x40)
            off += 2;

        if (control & 0x04) {
            if (off >= attr_len)
                return false;
            off += 1 + attr[off];
        }

        if (control & 0x08) {
            if (off >= attr_len)
                return false;
            off += 1 + attr[off];
        }

        if (!(control & 0x10) || off >= attr_len)
            continue;

        size_t info_len = attr[off];
        off++;

        if (info_len > attr_len - off)
            return false;

        return decode_service_info(attr + off, info_len, counter, out);
    }

    return false;
}

const char *ua_type_str(uint8_t ua_type) {
    switch (ua_type) {
        case 0: return "None";
        case 1: return "Aeroplane";
        case 2: return "Helicopter or multirotor";
        case 3: return "Gyroplane";
        case 4: return "Hybrid lift";
        case 5: return "Ornithopter";
        case 6: return "Glider";
        case 7: return "Kite";
        case 8: return "Free balloon";
        case 9: return "Captive balloon";
        case 10: return "Airship";
        case 11: return "Free fall or parachute";
        case 12: return "Rocket";
        case 13: return "Tethered powered aircraft";
        case 14: return "Ground obstacle";
        default: return "Other";
    }
}

const char *id_type_str(uint8_t id_type) {
    switch (static_cast<odid::id_type>(id_type)) {
        case odid::id_type::none: return "None";
        case odid::id_type::serial: return "Serial number";
        case odid::id_type::caa_registration: return "CAA registration";
        case odid::id_type::utm_uuid: return "UTM UUID";
        case odid::id_type::session_id: return "Session ID";
        default: return "Unknown";
    }
}

const char *status_str(uint8_t status) {
    switch (status) {
        case 0: return "Undeclared";
        case 1: return "Ground";
        case 2: return "Airborne";
        case 3: return "Emergency";
        case 4: return "Remote ID system failure";
        default: return "Unknown";
    }
}

}
