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

#include "btle_battery.h"

namespace btle_battery {

namespace {

constexpr uint16_t apple_company_id = 0x004C;
constexpr uint16_t ruuvi_company_id = 0x0499;
constexpr uint8_t apple_proximity_type = 0x07;

constexpr uint16_t fast_pair_uuid = 0xFE2C;
constexpr uint16_t bthome_uuid = 0xFCD2;
constexpr uint16_t env_sensing_uuid = 0x181A;
constexpr uint16_t eddystone_uuid = 0xFEAA;
constexpr uint16_t battery_service_uuid = 0x180F;

level percent_level(uint8_t pct, bool charging = false) {
    level l;
    if (pct <= 100) {
        l.known = true;
        l.percent = pct;
        l.charging = charging;
    }
    return l;
}

/* AirPods nibble: 0-10 in tens of a percent, 15 not connected */
level nibble_level(uint8_t n, bool charging) {
    level l;
    if (n <= 10) {
        l.known = true;
        l.percent = n * 10;
        l.charging = charging;
    }
    return l;
}

/* The lower of the two buds stands for the set */
void set_main_from_parts(info& out) {
    if (out.left.known && out.right.known)
        out.main = out.left.percent <= out.right.percent ? out.left : out.right;
    else if (out.left.known)
        out.main = out.left;
    else if (out.right.known)
        out.main = out.right;
}

bool decode_apple_proximity(const uint8_t *p, size_t plen, info& out) {
    size_t offt = 0;

    while (offt + 2 <= plen) {
        uint8_t type = p[offt];
        uint8_t tlv_len = p[offt + 1];
        const uint8_t *v = p + offt + 2;

        if (tlv_len > plen - offt - 2)
            return false;

        offt += 2 + tlv_len;

        if (type != apple_proximity_type)
            continue;

        if (tlv_len < 6)
            return false;

        const bool flipped = (v[3] & 0x20) == 0;
        const uint8_t lo = v[4] & 0x0F;
        const uint8_t hi = v[4] >> 4;

        out = info{};
        out.source = "apple_proximity";
        out.has_parts = true;
        out.left = nibble_level(flipped ? hi : lo, v[5] & (flipped ? 0x20 : 0x10));
        out.right = nibble_level(flipped ? lo : hi, v[5] & (flipped ? 0x10 : 0x20));
        out.case_ = nibble_level(v[5] & 0x0F, v[5] & 0x40);
        set_main_from_parts(out);

        return out.left.known || out.right.known || out.case_.known;
    }

    return false;
}

bool decode_fast_pair(const uint8_t *p, size_t plen, info& out) {
    /* Three bytes is a model ID, sent while discoverable */
    if (plen <= 3)
        return false;

    size_t offt = 1;

    while (offt < plen) {
        const uint8_t field_len = p[offt] >> 4;
        const uint8_t field_type = p[offt] & 0x0F;
        offt++;

        if (field_len > plen - offt)
            return false;

        if ((field_type == 3 || field_type == 4) && field_len >= 1 && field_len <= 3) {
            const uint8_t *b = p + offt;

            out = info{};
            out.source = "fast_pair";

            if (field_len == 1) {
                out.main = percent_level(b[0] & 0x7F, b[0] & 0x80);
            } else {
                out.has_parts = true;
                out.left = percent_level(b[0] & 0x7F, b[0] & 0x80);
                out.right = percent_level(b[1] & 0x7F, b[1] & 0x80);
                if (field_len == 3)
                    out.case_ = percent_level(b[2] & 0x7F, b[2] & 0x80);
                set_main_from_parts(out);
            }

            return out.main.known || out.case_.known;
        }

        offt += field_len;
    }

    return false;
}

bool decode_bthome(const uint8_t *p, size_t plen, info& out) {
    if (plen < 3)
        return false;

    /* Encrypted, or not version 2 */
    if ((p[0] & 0x01) || (p[0] >> 5) != 2)
        return false;

    size_t offt = 1;

    /* Packet id */
    if (p[offt] == 0x00)
        offt += 2;

    if (offt + 2 > plen || p[offt] != 0x01)
        return false;

    out = info{};
    out.source = "bthome";
    out.main = percent_level(p[offt + 1]);
    return out.main.known;
}

}

bool decode_service_data(const uint8_t *data, size_t len, info& out) {
    if (data == nullptr || len < 3)
        return false;

    const uint16_t uuid = (uint16_t) data[0] | ((uint16_t) data[1] << 8);
    const uint8_t *p = data + 2;
    const size_t plen = len - 2;

    switch (uuid) {
        case fast_pair_uuid:
            return decode_fast_pair(p, plen, out);

        case bthome_uuid:
            return decode_bthome(p, plen, out);

        case env_sensing_uuid:
            if (plen == 15) {
                out = info{};
                out.source = "pvvx";
                out.millivolts = (uint16_t) p[10] | ((uint16_t) p[11] << 8);
                out.main = percent_level(p[12]);
                return true;
            } else if (plen == 13) {
                out = info{};
                out.source = "atc1441";
                out.main = percent_level(p[9]);
                out.millivolts = ((uint16_t) p[10] << 8) | (uint16_t) p[11];
                return true;
            }
            return false;

        case eddystone_uuid:
            if (plen >= 4 && p[0] == 0x20 && p[1] == 0x00) {
                const uint16_t mv = ((uint16_t) p[2] << 8) | (uint16_t) p[3];
                if (mv == 0)
                    return false;
                out = info{};
                out.source = "eddystone_tlm";
                out.millivolts = mv;
                return true;
            }
            return false;

        case battery_service_uuid:
            if (plen != 1 || p[0] > 100)
                return false;
            out = info{};
            out.source = "battery_service";
            out.main = percent_level(p[0]);
            return true;

        default:
            return false;
    }
}

bool decode_manuf_data(const uint8_t *data, size_t len, info& out) {
    if (data == nullptr || len < 3)
        return false;

    const uint16_t company = (uint16_t) data[0] | ((uint16_t) data[1] << 8);
    const uint8_t *p = data + 2;
    const size_t plen = len - 2;

    if (company == apple_company_id)
        return decode_apple_proximity(p, plen, out);

    if (company == ruuvi_company_id && plen >= 24 && p[0] == 0x05) {
        const uint16_t power = ((uint16_t) p[13] << 8) | (uint16_t) p[14];
        const uint16_t v = power >> 5;

        /* All ones is "not available" */
        if (v == 0x7FF)
            return false;

        out = info{};
        out.source = "ruuvi";
        out.millivolts = 1600 + v;
        return true;
    }

    return false;
}

}
