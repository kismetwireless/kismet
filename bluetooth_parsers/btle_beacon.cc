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

#include "btle_beacon.h"

#include <iterator>

namespace btle_beacon {

namespace {

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

std::string to_uuid(const uint8_t *data) {
    std::string r;
    r.reserve(36);
    for (size_t i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            r.push_back('-');
        r.push_back(hexdigits[data[i] >> 4]);
        r.push_back(hexdigits[data[i] & 0x0F]);
    }
    return r;
}

constexpr const char *url_schemes[] = {
    "http://www.", "https://www.", "http://", "https://",
};

constexpr const char *url_expansions[] = {
    ".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
    ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov",
};

}

bool decode_manuf_data(const uint8_t *data, size_t len, info& out) {
    if (data == nullptr || len < 4)
        return false;

    const uint16_t company = (uint16_t) data[0] | ((uint16_t) data[1] << 8);
    const uint8_t *p = data + 2;
    const size_t plen = len - 2;

    if (company == 0x004C && plen == 23 && p[0] == 0x02 && p[1] == 0x15) {
        out.type = beacon_type::ibeacon;
    } else if (plen == 24 && p[0] == 0xBE && p[1] == 0xAC) {
        out.type = beacon_type::altbeacon;
    } else {
        return false;
    }

    out.uuid = to_uuid(p + 2);
    out.major = ((uint16_t) p[18] << 8) | p[19];
    out.minor = ((uint16_t) p[20] << 8) | p[21];

    return true;
}

bool decode_service_data(const uint8_t *data, size_t len, info& out) {
    /* UUID, frame type, power */
    if (data == nullptr || len < 4)
        return false;

    const uint16_t uuid = (uint16_t) data[0] | ((uint16_t) data[1] << 8);

    if (uuid != 0xFEAA)
        return false;

    const uint8_t *p = data + 2;
    const size_t plen = len - 2;

    if (p[0] == 0x00) {
        /* Frame, power, namespace, instance; 2 reserved bytes may follow */
        if (plen < 18)
            return false;

        out.type = beacon_type::eddystone_uid;
        out.eddystone_namespace = to_hex(p + 2, 10);
        out.eddystone_instance = to_hex(p + 12, 6);
        return true;
    }

    if (p[0] == 0x10) {
        /* Frame, power, scheme, up to 17 bytes of URL */
        if (plen < 3 || plen > 20 || p[2] >= std::size(url_schemes))
            return false;

        std::string url = url_schemes[p[2]];

        for (size_t i = 3; i < plen; i++) {
            if (p[i] < std::size(url_expansions))
                url += url_expansions[p[i]];
            else if (p[i] > 0x20 && p[i] < 0x7F)
                url.push_back((char) p[i]);
            else
                return false;
        }

        out.type = beacon_type::eddystone_url;
        out.url = std::move(url);
        return true;
    }

    return false;
}

const char *type_str(beacon_type t) {
    switch (t) {
        case beacon_type::ibeacon:
            return "ibeacon";
        case beacon_type::altbeacon:
            return "altbeacon";
        case beacon_type::eddystone_uid:
            return "eddystone_uid";
        case beacon_type::eddystone_url:
            return "eddystone_url";
        default:
            return "none";
    }
}

}

