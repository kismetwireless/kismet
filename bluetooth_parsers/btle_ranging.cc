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

#include "btle_ranging.h"

#include <cmath>

namespace btle_ranging {

bool decode_service_data(const uint8_t *data, size_t len, info& out) {
    if (data == nullptr || len < 4)
        return false;

    const uint16_t uuid = (uint16_t) data[0] | ((uint16_t) data[1] << 8);
    const uint8_t *p = data + 2;

    /* Eddystone UID and URL */
    if (uuid != 0xFEAA || (p[0] != 0x00 && p[0] != 0x10))
        return false;

    out.src = source::eddystone;
    out.ref_1m = (int8_t) p[1] - free_space_loss_1m;
    return true;
}

bool decode_manuf_data(const uint8_t *data, size_t len, info& out) {
    if (data == nullptr || len < 4)
        return false;

    const uint16_t company = (uint16_t) data[0] | ((uint16_t) data[1] << 8);
    const uint8_t *p = data + 2;
    const size_t plen = len - 2;

    if (company == 0x004C && plen == 23 && p[0] == 0x02 && p[1] == 0x15) {
        out.src = source::ibeacon;
        out.ref_1m = (int8_t) p[22];
        return true;
    }

    if (plen == 24 && p[0] == 0xBE && p[1] == 0xAC) {
        out.src = source::altbeacon;
        out.ref_1m = (int8_t) p[22];
        return true;
    }

    if (company == 0x0499 && plen >= 24 && p[0] == 0x05) {
        const uint8_t tx = p[14] & 0x1F;

        /* All ones is "not available" */
        if (tx == 0x1F)
            return false;

        out.src = source::ruuvi;
        out.ref_1m = -40 + 2 * tx - free_space_loss_1m;
        return true;
    }

    return false;
}

info from_tx_power(int8_t tx_power) {
    info i;
    i.src = source::tx_power_level;
    i.ref_1m = tx_power - free_space_loss_1m;
    return i;
}

const char *source_str(source s) {
    switch (s) {
        case source::tx_power_level:
            return "tx_power_level";
        case source::ruuvi:
            return "ruuvi";
        case source::eddystone:
            return "eddystone";
        case source::altbeacon:
            return "altbeacon";
        case source::ibeacon:
            return "ibeacon";
        default:
            return "none";
    }
}

double estimate_distance(int ref_1m, double rssi, double exponent) {
    if (exponent <= 0)
        exponent = 2.0;

    const double d = std::pow(10.0, (ref_1m - rssi) / (10.0 * exponent));

    if (d < 0.1)
        return 0.1;
    if (d > 1000)
        return 1000;
    return d;
}

}
