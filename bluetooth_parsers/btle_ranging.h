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


#ifndef __BTLE_RANGING_H__
#define __BTLE_RANGING_H__

/* What a device says about its own transmit power, for estimating distance from the
 * signal received.  Beacons advertise a calibrated level:
 *
 *   iBeacon (Apple 0x004C, type 0x02, length 0x15): the last byte is the RSSI
 *   measured at 1 m.
 *
 *   AltBeacon (any company, beacon code 0xBEAC, 24 bytes): byte 22 is the RSSI at
 *   1 m.
 *
 *   Eddystone UID (frame 0x00) and URL (0x10) on 0xFEAA: byte 1 is the power at 0 m.
 *
 * Other devices may send the TX Power Level record (0x0A), the radiated power in dBm;
 * Ruuvi data format 5 has it in the low 5 bits of bytes 14-15 (-40 + 2 * value).
 * Power at 0 m and the radiated power are moved to 1 m with the 2.4 GHz free space
 * loss over the first meter, about 41 dB.
 */

#include <cstddef>
#include <cstdint>

namespace btle_ranging {

constexpr int free_space_loss_1m = 41;

/* Better sources replace worse ones on the same device */
enum class source : uint8_t {
    none = 0,
    tx_power_level = 1,
    ruuvi = 2,
    eddystone = 3,
    altbeacon = 4,
    ibeacon = 5,
};

struct info {
    source src = source::none;
    /* Expected signal at 1 m, dBm */
    int ref_1m = 0;
};

bool decode_service_data(const uint8_t *data, size_t len, info& out);
bool decode_manuf_data(const uint8_t *data, size_t len, info& out);

/* From the TX Power Level record */
info from_tx_power(int8_t tx_power);

const char *source_str(source s);

/* Log-distance path loss: 10 ^ ((ref_1m - rssi) / (10 * exponent)), in meters,
 * held between 0.1 and 1000 */
double estimate_distance(int ref_1m, double rssi, double exponent);

}

#endif
