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

#ifndef __BTLE_BATTERY_H__
#define __BTLE_BATTERY_H__

/* Battery levels which devices advertise in the clear, without a connection.  The
 * GATT Battery Service needs a connection, so it's only read here when a device
 * repeats it as service data.
 *
 *   Apple Proximity Pairing (manufacturer 0x004C, Continuity type 0x07), AirPods and
 *   Beats: model in bytes 1-2; byte 3 bit 0x20 is the orientation, which swaps left
 *   and right; byte 4 holds the left and right levels as nibbles (0-10, tens of a
 *   percent; 15 not connected); byte 5 the charging flags (0x10, 0x20 for the buds,
 *   0x40 for the case) and the case level.  Orientation rule from OpenPods.
 *
 *   Google Fast Pair (service data 0xFE2C), not discoverable: a flags byte, then
 *   length/type fields (0bLLLLTTTT); type 3 or 4 is the battery field, one byte per
 *   part (left, right, case): bit 7 charging, bits 0-6 percent, 0x7F unknown.  The
 *   account key filter and salt are skipped and never kept.
 *
 *   BTHome v2 (0xFCD2): a device information byte (bit 0 encrypted, bits 5-7
 *   version), then objects in ascending id order; 0x00 is a packet id (1 byte) and
 *   0x01 the battery percent.
 *
 *   Environmental Sensing service data (0x181A) from the pvvx and ATC1441 custom
 *   thermometer firmware: pvvx is 15 bytes (little endian; mV at 10, percent at 12),
 *   ATC1441 13 bytes (big endian; percent at 9, mV at 10).
 *
 *   Eddystone TLM (0xFEAA, frame 0x20, version 0): battery mV at 2, big endian, 0 if
 *   not supported.
 *
 *   Battery Service (0x180F) as service data: one byte, percent.
 *
 *   Ruuvi data format 5 (manufacturer 0x0499): bytes 14-15 big endian, battery mV is
 *   1600 + (value >> 5).
 */

#include <cstddef>
#include <cstdint>

namespace btle_battery {

struct level {
    bool known = false;
    uint8_t percent = 0;
    bool charging = false;
};

struct info {
    /* apple_proximity, fast_pair, bthome, pvvx, atc1441, eddystone_tlm,
     * battery_service, ruuvi */
    const char *source = nullptr;
    level main;
    /* Battery voltage, 0 when not advertised */
    uint16_t millivolts = 0;
    /* Earbuds */
    bool has_parts = false;
    level left, right, case_;
};

/* 16-bit service data: the UUID, then the payload */
bool decode_service_data(const uint8_t *data, size_t len, info& out);

/* Manufacturer data: the company ID, then the payload */
bool decode_manuf_data(const uint8_t *data, size_t len, info& out);

}

#endif
