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

#ifndef __BTLE_BEACON_H__
#define __BTLE_BEACON_H__

/* The identity proximity beacons advertise:
 *
 *   iBeacon (Apple 0x004C, type 0x02, length 0x15): a 16 byte proximity UUID, then
 *   major and minor, big endian.
 *
 *   AltBeacon (any company, beacon code 0xBEAC): a 20 byte ID, by convention a 16 byte
 *   UUID and two 16 bit values like iBeacon's.
 *
 *   Eddystone (service data 0xFEAA): UID frames (0x00) carry a 10 byte namespace and a
 *   6 byte instance, URL frames (0x10) a compressed URL.
 */

#include <cstddef>
#include <cstdint>
#include <string>

namespace btle_beacon {

enum class beacon_type : uint8_t {
    none,
    ibeacon,
    altbeacon,
    eddystone_uid,
    eddystone_url,
};

struct info {
    beacon_type type = beacon_type::none;

    /* iBeacon and AltBeacon */
    std::string uuid;
    uint16_t major = 0;
    uint16_t minor = 0;

    /* Eddystone UID, as hex */
    std::string eddystone_namespace;
    std::string eddystone_instance;

    /* Eddystone URL */
    std::string url;
};

bool decode_manuf_data(const uint8_t *data, size_t len, info& out);
bool decode_service_data(const uint8_t *data, size_t len, info& out);

const char *type_str(beacon_type t);

}

#endif

