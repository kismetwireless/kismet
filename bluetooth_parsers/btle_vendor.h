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

#ifndef __BTLE_VENDOR_H__
#define __BTLE_VENDOR_H__

/* Vendor and ecosystem advertisements which say what a device is:
 *
 *   Microsoft CDP beacon (manufacturer 0x0006, scenario 0x01), [MS-CDP] "Bluetooth:
 *   Advertising Beacon": a byte of version (high 3 bits, 001) and device
 *   type (low 5 bits), a byte of version (001) and flags (bit 0, Nearby Share with
 *   everyone), then the device status byte (0x20 the BT address is the device ID,
 *   low nibble the extended status).  The 4 byte salt and the device hash which
 *   follow are skipped and never kept.
 *
 *   Microsoft Swift Pair (manufacturer 0x0006, beacon ID 0x03), learn.microsoft.com
 *   "Swift Pair": a sub scenario (0 LE only, 1 BR/EDR only, 2 LE and BR/EDR), a
 *   reserved RSSI byte (0x80), then for 1 the BR/EDR address (6 bytes, skipped), for
 *   1 and 2 a 3 byte class of device, then an optional display name.
 *
 *   Google Fast Pair (service data 0xFE2C), discoverable: exactly a 24 bit model ID,
 *   big endian (Fast Pair specification, "Advertising when discoverable").
 *
 *   Matter (service data 0xFFF6), opcode 0x00 commissionable, from connectedhomeip
 *   src/ble/CHIPBleServiceData.h and the Wireshark dissector: discriminator (12
 *   bits) and advertisement version (4 bits) little endian, vendor ID and product
 *   ID little endian, then flags (0x01 additional data, 0x02 extended announcement).
 *
 *   Car Connectivity Consortium (0xFFF5, Bluetooth SIG SDO UUID): the Digital Key
 *   payload isn't public, so only its presence is reported.
 *
 *   Tesla vehicles advertise the local name "S" + the first 8 bytes of the SHA1 of
 *   the VIN in hex + "C" (teslamotors/vehicle-command pkg/connector/ble).
 */

#include <cstddef>
#include <cstdint>
#include <string>

namespace btle_vendor {

enum class microsoft_type : uint8_t {
    none,
    cdp,
    swift_pair,
};

enum class swift_pair_mode : uint8_t {
    le = 0x00,
    bredr = 0x01,
    le_bredr = 0x02,
};

struct microsoft_info {
    microsoft_type type = microsoft_type::none;

    /* CDP beacon */
    uint8_t cdp_version = 0;
    uint8_t cdp_device_type = 0;
    bool cdp_share_everyone = false;
    bool cdp_addr_is_id = false;
    uint8_t cdp_status = 0;

    /* Swift Pair */
    swift_pair_mode sp_mode = swift_pair_mode::le;
    bool sp_has_cod = false;
    uint32_t sp_cod = 0;
    std::string sp_name;
};

struct fastpair_info {
    uint32_t model_id = 0;
    std::string model_id_hex;
};

struct matter_info {
    uint8_t opcode = 0;
    uint16_t discriminator = 0;
    uint8_t adv_version = 0;
    uint16_t vendor_id = 0;
    uint16_t product_id = 0;
    bool additional_data = false;
    bool extended_announcement = false;
};

constexpr uint16_t ccc_digital_key_uuid = 0xFFF5;

/* Manufacturer data: the company ID, then the payload */
bool decode_microsoft(const uint8_t *data, size_t len, microsoft_info& out);

/* 16-bit service data: the UUID, then the payload */
bool decode_fastpair(const uint8_t *data, size_t len, fastpair_info& out);
bool decode_matter(const uint8_t *data, size_t len, matter_info& out);
bool decode_ccc_digital_key(const uint8_t *data, size_t len);

const char *microsoft_type_str(microsoft_type t);
const char *cdp_device_type_str(uint8_t device_type);
const char *swift_pair_mode_str(swift_pair_mode m);
const char *matter_vendor_name(uint16_t vendor_id);

/* "ccc_digital_key" for the CCC UUID in a service list, otherwise nullptr */
const char *digital_key_hint(uint16_t uuid16);

/* "Tesla", or nullptr */
const char *vehicle_from_name(const std::string& name);

/* A short category for health, assistive and input services, or nullptr */
const char *service_class_hint(uint16_t uuid16);

}

#endif

