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

#ifndef __BTLE_SENSOR_H__
#define __BTLE_SENSOR_H__

/* Environmental readings (temperature, humidity, pressure, battery voltage) which
 * sensors advertise in the clear.  Battery percent is left to btle_battery.
 *
 *   Ruuvi (manufacturer 0x0499), big endian, docs.ruuvi.com data formats:
 *   format 5 (RAWv2): temperature int16 at 1 (0.005 C), humidity uint16 at 3
 *   (0.0025 %), pressure uint16 at 5 (Pa - 50000), power at 13 (battery mV - 1600
 *   in the top 11 bits).  Not available is 0x8000 signed, all ones unsigned.
 *   Format 3 (RAWv1): humidity at 1 (0.5 %), temperature at 2-3 (sign and whole
 *   degrees, then hundredths), pressure at 4 (Pa - 50000), battery mV at 12.
 *
 *   Xiaomi MiBeacon (service data 0xFE95), little endian, per xiaomi-ble: frame
 *   control (bit 3 encrypted, 4 MAC, 5 capability, 6 objects, 7 mesh, 12-15
 *   version), product id, counter, then the optional MAC and capability (and IO
 *   byte when capability bit 0x20 is set), then objects of id(2) len(1) data.
 *   0x1004 temperature int16 0.1 C, 0x1006 humidity uint16 0.1 %, 0x100D both.
 *   Only unencrypted v2+ non-mesh frames.
 *
 *   Govee (manufacturer data), per govee-ble, identified by the company and length
 *   only: 0xEC88 length 6 (H5072/H5075), a 24 bit big endian value at 1, bit 23
 *   the sign, temperature = (value & 0x7FFFFF) / 1000 tenths, humidity the
 *   remainder in tenths; byte 4 bit 7 an error flag.  0xEC88 length 7 (H5074) and 9
 *   (H5051): temperature int16 and humidity uint16 at 1, little endian, hundredths.
 *   0x8801 length 9 (H5179): the same at 4.
 *
 *   BTHome v2 (0xFCD2), bthome.io/format: device information byte, then objects
 *   (id, fixed little endian value); 0x02 temperature sint16 0.01, 0x45 sint16 0.1,
 *   0x57 sint8 1, 0x58 sint8 0.35; 0x03 humidity uint16 0.01, 0x2E uint8; 0x04
 *   pressure uint24 0.01 hPa; 0x0C voltage uint16 mV.  Parsing stops at an unknown
 *   id.  Unencrypted only.
 *
 *   pvvx custom firmware (0x181A, 15 bytes, little endian): MAC, temperature int16
 *   0.01 C at 6, humidity uint16 0.01 % at 8, mV at 10.  ATC1441 (0x181A, 13 bytes,
 *   big endian): MAC, temperature int16 0.1 C at 6, humidity % at 8, mV at 10.
 *
 *   Eddystone TLM (0xFEAA, frame 0x20, version 0), big endian: mV at 2 (0 not
 *   supported), temperature 8.8 fixed point at 4 (0x8000 not supported).
 */

#include <cstddef>
#include <cstdint>

namespace btle_sensor {

enum class source : uint8_t {
    none = 0,
    ruuvi = 1,
    xiaomi = 2,
    govee = 3,
    bthome = 4,
    pvvx = 5,
    atc1441 = 6,
    eddystone_tlm = 7,
};

struct info {
    source src = source::none;

    bool has_temperature = false;
    double temperature_c = 0;

    bool has_humidity = false;
    double humidity_pct = 0;

    bool has_pressure = false;
    double pressure_hpa = 0;

    bool has_battery_mv = false;
    unsigned int battery_mv = 0;
};

/* 16-bit service data: the UUID, then the payload */
bool decode_service_data(const uint8_t *data, size_t len, info& out);

/* Manufacturer data: the company ID, then the payload */
bool decode_manuf_data(const uint8_t *data, size_t len, info& out);

const char *source_str(source s);

}

#endif
