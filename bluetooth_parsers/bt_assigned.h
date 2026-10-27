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

#ifndef __BT_ASSIGNED_H__
#define __BT_ASSIGNED_H__

/* Names for the Bluetooth SIG assigned numbers a device describes itself with:
 *
 *   Class of Device (BR/EDR inquiry results and EIR type 0x0D), 24 bits: service
 *   classes in bits 13-23, the major class in bits 8-12, the minor class in bits 2-7.
 *
 *   Appearance (LE advertising type 0x19), 16 bits: the category in bits 6-15 and
 *   the subcategory in bits 0-5.
 */

#include <cstdint>
#include <string>
#include <vector>

namespace bt_assigned {

constexpr uint8_t cod_major(uint32_t cod) {
    return (cod >> 8) & 0x1F;
}

constexpr uint8_t cod_minor(uint32_t cod) {
    return (cod >> 2) & 0x3F;
}

/* A class of device of 0 is "nothing advertised" rather than a miscellaneous device */
constexpr bool cod_valid(uint32_t cod) {
    return (cod & 0xFFFFFC) != 0 && (cod & 0x03) == 0;
}

const char *cod_major_name(uint8_t major);
std::string cod_minor_name(uint8_t major, uint8_t minor);
std::vector<std::string> cod_service_names(uint32_t cod);

std::string appearance_name(uint16_t appearance);

}

#endif

