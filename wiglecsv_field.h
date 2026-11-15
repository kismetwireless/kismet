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

#ifndef __WIGLECSV_FIELD_H__
#define __WIGLECSV_FIELD_H__

#include <string>
#include <string_view>

// A text field for the WiGLE CSV, shared by the wiglecsv log and kismetdb_to_wiglecsv.
// Fields aren't quoted, so ',' and '"' and non-printable bytes are written as \ooo octal.
// A leading '=', '+', '-' or '@' is escaped the same way, so a spreadsheet opening the
// file doesn't read the field as a formula.
//
// SSIDs and Bluetooth names are stored with '\' already written as "\\"; text stored as it
// arrived, such as a cell operator name, sets raw_text so a '\' is written the same way and
// can't be read as one of the escapes.
inline std::string wiglecsv_munge(const std::string& in_data, bool raw_text = false) {
    std::string ret;

    ret.reserve(in_data.length());

    for (size_t i = 0; i < in_data.length(); i++) {
        const auto c = static_cast<unsigned char>(in_data[i]);

        const bool formula = i == 0 && (c == '=' || c == '+' || c == '-' || c == '@');

        if (raw_text && c == '\\') {
            ret += "\\\\";
        } else if (c >= 32 && c <= 126 && c != ',' && c != '"' && !formula) {
            ret += static_cast<char>(c);
        } else {
            ret += '\\';
            ret += static_cast<char>(((c >> 6) & 0x03) + '0');
            ret += static_cast<char>(((c >> 3) & 0x07) + '0');
            ret += static_cast<char>((c & 0x07) + '0');
        }
    }

    return ret;
}

// A MAC address as Kismet writes it, xx:xx:xx:xx:xx:xx
constexpr bool wiglecsv_valid_mac(std::string_view mac) {
    if (mac.length() != 17)
        return false;

    for (size_t i = 0; i < mac.length(); i++) {
        const auto c = mac[i];

        if (i % 3 == 2) {
            if (c != ':')
                return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }

    return true;
}

#endif
