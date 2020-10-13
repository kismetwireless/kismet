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

#include "config.h"

#include <string.h>

#include "base64.h"

const std::string base64::b64_values{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};

std::string base64::decode(const std::string& in_str) {
    auto len = in_str.size();
    int i = 0, j = 0, n = 0;
    unsigned char c4[4], c3[3];

    std::string ret;

    ret.reserve(len * 0.75);

    while (len-- && (in_str[n] != '=') && is_base64(in_str[n])) {
        c4[i++] = in_str[n++];

        if (i ==4) {
            for (i = 0; i < 4; i++)
                c4[i] = b64_values.find(c4[i]);

            c3[0] = (c4[0] << 2) + ((c4[1] & 0x30) >> 4);
            c3[1] = ((c4[1] & 0xf) << 4) + ((c4[2] & 0x3c) >> 2);
            c3[2] = ((c4[2] & 0x3) << 6) + c4[3];

            for (i = 0; (i < 3); i++)
                ret += c3[i];

            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            c4[j] = 0;

        for (j = 0; j < 4; j++)
            c4[j] = b64_values.find(c4[j]);

        c3[0] = (c4[0] << 2) + ((c4[1] & 0x30) >> 4);
        c3[1] = ((c4[1] & 0xf) << 4) + ((c4[2] & 0x3c) >> 2);
        c3[2] = ((c4[2] & 0x3) << 6) + c4[3];

        for (j = 0; (j < i - 1); j++) 
            ret += c3[j];
    }

    return ret;
}

std::string base64::encode(const std::string& in_str) {
	std::stringstream ss;
	size_t pos;

	for (pos = 0; pos < in_str.length(); pos += 3) {
		ss << b64_values[in_str[pos] >> 2];

		if (pos + 1 < in_str.length()) {
			ss << b64_values[((in_str[pos] & 0x03) << 4) | ((in_str[pos + 1] & 0xf0) >> 4)];
		} else {
			ss << b64_values[((in_str[pos] & 0x03) << 4)];
		}

		if (pos + 2 < in_str.length()) {
			ss << b64_values[((in_str[pos + 1] & 0x0f) << 2) | ((in_str[pos + 2] & 0xc0) >> 6)];
			ss << b64_values[in_str[pos + 2] & 0x3f];
		} else if (pos + 1 < in_str.length()) {
			ss << b64_values[((in_str[pos + 1] & 0x0f) << 2)];
			ss << '=';
		} else {
			ss << "==";
		}
	}

	return ss.str();
}

