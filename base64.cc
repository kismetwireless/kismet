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

const char base64::b64_values[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64::decodeblock(unsigned char *in, unsigned char *out) {
    out[0] = in[0] << 2 | in[1] >> 4;
    out[1] = in[1] << 4 | in[2] >> 2;
    out[2] = in[2] << 6 | in[3] >> 0;
    out[3] = 0;
}

std::string base64::decode(std::string in_str) {
    std::string out;
    unsigned char obuf[4], ibuf[4];
    int phase, c;
    unsigned int i;
    char *pos;

    memset(obuf, 0, 4);
    memset(ibuf, 0, 4);

    // Make a rough guess at the decoded length to optimise sizing
    out.reserve(in_str.length() * 0.75);

    phase = 0;

    for (i = 0; i < in_str.length(); i++) {
        c = in_str[i];

        if (c == '=') {
            decodeblock(ibuf, obuf);
            out.append((char *) obuf, phase);
            return out;
        }

        // Find the binary # this digit corresponds to
        pos = strchr((char *) b64_values, c);

        // Fail on invalid characters
        if (pos == NULL) {
            return out;
        }

        // Get the integer position in the table
        ibuf[phase] = pos - b64_values;

        phase = (phase + 1) % 4;

        // 4 characters read?
        if (phase == 0) {
            decodeblock(ibuf, obuf);
            out.append((char *) obuf, 3);
            memset(ibuf, 0, 4);
        }
    }

    return out;
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

