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

const char Base64::b64_values[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void Base64::decodeblock(unsigned char *in, unsigned char *out) {
    out[0] = in[0] << 2 | in[1] >> 4;
    out[1] = in[1] << 4 | in[2] >> 2;
    out[2] = in[2] << 6 | in[3] >> 0;
    out[3] = 0;
}

string Base64::decode(string in_str) {
    string out;
    unsigned char obuf[4], ibuf[4];
    int phase, c;
    unsigned int i;
    char *pos;

    // Make a rough guess at the decoded length to optimise sizing
    out.reserve(in_str.length() * 0.75);

    phase = 0;

    for (i = 0; i < in_str.length(); i++) {
        c = in_str[i];

        if (c == '=') {
            decodeblock(ibuf, obuf);
            out.append((char *) obuf);
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
            out.append((char *) obuf);
            memset(ibuf, 0, 4);
        }
    }

    return out;
}

