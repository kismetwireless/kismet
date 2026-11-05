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

    Fragment matching for the cellat selftests.

    The selftests check an observation's JSON for a fragment such as
    "\"band\":4". A plain strstr() also finds that fragment inside
    "\"band\":41", "\"rsrp\":-9" inside "\"rsrp\":-98", and "\"snr\":15"
    inside an unscaled "\"snr\":153", so a value wrong by a trailing digit
    passes. json_has() is strstr() with one extra rule: when the fragment
    ends in a digit, the number in the JSON must end there too -- the next
    character may not be a digit, nor a '.' followed by a digit. Fragments
    that end in anything else (a quote, a key with no value) match exactly
    as strstr() does.
*/

#ifndef CELLAT_SELFTEST_JSON_H
#define CELLAT_SELFTEST_JSON_H

#include <ctype.h>
#include <string.h>

static int json_number_continues(const char *p) {
    if (isdigit((unsigned char) p[0]))
        return 1;
    return p[0] == '.' && isdigit((unsigned char) p[1]);
}

static int json_has(const char *json, const char *frag) {
    size_t len = strlen(frag);
    int numeric_end;
    const char *p;

    if (json == NULL || len == 0)
        return 0;

    numeric_end = isdigit((unsigned char) frag[len - 1]);

    for (p = strstr(json, frag); p != NULL; p = strstr(p + 1, frag)) {
        if (!numeric_end || !json_number_continues(p + len))
            return 1;
    }

    return 0;
}

#endif
