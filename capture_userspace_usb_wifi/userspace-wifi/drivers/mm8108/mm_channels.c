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

#include <string.h>

#include "mm_channels.h"

const struct mm_s1g_region *mm_s1g_region(const char *country) {
    if (country == NULL || strlen(country) != 2)
        return NULL;

    for (size_t i = 0; i < mm_s1g_num_regions; i++)
        if (strncmp(country, mm_s1g_regions[i].country, 2) == 0)
            return &mm_s1g_regions[i];

    return NULL;
}

const struct mm_s1g_channel *mm_s1g_channel_lookup(const struct mm_s1g_region *region,
        unsigned int channel) {
    for (size_t i = 0; i < region->num_channels; i++)
        if (region->channels[i].channel == channel)
            return &region->channels[i];

    return NULL;
}

const struct mm_s1g_channel *mm_s1g_channel_by_5g(const struct mm_s1g_region *region,
        unsigned int chan_5g, unsigned int bw_mhz) {
    for (size_t i = 0; i < region->num_channels; i++)
        if (region->channels[i].chan_5g == chan_5g && region->channels[i].bw_mhz == bw_mhz)
            return &region->channels[i];

    return NULL;
}

void mm_s1g_countries(char *buf, size_t len) {
    size_t off = 0;

    if (len == 0)
        return;

    buf[0] = '\0';

    for (size_t i = 0; i < mm_s1g_num_regions && off + 4 < len; i++) {
        memcpy(buf + off, mm_s1g_regions[i].country, 2);
        off += 2;
        if (i + 1 < mm_s1g_num_regions)
            buf[off++] = ' ';
        buf[off] = '\0';
    }
}
