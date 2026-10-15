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

#ifndef __MM_CHANNELS_H__
#define __MM_CHANNELS_H__

#include <stddef.h>
#include <stdint.h>

/* 802.11ah channel plans, from morse_driver dot11ah/s1g_channels.c and s1g_channels_rules.c */

struct mm_s1g_channel {
    uint16_t channel;
    uint8_t bw_mhz;
    uint32_t freq_khz;
};

struct mm_s1g_region {
    const char *country;
    const struct mm_s1g_channel *channels;
    size_t num_channels;
};

/* Returns NULL for an unknown country */
const struct mm_s1g_region *mm_s1g_region(const char *country);
const struct mm_s1g_channel *mm_s1g_channel_lookup(const struct mm_s1g_region *region,
        unsigned int channel);
/* Comma-separated list of supported country codes */
const char *mm_s1g_countries(void);

#endif
