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

/* Center frequency is base + channel * 500 kHz, with a region-specific base */
#define CH(c, bw, base) { (c), (bw), (base) + (c) * 500 }

#define US_BASE 902000
#define EU_BASE 863000
#define GB_HIGH_BASE 901400
#define AU_HIGH_BASE 894000
#define JP_ODD_BASE 916500
#define JP_EVEN_BASE 922500
#define JP_HIGH_BASE 906500
#define KR_BASE 917500

static const struct mm_s1g_channel us_channels[] = {
    CH(1, 1, US_BASE), CH(3, 1, US_BASE), CH(5, 1, US_BASE), CH(7, 1, US_BASE),
    CH(9, 1, US_BASE), CH(11, 1, US_BASE), CH(13, 1, US_BASE), CH(15, 1, US_BASE),
    CH(17, 1, US_BASE), CH(19, 1, US_BASE), CH(21, 1, US_BASE), CH(23, 1, US_BASE),
    CH(25, 1, US_BASE), CH(27, 1, US_BASE), CH(29, 1, US_BASE), CH(31, 1, US_BASE),
    CH(33, 1, US_BASE), CH(35, 1, US_BASE), CH(37, 1, US_BASE), CH(39, 1, US_BASE),
    CH(41, 1, US_BASE), CH(43, 1, US_BASE), CH(45, 1, US_BASE), CH(47, 1, US_BASE),
    CH(49, 1, US_BASE), CH(51, 1, US_BASE),
    CH(2, 2, US_BASE), CH(6, 2, US_BASE), CH(10, 2, US_BASE), CH(14, 2, US_BASE),
    CH(18, 2, US_BASE), CH(22, 2, US_BASE), CH(26, 2, US_BASE), CH(30, 2, US_BASE),
    CH(34, 2, US_BASE), CH(38, 2, US_BASE), CH(42, 2, US_BASE), CH(46, 2, US_BASE),
    CH(50, 2, US_BASE),
    CH(8, 4, US_BASE), CH(16, 4, US_BASE), CH(24, 4, US_BASE), CH(32, 4, US_BASE),
    CH(40, 4, US_BASE), CH(48, 4, US_BASE),
    CH(12, 8, US_BASE), CH(28, 8, US_BASE), CH(44, 8, US_BASE),
};

static const struct mm_s1g_channel br_channels[] = {
    CH(1, 1, US_BASE), CH(3, 1, US_BASE), CH(5, 1, US_BASE), CH(7, 1, US_BASE),
    CH(9, 1, US_BASE), CH(27, 1, US_BASE), CH(29, 1, US_BASE), CH(31, 1, US_BASE),
    CH(33, 1, US_BASE), CH(35, 1, US_BASE), CH(37, 1, US_BASE), CH(39, 1, US_BASE),
    CH(41, 1, US_BASE), CH(43, 1, US_BASE), CH(45, 1, US_BASE), CH(47, 1, US_BASE),
    CH(49, 1, US_BASE), CH(51, 1, US_BASE),
    CH(2, 2, US_BASE), CH(6, 2, US_BASE), CH(30, 2, US_BASE), CH(34, 2, US_BASE),
    CH(38, 2, US_BASE), CH(42, 2, US_BASE), CH(46, 2, US_BASE), CH(50, 2, US_BASE),
    CH(32, 4, US_BASE), CH(40, 4, US_BASE), CH(48, 4, US_BASE),
    CH(44, 8, US_BASE),
};

static const struct mm_s1g_channel nz_channels[] = {
    CH(27, 1, US_BASE), CH(29, 1, US_BASE), CH(31, 1, US_BASE), CH(33, 1, US_BASE),
    CH(35, 1, US_BASE), CH(37, 1, US_BASE), CH(39, 1, US_BASE), CH(41, 1, US_BASE),
    CH(43, 1, US_BASE), CH(45, 1, US_BASE), CH(47, 1, US_BASE), CH(49, 1, US_BASE),
    CH(51, 1, US_BASE),
    CH(30, 2, US_BASE), CH(34, 2, US_BASE), CH(38, 2, US_BASE), CH(42, 2, US_BASE),
    CH(46, 2, US_BASE), CH(50, 2, US_BASE),
    CH(32, 4, US_BASE), CH(40, 4, US_BASE), CH(48, 4, US_BASE),
    CH(44, 8, US_BASE),
};

/* AU REVmf channelization, the driver default; also used for AR, CL and CO */
static const struct mm_s1g_channel au_channels[] = {
    CH(28, 1, US_BASE), CH(30, 1, US_BASE), CH(32, 1, US_BASE), CH(34, 1, US_BASE),
    CH(36, 1, US_BASE), CH(38, 1, US_BASE), CH(40, 1, US_BASE), CH(42, 1, US_BASE),
    CH(44, 1, US_BASE), CH(46, 1, US_BASE), CH(48, 1, US_BASE), CH(50, 1, US_BASE),
    CH(29, 2, US_BASE), CH(33, 2, US_BASE), CH(37, 2, US_BASE), CH(41, 2, US_BASE),
    CH(45, 2, US_BASE), CH(49, 2, US_BASE),
    CH(31, 4, US_BASE), CH(39, 4, US_BASE), CH(47, 4, US_BASE),
    CH(51, 4, AU_HIGH_BASE), CH(59, 4, AU_HIGH_BASE),
    CH(35, 8, US_BASE), CH(43, 8, US_BASE), CH(55, 8, AU_HIGH_BASE),
};

static const struct mm_s1g_channel eu_channels[] = {
    CH(1, 1, EU_BASE), CH(3, 1, EU_BASE), CH(5, 1, EU_BASE), CH(7, 1, EU_BASE),
    CH(9, 1, EU_BASE),
};

static const struct mm_s1g_channel gb_channels[] = {
    CH(1, 1, EU_BASE), CH(3, 1, EU_BASE), CH(5, 1, EU_BASE), CH(7, 1, EU_BASE),
    CH(9, 1, EU_BASE), CH(33, 1, GB_HIGH_BASE), CH(35, 1, GB_HIGH_BASE),
};

static const struct mm_s1g_channel in_channels[] = {
    CH(5, 1, EU_BASE), CH(7, 1, EU_BASE), CH(9, 1, EU_BASE),
};

static const struct mm_s1g_channel jp_channels[] = {
    CH(9, 1, JP_ODD_BASE), CH(13, 1, JP_ODD_BASE), CH(15, 1, JP_ODD_BASE),
    CH(17, 1, JP_ODD_BASE), CH(19, 1, JP_ODD_BASE), CH(21, 1, JP_ODD_BASE),
    CH(2, 2, JP_EVEN_BASE), CH(4, 2, JP_EVEN_BASE), CH(6, 2, JP_EVEN_BASE),
    CH(8, 2, JP_EVEN_BASE),
    CH(36, 4, JP_HIGH_BASE), CH(38, 4, JP_HIGH_BASE),
};

static const struct mm_s1g_channel kr_channels[] = {
    CH(1, 1, KR_BASE), CH(3, 1, KR_BASE), CH(5, 1, KR_BASE), CH(7, 1, KR_BASE),
    CH(9, 1, KR_BASE), CH(11, 1, KR_BASE), CH(18, 1, KR_BASE), CH(20, 1, KR_BASE),
    CH(22, 1, KR_BASE), CH(24, 1, KR_BASE),
    CH(2, 2, KR_BASE), CH(6, 2, KR_BASE), CH(10, 2, KR_BASE), CH(19, 2, KR_BASE),
    CH(23, 2, KR_BASE),
    CH(8, 4, KR_BASE),
};

static const struct mm_s1g_channel sg_channels[] = {
    CH(31, 1, US_BASE), CH(33, 1, US_BASE), CH(35, 1, US_BASE), CH(37, 1, US_BASE),
    CH(39, 1, US_BASE), CH(41, 1, US_BASE), CH(43, 1, US_BASE), CH(45, 1, US_BASE),
    CH(32, 2, US_BASE), CH(36, 2, US_BASE), CH(40, 2, US_BASE), CH(44, 2, US_BASE),
    CH(34, 4, US_BASE), CH(42, 4, US_BASE),
    CH(38, 8, US_BASE),
};

#define REGION(cc, t) { cc, t, sizeof(t) / sizeof(t[0]) }

static const struct mm_s1g_region regions[] = {
    REGION("US", us_channels),
    REGION("CA", us_channels),
    REGION("MX", us_channels),
    REGION("BR", br_channels),
    REGION("NZ", nz_channels),
    REGION("AU", au_channels),
    REGION("AR", au_channels),
    REGION("CL", au_channels),
    REGION("CO", au_channels),
    REGION("EU", eu_channels),
    REGION("GB", gb_channels),
    REGION("IN", in_channels),
    REGION("JP", jp_channels),
    REGION("KR", kr_channels),
    REGION("SG", sg_channels),
};

const struct mm_s1g_region *mm_s1g_region(const char *country) {
    if (country == NULL)
        return NULL;

    for (size_t i = 0; i < sizeof(regions) / sizeof(regions[0]); i++)
        if (strncmp(country, regions[i].country, 2) == 0 && strlen(country) == 2)
            return &regions[i];

    return NULL;
}

const struct mm_s1g_channel *mm_s1g_channel_lookup(const struct mm_s1g_region *region,
        unsigned int channel) {
    for (size_t i = 0; i < region->num_channels; i++)
        if (region->channels[i].channel == channel)
            return &region->channels[i];

    return NULL;
}

const char *mm_s1g_countries(void) {
    return "US, CA, MX, BR, NZ, AU, AR, CL, CO, EU, GB, IN, JP, KR, SG";
}
