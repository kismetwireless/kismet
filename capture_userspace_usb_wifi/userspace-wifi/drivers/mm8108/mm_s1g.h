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

#ifndef __MM_S1G_H__
#define __MM_S1G_H__

/* 802.11ah frames to and from the 802.11n/ac frames mac80211 expects of a 5GHz station, as
 * morse_driver's dot11ah layer converts them.
 *
 * Received S1G beacons become ordinary beacons; beacons, probe responses and association
 * responses get supported rates, HT, VHT and WMM elements describing the BSS's S1G channel
 * as its mapped 5GHz channel (see mm_channels.h), and S1G elements mac80211 doesn't know
 * are removed.  Probe and association requests lose the HT/VHT/HE elements and gain S1G
 * capabilities and, for association, an AID request.  Block ack action frames, which S1G
 * replaces with NDP block ack, are dropped both ways.  Data frames are unchanged. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mm_channels.h"

#define MM_S1G_MAX_BSS      32
/* Room the conversion may add to a frame */
#define MM_S1G_RX_GROWTH    256

/* What's known of a BSS from its probe responses and long beacons; short beacons carry
 * neither the SSID nor the security elements */
struct mm_s1g_bss {
    bool used;
    uint8_t bssid[6];
    uint64_t last_seen;

    uint8_t ssid[32];
    uint8_t ssid_len;
    bool have_ssid;

    uint8_t rsn[64];
    uint8_t rsn_len;
    uint8_t rsnx[16];
    uint8_t rsnx_len;

    /* S1G operation element body */
    uint8_t s1g_op[6];
    bool have_op;

    uint16_t beacon_int;
    uint16_t capab;
    uint32_t tsf_high;
};

/* The S1G channels of a BSS's operation */
struct mm_s1g_op {
    const struct mm_s1g_channel *op;
    const struct mm_s1g_channel *pri1;
    /* NULL for a 1MHz BSS */
    const struct mm_s1g_channel *pri2;
    /* Width of the primary channel, 1 or 2 MHz */
    uint8_t pri_bw;
};

struct mm_s1g_conv {
    const struct mm_s1g_region *region;
    struct mm_s1g_bss bss[MM_S1G_MAX_BSS];
    uint64_t now;
    /* After mm_s1g_rx(): the 5GHz primary channel of the BSS a converted beacon, probe or
     * association response describes, or 0 */
    uint8_t rx_pri_5g;
};

void mm_s1g_conv_init(struct mm_s1g_conv *c, const struct mm_s1g_region *region);

/* rx_chan is the 1MHz channel the frame was received on, for a BSS whose operation is still
 * unknown.  Returns the converted length, 0 to drop the frame, or -ENOSPC. */
int mm_s1g_rx(struct mm_s1g_conv *c, const struct mm_s1g_channel *rx_chan, const uint8_t *in,
        size_t len, uint8_t *out, size_t out_max);
int mm_s1g_tx(struct mm_s1g_conv *c, const uint8_t *in, size_t len, uint8_t *out, size_t out_max);

/* The channels an S1G operation element body describes; false if they aren't in the region */
bool mm_s1g_parse_op(const struct mm_s1g_region *region, const uint8_t *op_ie,
        struct mm_s1g_op *out);
/* A known BSS operating on op with its 1MHz primary on pri1, if any */
const struct mm_s1g_bss *mm_s1g_find_bss_on(const struct mm_s1g_conv *c,
        const struct mm_s1g_channel *op, const struct mm_s1g_channel *pri1);

/* The channel of a width containing ch, inside within (NULL for anywhere) */
const struct mm_s1g_channel *mm_s1g_containing(const struct mm_s1g_region *region,
        const struct mm_s1g_channel *ch, unsigned int bw_mhz, const struct mm_s1g_channel *within);

#endif
