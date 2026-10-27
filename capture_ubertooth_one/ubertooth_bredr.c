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

#include "../config.h"

#include <string.h>
/* ubertooth_control.h defines the byte order macros on macOS */
#ifndef __APPLE__
#include <endian.h>
#endif

#ifdef HAVE_UBERTOOTH_UBERTOOTH_H
#include <ubertooth/ubertooth.h>
#else
#include <ubertooth.h>
#endif

#include "ubertooth_bredr.h"

/* A bank is 400 symbols at 1Msym/s, 4000 ticks of the 100ns clock */
#define BANK_TICKS          4000
#define BANK_TICKS_SLOP     100

/* clk100ns wraps with the low 20 bits of CLKN, 3125 ticks per CLKN */
#define CLK100NS_WRAP       (3125ULL << 20)

/* Sync word, then the 4 symbol trailer and the 54 symbol header */
#define AC_SYNC_LEN         64
#define AC_HEADER_END       (68 + 54)

/* The cc2400 RSSI to dBm */
#define U1_RSSI_OFFSET      54

static uint64_t rx_ticks(const usb_pkt_rx *rx) {
    return (uint64_t) rx->clkn_high * CLK100NS_WRAP + le32toh(rx->clk100ns);
}

int u1_bredr_init(u1_bredr_t *st, int max_ac_errors) {
    memset(st, 0, sizeof(u1_bredr_t));
    st->max_ac_errors = max_ac_errors;

    if (btbb_init(max_ac_errors) < 0)
        return -1;

    return 1;
}

void u1_bredr_free(u1_bredr_t *st) {
    unsigned int i;

    for (i = 0; i < U1_BREDR_PICONETS; i++) {
        if (st->piconets[i].pn != NULL)
            btbb_piconet_unref(st->piconets[i].pn);
        st->piconets[i].pn = NULL;
    }
}

void u1_bredr_reset(u1_bredr_t *st) {
    st->have_prev = 0;
    st->skip = 0;
}

/* The piconet for a LAP, replacing the least recently seen one when the table is full */
static u1_bredr_piconet_t *piconet_for(u1_bredr_t *st, uint32_t lap) {
    u1_bredr_piconet_t *slot = NULL;
    unsigned int i;

    for (i = 0; i < U1_BREDR_PICONETS; i++) {
        u1_bredr_piconet_t *p = &st->piconets[i];

        if (p->pn != NULL && p->lap == lap)
            return p;

        if (slot == NULL || p->pn == NULL ||
                (slot->pn != NULL && p->last_seen < slot->last_seen))
            slot = p;
    }

    if (slot->pn != NULL)
        btbb_piconet_unref(slot->pn);

    slot->pn = btbb_piconet_new();
    if (slot->pn == NULL)
        return NULL;

    btbb_init_piconet(slot->pn, lap);
    slot->lap = lap;
    slot->seen = 0;

    return slot;
}

static int handle_find(u1_bredr_t *st, btbb_packet *pkt, unsigned int pos,
        unsigned int valid, u1_bredr_emit_cb emit, void *ctx) {
    /* Access codes are only searched for in the previous bank */
    const usb_pkt_rx *rx = &st->prev;
    u1_bredr_bb_header_t hdr;
    u1_bredr_piconet_t *p;
    uint64_t ticks;
    uint32_t clkn;
    uint32_t lap;
    uint16_t flags;

    /* CLKN of the access code, as libubertooth computes it */
    ticks = rx_ticks(rx) + pos * 10;
    clkn = (uint32_t) ((ticks >= BANK_TICKS ? ticks - BANK_TICKS : 0) / 3125) & 0x0FFFFFFF;

    btbb_packet_set_modulation(pkt, BTBB_MOD_GFSK);
    btbb_packet_set_transport(pkt, BTBB_TRANSPORT_ANY);
    btbb_packet_set_data(pkt, st->syms + pos, valid - pos, rx->channel, clkn);

    lap = btbb_packet_get_lap(pkt) & 0xFFFFFF;

    p = piconet_for(st, lap);
    if (p == NULL)
        return 0;

    p->last_seen = ++st->finds;
    if (p->seen < 0xFFFF)
        p->seen++;

    if (btbb_header_present(pkt) && !btbb_piconet_get_flag(p->pn, BTBB_UAP_VALID))
        btbb_uap_from_header(pkt, p->pn);

    /* A single access code with errors is too often noise */
    if (p->seen < 2)
        return 0;

    memset(&hdr, 0, sizeof(hdr));

    flags = U1_BREDR_REFLAP_VALID;

    hdr.rf_channel = rx->channel;
    hdr.access_code_offenses = btbb_packet_get_ac_errors(pkt);
    hdr.lap = htole32(lap);

    if (rx->rssi_count != 0) {
        hdr.signal_power = (int8_t) (rx->rssi_max - U1_RSSI_OFFSET);
        flags |= U1_BREDR_SIGPOWER_VALID;

        if (rx->rssi_min < rx->rssi_max) {
            hdr.noise_power = (int8_t) (rx->rssi_min - U1_RSSI_OFFSET);
            flags |= U1_BREDR_NOISEPOWER_VALID;
        }
    }

    if (btbb_piconet_get_flag(p->pn, BTBB_UAP_VALID)) {
        hdr.ref_lap_uap = htole32(lap | ((uint32_t) btbb_piconet_get_uap(p->pn) << 24));
        flags |= U1_BREDR_REFUAP_VALID;
    } else {
        hdr.ref_lap_uap = htole32(lap);
    }

    hdr.flags = htole16(flags);

    (*emit)(ctx, rx, (const uint8_t *) &hdr, sizeof(hdr));

    return 1;
}

/* Search the previous bank for access codes whose header ends within the first valid
 * symbols of the history */
static int search_prev(u1_bredr_t *st, unsigned int valid, u1_bredr_emit_cb emit, void *ctx) {
    unsigned int pos = st->skip;
    int emitted = 0;

    while (pos < U1_BREDR_BANK) {
        btbb_packet *pkt = NULL;
        int off;

        off = btbb_find_ac(st->syms + pos, U1_BREDR_BANK - pos, LAP_ANY,
                st->max_ac_errors, &pkt);

        if (off < 0) {
            if (pkt != NULL)
                btbb_packet_unref(pkt);
            pos = U1_BREDR_BANK;
            break;
        }

        pos += (unsigned int) off;

        /* The header has to be in the history to be any use */
        if (pos + AC_HEADER_END <= valid)
            emitted += handle_find(st, pkt, pos, valid, emit, ctx);

        btbb_packet_unref(pkt);

        pos += AC_SYNC_LEN;
    }

    st->skip = pos - U1_BREDR_BANK;

    return emitted;
}

int u1_bredr_feed(u1_bredr_t *st, const usb_pkt_rx *rx, u1_bredr_emit_cb emit, void *ctx) {
    int emitted = 0;

    /* Keepalives and the like; a gap they leave is caught by the clock */
    if (rx->pkt_type != BR_PACKET)
        return 0;

    if ((rx->status & DISCARD) || rx->channel >= NUM_BREDR_CHANNELS) {
        if (st->have_prev)
            emitted = search_prev(st, U1_BREDR_BANK, emit, ctx);
        u1_bredr_reset(st);
        return emitted;
    }

    /* The previous bank only joins this one if nothing was lost between them; if
     * something was, it's searched on its own */
    if (st->have_prev) {
        const uint64_t prev_t = rx_ticks(&st->prev);
        const uint64_t cur_t = rx_ticks(rx);

        if (rx->channel != st->prev.channel || cur_t < prev_t ||
                cur_t - prev_t < BANK_TICKS - BANK_TICKS_SLOP ||
                cur_t - prev_t > BANK_TICKS + BANK_TICKS_SLOP) {
            emitted += search_prev(st, U1_BREDR_BANK, emit, ctx);
            u1_bredr_reset(st);
        }
    }

    ubertooth_unpack_symbols(rx->data, st->syms + U1_BREDR_BANK);

    if (st->have_prev)
        emitted += search_prev(st, sizeof(st->syms), emit, ctx);
    else
        st->skip = 0;

    memmove(st->syms, st->syms + U1_BREDR_BANK, U1_BREDR_BANK);
    memcpy(&st->prev, rx, sizeof(usb_pkt_rx));
    st->have_prev = 1;

    return emitted;
}
