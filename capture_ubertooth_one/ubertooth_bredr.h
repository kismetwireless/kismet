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

#ifndef __UBERTOOTH_BREDR_H__
#define __UBERTOOTH_BREDR_H__

/* Classic (BR/EDR) piconet survey from Ubertooth basic rate symbols, as ubertooth-rx -z
 * does: find access codes for the LAP of each piconet, and recover the UAP from packet
 * headers over time.  Each find is reported as a LINKTYPE_BLUETOOTH_BREDR_BB frame. */

#include <stdint.h>
#include <stddef.h>

#ifdef HAVE_UBERTOOTH_UBERTOOTH_H
#include <ubertooth/ubertooth_interface.h>
#else
#include <ubertooth_interface.h>
#endif

#include <btbb.h>

#define U1_BREDR_DLT                255

#define U1_BREDR_BANK               (DMA_SIZE * 8)
#define U1_BREDR_PICONETS           128

/* LINKTYPE_BLUETOOTH_BREDR_BB header, little endian */
typedef struct {
    uint8_t rf_channel;
    int8_t signal_power;
    int8_t noise_power;
    uint8_t access_code_offenses;
    uint8_t payload_transport_rate;
    uint8_t corrected_header_bits;
    int16_t corrected_payload_bits;
    uint32_t lap;
    uint32_t ref_lap_uap;
    uint32_t bt_header;
    uint16_t flags;
} __attribute__((packed)) u1_bredr_bb_header_t;

#define U1_BREDR_SIGPOWER_VALID     0x0002
#define U1_BREDR_NOISEPOWER_VALID   0x0004
#define U1_BREDR_REFLAP_VALID       0x0010
#define U1_BREDR_REFUAP_VALID       0x0080

typedef struct {
    uint32_t lap;
    btbb_piconet *pn;
    unsigned int seen;
    uint64_t last_seen;
} u1_bredr_piconet_t;

typedef struct {
    /* The previous bank and the one after it, so an access code which starts near the
     * end of a bank still has its header */
    char syms[U1_BREDR_BANK * 2];
    usb_pkt_rx prev;
    int have_prev;

    /* Symbols at the start of the previous bank already covered by the last find */
    unsigned int skip;

    int max_ac_errors;

    u1_bredr_piconet_t piconets[U1_BREDR_PICONETS];
    uint64_t finds;
} u1_bredr_t;

typedef void (*u1_bredr_emit_cb)(void *ctx, const usb_pkt_rx *rx,
        const uint8_t *frame, size_t frame_sz);

int u1_bredr_init(u1_bredr_t *st, int max_ac_errors);
void u1_bredr_free(u1_bredr_t *st);

/* Forget the symbol history, after a retune or a reset */
void u1_bredr_reset(u1_bredr_t *st);

/* Feed one basic rate USB packet; returns the number of frames emitted */
int u1_bredr_feed(u1_bredr_t *st, const usb_pkt_rx *rx, u1_bredr_emit_cb emit, void *ctx);

#endif
