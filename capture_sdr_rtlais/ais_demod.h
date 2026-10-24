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

    Copyright (C) 2026 by Mike Kershaw <dragorn@kismetwireless.net>
*/

#ifndef __AIS_DEMOD_H__
#define __AIS_DEMOD_H__

#include <stdint.h>
#include <stddef.h>

/* AIS dual-channel GMSK demodulator and HDLC deframer.
 *
 * Input is raw unsigned 8-bit IQ (rtlsdr cu8) sampled at AIS_DEMOD_SAMPLE_RATE
 * and tuned to AIS_DEMOD_CENTER_FREQ; both AIS channels (161.975MHz and
 * 162.025MHz) are demodulated simultaneously.
 *
 * Valid (CRC-checked) frames are delivered via callback with the FCS removed,
 * in AIS (MSB-first) field order; this is the same bit stream represented by
 * the 6-bit armoring of an AIVDM sentence.
 */

#define AIS_DEMOD_SAMPLE_RATE       288000
#define AIS_DEMOD_CENTER_FREQ       162000000
#define AIS_DEMOD_CHANNEL_OFFSET    25000
#define AIS_DEMOD_BAUD              9600

/* AIS channel A (87B) and B (88B) */
#define AIS_CHANNEL_A               0
#define AIS_CHANNEL_B               1

/* Maximum payload: 5 slots */
#define AIS_MAX_PAYLOAD_BYTES       160

typedef void (*ais_frame_cb_t)(void *ctx, int channel,
        const uint8_t *payload, size_t payload_len, float level_dbfs);

typedef struct ais_demod ais_demod_t;

ais_demod_t *ais_demod_new(ais_frame_cb_t cb, void *ctx);
void ais_demod_free(ais_demod_t *demod);

/* Process a block of cu8 samples; len is in bytes (2 per complex sample).
 * State is preserved across calls so frames may span buffer boundaries. */
void ais_demod_process_cu8(ais_demod_t *demod, const uint8_t *buf, size_t len);

/* Statistics */
unsigned long ais_demod_frames(ais_demod_t *demod, int channel);
unsigned long ais_demod_crc_errors(ais_demod_t *demod, int channel);

#endif

