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

#ifndef __ADSB_DEMOD_H__
#define __ADSB_DEMOD_H__

/*
 * Mode S demodulator, the capture_sdr_rtladsb_v2 decoder (from librtlsdr's
 * rtl_adsb) with its state in one object, so it can share a radio with
 * other decoders.
 *
 * Input is raw unsigned 8-bit IQ (rtlsdr cu8) at ADSB_DEMOD_SAMPLE_RATE,
 * tuned to ADSB_DEMOD_CENTER_FREQ.  Frames that pass the Mode S CRC are
 * delivered whole, 7 or 14 bytes; frames spanning two buffers are lost.
 */

#include <stddef.h>
#include <stdint.h>

#define ADSB_DEMOD_SAMPLE_RATE      2000000
#define ADSB_DEMOD_CENTER_FREQ      1090000000

#define ADSB_MAX_FRAME_BYTES        14

typedef struct adsb_demod adsb_demod_t;

typedef void (*adsb_frame_cb_t)(void *ctx, const uint8_t *frame, size_t frame_len);

/* max_buf_len is the largest cu8 buffer that will be passed in */
adsb_demod_t *adsb_demod_new(size_t max_buf_len, adsb_frame_cb_t cb, void *ctx);
void adsb_demod_free(adsb_demod_t *demod);

void adsb_demod_process_cu8(adsb_demod_t *demod, const uint8_t *buf, size_t len);

unsigned long adsb_demod_frames(adsb_demod_t *demod);

#endif
