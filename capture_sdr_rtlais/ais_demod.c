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

/*
 * AIS demodulation pipeline, per channel:
 *
 *   cu8 IQ @ 288k -> mix by +/-25kHz -> FIR lowpass + decimate /6 -> 48k
 *   -> FM discriminator -> smoothing -> DC (frequency offset) removal
 *   -> 5 parallel slicers, one per sample phase (5 samples/symbol)
 *   -> NRZI decode -> HDLC flag / bit-destuff -> CRC16 check -> dedupe
 *
 * Running every sample phase as an independent slicer replaces a symbol
 * clock recovery loop; at 9600 baud this is cheap, and duplicate frames
 * decoded by adjacent phases are suppressed before being reported.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ais_demod.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define AIS_DECIM           6
#define AIS_SPS             5
#define AIS_FIR_TAPS        47
#define AIS_FIR_CUTOFF      10000.0

/* 25kHz at 288k completes exactly 25 cycles in 288 samples */
#define AIS_LO_LEN          288

/* Max destuffed bits: 1008 payload + 16 FCS, plus 7 bits of trailing flag */
#define AIS_MAX_FRAME_BITS  (1008 + 16 + 8)
#define AIS_MIN_FRAME_BITS  (40 + 16)

/* Suppress identical frames from adjacent slicer phases within 50ms */
#define AIS_DEDUPE_SAMPLES  ((AIS_DEMOD_SAMPLE_RATE / AIS_DECIM) / 20)

/* DC tracking time constants, in decimated samples */
#define AIS_DC_SLOW         (1.0f / 192.0f)
#define AIS_DC_FAST         (1.0f / 24.0f)
#define AIS_DC_FAST_HOLD    120

typedef struct {
    uint8_t reg;
    int ones;
    int in_frame;
    int prev_level;
    unsigned int nbits;
    uint8_t bits[AIS_MAX_FRAME_BITS];
} ais_hdlc_t;

typedef struct {
    float lo_i[AIS_LO_LEN];
    float lo_q[AIS_LO_LEN];

    /* Doubled history so the FIR never has to wrap */
    float hist_i[AIS_FIR_TAPS * 2];
    float hist_q[AIS_FIR_TAPS * 2];

    float prev_i, prev_q;
    float smooth[3];

    float dc;
    int dc_fast_hold;

    float pw_fast;
    float pw_slow;
    float pw_level;
    int onset_armed;

    unsigned long sample_count;

    ais_hdlc_t slicers[AIS_SPS];

    uint16_t last_fcs;
    size_t last_len;
    unsigned long last_sample;

    unsigned long frames;
    unsigned long crc_errors;
} ais_channel_t;

struct ais_demod {
    ais_frame_cb_t cb;
    void *cb_ctx;

    float cu8_lut[256];
    float fir[AIS_FIR_TAPS];

    unsigned int lo_pos;
    unsigned int hist_pos;
    unsigned int decim_count;

    ais_channel_t channels[2];
};

static uint8_t ais_reverse_byte(uint8_t b) {
    b = (uint8_t) (((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
    b = (uint8_t) (((b & 0xCC) >> 2) | ((b & 0x33) << 2));
    b = (uint8_t) (((b & 0xAA) >> 1) | ((b & 0x55) << 1));
    return b;
}

/* CRC-16/X.25; computed over the data and the FCS the residue is 0xF0B8 */
static uint16_t ais_crc16(const uint8_t *buf, size_t len) {
    uint16_t crc = 0xFFFF;
    size_t i;
    int b;

    for (i = 0; i < len; i++) {
        crc ^= buf[i];
        for (b = 0; b < 8; b++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0x8408;
            else
                crc >>= 1;
        }
    }

    return crc;
}

static void ais_frame_complete(ais_demod_t *demod, ais_channel_t *chan,
        int channel, ais_hdlc_t *hdlc) {
    uint8_t frame[AIS_MAX_FRAME_BITS / 8];
    unsigned int nbits, nbytes, i;
    uint16_t fcs;

    /* Trailing 7 bits are the 0111111 of the closing flag */
    if (hdlc->nbits < 7)
        return;

    nbits = hdlc->nbits - 7;

    if (nbits < AIS_MIN_FRAME_BITS || (nbits % 8) != 0)
        return;

    nbytes = nbits / 8;

    /* Bits arrive LSB-first within each byte */
    memset(frame, 0, nbytes);
    for (i = 0; i < nbits; i++) {
        if (hdlc->bits[i])
            frame[i / 8] |= (uint8_t) (1 << (i % 8));
    }

    if (ais_crc16(frame, nbytes) != 0xF0B8) {
        chan->crc_errors++;
        return;
    }

    fcs = (uint16_t) (frame[nbytes - 2] | (frame[nbytes - 1] << 8));
    nbytes -= 2;

    if (chan->frames > 0 && chan->last_fcs == fcs && chan->last_len == nbytes &&
            chan->sample_count - chan->last_sample < AIS_DEDUPE_SAMPLES)
        return;

    chan->last_fcs = fcs;
    chan->last_len = nbytes;
    chan->last_sample = chan->sample_count;
    chan->frames++;

    /* AIS fields are packed MSB-first */
    for (i = 0; i < nbytes; i++)
        frame[i] = ais_reverse_byte(frame[i]);

    if (demod->cb != NULL)
        demod->cb(demod->cb_ctx, channel, frame, nbytes,
                10.0f * log10f(chan->pw_level + 1e-20f));
}

static void ais_hdlc_bit(ais_demod_t *demod, ais_channel_t *chan, int channel,
        ais_hdlc_t *hdlc, int level) {
    /* NRZI: no transition is a 1, a transition is a 0 */
    int bit = (level == hdlc->prev_level);
    hdlc->prev_level = level;

    if (bit) {
        hdlc->ones++;

        if (hdlc->ones > 6) {
            /* Abort / idle */
            hdlc->in_frame = 0;
            return;
        }
    } else {
        if (hdlc->ones == 5) {
            /* Stuffed bit */
            hdlc->ones = 0;
            return;
        }

        if (hdlc->ones == 6) {
            /* Flag; close any open frame and start a new one */
            if (hdlc->in_frame)
                ais_frame_complete(demod, chan, channel, hdlc);

            hdlc->in_frame = 1;
            hdlc->nbits = 0;
            hdlc->ones = 0;
            return;
        }

        hdlc->ones = 0;
    }

    if (!hdlc->in_frame)
        return;

    if (hdlc->nbits >= AIS_MAX_FRAME_BITS) {
        hdlc->in_frame = 0;
        return;
    }

    hdlc->bits[hdlc->nbits++] = (uint8_t) bit;
}

/* Process one decimated baseband sample on a channel */
static void ais_channel_sample(ais_demod_t *demod, int channel, float i, float q) {
    ais_channel_t *chan = &demod->channels[channel];
    float re, im, d, v, pw;

    pw = i * i + q * q;

    /* Burst onset: short-term power jumps well above the longer-term average.
     * Re-arm once the short-term power falls back toward the average. */
    chan->pw_fast += (pw - chan->pw_fast) * (1.0f / 16.0f);
    chan->pw_slow += (pw - chan->pw_slow) * (1.0f / 512.0f);
    chan->pw_level += (pw - chan->pw_level) * (1.0f / 128.0f);

    if (chan->onset_armed && chan->pw_fast > chan->pw_slow * 4.0f) {
        chan->dc_fast_hold = AIS_DC_FAST_HOLD;
        chan->onset_armed = 0;
    } else if (!chan->onset_armed && chan->pw_fast < chan->pw_slow * 2.0f) {
        chan->onset_armed = 1;
    }

    /* FM discriminator: arg(z[n] * conj(z[n-1])) */
    re = i * chan->prev_i + q * chan->prev_q;
    im = q * chan->prev_i - i * chan->prev_q;
    chan->prev_i = i;
    chan->prev_q = q;

    d = atan2f(im, re);

    chan->smooth[0] = chan->smooth[1];
    chan->smooth[1] = chan->smooth[2];
    chan->smooth[2] = d;
    v = (chan->smooth[0] + chan->smooth[1] + chan->smooth[2]) * (1.0f / 3.0f);

    /* Remove residual frequency offset; track quickly at the start of a burst
     * so the training sequence pulls the estimate in before the start flag */
    if (chan->dc_fast_hold > 0) {
        chan->dc += (v - chan->dc) * AIS_DC_FAST;
        chan->dc_fast_hold--;
    } else {
        chan->dc += (v - chan->dc) * AIS_DC_SLOW;
    }

    ais_hdlc_bit(demod, chan, channel,
            &chan->slicers[chan->sample_count % AIS_SPS], (v - chan->dc) > 0);

    chan->sample_count++;
}

ais_demod_t *ais_demod_new(ais_frame_cb_t cb, void *ctx) {
    ais_demod_t *demod;
    double sum = 0, x, w, h, theta;
    int n, c;

    demod = (ais_demod_t *) calloc(1, sizeof(ais_demod_t));
    if (demod == NULL)
        return NULL;

    demod->cb = cb;
    demod->cb_ctx = ctx;

    for (n = 0; n < 256; n++)
        demod->cu8_lut[n] = ((float) n - 127.4f) / 128.0f;

    /* Hamming-windowed sinc lowpass */
    for (n = 0; n < AIS_FIR_TAPS; n++) {
        x = n - (AIS_FIR_TAPS - 1) / 2.0;
        if (x == 0)
            h = 2.0 * AIS_FIR_CUTOFF / AIS_DEMOD_SAMPLE_RATE;
        else
            h = sin(2.0 * M_PI * AIS_FIR_CUTOFF / AIS_DEMOD_SAMPLE_RATE * x) / (M_PI * x);
        w = 0.54 - 0.46 * cos(2.0 * M_PI * n / (AIS_FIR_TAPS - 1));
        demod->fir[n] = (float) (h * w);
        sum += h * w;
    }

    for (n = 0; n < AIS_FIR_TAPS; n++)
        demod->fir[n] = (float) (demod->fir[n] / sum);

    /* Channel A sits at -25kHz and is shifted up; channel B at +25kHz is
     * shifted down */
    for (n = 0; n < AIS_LO_LEN; n++) {
        theta = 2.0 * M_PI * (double) AIS_DEMOD_CHANNEL_OFFSET * n / AIS_DEMOD_SAMPLE_RATE;
        demod->channels[AIS_CHANNEL_A].lo_i[n] = (float) cos(theta);
        demod->channels[AIS_CHANNEL_A].lo_q[n] = (float) sin(theta);
        demod->channels[AIS_CHANNEL_B].lo_i[n] = (float) cos(theta);
        demod->channels[AIS_CHANNEL_B].lo_q[n] = (float) -sin(theta);
    }

    for (c = 0; c < 2; c++) {
        demod->channels[c].onset_armed = 1;
        demod->channels[c].prev_i = 1.0f;
    }

    return demod;
}

void ais_demod_free(ais_demod_t *demod) {
    free(demod);
}

void ais_demod_process_cu8(ais_demod_t *demod, const uint8_t *buf, size_t len) {
    size_t s;
    int c, t;
    float x, y, mi, mq, acc_i, acc_q;
    ais_channel_t *chan;
    const float *hi, *hq;

    for (s = 0; s + 1 < len; s += 2) {
        x = demod->cu8_lut[buf[s]];
        y = demod->cu8_lut[buf[s + 1]];

        for (c = 0; c < 2; c++) {
            chan = &demod->channels[c];

            mi = x * chan->lo_i[demod->lo_pos] - y * chan->lo_q[demod->lo_pos];
            mq = x * chan->lo_q[demod->lo_pos] + y * chan->lo_i[demod->lo_pos];

            chan->hist_i[demod->hist_pos] = chan->hist_i[demod->hist_pos + AIS_FIR_TAPS] = mi;
            chan->hist_q[demod->hist_pos] = chan->hist_q[demod->hist_pos + AIS_FIR_TAPS] = mq;
        }

        if (++demod->lo_pos >= AIS_LO_LEN)
            demod->lo_pos = 0;

        if (++demod->hist_pos >= AIS_FIR_TAPS)
            demod->hist_pos = 0;

        if (++demod->decim_count < AIS_DECIM)
            continue;

        demod->decim_count = 0;

        /* hist[hist_pos .. hist_pos + TAPS) is oldest to newest; the filter
         * is symmetric so tap order does not matter */
        for (c = 0; c < 2; c++) {
            chan = &demod->channels[c];
            hi = &chan->hist_i[demod->hist_pos];
            hq = &chan->hist_q[demod->hist_pos];
            acc_i = acc_q = 0;

            for (t = 0; t < AIS_FIR_TAPS; t++) {
                acc_i += hi[t] * demod->fir[t];
                acc_q += hq[t] * demod->fir[t];
            }

            ais_channel_sample(demod, c, acc_i, acc_q);
        }
    }
}

unsigned long ais_demod_frames(ais_demod_t *demod, int channel) {
    if (channel < 0 || channel > 1)
        return 0;
    return demod->channels[channel].frames;
}

unsigned long ais_demod_crc_errors(ais_demod_t *demod, int channel) {
    if (channel < 0 || channel > 1)
        return 0;
    return demod->channels[channel].crc_errors;
}

#ifdef AIS_DEMOD_MAIN
/* Standalone test harness:
 *   rtl_sdr -f 162000000 -s 288000 - | ./ais_demod_test
 *   ./ais_demod_test < capture.cu8
 */
static void test_cb(void *ctx, int channel, const uint8_t *payload,
        size_t payload_len, float level_dbfs) {
    size_t i;

    (void) ctx;

    printf("%c %5.1f ", channel == AIS_CHANNEL_A ? 'A' : 'B', level_dbfs);
    for (i = 0; i < payload_len; i++)
        printf("%02x", payload[i]);
    printf("\n");
    fflush(stdout);
}

int main(void) {
    uint8_t buf[65536];
    size_t r;
    ais_demod_t *demod = ais_demod_new(test_cb, NULL);

    if (demod == NULL)
        return 1;

    while ((r = fread(buf, 1, sizeof(buf), stdin)) > 0)
        ais_demod_process_cu8(demod, buf, r);

    fprintf(stderr, "A: %lu frames, %lu crc errors; B: %lu frames, %lu crc errors\n",
            ais_demod_frames(demod, AIS_CHANNEL_A), ais_demod_crc_errors(demod, AIS_CHANNEL_A),
            ais_demod_frames(demod, AIS_CHANNEL_B), ais_demod_crc_errors(demod, AIS_CHANNEL_B));

    ais_demod_free(demod);

    return 0;
}
#endif

