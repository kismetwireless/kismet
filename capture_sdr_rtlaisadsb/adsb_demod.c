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

    This ADSB code was derived from the ADSB code of librtlsdr,

    Kismet additions,
    Copyright (C) 2024 by Mike Kershaw <dragorn@kismetwireless.net>

    rtl-sdr, turns your Realtek RTL2832 based DVB dongle into a SDR receiver

    Copyright (C) 2012 by Steve Markgraf <steve@steve-m.de>
    Copyright (C) 2012 by Hoernchen <la@tfc-server.de>
    Copyright (C) 2012 by Kyle Keen <keenerd@gmail.com>
    Copyright (C) 2012 by Youssef Touil <youssef@sdrsharp.com>
    Copyright (C) 2012 by Ian Gilmour <ian@sdrsharp.com>
*/

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "adsb_demod.h"

#define PREAMBLE_LEN    16
#define LONG_FRAME      112
#define SHORT_FRAME     56

#define MESSAGEGO       253
#define OVERWRITE       254
#define BADSAMPLE       255

/* Manchester checking strictness and tolerated errors, as capture_sdr_rtladsb_v2 */
#define ADSB_QUALITY        10
#define ADSB_ALLOWED_ERRORS 5

/* Bits averaged for the signal level; every frame has at least this many */
#define LEVEL_BITS          SHORT_FRAME
/* Magnitude of a full scale cu8 sample, (128^2) */
#define FULL_SCALE          16384.0f

struct adsb_demod {
    adsb_frame_cb_t cb;
    void *cb_ctx;

    uint16_t squares[256];

    uint16_t *mag;
    size_t mag_len;

    /* Mean pulse magnitude of each run of bits, at the index the run starts */
    uint32_t *power;

    unsigned long frames;
};

static const uint32_t modes_checksum_table[] = {
        0x3935ea, 0x1c9af5, 0xf1b77e, 0x78dbbf, 0xc397db, 0x9e31e9,
        0xb0e2f0, 0x587178, 0x2c38bc, 0x161c5e, 0x0b0e2f, 0xfa7d13,
        0x82c48d, 0xbe9842, 0x5f4c21, 0xd05c14, 0x682e0a, 0x341705,
        0xe5f186, 0x72f8c3, 0xc68665, 0x9cb936, 0x4e5c9b, 0xd8d449,
        0x939020, 0x49c810, 0x24e408, 0x127204, 0x093902, 0x049c81,
        0xfdb444, 0x7eda22, 0x3f6d11, 0xe04c8c, 0x702646, 0x381323,
        0xe3f395, 0x8e03ce, 0x4701e7, 0xdc7af7, 0x91c77f, 0xb719bb,
        0xa476d9, 0xadc168, 0x56e0b4, 0x2b705a, 0x15b82d, 0xf52612,
        0x7a9309, 0xc2b380, 0x6159c0, 0x30ace0, 0x185670, 0x0c2b38,
        0x06159c, 0x030ace, 0x018567, 0xff38b7, 0x80665f, 0xbfc92b,
        0xa01e91, 0xaff54c, 0x57faa6, 0x2bfd53, 0xea04ad, 0x8af852,
        0x457c29, 0xdd4410, 0x6ea208, 0x375104, 0x1ba882, 0x0dd441,
        0xf91024, 0x7c8812, 0x3e4409, 0xe0d800, 0x706c00, 0x383600,
        0x1c1b00, 0x0e0d80, 0x0706c0, 0x038360, 0x01c1b0, 0x00e0d8,
        0x00706c, 0x003836, 0x001c1b, 0xfff409, 0x000000, 0x000000,
        0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000,
        0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000,
        0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000,
        0x000000, 0x000000, 0x000000, 0x000000
};

static int abs8(int x) {
    if (x >= 127)
        return x - 127;
    return 127 - x;
}

/* takes 4 consecutive real samples, return 0 or 1, BADSAMPLE on error */
static uint16_t single_manchester(uint16_t a, uint16_t b, uint16_t c, uint16_t d) {
    int bit, bit_p;
    bit_p = a > b;
    bit = c > d;

    if (bit && bit_p && c > b)
        return 1;
    if (bit && !bit_p && d < b)
        return 1;
    if (!bit && bit_p && d > b)
        return 0;
    if (!bit && !bit_p && c < b)
        return 0;

    return BADSAMPLE;
}

static uint32_t modes_checksum(const uint8_t *buf, size_t len) {
    uint32_t crc = 0;
    size_t offset = 0;
    unsigned int j;

    if (len < 7)
        return 0;

    if (len != 14)
        offset = LONG_FRAME - SHORT_FRAME;

    for (j = 0; j < len * 8; j++) {
        if (buf[j / 8] & (1 << (7 - (j % 8))))
            crc ^= modes_checksum_table[j + offset];
    }

    return crc & 0x00FFFFFF;
}

static uint32_t adsb_msg_get_crc(const uint8_t *buf, size_t len) {
    if (len < 7)
        return 0;

    return ((uint32_t) buf[len - 3] << 16 | (uint32_t) buf[len - 2] << 8 | buf[len - 1]) &
        0x00FFFFFF;
}

/* returns 0/1 for preamble at index i */
static int preamble(const uint16_t *buf, size_t i) {
    int i2;
    uint16_t low = 0;
    uint16_t high = 65535;

    for (i2 = 0; i2 < PREAMBLE_LEN; i2++) {
        switch (i2) {
            case 0:
            case 2:
            case 7:
            case 9:
                high = buf[i + i2];
                break;
            default:
                low = buf[i + i2];
                break;
        }

        if (high <= low)
            return 0;
    }

    return 1;
}

/* overwrites magnitude buffer with valid bits (BADSAMPLE on errors) */
static void manchester(uint16_t *buf, uint32_t *power, size_t len) {
    /* a and b hold old values to verify local manchester */
    uint16_t a = 0, b = 0;
    uint16_t bit;
    size_t i, i2, start;
    uint32_t sum, nbits;
    int errors;

    if (len <= PREAMBLE_LEN + 1)
        return;

    i = 0;

    while (i < len - 1) {
        /* find preamble */
        for (; i < len - PREAMBLE_LEN; i++) {
            if (!preamble(buf, i))
                continue;

            a = buf[i];
            b = buf[i + 1];
            for (i2 = 0; i2 < PREAMBLE_LEN; i2++)
                buf[i + i2] = MESSAGEGO;
            i += PREAMBLE_LEN;
            break;
        }

        i2 = start = i;
        errors = 0;
        sum = nbits = 0;

        /* mark bits until encoding breaks */
        for (; i < len - 1; i += 2, i2++) {
            /* The pulse is in whichever half of the bit is high */
            if (nbits < LEVEL_BITS) {
                sum += buf[i] > buf[i + 1] ? buf[i] : buf[i + 1];
                nbits++;
            }

            bit = single_manchester(a, b, buf[i], buf[i + 1]);
            a = buf[i];
            b = buf[i + 1];
            if (bit == BADSAMPLE) {
                errors += 1;
                if (errors > ADSB_ALLOWED_ERRORS) {
                    buf[i2] = BADSAMPLE;
                    break;
                } else {
                    bit = a > b;
                    /* these don't have to match the bit */
                    a = 0;
                    b = 65535;
                }
            }
            buf[i] = buf[i + 1] = OVERWRITE;
            buf[i2] = bit;
        }

        if (start < len)
            power[start] = nbits ? sum / nbits : 0;
    }
}

static void messages(adsb_demod_t *demod, const uint16_t *buf, size_t len) {
    uint8_t frame[ADSB_MAX_FRAME_BYTES];
    size_t i;
    int data_i, frame_len;
    uint32_t run_power = 0;

    for (i = 0; i < len; i++) {
        if (buf[i] > 1)
            continue;

        /* A frame starting partway through a run has the run's level */
        if (i == 0 || buf[i - 1] > 1)
            run_power = demod->power[i];

        frame_len = LONG_FRAME;
        data_i = 0;

        memset(frame, 0, sizeof(frame));

        for (; i < len && buf[i] <= 1 && data_i < frame_len; i++, data_i++) {
            if (buf[i])
                frame[data_i / 8] |= (uint8_t) (1 << (7 - (data_i % 8)));

            if (data_i == 7) {
                if (frame[0] == 0)
                    break;

                if (frame[0] & 0x80)
                    frame_len = LONG_FRAME;
                else
                    frame_len = SHORT_FRAME;
            }
        }

        if (data_i < (frame_len - 1))
            continue;

        if (adsb_msg_get_crc(frame, frame_len / 8) != modes_checksum(frame, frame_len / 8))
            continue;

        demod->frames++;

        if (demod->cb != NULL)
            demod->cb(demod->cb_ctx, frame, frame_len / 8,
                    10.0f * log10f(((float) run_power + 1e-3f) / FULL_SCALE));
    }
}

adsb_demod_t *adsb_demod_new(size_t max_buf_len, adsb_frame_cb_t cb, void *ctx) {
    adsb_demod_t *demod;
    int i, j;

    demod = (adsb_demod_t *) calloc(1, sizeof(adsb_demod_t));
    if (demod == NULL)
        return NULL;

    demod->mag_len = max_buf_len / 2;
    demod->mag = (uint16_t *) malloc(sizeof(uint16_t) * (demod->mag_len + 1));
    demod->power = (uint32_t *) calloc(demod->mag_len + 1, sizeof(uint32_t));
    if (demod->mag == NULL || demod->power == NULL) {
        free(demod->mag);
        free(demod->power);
        free(demod);
        return NULL;
    }

    demod->cb = cb;
    demod->cb_ctx = ctx;

    for (i = 0; i < 256; i++) {
        j = abs8(i);
        demod->squares[i] = (uint16_t) (j * j);
    }

    return demod;
}

void adsb_demod_free(adsb_demod_t *demod) {
    if (demod == NULL)
        return;

    free(demod->mag);
    free(demod->power);
    free(demod);
}

void adsb_demod_process_cu8(adsb_demod_t *demod, const uint8_t *buf, size_t len) {
    size_t i, n;

    n = len / 2;
    if (n > demod->mag_len)
        n = demod->mag_len;

    for (i = 0; i < n; i++)
        demod->mag[i] = demod->squares[buf[i * 2]] + demod->squares[buf[i * 2 + 1]];

    manchester(demod->mag, demod->power, n);
    messages(demod, demod->mag, n);
}

unsigned long adsb_demod_frames(adsb_demod_t *demod) {
    return demod->frames;
}
