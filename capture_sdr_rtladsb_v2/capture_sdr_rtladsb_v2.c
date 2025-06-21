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

/* 
 * Interface format:  rtladsb, rtlsdb-[devnum], rtladsb-[serial]
 *
 * Parameters: gain=xyz, ppm=xyz, uuid=xyz, biast=bool, biastgpio=#, pass_invalid=bool
 *
 */

#include "../config.h"

#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>

#include <sched.h>

#include <string.h>

/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <dirent.h>

#include <unistd.h>
#include <errno.h>

#include <time.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <stdint.h>
#include <stdio.h>
#include <rtl-sdr.h>

#include "../capture_framework.h"

#define ADSB_RATE			        2000000
#define ADSB_FREQ			        1090000000
#define DEFAULT_ASYNC_BUF_NUMBER	12
#define DEFAULT_BUF_LENGTH		    (16 * 16384)
#define AUTO_GAIN			        -100
#define preamble_len		        16
#define long_frame		            112
#define short_frame		            56

#define MESSAGEGO    253
#define OVERWRITE    254
#define BADSAMPLE    255

typedef struct {
    pthread_t demod_thread;

    rtlsdr_dev_t *dev;

    pthread_cond_t ready;
    pthread_mutex_t ready_mutex;

    uint16_t squares[256];

    int quality;
    int allowed_errors;
    int pass_non_crc;

    uint8_t adsb_frame[14];

    int do_exit;

    uint8_t buffer[DEFAULT_BUF_LENGTH];

    int gain;
    int ppm;

    int bias_tee;
    int bias_tee_gpio;
} local_adsb_t;

uint32_t modes_checksum_table[] = {
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

/* Find the nearest supported gain */
int nearest_gain(rtlsdr_dev_t *dev, int target_gain) {
    int i, r, err1, err2, count, nearest;
    int *gains;

    r = rtlsdr_set_tuner_gain_mode(dev, 1);

    if (r < 0) {
        fprintf(stderr, "WARNING: Failed to enable manual gain.\n");
        return r;
    }

    count = rtlsdr_get_tuner_gains(dev, NULL);
    if (count <= 0) {
        return 0;
    }

    gains = malloc(sizeof(int) * count);
    count = rtlsdr_get_tuner_gains(dev, gains);
    nearest = gains[0];
    for (i = 0; i < count; i++) {
        err1 = abs(target_gain - nearest);
        err2 = abs(target_gain - gains[i]);
        if (err2 < err1) {
            nearest = gains[i];
        }
    }
    free(gains);

    return nearest;
}

/* Precompute squares as a LUT */
int abs8(int x) {
    if (x >= 127)
        return x - 127;
    return 127 - x;
}

void compute_squares(local_adsb_t *local) {
    int i, j;

    for (i = 0; i < 256; i++) {
        j = abs8(i);
        local->squares[i] = (uint16_t)(j * j);
    }
}

/* Compute magnitude of iq */
int magnitude(kis_capture_handler_t *caph, uint8_t *buf, int len) {
    local_adsb_t *adsb = (local_adsb_t *) caph->userdata;
    int i;
    uint16_t *m;

    for (i = 0; i < len; i += 2) {
        m = (uint16_t *) (&buf[i]);
        *m = adsb->squares[buf[i]] + adsb->squares[buf[i+1]];
    }

    return len / 2;
}

/* takes 4 consecutive real samples, return 0 or 1, BADSAMPLE on error */
uint16_t single_manchester(kis_capture_handler_t *caph, uint16_t a, 
        uint16_t b, uint16_t c, uint16_t d) {
    local_adsb_t *adsb = (local_adsb_t *) caph->userdata;
    int bit, bit_p;
    bit_p = a > b;
    bit = c > d;

    if (adsb->quality == 0) {
        return bit;
    }

    if (adsb->quality == 5) {
        if (bit && bit_p && b > c) {
            return BADSAMPLE;
        }
        if (!bit && !bit_p && b < c) {
            return BADSAMPLE;
        }
        return bit;
    }

    if (adsb->quality == 10) {
        if (bit && bit_p && c > b) {
            return 1;
        }
        if (bit && !bit_p && d < b) {
            return 1;
        }
        if (!bit && bit_p && d > b) {
            return 0;
        }
        if (!bit && !bit_p && c < b) {
            return 0;
        }
        return BADSAMPLE;
    }

    if (bit && bit_p && c > b && d < a) {
        return 1;
    }
    if (bit && !bit_p && c > a && d < b) {
        return 1;
    }
    if (!bit && bit_p && c < a && d > b) {
        return 0;
    }
    if (!bit && !bit_p && c < b && d > a) {
        return 0;
    }

    return BADSAMPLE;
}

inline uint16_t min16(uint16_t a, uint16_t b) { return a < b ? a : b; }
inline uint16_t max16(uint16_t a, uint16_t b) { return a > b ? a : b; }

uint32_t modes_checksum(const uint8_t *buf, size_t len) {
    uint32_t crc = 0;
    size_t offset = 0;

    if (len < 7)
        return 0;

    if (len != 14)
        offset = 112 - 56;

    for (unsigned int j = 0; j < len * 8; j++) {
        uint8_t b = j / 8;
        uint8_t bit = j % 8;
        uint8_t mask = 1 << (7 - bit);

        if (buf[b] & mask) {
            crc ^= modes_checksum_table[j + offset];
        }
    }

    return (crc & 0x00FFFFFF);
}

uint32_t adsb_msg_get_crc(const uint8_t *buf, size_t len) {
    if (len < 7) {
        return 0;
    }

    uint32_t crc = 0;

    crc = buf[len - 3] << 16;
    crc |= buf[len - 2] << 8;
    crc |= buf[len - 1];

    return crc & 0x00FFFFFF;
}

/* returns 0/1 for preamble at index i */
int preamble(uint16_t *buf, int i) {
    int i2;
    uint16_t low = 0;
    uint16_t high = 65535;

    for (i2 = 0; i2 < preamble_len; i2++) {
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

        if (high <= low) {
            return 0;
        }
    }

    return 1;
}

/* overwrites magnitude buffer with valid bits (BADSAMPLE on errors) */
void manchester(kis_capture_handler_t *caph, uint16_t *buf, int len) {
    local_adsb_t *adsb = (local_adsb_t *) caph->userdata;
    /* a and b hold old values to verify local manchester */
    uint16_t a = 0, b = 0;
    uint16_t bit;
    int i, i2, start, errors;
    int maximum_i = len - 1; // len-1 since we look at i and i+1
    i = 0;

    while (i < maximum_i) {
        /* find preamble */
        for (; i < (len - preamble_len); i++) {
            if (!preamble(buf, i)) {
                continue;
            }

            a = buf[i];
            b = buf[i + 1];
            for (i2 = 0; i2 < preamble_len; i2++) {
                buf[i + i2] = MESSAGEGO;
            }
            i += preamble_len;
            break;
        }

        i2 = start = i;
        errors = 0;

        /* mark bits until encoding breaks */
        for (; i < maximum_i; i += 2, i2++) {
            bit = single_manchester(caph, a, b, buf[i], buf[i + 1]);
            a = buf[i];
            b = buf[i + 1];
            if (bit == BADSAMPLE) {
                errors += 1;
                if (errors > adsb->allowed_errors) {
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
    }
}

void messages(kis_capture_handler_t *caph, uint16_t *buf, int len) {
    local_adsb_t *adsb = (local_adsb_t *) caph->userdata;
    int i, data_i, index, shift, frame_len, r, df;
    struct timeval tv;
    char adsb_char[(14*2) + 1];
    char json[256];
    uint32_t crc1, crc2;

    for (i = 0; i < len; i++) {
        if (buf[i] > 1) {
            continue;
        }

        frame_len = long_frame;
        data_i = 0;

        for (index = 0; index < 14; index++) {
            adsb->adsb_frame[index] = 0;
        }

        for (; i < len && buf[i] <= 1 && data_i < frame_len; i++, data_i++) {
            if (buf[i]) {
                index = data_i / 8;
                shift = 7 - (data_i % 8);
                adsb->adsb_frame[index] |= (uint8_t) (1 << shift);
            }

            if (data_i == 7) {
                if (adsb->adsb_frame[0] == 0) {
                    break;
                }

                if (adsb->adsb_frame[0] & 0x80) {
                    frame_len = long_frame;
                } else {
                    frame_len = short_frame;
                }
            }
        }

        if (data_i < (frame_len - 1)) {
            continue;
        }

        crc1 = adsb_msg_get_crc(adsb->adsb_frame, frame_len / 8);
        crc2 = modes_checksum(adsb->adsb_frame, frame_len / 8);

        if (crc1 != crc2) {
            continue;
        }

        df = (adsb->adsb_frame[0] >> 3) & 0x1f;
        if (adsb->quality == 0 && !(df == 11 || df == 17 || df == 18 || df == 19)) {
            continue;
        }

        for (r = 0; r < ((frame_len + 7) / 8); r++) {
            sprintf(adsb_char + (r * 2), "%02x", adsb->adsb_frame[r]);
        }

        snprintf(json, 256, "{\"adsb\": \"*%s;\"}", adsb_char);

        /* Transmit the adsb frame as a JSON */

        gettimeofday(&tv, NULL);

        while (1) { 
            if ((r = cf_send_json(caph, NULL, 0, NULL, NULL, tv, "adsb", json)) < 0) {
                cf_send_error(caph, 0, "unable to send JSON frame");
                cf_handler_spindown(caph);
                continue;
            } else if (r == 0) {
                cf_handler_wait_ringbuffer(caph);
            } else {
                break;
            }
        }

        /* display(adsb_frame, frame_len); */
    }
}

static void rtlsdr_callback(unsigned char *buf, uint32_t len, void *ctx) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) ctx;
    local_adsb_t *adsb = (local_adsb_t *) caph->userdata;

    if (caph->spindown || adsb->do_exit) {
        return;
    }

    memcpy(adsb->buffer, buf, len);

    wrap_cond_signal(&adsb->ready, &adsb->ready_mutex);
}

static void *rtlsdr_demod_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;
    local_adsb_t *adsb = (local_adsb_t *) caph->userdata;

    int len;

    while (!caph->spindown && !adsb->do_exit) {
        wrap_cond_wait(&adsb->ready, &adsb->ready_mutex);
        len = magnitude(caph, adsb->buffer, DEFAULT_BUF_LENGTH);
        manchester(caph, (uint16_t *) adsb->buffer, len);
        messages(caph, (uint16_t *) adsb->buffer, len);
        pthread_mutex_unlock(&adsb->ready_mutex);
    }

    rtlsdr_cancel_async(adsb->dev);
    return NULL;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg, 
        cf_params_list_interface_t ***interfaces) {
    unsigned int num_radios = rtlsdr_get_device_count();
    int i;
    char buf[256];

    *interfaces =
            (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) *
                                                           num_radios);

    for (i = 0; i < num_radios; i++) {
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));
        snprintf(buf, 256, "rtladsb-%u", i);
        (*interfaces)[i]->interface = strdup(buf);
        (*interfaces)[i]->hardware = strdup("rtlsdr");
    }

    return num_radios;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition, 
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface, 
        cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char *subinterface;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    unsigned int num_devices = 0;
    int matched_device = 0;
    int num_device = 0;

    char manuf_buf[256];
    char product_buf[256];
    char serial_buf[256];

    char buf[STATUS_MAX];

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for:
     * rtladsb
     * rtladsb-[serial]
     * rtladsb-[0, 1, 2, 3...]
     */

    /* Look for the interface type */
    if (strstr(interface, "rtladsb") != interface) {
        free(interface);
        return 0;
    }

    num_devices = rtlsdr_get_device_count();

    if (strlen(interface) == strlen("rtladsb")) {
        matched_device = 1;
        num_device = 0;
    } else {
        subinterface = strstr(interface, "-");
        if (subinterface == NULL) {
            free(interface);
            snprintf(msg, STATUS_MAX, "Unable to parse rtladsb interface in definition");
            return 0;
        }

        /* Is this a serial #? */
        num_device = rtlsdr_get_index_by_serial(subinterface + 1);

        if (num_device >= 0) {
            matched_device = 1;
        } else {
            if (sscanf(subinterface, "%u", &num_device) == 1) {
                if (num_device >= 0 && num_device < num_devices) {
                    matched_device = 1;
                }
            }
        }
    }

    if (matched_device == 0) {
        free(interface);
        snprintf(msg, STATUS_MAX, "Unable to find rtladsb device");
        return 0;
    }

    free(interface);
    interface = NULL;

    snprintf(buf, STATUS_MAX, "rtladsb-%d", num_device);
    (*ret_interface)->capif = strdup(buf);
    (*ret_interface)->hardware = strdup("rtlsdr");

    if (rtlsdr_get_device_usb_strings(num_device, manuf_buf,
                                      product_buf, serial_buf) != 0) {
        snprintf(msg, STATUS_MAX, "Unable to find rtladsb device");
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        uint32_t hash;

        snprintf(buf, STATUS_MAX, "%s%s%s", manuf_buf, product_buf, serial_buf);
        hash = adler32_csum((unsigned char *) buf, strlen(buf));

        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                 adler32_csum((unsigned char *) "kismet_cap_sdr_rtladsb",
                              strlen("kismet_cap_sdr_rtladsb")) & 0xFFFFFFFF,
                 hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    (*ret_interface)->channels = (char **) malloc(sizeof(char *));
    (*ret_interface)->channels[0] = strdup("1090MHz");
    (*ret_interface)->channels_len = 1;

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_adsb_t *adsb = (local_adsb_t *) caph->userdata;

    char *placeholder = NULL;
    int placeholder_len = 0;
    char *tmp = NULL;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    char *interface;
    char *subinterface;

    unsigned int num_devices = 0;
    int matched_device = 0;
    int num_device = 0;

    char manuf_buf[256];
    char product_buf[256];
    char serial_buf[256];

    char buf[STATUS_MAX];
    char errstr[STATUS_MAX];

    int r;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "rtladsb") != interface) {
        free(interface);
        return 0;
    }

    num_devices = rtlsdr_get_device_count();

    if (strlen(interface) == strlen("rtladsb")) {
        matched_device = 1;
        num_device = 0;
    } else {
        subinterface = strstr(interface, "-");
        if (subinterface == NULL) {
            free(interface);
            snprintf(msg, STATUS_MAX, "Unable to parse rtladsb interface in definition");
            return 0;
        }

        /* Is this a serial #? */
        num_device = rtlsdr_get_index_by_serial(subinterface + 1);

        if (num_device >= 0) {
            matched_device = 1;
        } else {
            if (sscanf(subinterface + 1, "%u", &num_device) == 1) {
                if (num_device >= 0 && num_device < num_devices) {
                    matched_device = 1;
                }
            }
        }
    }

    if (matched_device == 0) {
        free(interface);
        snprintf(msg, STATUS_MAX, "Unable to find rtladsb device");
        return 0;
    }

    free(interface);
    interface = NULL;

    snprintf(buf, STATUS_MAX, "rtladsb-%d", num_device);
    (*ret_interface)->capif = strdup(buf);
    (*ret_interface)->hardware = strdup("rtlsdr");

    if (rtlsdr_get_device_usb_strings(num_device, manuf_buf, product_buf, serial_buf) != 0) {
        snprintf(msg, STATUS_MAX, "Unable to find rtladsb device");
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        uint32_t hash;

        snprintf(buf, STATUS_MAX, "%s%s%s", manuf_buf, product_buf, serial_buf);
        hash = adler32_csum((unsigned char *) buf, strlen(buf));

        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                 adler32_csum((unsigned char *) "kismet_cap_sdr_rtladsb",
                              strlen("kismet_cap_sdr_rtladsb")) & 0xFFFFFFFF,
                 hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "gain", definition)) > 0) {
        tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%d", &adsb->gain) != 1) { 
            snprintf(msg, STATUS_MAX, "%s: expected gain=X", interface); 
            free(tmp);
            return -1;
        }

        free(tmp);
        tmp = NULL;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "ppm", definition)) > 0) {
        tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%d", &adsb->ppm) != 1) { 
            snprintf(msg, STATUS_MAX, "%s: expected ppm=X", interface); 
            free(tmp);
            return -1;
        }

        free(tmp);
        tmp = NULL;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "pass_invalid", definition)) > 0) {
        if (strncmp(placeholder, "true", placeholder_len) == 0) {
            adsb->pass_non_crc = 1;
        }
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "biast", definition)) > 0) {
#ifdef HAVE_LIBRTLSDR_BIAS_T
        if (strncmp(placeholder, "true", placeholder_len) == 0) {
            adsb->bias_tee = 1;
        }
#else
        snprintf(msg, STATUS_MAX, "%s: the version of librtlsdr used does not support the bias-tee control", interface); 
        return -1;

#endif
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "biastgpio", definition)) > 0) {
#ifdef HAVE_LIBRTLSDR_BIAS_T
        tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%d", &adsb->bias_tee_gpio) != 1) { 
            snprintf(msg, STATUS_MAX, "%s: expected biastgpio=[GPIO#]", interface); 
            free(tmp);
            return -1;
        }

        adsb->bias_tee = 2;

        free(tmp);
        tmp = NULL;
#else
        snprintf(msg, STATUS_MAX, "%s: the version of librtlsdr used does not support the bias-tee control", interface); 
        return -1;

#endif
    }


    r = rtlsdr_open(&adsb->dev, num_device);
    if (r < 0) {
        snprintf(msg, STATUS_MAX, "%s: failed to open device %s", interface, (*ret_interface)->capif);
        return -1;
    }

    /* Gain is allowed to fail */
    if (adsb->gain == AUTO_GAIN) {
        r = rtlsdr_set_tuner_gain_mode(adsb->dev, 0);
        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "%s: could not set auto-gain control on %s",
                    interface, (*ret_interface)->capif);
            cf_send_warning(caph, errstr);
        } 
    } else {
        adsb->gain = nearest_gain(adsb->dev, adsb->gain);
        r = rtlsdr_set_tuner_gain_mode(adsb->dev, 1);
        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "%s: could not set manual gain control on %s", 
                    interface, (*ret_interface)->capif);
            cf_send_warning(caph, errstr);
        } else {
            r = rtlsdr_set_tuner_gain(adsb->dev, adsb->gain);
            if (r < 0) {
                snprintf(errstr, STATUS_MAX, "%s: could not set gain level on %s", 
                        interface, (*ret_interface)->capif);
                cf_send_warning(caph, errstr);
            }
        }
    }

    /* ppm is mandatory */ 
    if (adsb->ppm != 0) {
        r = rtlsdr_set_freq_correction(adsb->dev, adsb->ppm);
        if (r < 0) {
            snprintf(msg, STATUS_MAX, "%s: could not set ppm correction on %s", 
                    interface, (*ret_interface)->capif);
            return -1;
        }
    }

    /* set AGC, ignore errors */
    r = rtlsdr_set_agc_mode(adsb->dev, 1);

    /* Tuning and same rates are of course mandatory */
    r = rtlsdr_set_center_freq(adsb->dev, ADSB_FREQ);
    if (r < 0) {
        snprintf(msg, STATUS_MAX, "%s: could not set tuning on %s", interface, (*ret_interface)->capif);
        return -1;
    }

    r = rtlsdr_set_sample_rate(adsb->dev, ADSB_RATE);
    if (r < 0) {
        snprintf(msg, STATUS_MAX, "%s: could not set sample rate on %s", interface, (*ret_interface)->capif);
        return -1;
    }

#ifdef HAVE_LIBRTLSDR_BIAS_T
    if (adsb->bias_tee == 1) {
        r = rtlsdr_set_bias_tee(adsb->dev, 1);
        if (r < 0) {
            snprintf(msg, STATUS_MAX, "%s: could not enable bias-tee power on %s", 
                    interface, (*ret_interface)->capif);
            return -1;
        }
    }
#endif

#ifdef HAVE_LIBRTLSDR_BIAS_T_GPIO
    if (adsb->bias_tee == 2) {
        r = rtlsdr_set_bias_tee_gpio(adsb->dev, adsb->bias_tee_gpio, 1);
        if (r < 0) {
            snprintf(msg, STATUS_MAX, "%s: could not enable bias-tee power for "
                    "gpio %d on %s", interface, adsb->bias_tee_gpio, 
                    (*ret_interface)->capif);
            return -1;
        }
    }
#endif

    r = rtlsdr_reset_buffer(adsb->dev);
    if (r < 0) {
        snprintf(msg, STATUS_MAX, "%s: could not reset buffer on %s", interface, (*ret_interface)->capif);
        return -1;
    }

    (*ret_interface)->hardware = strdup("rtlsdr");
    (*ret_interface)->channels = (char **) malloc(sizeof(char *));
    (*ret_interface)->channels[0] = strdup("1090MHz");
    (*ret_interface)->channels_len = 1;

    pthread_create(&adsb->demod_thread, NULL, rtlsdr_demod_thread, (void *) caph);

    /* Defer launching async to the service thread */

    return 1;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_adsb_t *adsb = (local_adsb_t *) caph->userdata;

    /* Start the async io that feeds the demod thread */

    rtlsdr_read_async(adsb->dev, rtlsdr_callback, caph,
            DEFAULT_ASYNC_BUF_NUMBER, DEFAULT_BUF_LENGTH);

    /* do nothing until we're done */

    rtlsdr_cancel_async(adsb->dev); 

    pthread_cond_destroy(&adsb->ready);
    pthread_mutex_destroy(&adsb->ready_mutex);

    rtlsdr_close(adsb->dev);
    adsb->dev = NULL;
}

int main(int argc, char *argv[]) {
    local_adsb_t local_adsb = {
        .dev = NULL,
        .quality = 10, 
        .allowed_errors = 5,
        .pass_non_crc = 0,
        .do_exit = 0,
        .gain = AUTO_GAIN, 
        .ppm = 0,
        .bias_tee = 0,
        .bias_tee_gpio = 0,
    };


    pthread_cond_init(&local_adsb.ready, NULL);
    pthread_mutex_init(&local_adsb.ready_mutex, NULL);
    compute_squares(&local_adsb);

    kis_capture_handler_t *caph = cf_handler_init("rtladsb");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    cf_handler_set_userdata(caph, &local_adsb);

    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback); 
    cf_handler_set_listdevices_cb(caph, list_callback); 
    cf_handler_set_capture_cb(caph, capture_thread); 

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_remote_capture(caph); 

    cf_jail_filesystem(caph); 
    cf_drop_most_caps(caph); 

    cf_handler_loop(caph); 

    cf_handler_shutdown(caph);

    return 0;
}


