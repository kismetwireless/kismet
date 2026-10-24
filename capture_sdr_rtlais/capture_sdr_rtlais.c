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
 * Interface format:  rtlais, rtlais-[devnum], rtlais-[serial]
 *
 * Parameters: gain=xyz, ppm=xyz, uuid=xyz, biast=bool, biastgpio=#
 *
 * Tunes between the two AIS channels and demodulates both simultaneously;
 * valid frames are sent to Kismet as hex-encoded payloads in a JSON record:
 *
 * {"ais": "<hex>", "channel": "A", "freq_khz": 161975, "level": -23.1}
 */

#include "../config.h"

#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <stdlib.h>

#include <sys/time.h>
#include <sys/types.h>

#include <unistd.h>
#include <errno.h>

#include <stdint.h>
#include <stdio.h>
#include <rtl-sdr.h>

#include "../capture_framework.h"

#include "ais_demod.h"

#define DEFAULT_ASYNC_BUF_NUMBER	12
/* ~114ms of samples at 288k */
#define DEFAULT_BUF_LENGTH		    (4 * 16384)
#define AUTO_GAIN			        -100

typedef struct {
    pthread_t demod_thread;

    rtlsdr_dev_t *dev;

    pthread_cond_t ready;
    pthread_mutex_t ready_mutex;
    int data_ready;
    uint32_t data_len;

    ais_demod_t *demod;

    kis_capture_handler_t *caph;

    int do_exit;

    uint8_t buffer[DEFAULT_BUF_LENGTH];

    int gain;
    int ppm;

    int bias_tee;
    int bias_tee_gpio;
} local_ais_t;

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
    if (gains == NULL)
        return 0;

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

static void ais_frame_cb(void *ctx, int channel, const uint8_t *payload,
        size_t payload_len, float level_dbfs) {
    local_ais_t *ais = (local_ais_t *) ctx;
    kis_capture_handler_t *caph = ais->caph;
    struct timeval tv;
    struct cf_params_signal signal;
    char hex[(AIS_MAX_PAYLOAD_BYTES * 2) + 1];
    char json[512];
    char chanstr[16];
    unsigned int freq_khz;
    size_t i;
    int r;

    if (payload_len > AIS_MAX_PAYLOAD_BYTES)
        return;

    for (i = 0; i < payload_len; i++)
        snprintf(hex + (i * 2), 3, "%02x", payload[i]);
    hex[payload_len * 2] = 0;

    if (channel == AIS_CHANNEL_A) {
        freq_khz = 161975;
        snprintf(chanstr, sizeof(chanstr), "161.975MHz");
    } else {
        freq_khz = 162025;
        snprintf(chanstr, sizeof(chanstr), "162.025MHz");
    }

    snprintf(json, sizeof(json),
            "{\"ais\": \"%s\", \"channel\": \"%c\", \"freq_khz\": %u, \"level\": %.1f}",
            hex, channel == AIS_CHANNEL_A ? 'A' : 'B', freq_khz, level_dbfs);

    memset(&signal, 0, sizeof(struct cf_params_signal));
    signal.signal_dbm = (int32_t) (level_dbfs < 0 ? level_dbfs - 0.5f : level_dbfs + 0.5f);
    signal.freq_khz = freq_khz;
    signal.channel = chanstr;

    gettimeofday(&tv, NULL);

    while (1) {
        if ((r = cf_send_json(caph, NULL, 0, &signal, NULL, tv, "ais", json)) < 0) {
            cf_send_error(caph, 0, "unable to send JSON frame");
            cf_handler_spindown(caph);
            break;
        } else if (r == 0) {
            cf_handler_wait_ringbuffer(caph);
        } else {
            break;
        }
    }
}

static void rtlsdr_callback(unsigned char *buf, uint32_t len, void *ctx) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) ctx;
    local_ais_t *ais = (local_ais_t *) caph->userdata;

    if (caph->spindown || ais->do_exit) {
        rtlsdr_cancel_async(ais->dev);
        return;
    }

    if (len > DEFAULT_BUF_LENGTH)
        len = DEFAULT_BUF_LENGTH;

    pthread_mutex_lock(&ais->ready_mutex);
    memcpy(ais->buffer, buf, len);
    ais->data_len = len;
    ais->data_ready = 1;
    pthread_cond_signal(&ais->ready);
    pthread_mutex_unlock(&ais->ready_mutex);
}

static void *rtlsdr_demod_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;
    local_ais_t *ais = (local_ais_t *) caph->userdata;

    pthread_mutex_lock(&ais->ready_mutex);

    while (!caph->spindown && !ais->do_exit) {
        while (!ais->data_ready && !caph->spindown && !ais->do_exit)
            pthread_cond_wait(&ais->ready, &ais->ready_mutex);

        if (!ais->data_ready)
            break;

        ais_demod_process_cu8(ais->demod, ais->buffer, ais->data_len);
        ais->data_ready = 0;
    }

    pthread_mutex_unlock(&ais->ready_mutex);

    if (ais->dev != NULL)
        rtlsdr_cancel_async(ais->dev);

    return NULL;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
        cf_params_list_interface_t ***interfaces) {
    unsigned int num_radios = rtlsdr_get_device_count();
    unsigned int i;
    char buf[256];

    if (num_radios == 0)
        return 0;

    *interfaces =
            (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) *
                                                           num_radios);

    for (i = 0; i < num_radios; i++) {
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));
        snprintf(buf, 256, "rtlais-%u", i);
        (*interfaces)[i]->interface = strdup(buf);
        (*interfaces)[i]->hardware = strdup("rtlsdr");
    }

    return num_radios;
}

/* Resolve an rtlais interface definition to a device index; returns the
 * index or -1 if the definition doesn't match a device */
static int find_rtlais_device(char *definition, char *msg) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char *subinterface;
    unsigned int num_devices;
    int num_device = -1;
    unsigned int parsed;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for:
     * rtlais
     * rtlais-[serial]
     * rtlais-[0, 1, 2, 3...]
     */
    /* Not rtlaisadsb, which shares the prefix */
    if (strncmp(interface, "rtlais", strlen("rtlais")) != 0 ||
            (interface[strlen("rtlais")] != 0 && interface[strlen("rtlais")] != '-')) {
        snprintf(msg, STATUS_MAX, "Expected a rtlais interface, skipping");
        free(interface);
        return -1;
    }

    num_devices = rtlsdr_get_device_count();

    if (strlen(interface) == strlen("rtlais")) {
        if (num_devices > 0)
            num_device = 0;
    } else {
        subinterface = strstr(interface, "-");

        if (subinterface == NULL) {
            snprintf(msg, STATUS_MAX, "Unable to parse rtlais interface in definition");
            free(interface);
            return -1;
        }

        /* Is this a serial #? */
        num_device = rtlsdr_get_index_by_serial(subinterface + 1);

        if (num_device < 0) {
            if (sscanf(subinterface + 1, "%u", &parsed) == 1 && parsed < num_devices)
                num_device = (int) parsed;
            else
                num_device = -1;
        }
    }

    free(interface);

    if (num_device < 0)
        snprintf(msg, STATUS_MAX, "Unable to find rtlais device");

    return num_device;
}

/* Fill in the common interface, uuid, and channel records */
static int populate_interface(int num_device, char *definition, char *msg, char **uuid,
        cf_params_interface_t *ret_interface) {
    char *placeholder = NULL;
    int placeholder_len;
    char manuf_buf[256];
    char product_buf[256];
    char serial_buf[256];
    char buf[STATUS_MAX];
    uint32_t hash;

    if (rtlsdr_get_device_usb_strings(num_device, manuf_buf, product_buf, serial_buf) != 0) {
        snprintf(msg, STATUS_MAX, "Unable to find rtlais device");
        return 0;
    }

    snprintf(buf, STATUS_MAX, "rtlais-%d", num_device);
    ret_interface->capif = strdup(buf);
    ret_interface->hardware = strdup("rtlsdr");

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(buf, STATUS_MAX, "%s%s%s", manuf_buf, product_buf, serial_buf);
        hash = adler32_csum((unsigned char *) buf, strlen(buf));

        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                 adler32_csum((unsigned char *) "kismet_cap_sdr_rtlais",
                              strlen("kismet_cap_sdr_rtlais")) & 0xFFFFFFFF,
                 hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    ret_interface->channels = (char **) malloc(sizeof(char *) * 2);
    ret_interface->channels[0] = strdup("161.975MHz");
    ret_interface->channels[1] = strdup("162.025MHz");
    ret_interface->channels_len = 2;

    return 1;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    int num_device;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((num_device = find_rtlais_device(definition, msg)) < 0)
        return 0;

    return populate_interface(num_device, definition, msg, uuid, *ret_interface);
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_ais_t *ais = (local_ais_t *) caph->userdata;

    char *placeholder = NULL;
    int placeholder_len = 0;
    char *tmp = NULL;

    char errstr[STATUS_MAX];

    int num_device;
    int r;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((num_device = find_rtlais_device(definition, msg)) < 0)
        return -1;

    if (populate_interface(num_device, definition, msg, uuid, *ret_interface) <= 0)
        return -1;

    if ((placeholder_len = cf_find_flag(&placeholder, "gain", definition)) > 0) {
        tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%d", &ais->gain) != 1) {
            snprintf(msg, STATUS_MAX, "%s: expected gain=X", (*ret_interface)->capif);
            free(tmp);
            return -1;
        }

        free(tmp);
        tmp = NULL;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "ppm", definition)) > 0) {
        tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%d", &ais->ppm) != 1) {
            snprintf(msg, STATUS_MAX, "%s: expected ppm=X", (*ret_interface)->capif);
            free(tmp);
            return -1;
        }

        free(tmp);
        tmp = NULL;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "biast", definition)) > 0) {
#ifdef HAVE_LIBRTLSDR_BIAS_T
        if (strncmp(placeholder, "true", placeholder_len) == 0) {
            ais->bias_tee = 1;
        }
#else
        snprintf(msg, STATUS_MAX, "%s: the version of librtlsdr used does not support the "
                "bias-tee control", (*ret_interface)->capif);
        return -1;
#endif
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "biastgpio", definition)) > 0) {
#ifdef HAVE_LIBRTLSDR_BIAS_T_GPIO
        tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%d", &ais->bias_tee_gpio) != 1) {
            snprintf(msg, STATUS_MAX, "%s: expected biastgpio=[GPIO#]", (*ret_interface)->capif);
            free(tmp);
            return -1;
        }

        ais->bias_tee = 2;

        free(tmp);
        tmp = NULL;
#else
        snprintf(msg, STATUS_MAX, "%s: the version of librtlsdr used does not support the "
                "bias-tee gpio control", (*ret_interface)->capif);
        return -1;
#endif
    }

    r = rtlsdr_open(&ais->dev, num_device);
    if (r < 0) {
        snprintf(msg, STATUS_MAX, "failed to open device %s", (*ret_interface)->capif);
        ais->dev = NULL;
        return -1;
    }

    /* Gain is allowed to fail */
    if (ais->gain == AUTO_GAIN) {
        r = rtlsdr_set_tuner_gain_mode(ais->dev, 0);
        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "could not set auto-gain control on %s",
                    (*ret_interface)->capif);
            cf_send_warning(caph, errstr);
        }
    } else {
        ais->gain = nearest_gain(ais->dev, ais->gain);
        r = rtlsdr_set_tuner_gain_mode(ais->dev, 1);
        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "could not set manual gain control on %s",
                    (*ret_interface)->capif);
            cf_send_warning(caph, errstr);
        } else {
            r = rtlsdr_set_tuner_gain(ais->dev, ais->gain);
            if (r < 0) {
                snprintf(errstr, STATUS_MAX, "could not set gain level on %s",
                        (*ret_interface)->capif);
                cf_send_warning(caph, errstr);
            }
        }
    }

    /* ppm correction matters far more for AIS than ADSB; the channels are
     * only 25kHz either side of the center */
    if (ais->ppm != 0) {
        r = rtlsdr_set_freq_correction(ais->dev, ais->ppm);
        if (r < 0) {
            snprintf(msg, STATUS_MAX, "could not set ppm correction on %s",
                    (*ret_interface)->capif);
            goto fail;
        }
    }

    /* Tuning and sample rates are mandatory */
    r = rtlsdr_set_center_freq(ais->dev, AIS_DEMOD_CENTER_FREQ);
    if (r < 0) {
        snprintf(msg, STATUS_MAX, "could not set tuning on %s", (*ret_interface)->capif);
        goto fail;
    }

    r = rtlsdr_set_sample_rate(ais->dev, AIS_DEMOD_SAMPLE_RATE);
    if (r < 0) {
        snprintf(msg, STATUS_MAX, "could not set sample rate on %s", (*ret_interface)->capif);
        goto fail;
    }

#ifdef HAVE_LIBRTLSDR_BIAS_T
    if (ais->bias_tee == 1) {
        r = rtlsdr_set_bias_tee(ais->dev, 1);
        if (r < 0) {
            snprintf(msg, STATUS_MAX, "could not enable bias-tee power on %s",
                    (*ret_interface)->capif);
            goto fail;
        }
    }
#endif

#ifdef HAVE_LIBRTLSDR_BIAS_T_GPIO
    if (ais->bias_tee == 2) {
        r = rtlsdr_set_bias_tee_gpio(ais->dev, ais->bias_tee_gpio, 1);
        if (r < 0) {
            snprintf(msg, STATUS_MAX, "could not enable bias-tee power for "
                    "gpio %d on %s", ais->bias_tee_gpio, (*ret_interface)->capif);
            goto fail;
        }
    }
#endif

    r = rtlsdr_reset_buffer(ais->dev);
    if (r < 0) {
        snprintf(msg, STATUS_MAX, "could not reset buffer on %s", (*ret_interface)->capif);
        goto fail;
    }

    ais->demod = ais_demod_new(ais_frame_cb, ais);
    if (ais->demod == NULL) {
        snprintf(msg, STATUS_MAX, "could not allocate AIS demodulator for %s",
                (*ret_interface)->capif);
        goto fail;
    }

    if (pthread_create(&ais->demod_thread, NULL, rtlsdr_demod_thread, (void *) caph) != 0) {
        snprintf(msg, STATUS_MAX, "could not start the AIS demodulator for %s",
                (*ret_interface)->capif);
        goto fail;
    }

    /* Defer launching async to the service thread */

    return 1;

fail:
    /* Release the device so a later re-open can claim it */
    if (ais->demod != NULL) {
        ais_demod_free(ais->demod);
        ais->demod = NULL;
    }

    rtlsdr_close(ais->dev);
    ais->dev = NULL;

    return -1;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_ais_t *ais = (local_ais_t *) caph->userdata;

    /* Start the async io that feeds the demod thread; returns when cancelled */
    rtlsdr_read_async(ais->dev, rtlsdr_callback, caph,
            DEFAULT_ASYNC_BUF_NUMBER, DEFAULT_BUF_LENGTH);

    /* Wake and reap the demod thread */
    pthread_mutex_lock(&ais->ready_mutex);
    ais->do_exit = 1;
    pthread_cond_signal(&ais->ready);
    pthread_mutex_unlock(&ais->ready_mutex);

    pthread_join(ais->demod_thread, NULL);

    rtlsdr_close(ais->dev);
    ais->dev = NULL;

    ais_demod_free(ais->demod);
    ais->demod = NULL;

    /* If we weren't asked to stop, the device went away; tell Kismet so it can
     * re-open the source */
    if (!caph->spindown)
        cf_send_error(caph, 0, "rtlsdr device stopped returning data");

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_ais_t local_ais = {
        .dev = NULL,
        .data_ready = 0,
        .data_len = 0,
        .demod = NULL,
        .caph = NULL,
        .do_exit = 0,
        .gain = AUTO_GAIN,
        .ppm = 0,
        .bias_tee = 0,
        .bias_tee_gpio = 0,
    };

    pthread_cond_init(&local_ais.ready, NULL);
    pthread_mutex_init(&local_ais.ready_mutex, NULL);

    kis_capture_handler_t *caph = cf_handler_init("rtlais");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    local_ais.caph = caph;

    cf_handler_set_userdata(caph, &local_ais);

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

    pthread_cond_destroy(&local_ais.ready);
    pthread_mutex_destroy(&local_ais.ready_mutex);

    return 0;
}

