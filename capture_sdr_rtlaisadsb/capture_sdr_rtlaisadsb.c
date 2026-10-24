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
 * Interface format:  rtlaisadsb, rtlaisadsb-[devnum], rtlaisadsb-[serial]
 *
 * Parameters: gain=xyz, ais_gain=xyz, adsb_gain=xyz, ppm=xyz, uuid=xyz,
 *             biast=bool, biastgpio=#,
 *             hop_mode=adaptive|fixed, ais_dwell=seconds, adsb_dwell=seconds
 *
 * One rtl-sdr alternates between AIS (162MHz) and ADS-B (1090MHz), with the
 * rtlais and rtladsb decoders.  The channels are "AIS" and "ADSB"; setting
 * either locks the radio there, and hopping returns to alternating.
 *
 * Adaptive hopping sizes the dwells from what each band is hearing:
 *  - ADS-B dwells long enough for an aircraft to send an even and an odd
 *    position (Kismet needs both within 10 seconds to place it), so weaker
 *    reception gets longer dwells
 *  - the bands split the time evenly; splitting by station counts only
 *    moves coverage from one band to the other.  A band with no stations
 *    drops to EMPTY_SHARE so it still finds new ones
 *  - every dwell is jittered, so the cycle can't lock to the fixed slot
 *    timing of AIS reports and keep missing the same stations
 * Fixed hopping uses ais_dwell and adsb_dwell, with the same jitter.
 */

#include "../config.h"

#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <sys/time.h>

#include <rtl-sdr.h>

#include "../capture_framework.h"

#include "adsb_demod.h"
#include "ais_demod.h"

#define BAND_AIS                0
#define BAND_ADSB               1
#define NUM_BANDS               2

#define ASYNC_BUF_NUMBER        8
#define AUTO_GAIN               -100
#define GAIN_UNSET              -200

/* Samples to drop after retuning while the tuner settles */
#define SETTLE_SECONDS          0.005

/* Stations count as active for this many seconds of listening to their band */
#define STATION_WINDOW          60.0
#define STATION_SLOTS           1024
#define STATION_PROBES          32

/* Adaptive hopping limits, in seconds */
#define ADSB_DWELL_MIN          1.0
#define ADSB_DWELL_MAX          20.0
#define ADSB_DWELL_DEFAULT      2.0
/* Position frames an aircraft should send per dwell to get both CPR parities */
#define ADSB_DWELL_POSITIONS    3.0
#define AIS_DWELL_MIN           1.0
#define AIS_DWELL_MAX           30.0
#define EMPTY_SHARE             0.25

#define DWELL_JITTER            0.2

#define DEFAULT_AIS_DWELL       2.0
#define DEFAULT_ADSB_DWELL      2.0

typedef struct {
    const char *name;
    uint32_t freq;
    uint32_t rate;
    uint32_t buf_len;
    unsigned int freq_khz;
    const char *chan;
} band_def_t;

static const band_def_t band_defs[NUM_BANDS] = {
    /* ~57ms and ~65ms buffers */
    { "AIS", AIS_DEMOD_CENTER_FREQ, AIS_DEMOD_SAMPLE_RATE, 32768, 162000, "162MHz" },
    { "ADSB", ADSB_DEMOD_CENTER_FREQ, ADSB_DEMOD_SAMPLE_RATE, 262144, 1090000, "1090MHz" },
};

typedef struct {
    uint32_t key;
    double last;
    double pos_rate;
    double pos_last;
} station_t;

typedef struct {
    station_t stations[STATION_SLOTS];
    /* Seconds spent receiving on the band */
    double listened;
} band_state_t;

typedef struct {
    rtlsdr_dev_t *dev;
    kis_capture_handler_t *caph;

    ais_demod_t *ais;
    adsb_demod_t *adsb;

    int gain[NUM_BANDS];
    int ppm;
    int bias_tee;
    int bias_tee_gpio;

    int adaptive;
    double fixed_dwell[NUM_BANDS];

    /* Owned by the capture thread */
    band_state_t bands[NUM_BANDS];
    int cur_band;
    uint64_t dwell_samples;
    uint64_t dwell_count;
    uint64_t settle_bytes;
    int cancelled;
    unsigned int seed;
    double last_plan[NUM_BANDS];
    time_t last_plan_msg;

    /* Set from the channel control thread, under lock */
    pthread_mutex_t lock;
    int hopping;
    int locked_band;
    int switch_pending;
} local_rtl_t;

/* Find the nearest supported gain */
static int nearest_gain(rtlsdr_dev_t *dev, int target_gain) {
    int i, err1, err2, count, nearest;
    int *gains;

    count = rtlsdr_get_tuner_gains(dev, NULL);
    if (count <= 0)
        return 0;

    gains = malloc(sizeof(int) * count);
    if (gains == NULL)
        return 0;

    count = rtlsdr_get_tuner_gains(dev, gains);
    nearest = gains[0];
    for (i = 0; i < count; i++) {
        err1 = abs(target_gain - nearest);
        err2 = abs(target_gain - gains[i]);
        if (err2 < err1)
            nearest = gains[i];
    }
    free(gains);

    return nearest;
}

static double band_listen_now(local_rtl_t *local, int band) {
    double t = local->bands[band].listened;

    if (band == local->cur_band)
        t += (double) local->dwell_count / band_defs[band].rate;

    return t;
}

static int station_active(const station_t *s, double now) {
    return s->key != 0 && now - s->last < STATION_WINDOW;
}

/* Note a frame from a station; positions feed its position rate.  Station
 * ids get a marker bit so 0 can mean an empty slot. */
static void station_heard(local_rtl_t *local, int band, uint32_t id, int position) {
    band_state_t *bs = &local->bands[band];
    double now = band_listen_now(local, band);
    uint32_t key = id | 0x80000000;
    uint32_t h = (key * 2654435761u) & (STATION_SLOTS - 1);
    station_t *s = NULL, *free_slot = NULL;
    double dt;
    int i;

    for (i = 0; i < STATION_PROBES; i++) {
        station_t *c = &bs->stations[(h + i) & (STATION_SLOTS - 1)];

        if (c->key == key) {
            s = c;
            break;
        }

        if (free_slot == NULL && !station_active(c, now))
            free_slot = c;
    }

    if (s == NULL) {
        /* A full neighborhood drops the station from the hop plan only */
        if (free_slot == NULL)
            return;

        s = free_slot;
        memset(s, 0, sizeof(*s));
        s->key = key;
        s->pos_last = now;
    }

    s->last = now;

    if (position) {
        /* Positions per second of listening, averaged over the station window */
        dt = now - s->pos_last;
        if (dt < 0)
            dt = 0;
        s->pos_rate = s->pos_rate * exp(-dt / STATION_WINDOW) + 1.0 / STATION_WINDOW;
        s->pos_last = now;
    }
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *) a, y = *(const double *) b;
    return (x > y) - (x < y);
}

static void send_frame_json(kis_capture_handler_t *caph, struct cf_params_signal *signal,
        const char *type, const char *json) {
    struct timeval tv;
    int r;

    gettimeofday(&tv, NULL);

    while (1) {
        if ((r = cf_send_json(caph, NULL, 0, signal, NULL, tv, type, json)) < 0) {
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

static void ais_frame_cb(void *ctx, int channel, const uint8_t *payload,
        size_t payload_len, float level_dbfs) {
    local_rtl_t *local = (local_rtl_t *) ctx;
    struct cf_params_signal signal;
    char hex[(AIS_MAX_PAYLOAD_BYTES * 2) + 1];
    char json[512];
    char chanstr[16];
    unsigned int freq_khz, type;
    uint32_t mmsi;
    size_t i;

    if (payload_len > AIS_MAX_PAYLOAD_BYTES || payload_len < 5)
        return;

    type = payload[0] >> 2;
    mmsi = (((uint32_t) payload[1] << 24) | ((uint32_t) payload[2] << 16) |
            ((uint32_t) payload[3] << 8) | payload[4]) >> 2;

    station_heard(local, BAND_AIS, mmsi,
            (type >= 1 && type <= 4) || type == 18 || type == 19 || type == 21 || type == 27);

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

    send_frame_json(local->caph, &signal, "ais", json);
}

static void adsb_frame_cb(void *ctx, const uint8_t *frame, size_t frame_len) {
    local_rtl_t *local = (local_rtl_t *) ctx;
    struct cf_params_signal signal;
    char hex[(ADSB_MAX_FRAME_BYTES * 2) + 1];
    char json[64];
    char chanstr[16];
    unsigned int df, tc;
    size_t i;

    if (frame_len > ADSB_MAX_FRAME_BYTES || frame_len < 7)
        return;

    df = frame[0] >> 3;

    /* Only these carry the aircraft address in the clear */
    if (df == 11 || df == 17 || df == 18) {
        tc = frame_len == 14 ? frame[4] >> 3 : 0;
        station_heard(local, BAND_ADSB,
                ((uint32_t) frame[1] << 16) | ((uint32_t) frame[2] << 8) | frame[3],
                df != 11 && ((tc >= 9 && tc <= 18) || (tc >= 20 && tc <= 22)));
    }

    for (i = 0; i < frame_len; i++)
        snprintf(hex + (i * 2), 3, "%02x", frame[i]);
    hex[frame_len * 2] = 0;

    snprintf(json, sizeof(json), "{\"adsb\": \"*%s;\"}", hex);

    snprintf(chanstr, sizeof(chanstr), "%s", band_defs[BAND_ADSB].chan);

    memset(&signal, 0, sizeof(struct cf_params_signal));
    signal.freq_khz = band_defs[BAND_ADSB].freq_khz;
    signal.channel = chanstr;

    send_frame_json(local->caph, &signal, "adsb", json);
}

static double jitter(local_rtl_t *local, double d) {
    return d * (1.0 + DWELL_JITTER * (2.0 * ((double) rand_r(&local->seed) / RAND_MAX) - 1.0));
}

/* Size both dwells from the stations each band has been hearing */
static void adaptive_plan(local_rtl_t *local, double *dwell) {
    double rates[STATION_SLOTS];
    double now[NUM_BANDS];
    unsigned int active[NUM_BANDS] = { 0, 0 };
    unsigned int nrates = 0, i;
    double share, d_adsb;
    int b;

    for (b = 0; b < NUM_BANDS; b++) {
        now[b] = band_listen_now(local, b);

        for (i = 0; i < STATION_SLOTS; i++) {
            station_t *s = &local->bands[b].stations[i];

            if (!station_active(s, now[b]))
                continue;

            active[b]++;

            if (b == BAND_ADSB && s->pos_rate > 0)
                rates[nrates++] = s->pos_rate * exp(-(now[b] - s->pos_last) / STATION_WINDOW);
        }
    }

    d_adsb = ADSB_DWELL_DEFAULT;

    if (nrates > 0) {
        qsort(rates, nrates, sizeof(double), cmp_double);

        if (rates[nrates / 2] > 0)
            d_adsb = ADSB_DWELL_POSITIONS / rates[nrates / 2];
    }

    if (d_adsb < ADSB_DWELL_MIN)
        d_adsb = ADSB_DWELL_MIN;
    if (d_adsb > ADSB_DWELL_MAX)
        d_adsb = ADSB_DWELL_MAX;

    /* AIS share of the time */
    if (active[BAND_AIS] == 0 && active[BAND_ADSB] > 0)
        share = EMPTY_SHARE;
    else if (active[BAND_ADSB] == 0 && active[BAND_AIS] > 0)
        share = 1.0 - EMPTY_SHARE;
    else
        share = 0.5;

    dwell[BAND_ADSB] = d_adsb;
    dwell[BAND_AIS] = d_adsb * share / (1.0 - share);

    if (dwell[BAND_AIS] < AIS_DWELL_MIN)
        dwell[BAND_AIS] = AIS_DWELL_MIN;
    if (dwell[BAND_AIS] > AIS_DWELL_MAX)
        dwell[BAND_AIS] = AIS_DWELL_MAX;
}

/* Tell the user when the adaptive plan moves, at most once a minute */
static void report_plan(local_rtl_t *local, const double *dwell) {
    char msg[STATUS_MAX];
    time_t now = time(NULL);
    int b, moved = 0;

    for (b = 0; b < NUM_BANDS; b++) {
        if (local->last_plan[b] == 0 ||
                fabs(dwell[b] - local->last_plan[b]) > local->last_plan[b] * 0.25)
            moved = 1;
    }

    if (!moved || now - local->last_plan_msg < 60)
        return;

    for (b = 0; b < NUM_BANDS; b++)
        local->last_plan[b] = dwell[b];
    local->last_plan_msg = now;

    snprintf(msg, sizeof(msg), "rtlaisadsb hopping AIS %.1fs / ADS-B %.1fs",
            dwell[BAND_AIS], dwell[BAND_ADSB]);
    cf_send_message(local->caph, msg, MSGFLAG_INFO);
}

/* Pick the next band and how long to stay; 0 means until the lock changes */
static int next_band(local_rtl_t *local, double *dwell_sec) {
    double dwell[NUM_BANDS];
    int hopping, locked, band;

    pthread_mutex_lock(&local->lock);
    hopping = local->hopping;
    locked = local->locked_band;
    local->switch_pending = 0;
    pthread_mutex_unlock(&local->lock);

    if (!hopping) {
        *dwell_sec = 0;
        return locked;
    }

    band = local->cur_band == BAND_AIS ? BAND_ADSB : BAND_AIS;

    if (local->adaptive) {
        adaptive_plan(local, dwell);
        report_plan(local, dwell);
    } else {
        dwell[BAND_AIS] = local->fixed_dwell[BAND_AIS];
        dwell[BAND_ADSB] = local->fixed_dwell[BAND_ADSB];
    }

    *dwell_sec = jitter(local, dwell[band]);

    return band;
}

static int tune_band(local_rtl_t *local, int band, char *msg) {
    const band_def_t *bd = &band_defs[band];
    int r;

    if (rtlsdr_set_sample_rate(local->dev, bd->rate) < 0) {
        snprintf(msg, STATUS_MAX, "could not set the %s sample rate", bd->name);
        return -1;
    }

    if (rtlsdr_set_center_freq(local->dev, bd->freq) < 0) {
        snprintf(msg, STATUS_MAX, "could not tune to %s", bd->name);
        return -1;
    }

    /* Gain is allowed to fail */
    if (local->gain[band] == AUTO_GAIN) {
        rtlsdr_set_tuner_gain_mode(local->dev, 0);
    } else {
        r = rtlsdr_set_tuner_gain_mode(local->dev, 1);
        if (r >= 0)
            rtlsdr_set_tuner_gain(local->dev, local->gain[band]);
    }

    if (rtlsdr_reset_buffer(local->dev) < 0) {
        snprintf(msg, STATUS_MAX, "could not reset the sample buffer");
        return -1;
    }

    return 0;
}

static void rtlsdr_callback(unsigned char *buf, uint32_t len, void *ctx) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) ctx;
    local_rtl_t *local = (local_rtl_t *) caph->userdata;
    int pending;

    if (caph->spindown) {
        local->cancelled = 1;
        rtlsdr_cancel_async(local->dev);
        return;
    }

    /* Draining after a cancel */
    if (local->cancelled)
        return;

    if (local->settle_bytes > 0) {
        if (len <= local->settle_bytes) {
            local->settle_bytes -= len;
            return;
        }

        buf += local->settle_bytes;
        len -= (uint32_t) local->settle_bytes;
        local->settle_bytes = 0;
    }

    if (local->cur_band == BAND_AIS)
        ais_demod_process_cu8(local->ais, buf, len);
    else
        adsb_demod_process_cu8(local->adsb, buf, len);

    local->dwell_count += len / 2;

    pthread_mutex_lock(&local->lock);
    pending = local->switch_pending;
    pthread_mutex_unlock(&local->lock);

    if (pending || local->dwell_count >= local->dwell_samples) {
        local->cancelled = 1;
        rtlsdr_cancel_async(local->dev);
    }
}

static void *chantranslate_cb(kis_capture_handler_t *caph, const char *chanstr) {
    int *band;

    if (strcasecmp(chanstr, "AIS") == 0 || strcasecmp(chanstr, "162MHz") == 0) {
        band = (int *) malloc(sizeof(int));
        if (band != NULL)
            *band = BAND_AIS;
        return band;
    }

    if (strcasecmp(chanstr, "ADSB") == 0 || strcasecmp(chanstr, "ADS-B") == 0 ||
            strcasecmp(chanstr, "1090MHz") == 0) {
        band = (int *) malloc(sizeof(int));
        if (band != NULL)
            *band = BAND_ADSB;
        return band;
    }

    return NULL;
}

/* Called with seqno 0 by the framework's hop timer, which only keeps us
 * hopping; we schedule the bands ourselves.  Any other call locks a band. */
static int chancontrol_cb(kis_capture_handler_t *caph, uint32_t seqno, void *privchan,
        char *msg) {
    local_rtl_t *local = (local_rtl_t *) caph->userdata;
    int band;

    if (privchan == NULL) {
        snprintf(msg, STATUS_MAX, "unknown channel; expected AIS or ADSB");
        return -1;
    }

    band = *(int *) privchan;

    pthread_mutex_lock(&local->lock);

    if (seqno == 0) {
        if (!local->hopping) {
            local->hopping = 1;
            local->switch_pending = 1;
        }
    } else {
        if (local->hopping || local->locked_band != band)
            local->switch_pending = 1;

        local->hopping = 0;
        local->locked_band = band;
    }

    pthread_mutex_unlock(&local->lock);

    return 1;
}

static void chanfree_cb(void *privchan) {
    free(privchan);
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
    if (*interfaces == NULL)
        return 0;

    for (i = 0; i < num_radios; i++) {
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));
        snprintf(buf, 256, "rtlaisadsb-%u", i);
        (*interfaces)[i]->interface = strdup(buf);
        (*interfaces)[i]->hardware = strdup("rtlsdr");
    }

    return num_radios;
}

/* Resolve an rtlaisadsb interface definition to a device index; returns the
 * index or -1 if the definition doesn't match a device */
static int find_device(char *definition, char *msg) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    unsigned int num_devices;
    int num_device = -1;
    unsigned int parsed;
    size_t plen = strlen("rtlaisadsb");

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    interface = strndup(placeholder, placeholder_len);
    if (interface == NULL)
        return -1;

    /* rtlaisadsb, rtlaisadsb-[serial], rtlaisadsb-[0, 1, 2...] */
    if (strncmp(interface, "rtlaisadsb", plen) != 0 ||
            (interface[plen] != 0 && interface[plen] != '-')) {
        snprintf(msg, STATUS_MAX, "Expected a rtlaisadsb interface, skipping");
        free(interface);
        return -1;
    }

    num_devices = rtlsdr_get_device_count();

    if (interface[plen] == 0) {
        if (num_devices > 0)
            num_device = 0;
    } else {
        /* Is this a serial #? */
        num_device = rtlsdr_get_index_by_serial(interface + plen + 1);

        if (num_device < 0) {
            if (sscanf(interface + plen + 1, "%u", &parsed) == 1 && parsed < num_devices)
                num_device = (int) parsed;
            else
                num_device = -1;
        }
    }

    free(interface);

    if (num_device < 0)
        snprintf(msg, STATUS_MAX, "Unable to find rtlaisadsb device");

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
        snprintf(msg, STATUS_MAX, "Unable to find rtlaisadsb device");
        return 0;
    }

    snprintf(buf, STATUS_MAX, "rtlaisadsb-%d", num_device);
    ret_interface->capif = strdup(buf);
    ret_interface->hardware = strdup("rtlsdr");

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(buf, STATUS_MAX, "%s%s%s", manuf_buf, product_buf, serial_buf);
        hash = adler32_csum((unsigned char *) buf, strlen(buf));

        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                 adler32_csum((unsigned char *) "kismet_cap_sdr_rtlaisadsb",
                              strlen("kismet_cap_sdr_rtlaisadsb")) & 0xFFFFFFFF,
                 hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    ret_interface->channels = (char **) malloc(sizeof(char *) * NUM_BANDS);
    if (ret_interface->channels == NULL)
        return 0;
    ret_interface->channels[0] = strdup(band_defs[BAND_AIS].name);
    ret_interface->channels[1] = strdup(band_defs[BAND_ADSB].name);
    ret_interface->channels_len = NUM_BANDS;

    return 1;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    int num_device;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((num_device = find_device(definition, msg)) < 0)
        return 0;

    return populate_interface(num_device, definition, msg, uuid, *ret_interface);
}

/* Parse name=int; returns 0 if absent, 1 if parsed, -1 if malformed */
static int parse_int_flag(const char *name, char *definition, int *ret) {
    char *placeholder = NULL;
    int placeholder_len;
    char *tmp;
    int r;

    if ((placeholder_len = cf_find_flag(&placeholder, (char *) name, definition)) <= 0)
        return 0;

    tmp = strndup(placeholder, placeholder_len);
    if (tmp == NULL)
        return -1;

    r = sscanf(tmp, "%d", ret) == 1 ? 1 : -1;
    free(tmp);

    return r;
}

/* Parse name=seconds within [lo, hi]; returns 0 if absent, 1 if parsed, -1 if bad */
static int parse_dwell_flag(const char *name, char *definition, double lo, double hi,
        double *ret) {
    char *placeholder = NULL;
    int placeholder_len;
    char *tmp;
    double v;
    int r;

    if ((placeholder_len = cf_find_flag(&placeholder, (char *) name, definition)) <= 0)
        return 0;

    tmp = strndup(placeholder, placeholder_len);
    if (tmp == NULL)
        return -1;

    r = sscanf(tmp, "%lf", &v) == 1 && isfinite(v) && v >= lo && v <= hi ? 1 : -1;
    free(tmp);

    if (r > 0)
        *ret = v;

    return r;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_rtl_t *local = (local_rtl_t *) caph->userdata;

    char *placeholder = NULL;
    int placeholder_len = 0;
    char *tmp = NULL;

    int num_device;
    int gain = AUTO_GAIN;
    int b, r;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((num_device = find_device(definition, msg)) < 0)
        return -1;

    if (populate_interface(num_device, definition, msg, uuid, *ret_interface) <= 0)
        return -1;

    if (parse_int_flag("gain", definition, &gain) < 0) {
        snprintf(msg, STATUS_MAX, "%s: expected gain=X", (*ret_interface)->capif);
        return -1;
    }

    local->gain[BAND_AIS] = local->gain[BAND_ADSB] = gain;

    if (parse_int_flag("ais_gain", definition, &local->gain[BAND_AIS]) < 0) {
        snprintf(msg, STATUS_MAX, "%s: expected ais_gain=X", (*ret_interface)->capif);
        return -1;
    }

    if (parse_int_flag("adsb_gain", definition, &local->gain[BAND_ADSB]) < 0) {
        snprintf(msg, STATUS_MAX, "%s: expected adsb_gain=X", (*ret_interface)->capif);
        return -1;
    }

    if (parse_int_flag("ppm", definition, &local->ppm) < 0) {
        snprintf(msg, STATUS_MAX, "%s: expected ppm=X", (*ret_interface)->capif);
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "hop_mode", definition)) > 0) {
        if (strncasecmp(placeholder, "adaptive", placeholder_len) == 0 &&
                placeholder_len == (int) strlen("adaptive")) {
            local->adaptive = 1;
        } else if (strncasecmp(placeholder, "fixed", placeholder_len) == 0 &&
                placeholder_len == (int) strlen("fixed")) {
            local->adaptive = 0;
        } else {
            snprintf(msg, STATUS_MAX, "%s: expected hop_mode=adaptive or hop_mode=fixed",
                    (*ret_interface)->capif);
            return -1;
        }
    }

    if (parse_dwell_flag("ais_dwell", definition, 0.25, 600,
                &local->fixed_dwell[BAND_AIS]) < 0) {
        snprintf(msg, STATUS_MAX, "%s: expected ais_dwell=seconds, from 0.25 to 600",
                (*ret_interface)->capif);
        return -1;
    }

    if (parse_dwell_flag("adsb_dwell", definition, 0.25, 600,
                &local->fixed_dwell[BAND_ADSB]) < 0) {
        snprintf(msg, STATUS_MAX, "%s: expected adsb_dwell=seconds, from 0.25 to 600",
                (*ret_interface)->capif);
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "biast", definition)) > 0) {
#ifdef HAVE_LIBRTLSDR_BIAS_T
        if (strncmp(placeholder, "true", placeholder_len) == 0)
            local->bias_tee = 1;
#else
        snprintf(msg, STATUS_MAX, "%s: the version of librtlsdr used does not support the "
                "bias-tee control", (*ret_interface)->capif);
        return -1;
#endif
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "biastgpio", definition)) > 0) {
#ifdef HAVE_LIBRTLSDR_BIAS_T_GPIO
        tmp = strndup(placeholder, placeholder_len);
        if (tmp == NULL)
            return -1;

        if (sscanf(tmp, "%d", &local->bias_tee_gpio) != 1) {
            snprintf(msg, STATUS_MAX, "%s: expected biastgpio=[GPIO#]", (*ret_interface)->capif);
            free(tmp);
            return -1;
        }

        local->bias_tee = 2;

        free(tmp);
        tmp = NULL;
#else
        snprintf(msg, STATUS_MAX, "%s: the version of librtlsdr used does not support the "
                "bias-tee gpio control", (*ret_interface)->capif);
        return -1;
#endif
    }

    r = rtlsdr_open(&local->dev, num_device);
    if (r < 0) {
        snprintf(msg, STATUS_MAX, "failed to open device %s", (*ret_interface)->capif);
        local->dev = NULL;
        return -1;
    }

    for (b = 0; b < NUM_BANDS; b++) {
        if (local->gain[b] != AUTO_GAIN)
            local->gain[b] = nearest_gain(local->dev, local->gain[b]);
    }

    /* ppm correction matters for AIS, whose channels are 25kHz from the center */
    if (local->ppm != 0) {
        r = rtlsdr_set_freq_correction(local->dev, local->ppm);
        if (r < 0) {
            snprintf(msg, STATUS_MAX, "could not set ppm correction on %s",
                    (*ret_interface)->capif);
            goto fail;
        }
    }

    /* Make sure both bands tune before claiming the source */
    for (b = NUM_BANDS - 1; b >= 0; b--) {
        if (tune_band(local, b, msg) < 0)
            goto fail;
    }

#ifdef HAVE_LIBRTLSDR_BIAS_T
    if (local->bias_tee == 1) {
        r = rtlsdr_set_bias_tee(local->dev, 1);
        if (r < 0) {
            snprintf(msg, STATUS_MAX, "could not enable bias-tee power on %s",
                    (*ret_interface)->capif);
            goto fail;
        }
    }
#endif

#ifdef HAVE_LIBRTLSDR_BIAS_T_GPIO
    if (local->bias_tee == 2) {
        r = rtlsdr_set_bias_tee_gpio(local->dev, local->bias_tee_gpio, 1);
        if (r < 0) {
            snprintf(msg, STATUS_MAX, "could not enable bias-tee power for "
                    "gpio %d on %s", local->bias_tee_gpio, (*ret_interface)->capif);
            goto fail;
        }
    }
#endif

    local->ais = ais_demod_new(ais_frame_cb, local);
    local->adsb = adsb_demod_new(band_defs[BAND_ADSB].buf_len, adsb_frame_cb, local);

    if (local->ais == NULL || local->adsb == NULL) {
        snprintf(msg, STATUS_MAX, "could not allocate the demodulators for %s",
                (*ret_interface)->capif);
        goto fail;
    }

    /* Defer launching async to the capture thread */

    return 1;

fail:
    /* Release the device so a later re-open can claim it */
    ais_demod_free(local->ais);
    local->ais = NULL;
    adsb_demod_free(local->adsb);
    local->adsb = NULL;

    rtlsdr_close(local->dev);
    local->dev = NULL;

    return -1;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_rtl_t *local = (local_rtl_t *) caph->userdata;
    char msg[STATUS_MAX];
    double dwell;
    int band, r, failed = 0, tuned = 0;

    while (!caph->spindown) {
        band = next_band(local, &dwell);

        if (band != local->cur_band || !tuned) {
            if (tune_band(local, band, msg) < 0) {
                cf_send_error(caph, 0, msg);
                failed = 1;
                break;
            }

            local->settle_bytes =
                ((uint64_t) (band_defs[band].rate * SETTLE_SECONDS)) * 2;
            tuned = 1;
        }

        local->cur_band = band;
        local->dwell_samples = dwell > 0 ? (uint64_t) (dwell * band_defs[band].rate) : UINT64_MAX;
        local->dwell_count = 0;
        local->cancelled = 0;

        r = rtlsdr_read_async(local->dev, rtlsdr_callback, caph,
                ASYNC_BUF_NUMBER, band_defs[band].buf_len);

        local->bands[band].listened += (double) local->dwell_count / band_defs[band].rate;

        /* Ending on its own means the device went away */
        if (!local->cancelled || r < 0)
            break;
    }

    rtlsdr_close(local->dev);
    local->dev = NULL;

    ais_demod_free(local->ais);
    local->ais = NULL;
    adsb_demod_free(local->adsb);
    local->adsb = NULL;

    /* If we weren't asked to stop, the device went away; tell Kismet so it can
     * re-open the source */
    if (!caph->spindown && !failed)
        cf_send_error(caph, 0, "rtlsdr device stopped returning data");

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_rtl_t *local;
    int r;

    /* Too large for the stack with the station tables */
    local = (local_rtl_t *) calloc(1, sizeof(local_rtl_t));
    if (local == NULL) {
        fprintf(stderr, "FATAL: Could not allocate rtlaisadsb state\n");
        return -1;
    }

    local->gain[BAND_AIS] = local->gain[BAND_ADSB] = AUTO_GAIN;
    local->adaptive = 1;
    local->fixed_dwell[BAND_AIS] = DEFAULT_AIS_DWELL;
    local->fixed_dwell[BAND_ADSB] = DEFAULT_ADSB_DWELL;
    local->cur_band = BAND_ADSB;
    local->hopping = 1;
    local->locked_band = BAND_AIS;
    local->seed = (unsigned int) time(NULL) ^ (unsigned int) getpid();

    pthread_mutex_init(&local->lock, NULL);

    kis_capture_handler_t *caph = cf_handler_init("rtlaisadsb");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        free(local);
        return -1;
    }

    local->caph = caph;

    cf_handler_set_userdata(caph, local);

    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_chantranslate_cb(caph, chantranslate_cb);
    cf_handler_set_chancontrol_cb(caph, chancontrol_cb);
    cf_handler_set_chanfree_cb(caph, chanfree_cb);
    cf_handler_set_capture_cb(caph, capture_thread);

    r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        free(local);
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        free(local);
        return -1;
    }

    cf_handler_remote_capture(caph);

    cf_jail_filesystem(caph);
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    pthread_mutex_destroy(&local->lock);
    free(local);

    return 0;
}
