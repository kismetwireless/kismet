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

/* Kismet capture binary for Morse Micro MM8108 USB 802.11ah (Wi-Fi HaLow) adapters, using
 * the userspace-wifi mm8108 driver (../capture_userspace_usb_wifi/userspace-wifi).
 *
 * Adapters are named mm8108-0, mm8108-1, ... in USB port order.  Channels are 802.11ah
 * channel numbers in the regulatory domain's channel plan, named as Kismet names S1G
 * channels, such as 27ah; each number identifies one channel and width.  mm8108_kismet.c
 * translates them to and from the 5GHz channels the driver presents to mac80211.
 *
 * Source options:
 *   country=XX       regulatory domain (default: the adapter OTP, else US)
 *   widths=1,2,...   only use channels of these widths in MHz
 *   firmwaredir=DIR  directory searched first for firmware and board config files; then
 *                    Kismet's, and on Linux the system firmware directories
 *   firmware=FILE    firmware file name to load instead of the one chosen by chip revision;
 *                    found in the firmware directories, not a path
 *   boardfile=FILE   board config (BCF) file name to load instead of the one chosen by the
 *                    board type in OTP; found in the firmware directories, not a path.
 *                    Without a known board type, the MM8108 reference module's
 *                    bcf_mf15457.bin shipped with Kismet is used, and only if it's missing,
 *                    on Linux, the system's bcf_default.bin
 *   verbose=true     driver logging
 *
 * Firmware and board config files from https://github.com/MorseMicro/morse-firmware are
 * installed to Kismet's share/kismet/firmware/morse, under Morse Micro's license
 */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../config.h"
#include "../capture_framework.h"

#include "mm8108_kismet.h"

#ifndef FIRMWAREDIR
#define FIRMWAREDIR "/usr/local/share/kismet/firmware"
#endif

#define KDLT_IEEE802_11_RADIO 127

/* Kernel log levels */
#define KLOG_ERR 3
#define KLOG_WARNING 4
#define KLOG_INFO 6

/* Frames and driver messages waiting for the capture thread */
#define MM8108_QUEUE_MAX (4 * 1024 * 1024)

struct mm8108_qent {
    struct mm8108_qent *next;
    struct timeval ts;
    unsigned int msgflags;      /* 0 for a frame, else a driver message */
    uint32_t len;
    uint8_t data[];
};

typedef struct {
    kis_capture_handler_t *caph;
    struct uwifi_dev *dev;
    char *interface;
    char *name;
    bool verbose;
    volatile bool error;

    /* The framework holds its handler lock while tuning, and cf_send_* takes it; the driver
     * thread delivers frames under the driver's lock, which tuning also takes.  Frames and
     * messages queue here and only the capture thread talks to the framework. */
    pthread_mutex_t qlock;
    pthread_cond_t qcond;
    struct mm8108_qent *qhead, *qtail;
    size_t qbytes;
    uint64_t qdrops;

    /* The framework cancels the capture thread asynchronously when the server goes away,
     * which can leave qlock or the framework's own locks held, so the thread runs with
     * cancellation off.  main() stops it with these instead, under qlock, before closing
     * the device. */
    bool cap_started, cap_stop, cap_done;
    pthread_cond_t donecond;
} local_mm8108_t;

static void mm8108_enqueue(local_mm8108_t *local, unsigned int msgflags, const uint8_t *a,
        size_t a_len, const uint8_t *b, size_t b_len) {
    const size_t len = a_len + b_len;
    struct mm8108_qent *e;
    struct timeval ts;

    gettimeofday(&ts, NULL);

    pthread_mutex_lock(&local->qlock);

    if (len < a_len || local->qbytes + len > MM8108_QUEUE_MAX || len > UINT32_MAX ||
            (e = malloc(sizeof(*e) + len)) == NULL) {
        local->qdrops++;
        pthread_mutex_unlock(&local->qlock);
        return;
    }

    e->next = NULL;
    e->ts = ts;
    e->msgflags = msgflags;
    e->len = (uint32_t) len;
    memcpy(e->data, a, a_len);
    if (b_len)
        memcpy(e->data + a_len, b, b_len);

    if (local->qtail)
        local->qtail->next = e;
    else
        local->qhead = e;
    local->qtail = e;
    local->qbytes += len;

    pthread_cond_signal(&local->qcond);
    pthread_mutex_unlock(&local->qlock);
}

static void mm8108_queue_free(struct mm8108_qent *e) {
    while (e) {
        struct mm8108_qent *n = e->next;
        free(e);
        e = n;
    }
}

static void mm8108_log(void *ctx, int level, const char *msg) {
    local_mm8108_t *local = ctx;
    char buf[STATUS_MAX];
    size_t len;

    if (local == NULL || local->caph == NULL)
        return;

    /* Without verbose: warnings, and the driver's own notices (the boot summary, restarts),
     * but not its "mm8108: " step by step messages */
    if (!local->verbose && level > KLOG_WARNING &&
            (level > KLOG_INFO || strncmp(msg, "mm8108: ", 8) == 0))
        return;

    snprintf(buf, sizeof(buf), "%s: %s", local->name ? local->name : "mm8108", msg);
    len = strlen(buf);
    if (len && buf[len - 1] == '\n')
        buf[--len] = 0;

    mm8108_enqueue(local, level <= KLOG_ERR ? MSGFLAG_ERROR : MSGFLAG_INFO, (uint8_t *) buf,
            len + 1, NULL, 0);
}

/* Firmware directories: the source option, Kismet's share directory, then on Linux the
 * system firmware directories in the kernel's search order.  The driver looks in each for
 * morse/ and a morse-firmware checkout's layout. */
static int mm8108_init(local_mm8108_t *local, const char *fw_dir) {
    char sys_dirs[CF_FIRMWARE_MAX_DIRS][CF_FIRMWARE_PATH_LEN];
    const char *paths[3 + CF_FIRMWARE_MAX_DIRS];
    size_t n = 0, num_sys = cf_system_firmware_dirs(sys_dirs);

    if (fw_dir != NULL)
        paths[n++] = fw_dir;

    paths[n++] = FIRMWAREDIR;
    paths[n++] = "/usr/share/kismet/firmware";

    for (size_t i = 0; i < num_sys; i++)
        paths[n++] = sys_dirs[i];

    return mm_kis_init(paths, n, mm8108_log, local, KLOG_INFO);
}

static bool flag_true(char *definition, const char *flag, bool dfl) {
    char *placeholder = NULL;
    int len;

    if ((len = cf_find_flag(&placeholder, flag, definition)) <= 0)
        return dfl;

    if (strncasecmp(placeholder, "true", len) == 0)
        return true;
    if (strncasecmp(placeholder, "false", len) == 0)
        return false;

    return dfl;
}

static char *flag_dup(char *definition, const char *flag) {
    char *placeholder = NULL;
    int len;

    if ((len = cf_find_flag(&placeholder, flag, definition)) <= 0)
        return NULL;

    return strndup(placeholder, len);
}

/* A bare file name, so firmware= can't reach outside the firmware directories */
static bool firmware_name_valid(const char *name) {
    return name[0] != 0 && strlen(name) < 64 && strchr(name, '/') == NULL &&
        strchr(name, '\\') == NULL && strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

/* The UUID follows the adapter MAC so it survives re-plugging */
static char *mm8108_uuid(struct uwifi_dev *dev) {
    const uint8_t *mac = mm_kis_mac(dev);
    char buf[64];

    snprintf(buf, sizeof(buf), "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
            adler32_csum((uint8_t *) "kismet_cap_mm8108_halow",
                strlen("kismet_cap_mm8108_halow")) & 0xFFFFFFFF,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return strdup(buf);
}

/* Validates the firmware and region options and opens the adapter */
static int mm8108_open(local_mm8108_t *local, char *definition, const char *ifname, char *msg) {
    char *fw_dir, *fw_name, *bcf_name, *country;
    char errstr[STATUS_MAX], countries[256];
    int ret = -1;

    fw_dir = flag_dup(definition, "firmwaredir");
    fw_name = flag_dup(definition, "firmware");
    bcf_name = flag_dup(definition, "boardfile");
    country = flag_dup(definition, "country");

    if (fw_name != NULL && !firmware_name_valid(fw_name)) {
        snprintf(msg, STATUS_MAX, "%s firmware= takes a firmware file name, not a path; use "
                "firmwaredir= to set the directory", ifname);
        goto out;
    }

    if (bcf_name != NULL && !firmware_name_valid(bcf_name)) {
        snprintf(msg, STATUS_MAX, "%s boardfile= takes a board config file name, not a path; "
                "use firmwaredir= to set the directory", ifname);
        goto out;
    }

    if (country != NULL && !mm_kis_country_known(country)) {
        mm_kis_countries(countries, sizeof(countries));
        snprintf(msg, STATUS_MAX, "%s unknown country '%s'; supported: %s", ifname, country,
                countries);
        goto out;
    }

    if (mm8108_init(local, fw_dir) < 0) {
        snprintf(msg, STATUS_MAX, "%s could not initialize USB", ifname);
        goto out;
    }

    if ((local->dev = mm_kis_open(ifname, fw_name, bcf_name, country, errstr,
                    sizeof(errstr))) == NULL) {
        snprintf(msg, STATUS_MAX, "%s", errstr);
        goto out;
    }

    /* The OTP country locks the regulatory domain */
    if (country != NULL && mm_kis_country(local->dev) != NULL &&
            strncasecmp(country, mm_kis_country(local->dev), 2) != 0) {
        snprintf(errstr, sizeof(errstr), "%s is locked to regulatory domain %s; ignoring "
                "country=%s", ifname, mm_kis_country(local->dev), country);
        cf_send_warning(local->caph, errstr);
    }

    ret = 0;

out:
    free(fw_dir);
    free(fw_name);
    free(bcf_name);
    free(country);
    return ret;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
        cf_params_list_interface_t ***interfaces) {
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;
    struct mm_kis_iface *list;
    size_t n;

    *interfaces = NULL;

    if (mm8108_init(local, NULL) < 0 || mm_kis_list(&list, &n) < 0 || n == 0)
        return 0;

    *interfaces = (cf_params_list_interface_t **) calloc(n, sizeof(cf_params_list_interface_t *));
    if (*interfaces == NULL) {
        free(list);
        return 0;
    }

    for (size_t i = 0; i < n; i++) {
        (*interfaces)[i] = (cf_params_list_interface_t *) calloc(1, sizeof(cf_params_list_interface_t));
        if ((*interfaces)[i] == NULL)
            continue;
        (*interfaces)[i]->interface = strdup(list[i].ifname);
        (*interfaces)[i]->hardware = strdup(list[i].hardware);
    }

    free(list);
    return (int) n;
}

/* Probing only matches USB enumeration; booting the firmware would outlast the probe
 * timeout, so channels and the MAC-derived UUID come from opening.  As a remote capture the
 * probe runs locally with no timeout and the server needs the UUID to match reconnects, so
 * the adapter is opened here and kept for the open callback */
int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;
    char *placeholder = NULL, *ifname;
    char hw[128];
    int len, ret = 0;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    if ((ifname = strndup(placeholder, len)) == NULL)
        return 0;

    if (mm8108_init(local, NULL) == 0 && mm_kis_find(ifname, hw, sizeof(hw))) {
        (*ret_interface)->capif = strdup(ifname);
        (*ret_interface)->hardware = strdup(hw);
        *uuid = flag_dup(definition, "uuid");
        ret = 1;

        if (*uuid == NULL && caph->remote_host != NULL) {
            if (local->dev == NULL && mm8108_open(local, definition, ifname, msg) < 0)
                ret = 0;
            else
                *uuid = mm8108_uuid(local->dev);
        }
    } else {
        snprintf(msg, STATUS_MAX, "%s is not an attached MM8108 HaLow adapter", ifname);
    }

    free(ifname);
    return ret;
}

static void mm8108_rx(void *ctx, const uint8_t *rtap, size_t rtap_len, const uint8_t *frame,
        size_t frame_len) {
    local_mm8108_t *local = ctx;

    if (!local->error)
        mm8108_enqueue(local, 0, rtap, rtap_len, frame, frame_len);
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;
    char *placeholder = NULL, *widths = NULL, *chan_def = NULL;
    void *start = NULL;
    char hw[160], buf[STATUS_MAX];
    int len, ret = -1;

    *uuid = NULL;
    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    local->interface = strndup(placeholder, len);
    if ((local->name = flag_dup(definition, "name")) == NULL)
        local->name = strdup(local->interface);
    local->verbose = flag_true(definition, "verbose", false);

    if (local->interface == NULL || local->name == NULL) {
        snprintf(msg, STATUS_MAX, "out of memory");
        return -1;
    }

    /* A remote capture already opened the adapter while probing */
    if (local->dev == NULL && mm8108_open(local, definition, local->interface, msg) < 0)
        return -1;

    widths = flag_dup(definition, "widths");
    chan_def = flag_dup(definition, "channel");

    if (mm_kis_channels(local->dev, widths, &(*ret_interface)->channels,
                &(*ret_interface)->channels_len) < 0 || (*ret_interface)->channels_len == 0) {
        snprintf(msg, STATUS_MAX, "%s has no usable channels in %s", local->name,
                mm_kis_country(local->dev) ? mm_kis_country(local->dev) : "its region");
        goto out;
    }

    /* channel= sets the starting channel, which is where a source that doesn't hop stays */
    if (chan_def != NULL) {
        size_t c;

        if ((start = mm_kis_parse_channel(local->dev, chan_def)) != NULL) {
            for (c = 0; c < (*ret_interface)->channels_len; c++)
                if (strcmp((*ret_interface)->channels[c], mm_kis_channel_name(start)) == 0)
                    break;
            if (c == (*ret_interface)->channels_len) {
                free(start);
                start = NULL;
            }
        }

        if (start == NULL) {
            snprintf(msg, STATUS_MAX, "%s channel=%s is not a usable 802.11ah channel in %s",
                    local->name, chan_def, mm_kis_country(local->dev));
            goto out;
        }
    } else if ((start = mm_kis_parse_channel(local->dev, (*ret_interface)->channels[0])) == NULL) {
        snprintf(msg, STATUS_MAX, "%s has no usable channels", local->name);
        goto out;
    }

    (*ret_interface)->chanset = strdup(mm_kis_channel_name(start));

    if (mm_kis_start(local->dev, mm8108_rx, local) < 0 || mm_kis_set_channel(local->dev, start) < 0) {
        snprintf(msg, STATUS_MAX, "%s could not enter monitor mode", local->name);
        goto out;
    }

    mm_kis_hardware(local->dev, hw, sizeof(hw));
    (*ret_interface)->hardware = strdup(hw);
    (*ret_interface)->capif = strdup(local->interface);

    if ((*uuid = flag_dup(definition, "uuid")) == NULL)
        *uuid = mm8108_uuid(local->dev);

    snprintf(buf, sizeof(buf), "%s %s, regulatory domain %s, %zu channels", local->name, hw,
            mm_kis_country(local->dev), (*ret_interface)->channels_len);
    cf_send_message(caph, buf, MSGFLAG_INFO);

    *dlt = KDLT_IEEE802_11_RADIO;
    ret = 1;

out:
    free(start);
    free(widths);
    free(chan_def);
    return ret;
}

void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;
    char errstr[STATUS_MAX];
    void *chan;

    if (local->dev == NULL || chanstr == NULL)
        return NULL;

    if ((chan = mm_kis_parse_channel(local->dev, chanstr)) == NULL) {
        snprintf(errstr, STATUS_MAX, "%s - '%s' is not a usable 802.11ah channel in %s",
                local->name, chanstr, mm_kis_country(local->dev));
        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    return chan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;

    if (local->dev == NULL || privchan == NULL)
        return 0;

    if (mm_kis_set_channel(local->dev, privchan) < 0) {
        snprintf(msg, STATUS_MAX, "%s could not tune to channel %s", local->name,
                mm_kis_channel_name(privchan));
        return -1;
    }

    return 1;
}

static bool mm8108_stopping(local_mm8108_t *local) {
    bool r;

    pthread_mutex_lock(&local->qlock);
    r = local->cap_stop;
    pthread_mutex_unlock(&local->qlock);

    return r;
}

/* Stop the capture thread and wait for it, so nothing uses the device as it closes */
static void mm8108_stop_capture(local_mm8108_t *local) {
    struct timespec deadline;
    int r = 0;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;

    pthread_mutex_lock(&local->qlock);
    local->cap_stop = true;
    pthread_cond_signal(&local->qcond);

    while (local->cap_started && !local->cap_done && r != ETIMEDOUT)
        r = pthread_cond_timedwait(&local->donecond, &local->qlock, &deadline);

    pthread_mutex_unlock(&local->qlock);

    /* A hung helper never gets restarted; exit and let --daemonize start a new one */
    if (r == ETIMEDOUT) {
        fprintf(stderr, "FATAL: %s capture thread did not stop\n", local->name ? local->name : "mm8108");
        _exit(1);
    }
}

static int mm8108_send(local_mm8108_t *local, struct mm8108_qent *e) {
    int r;

    if (e->msgflags) {
        cf_send_message(local->caph, (char *) e->data, e->msgflags);
        return 0;
    }

    while (1) {
        r = cf_send_data(local->caph, NULL, 0, NULL, NULL, e->ts, KDLT_IEEE802_11_RADIO,
                e->len, e->len, e->data);

        if (r < 0) {
            cf_send_error(local->caph, 0, "unable to send DATA frame");
            return -1;
        }

        if (r > 0)
            return 0;

        /* A server that went away never drains the buffer */
        if (mm8108_stopping(local))
            return -1;

        /* Wait for the write buffer to drain */
        cf_handler_wait_ringbuffer(local->caph);
    }
}

void capture_thread(kis_capture_handler_t *caph) {
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;
    struct mm8108_qent *batch, *e;
    char errstr[STATUS_MAX];
    uint64_t drops, reported_drops = 0;
    time_t last_check = 0, last_drop_report = 0;
    struct timespec deadline;
    bool stop;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    pthread_mutex_lock(&local->qlock);
    stop = local->cap_stop;
    local->cap_started = !stop;
    pthread_mutex_unlock(&local->qlock);

    while (!stop && !local->error && caph->spindown == 0) {
        time_t now = time(NULL);

        if (now != last_check) {
            last_check = now;

            if (!mm_kis_alive(local->dev)) {
                snprintf(errstr, sizeof(errstr), "%s was removed or stopped responding", local->name);
                cf_send_error(caph, 0, errstr);
                local->error = true;
                break;
            }
        }

        pthread_mutex_lock(&local->qlock);
        if (local->qhead == NULL && !local->cap_stop) {
            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += 1;
            pthread_cond_timedwait(&local->qcond, &local->qlock, &deadline);
        }
        if ((stop = local->cap_stop)) {
            pthread_mutex_unlock(&local->qlock);
            break;
        }
        batch = local->qhead;
        local->qhead = local->qtail = NULL;
        local->qbytes = 0;
        drops = local->qdrops;
        pthread_mutex_unlock(&local->qlock);

        for (e = batch; e != NULL && !local->error; e = e->next)
            if (mm8108_send(local, e) < 0)
                local->error = true;

        mm8108_queue_free(batch);

        if (drops != reported_drops && now - last_drop_report >= 10) {
            snprintf(errstr, sizeof(errstr), "%s dropped %llu frames because Kismet could not "
                    "keep up", local->name, (unsigned long long) (drops - reported_drops));
            cf_send_warning(caph, errstr);
            reported_drops = drops;
            last_drop_report = now;
        }
    }

    cf_handler_spindown(caph);

    pthread_mutex_lock(&local->qlock);
    local->cap_done = true;
    pthread_cond_broadcast(&local->donecond);
    pthread_mutex_unlock(&local->qlock);
}

int main(int argc, char *argv[]) {
    local_mm8108_t local = { 0 };
    kis_capture_handler_t *caph = cf_handler_init("mm8108");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    local.caph = caph;
    pthread_mutex_init(&local.qlock, NULL);
    pthread_cond_init(&local.qcond, NULL);
    pthread_cond_init(&local.donecond, NULL);
    cf_handler_set_userdata(caph, &local);

    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);
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

    mm8108_stop_capture(&local);

    /* Removes the monitor interface and resets the chip, then releases USB */
    if (local.dev)
        mm_kis_close(local.dev);

    /* The driver is stopped, so nothing else touches the queue */
    mm8108_queue_free(local.qhead);
    mm_kis_exit();

    cf_handler_shutdown(caph);
    cf_handler_free(caph);

    return 1;
}
