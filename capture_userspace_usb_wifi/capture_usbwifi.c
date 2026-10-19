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

/* Kismet capture binary for USB Wi-Fi adapters driven by Linux drivers in userspace.
 *
 * Adapters are named by driver and index, such as "mt7921-0" for the first MT7921 USB
 * adapter, in USB path order.  Channels use Kismet's Wi-Fi names; Kismet does the hopping.
 *
 * Source options:
 *   ht_channels=true|false   include HT40 channels (default true)
 *   vht_channels=true|false  include VHT80/160 channels (default true)
 *   country=XX               regulatory country reported to the driver
 *   firmware=DIR             directory searched first for driver firmware
 *   verbose=true             forward driver informational messages
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../config.h"
#include "../capture_framework.h"

#include "common/uwifi_kismet.h"

#ifndef FIRMWAREDIR
#define FIRMWAREDIR "/usr/local/share/kismet/firmware"
#endif

#define KDLT_IEEE802_11_RADIO 127

/* Kernel log levels */
#define KLOG_ERR 3
#define KLOG_INFO 6

/* Frames and driver messages waiting for the capture thread */
#define USBWIFI_QUEUE_MAX (8 * 1024 * 1024)

struct usbwifi_qent {
    struct usbwifi_qent *next;
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

    /* The framework holds its handler lock while tuning, and cf_send_* takes it; driver
     * threads must not block on it, or the response the tune waits for can't be delivered.
     * They queue here and only the capture thread talks to the framework. */
    pthread_mutex_t qlock;
    pthread_cond_t qcond;
    struct usbwifi_qent *qhead, *qtail;
    size_t qbytes;
    uint64_t qdrops;
} local_usbwifi_t;

static void usbwifi_enqueue(local_usbwifi_t *local, unsigned int msgflags, const uint8_t *data,
        size_t len) {
    struct usbwifi_qent *e;
    struct timeval ts;

    gettimeofday(&ts, NULL);

    pthread_mutex_lock(&local->qlock);

    if (local->qbytes + len > USBWIFI_QUEUE_MAX || len > UINT32_MAX ||
            (e = malloc(sizeof(*e) + len)) == NULL) {
        local->qdrops++;
        pthread_mutex_unlock(&local->qlock);
        return;
    }

    e->next = NULL;
    e->ts = ts;
    e->msgflags = msgflags;
    e->len = (uint32_t) len;
    memcpy(e->data, data, len);

    if (local->qtail)
        local->qtail->next = e;
    else
        local->qhead = e;
    local->qtail = e;
    local->qbytes += len;

    pthread_cond_signal(&local->qcond);
    pthread_mutex_unlock(&local->qlock);
}

static void usbwifi_queue_free(struct usbwifi_qent *e) {
    while (e) {
        struct usbwifi_qent *n = e->next;
        free(e);
        e = n;
    }
}

static void usbwifi_log(void *ctx, int level, const char *msg) {
    local_usbwifi_t *local = ctx;
    char buf[STATUS_MAX];
    size_t len;

    if (local == NULL || local->caph == NULL)
        return;

    if (level > KLOG_ERR && !local->verbose)
        return;

    snprintf(buf, sizeof(buf), "%s: %s", local->name ? local->name : "usbwifi", msg);
    len = strlen(buf);
    if (len && buf[len - 1] == '\n')
        buf[--len] = 0;

    usbwifi_enqueue(local, level <= KLOG_ERR ? MSGFLAG_ERROR : MSGFLAG_INFO, (uint8_t *) buf, len + 1);
}

/* Firmware directories: the source option, Kismet's share directory, then on Linux the
 * system firmware directories in the kernel's search order */
static int usbwifi_init(local_usbwifi_t *local, const char *fw_dir) {
    char sys_dirs[CF_FIRMWARE_MAX_DIRS][CF_FIRMWARE_PATH_LEN];
    const char *paths[3 + CF_FIRMWARE_MAX_DIRS];
    size_t n = 0, num_sys = cf_system_firmware_dirs(sys_dirs);

    if (fw_dir != NULL)
        paths[n++] = fw_dir;

    paths[n++] = FIRMWAREDIR;
    paths[n++] = "/usr/share/kismet/firmware";

    for (size_t i = 0; i < num_sys; i++)
        paths[n++] = sys_dirs[i];

    return uwifi_kis_init(paths, n, usbwifi_log, local, local->verbose ? KLOG_INFO : KLOG_ERR);
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

/* Finds one of our interface names among present adapters and fills its hardware */
static bool usbwifi_known(const char *ifname, char *hw, size_t hw_len) {
    struct uwifi_kis_iface *list;
    size_t n;
    bool found = false;

    if (uwifi_kis_list(&list, &n) < 0)
        return false;

    for (size_t i = 0; i < n && !found; i++) {
        if (strcmp(list[i].ifname, ifname) == 0) {
            snprintf(hw, hw_len, "%s", list[i].hardware);
            found = true;
        }
    }

    free(list);
    return found;
}

/* The UUID is derived from the adapter's MAC so it survives re-plugging */
static char *usbwifi_uuid(struct uwifi_dev *dev) {
    const uint8_t *mac = uwifi_kis_mac(dev);
    char buf[64];

    snprintf(buf, sizeof(buf), "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
            adler32_csum((uint8_t *) "kismet_cap_usbwifi", strlen("kismet_cap_usbwifi")) & 0xFFFFFFFF,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return strdup(buf);
}

static int usbwifi_fill_interface(struct uwifi_dev *dev, const char *ifname, bool ht, bool vht,
        cf_params_interface_t *iface, char *msg) {
    char hw[128];

    if (uwifi_kis_channels(dev, ht, vht, &iface->channels, &iface->channels_len) < 0 ||
            iface->channels_len == 0) {
        snprintf(msg, STATUS_MAX, "%s has no usable channels", ifname);
        return -1;
    }

    uwifi_kis_hardware(dev, hw, sizeof(hw));
    iface->hardware = strdup(hw);
    iface->capif = strdup(ifname);

    return 0;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
        cf_params_list_interface_t ***interfaces) {
    local_usbwifi_t *local = (local_usbwifi_t *) caph->userdata;
    struct uwifi_kis_iface *list;
    size_t n;

    *interfaces = NULL;

    if (usbwifi_init(local, NULL) < 0 || uwifi_kis_list(&list, &n) < 0 || n == 0)
        return 0;

    *interfaces = (cf_params_list_interface_t **) calloc(n, sizeof(cf_params_list_interface_t *));
    if (*interfaces == NULL) {
        free(list);
        return 0;
    }

    for (size_t i = 0; i < n; i++) {
        (*interfaces)[i] = (cf_params_list_interface_t *) calloc(1, sizeof(cf_params_list_interface_t));
        (*interfaces)[i]->interface = strdup(list[i].ifname);
        (*interfaces)[i]->hardware = strdup(list[i].hardware);
    }

    free(list);
    return (int) n;
}

/* Probing only matches USB enumeration; loading firmware would outlast the probe timeout,
 * so channels and the MAC-derived UUID come from opening.  As a remote capture the probe
 * runs locally with no timeout and the server needs the UUID to match reconnects, so the
 * adapter is opened here and kept for the open callback */
int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_usbwifi_t *local = (local_usbwifi_t *) caph->userdata;
    char *placeholder = NULL, *ifname;
    char hw[128];
    int len, ret = 0;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    ifname = strndup(placeholder, len);

    if (usbwifi_init(local, NULL) == 0 && usbwifi_known(ifname, hw, sizeof(hw))) {
        (*ret_interface)->capif = strdup(ifname);
        (*ret_interface)->hardware = strdup(hw);
        *uuid = flag_dup(definition, "uuid");
        ret = 1;

        if (*uuid == NULL && caph->remote_host != NULL) {
            char errstr[STATUS_MAX];
            char *fw_dir = flag_dup(definition, "firmware");

            if (fw_dir != NULL)
                usbwifi_init(local, fw_dir);
            free(fw_dir);

            if (local->dev == NULL)
                local->dev = uwifi_kis_open(ifname, errstr, sizeof(errstr));

            if (local->dev != NULL) {
                *uuid = usbwifi_uuid(local->dev);
            } else {
                snprintf(msg, STATUS_MAX, "%s: %s", ifname, errstr);
                ret = 0;
            }
        }
    } else {
        snprintf(msg, STATUS_MAX, "%s is not a supported USB Wi-Fi adapter", ifname);
    }

    free(ifname);
    return ret;
}

static void usbwifi_rx(void *ctx, const uint8_t *data, size_t len) {
    local_usbwifi_t *local = ctx;

    if (!local->error)
        usbwifi_enqueue(local, 0, data, len);
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_usbwifi_t *local = (local_usbwifi_t *) caph->userdata;
    char *placeholder = NULL, *fw_dir, *country;
    char errstr[STATUS_MAX];
    int len;

    *uuid = NULL;
    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    local->interface = strndup(placeholder, len);
    local->name = flag_dup(definition, "name");
    if (local->name == NULL)
        local->name = strdup(local->interface);
    local->verbose = flag_true(definition, "verbose", false);

    fw_dir = flag_dup(definition, "firmware");
    if (usbwifi_init(local, fw_dir) < 0) {
        free(fw_dir);
        snprintf(msg, STATUS_MAX, "%s could not initialize USB", local->name);
        return -1;
    }
    free(fw_dir);

    /* A remote capture already opened the adapter while probing */
    if (local->dev == NULL &&
            (local->dev = uwifi_kis_open(local->interface, errstr, sizeof(errstr))) == NULL) {
        snprintf(msg, STATUS_MAX, "%s: %s", local->name, errstr);
        return -1;
    }

    if (usbwifi_fill_interface(local->dev, local->interface, flag_true(definition, "ht_channels", true),
                flag_true(definition, "vht_channels", true), *ret_interface, msg) < 0)
        return -1;

    if ((*uuid = flag_dup(definition, "uuid")) == NULL)
        *uuid = usbwifi_uuid(local->dev);

    if (uwifi_kis_start(local->dev, usbwifi_rx, local) < 0) {
        snprintf(msg, STATUS_MAX, "%s could not enter monitor mode", local->name);
        return -1;
    }

    if ((country = flag_dup(definition, "country")) != NULL) {
        if (uwifi_kis_set_country(local->dev, country) < 0) {
            snprintf(errstr, sizeof(errstr), "%s: invalid country '%s'", local->name, country);
            cf_send_warning(caph, errstr);
        }
        free(country);
    }

    *dlt = KDLT_IEEE802_11_RADIO;
    return 1;
}

void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_usbwifi_t *local = (local_usbwifi_t *) caph->userdata;
    char errstr[STATUS_MAX], msg[STATUS_MAX];
    void *chan;

    if (local->dev == NULL)
        return NULL;

    if ((chan = uwifi_kis_parse_channel(local->dev, chanstr, errstr, sizeof(errstr))) == NULL) {
        snprintf(msg, sizeof(msg), "%s: %s", local->name, errstr);
        cf_send_message(caph, msg, MSGFLAG_INFO);
    }

    return chan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_usbwifi_t *local = (local_usbwifi_t *) caph->userdata;

    if (local->dev == NULL || privchan == NULL)
        return 0;

    /* A rejected channel is dropped from hopping rather than closing the source */
    if (uwifi_kis_set_channel(local->dev, privchan) <= 0) {
        snprintf(msg, STATUS_MAX, "%s could not tune to channel %s", local->name,
                uwifi_kis_channel_name(privchan));
        return 0;
    }

    return 1;
}

static int usbwifi_send(local_usbwifi_t *local, struct usbwifi_qent *e) {
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

        /* Wait for the write buffer to drain */
        cf_handler_wait_ringbuffer(local->caph);
    }
}

void capture_thread(kis_capture_handler_t *caph) {
    local_usbwifi_t *local = (local_usbwifi_t *) caph->userdata;
    struct usbwifi_qent *batch, *e;
    char errstr[STATUS_MAX];
    uint64_t drops, reported_drops = 0;
    time_t last_check = 0, last_drop_report = 0;
    struct timespec deadline;

    while (!local->error && caph->spindown == 0) {
        time_t now = time(NULL);

        if (now != last_check) {
            last_check = now;

            if (!uwifi_kis_alive(local->dev)) {
                snprintf(errstr, sizeof(errstr), "%s was removed or stopped responding", local->name);
                cf_send_error(caph, 0, errstr);
                local->error = true;
                break;
            }
        }

        pthread_mutex_lock(&local->qlock);
        if (local->qhead == NULL) {
            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += 1;
            pthread_cond_timedwait(&local->qcond, &local->qlock, &deadline);
        }
        batch = local->qhead;
        local->qhead = local->qtail = NULL;
        local->qbytes = 0;
        drops = local->qdrops;
        pthread_mutex_unlock(&local->qlock);

        for (e = batch; e != NULL && !local->error; e = e->next)
            if (usbwifi_send(local, e) < 0)
                local->error = true;

        usbwifi_queue_free(batch);

        if (drops != reported_drops && now - last_drop_report >= 10) {
            snprintf(errstr, sizeof(errstr), "%s dropped %llu frames because Kismet could not "
                    "keep up", local->name, (unsigned long long) (drops - reported_drops));
            cf_send_warning(caph, errstr);
            reported_drops = drops;
            last_drop_report = now;
        }
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_usbwifi_t local = { 0 };
    kis_capture_handler_t *caph = cf_handler_init("usbwifi");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    local.caph = caph;
    pthread_mutex_init(&local.qlock, NULL);
    pthread_cond_init(&local.qcond, NULL);
    cf_handler_set_userdata(caph, &local);

    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);
    cf_handler_set_capture_cb(caph, capture_thread);

    /* Spread hops so adjacent 2.4GHz channels aren't visited consecutively */
    cf_handler_set_hop_shuffle_spacing(caph, 4);

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

    if (local.dev)
        uwifi_kis_close(local.dev);

    /* The driver is stopped, so nothing else touches the queue */
    usbwifi_queue_free(local.qhead);

    cf_handler_shutdown(caph);
    cf_handler_free(caph);

    return 1;
}
