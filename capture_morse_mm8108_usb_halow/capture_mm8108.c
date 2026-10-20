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
 * the userspace driver in libmm8108.
 *
 * Adapters are named mm8108-0, mm8108-1, ... in USB port order.  Channels are 802.11ah
 * channel numbers in the regulatory domain's channel plan, named as Kismet names S1G
 * channels, such as 27ah; each number identifies one channel and width.
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

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../config.h"
#include "../capture_framework.h"
#include "../firmware_file.h"

#include "libmm8108/mm8108.h"
#include "libmm8108/mm_channels.h"
#include "libmm8108/mm_radiotap.h"

#ifndef FIRMWAREDIR
#define FIRMWAREDIR "/usr/local/share/kismet/firmware"
#endif

#define KDLT_IEEE802_11_RADIO 127

#define MM8108_IFNAME "mm8108"
#define MM8108_MAX_DEVICES 16
#define MM8108_MAX_CHANNELS 128

/* Frames waiting for the capture thread */
#define MM8108_QUEUE_MAX (4 * 1024 * 1024)

struct mm8108_qent {
    struct mm8108_qent *next;
    struct timeval ts;
    uint32_t len;
    uint8_t data[];
};

typedef struct {
    kis_capture_handler_t *caph;

    char *name;
    char *interface;

    /* The driver is single threaded; commands from the hop thread and servicing from the
     * capture thread take turns */
    pthread_mutex_t dev_lock;
    volatile int cmd_waiting;
    struct mm8108_dev dev;
    bool dev_init;

    const struct mm_s1g_region *region;

    /* Frames arrive inside driver calls, under dev_lock, from either thread.  The framework
     * holds its handler lock while tuning and sending takes it, so frames are queued and
     * only the capture thread sends them, after releasing dev_lock. */
    pthread_mutex_t q_lock;
    struct mm8108_qent *qhead, *qtail;
    size_t qbytes;
    uint64_t qdrops;
    uint64_t ndp;
} local_mm8108_t;

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

static int mm8108_list_devices(struct mm_usb_devinfo *out, size_t max) {
    libusb_context *ctx;
    int n;

    if (libusb_init(&ctx) < 0)
        return -1;

    n = mm_usb_list(ctx, out, max);
    libusb_exit(ctx);

    return n;
}

/* Index from an interface name such as mm8108-0, or -1 */
static int mm8108_ifindex(const char *ifname) {
    const size_t plen = strlen(MM8108_IFNAME);
    char *end;
    long idx;

    if (strncmp(ifname, MM8108_IFNAME "-", plen + 1) != 0 || ifname[plen + 1] == 0)
        return -1;

    idx = strtol(ifname + plen + 1, &end, 10);

    if (*end != 0 || idx < 0 || idx >= MM8108_MAX_DEVICES)
        return -1;

    return (int) idx;
}

static bool mm8108_find_device(const char *ifname, struct mm_usb_devinfo *info) {
    struct mm_usb_devinfo devs[MM8108_MAX_DEVICES];
    const int idx = mm8108_ifindex(ifname);
    const int n = mm8108_list_devices(devs, MM8108_MAX_DEVICES);

    if (idx < 0 || n <= idx)
        return false;

    *info = devs[idx];
    return true;
}

static bool file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* A truncated path could name some other file, so it never matches */
static bool try_path(char *out, size_t out_len, const char *fmt, ...) {
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(out, out_len, fmt, ap);
    va_end(ap);

    return n > 0 && (size_t) n < out_len && file_exists(out);
}

/* Finds name in the firmwaredir= directory and Kismet's, as installed or in the layout of a
 * morse-firmware checkout; in each, as named and then in each compressed form. */
static bool find_firmware_kismet(const char *fw_dir, const char *name, char *out, size_t out_len) {
    static const char *subdirs[] = { "", "/firmware", "/bcf/morsemicro" };
    const char *dirs[] = { fw_dir, FIRMWAREDIR "/morse" };
    const char *suffixes[FW_FILE_MAX_SUFFIXES];
    size_t num_suffixes = fw_file_suffixes(suffixes);

    for (size_t d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++) {
        if (dirs[d] == NULL)
            continue;

        for (size_t s = 0; s < sizeof(subdirs) / sizeof(subdirs[0]); s++)
            for (size_t x = 0; x < num_suffixes; x++)
                if (try_path(out, out_len, "%s%s/%s%s", dirs[d], subdirs[s], name, suffixes[x]))
                    return true;
    }

    return false;
}

/* Finds name on Linux in the system firmware directories, in the linux-firmware layout
 * (morsemicro/mm81x/v<firmware interface version>) and morse_driver's (morse) */
static bool find_firmware_system(const char *name, char *out, size_t out_len) {
    char sys_dirs[CF_FIRMWARE_MAX_DIRS][CF_FIRMWARE_PATH_LEN];
    const char *suffixes[FW_FILE_MAX_SUFFIXES];
    size_t num_sys = cf_system_firmware_dirs(sys_dirs);
    size_t num_suffixes = fw_file_suffixes(suffixes);

    for (size_t d = 0; d < num_sys; d++) {
        for (size_t x = 0; x < num_suffixes; x++)
            if (try_path(out, out_len, "%s/morsemicro/mm81x/v%u/%s%s", sys_dirs[d],
                        (unsigned int) MM8108_FW_SEMVER_MAJOR, name, suffixes[x]))
                return true;

        for (size_t x = 0; x < num_suffixes; x++)
            if (try_path(out, out_len, "%s/morse/%s%s", sys_dirs[d], name, suffixes[x]))
                return true;
    }

    return false;
}

static bool find_firmware(const char *fw_dir, const char *name, char *out, size_t out_len) {
    return find_firmware_kismet(fw_dir, name, out, out_len) ||
        find_firmware_system(name, out, out_len);
}

/* linux-firmware firmware for an interface version this driver can't use, as a hint */
static bool find_other_fw_version(char *out, size_t out_len) {
    char sys_dirs[CF_FIRMWARE_MAX_DIRS][CF_FIRMWARE_PATH_LEN];
    char path[CF_FIRMWARE_PATH_LEN + 32];
    size_t num_sys = cf_system_firmware_dirs(sys_dirs);

    for (size_t d = 0; d < num_sys; d++) {
        struct dirent *de;
        DIR *dir;

        snprintf(path, sizeof(path), "%s/morsemicro/mm81x", sys_dirs[d]);
        if ((dir = opendir(path)) == NULL)
            continue;

        while ((de = readdir(dir)) != NULL) {
            unsigned int v;
            char tail;

            if (sscanf(de->d_name, "v%u%c", &v, &tail) == 1 && v != MM8108_FW_SEMVER_MAJOR) {
                snprintf(out, out_len, "%s/%s", path, de->d_name);
                closedir(dir);
                return true;
            }
        }

        closedir(dir);
    }

    return false;
}

/* A bare file name, so firmware= can't reach outside the firmware directories */
static bool firmware_name_valid(const char *name) {
    return name[0] != 0 && strchr(name, '/') == NULL && strchr(name, '\\') == NULL &&
        strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

static bool width_allowed(const char *widths, unsigned int bw) {
    char buf[64], *save = NULL;

    if (widths == NULL)
        return true;

    snprintf(buf, sizeof(buf), "%s", widths);

    for (char *t = strtok_r(buf, ",", &save); t != NULL; t = strtok_r(NULL, ",", &save))
        if ((unsigned int) strtoul(t, NULL, 10) == bw)
            return true;

    return false;
}

static bool channel_disabled(const struct mm_s1g_channel *ch,
        const struct mm_disabled_channel *dis, size_t num_dis) {
    for (size_t i = 0; i < num_dis; i++)
        if (dis[i].freq_khz == ch->freq_khz && (dis[i].bw_mhz == 0 || dis[i].bw_mhz == ch->bw_mhz))
            return true;

    return false;
}

/* The primary is the lowest 1MHz (or 2MHz) sub-channel, as the Linux driver defaults */
static int mm8108_tune(struct mm8108_dev *dev, const struct mm_s1g_channel *ch) {
    const uint8_t pri_bw = ch->bw_mhz == 1 ? 1 : 2;
    return mm_cmd_set_channel(dev, ch->freq_khz, ch->bw_mhz, pri_bw, 0);
}

static void mm8108_lock_cmd(local_mm8108_t *local) {
    local->cmd_waiting = 1;
    pthread_mutex_lock(&local->dev_lock);
    local->cmd_waiting = 0;
}

static void mm8108_queue_free(struct mm8108_qent *e) {
    while (e) {
        struct mm8108_qent *n = e->next;
        free(e);
        e = n;
    }
}

static void mm8108_rx(void *ctx, const struct mm_rx_status *st, const uint8_t *frame,
        size_t frame_len) {
    local_mm8108_t *local = ctx;
    uint8_t rt[MM_RADIOTAP_MAX_LEN];
    struct mm8108_qent *e;
    size_t rt_len, len;

    /* NDP frames carry SIG fields, not an 802.11 frame */
    if (st->flags & MM_RX_FLAG_NDP) {
        local->ndp++;
        return;
    }

    if ((rt_len = mm_radiotap_build(st, rt, sizeof(rt))) == 0)
        return;

    len = rt_len + frame_len;

    pthread_mutex_lock(&local->q_lock);

    if (local->qbytes + len > MM8108_QUEUE_MAX || (e = malloc(sizeof(*e) + len)) == NULL) {
        local->qdrops++;
        pthread_mutex_unlock(&local->q_lock);
        return;
    }

    e->next = NULL;
    gettimeofday(&e->ts, NULL);
    e->len = (uint32_t) len;
    memcpy(e->data, rt, rt_len);
    memcpy(e->data + rt_len, frame, frame_len);

    if (local->qtail)
        local->qtail->next = e;
    else
        local->qhead = e;
    local->qtail = e;
    local->qbytes += len;

    pthread_mutex_unlock(&local->q_lock);
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
        cf_params_list_interface_t ***interfaces) {
    struct mm_usb_devinfo devs[MM8108_MAX_DEVICES];
    char buf[64];
    int n;

    *interfaces = NULL;

    if ((n = mm8108_list_devices(devs, MM8108_MAX_DEVICES)) <= 0)
        return 0;

    *interfaces = (cf_params_list_interface_t **) calloc(n, sizeof(cf_params_list_interface_t *));
    if (*interfaces == NULL)
        return 0;

    for (int i = 0; i < n; i++) {
        (*interfaces)[i] = (cf_params_list_interface_t *) calloc(1, sizeof(cf_params_list_interface_t));
        if ((*interfaces)[i] == NULL)
            continue;

        snprintf(buf, sizeof(buf), "%s-%d", MM8108_IFNAME, i);
        (*interfaces)[i]->interface = strdup(buf);
        snprintf(buf, sizeof(buf), "Morse Micro MM8108 HaLow (%04x:%04x)", MM8108_USB_VID,
                MM8108_USB_PID);
        (*interfaces)[i]->hardware = strdup(buf);
    }

    return n;
}

/* Probing only matches USB enumeration; booting the firmware happens on open */
int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL, *ifname;
    struct mm_usb_devinfo info;
    char hw[64];
    int len, ret = 0;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    ifname = strndup(placeholder, len);

    if (ifname != NULL && mm8108_find_device(ifname, &info)) {
        snprintf(hw, sizeof(hw), "Morse Micro MM8108 HaLow (%04x:%04x)", MM8108_USB_VID,
                MM8108_USB_PID);
        (*ret_interface)->capif = strdup(ifname);
        (*ret_interface)->hardware = strdup(hw);
        *uuid = flag_dup(definition, "uuid");
        ret = 1;
    } else {
        snprintf(msg, STATUS_MAX, "%s is not an attached MM8108 HaLow adapter",
                ifname ? ifname : "interface");
    }

    free(ifname);
    return ret;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;
    struct mm_disabled_channel dis[256];
    struct mm8108_boot_config boot;
    struct mm_usb_devinfo info;
    char *placeholder = NULL, *country = NULL, *fw_dir = NULL, *fw_name = NULL, *bcf_name = NULL;
    char *widths = NULL;
    char fw_path[1024], bcf_path[1024], fname[64], version[129], buf[256];
    struct mm8108_dev *dev = &local->dev;
    size_t num_dis = 0;
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

    if (local->interface == NULL || local->name == NULL) {
        snprintf(msg, STATUS_MAX, "out of memory");
        return -1;
    }

    if ((fw_name = flag_dup(definition, "firmware")) != NULL &&
            (!firmware_name_valid(fw_name) || strlen(fw_name) >= sizeof(fname))) {
        snprintf(msg, STATUS_MAX, "%s firmware= takes a firmware file name, not a path; use "
                "firmwaredir= to set the directory", local->name);
        free(fw_name);
        return -1;
    }

    if ((bcf_name = flag_dup(definition, "boardfile")) != NULL &&
            (!firmware_name_valid(bcf_name) || strlen(bcf_name) >= sizeof(fname))) {
        snprintf(msg, STATUS_MAX, "%s boardfile= takes a board config file name, not a path; "
                "use firmwaredir= to set the directory", local->name);
        free(fw_name);
        free(bcf_name);
        return -1;
    }

    if (!mm8108_find_device(local->interface, &info)) {
        snprintf(msg, STATUS_MAX, "%s is not an attached MM8108 HaLow adapter", local->name);
        free(fw_name);
        free(bcf_name);
        return -1;
    }

    country = flag_dup(definition, "country");
    fw_dir = flag_dup(definition, "firmwaredir");
    widths = flag_dup(definition, "widths");

    pthread_mutex_lock(&local->dev_lock);

    if (mm8108_init(dev, flag_true(definition, "verbose", false) ? 1 : 0) < 0) {
        snprintf(msg, STATUS_MAX, "%s: %s", local->name, dev->errstr);
        goto out;
    }

    local->dev_init = true;
    mm8108_set_rx_cb(dev, mm8108_rx, local);

    if (mm_usb_open(dev, info.bus, info.address) < 0 || mm_read_chip_id(dev) < 0 ||
            mm_read_otp(dev) < 0) {
        snprintf(msg, STATUS_MAX, "%s: %s", local->name, dev->errstr);
        goto out;
    }

    /* The OTP country locks the regulatory domain */
    if (dev->otp_country[0] != 0) {
        if (country != NULL && strncasecmp(country, dev->otp_country, 2) != 0) {
            snprintf(buf, sizeof(buf), "%s is locked to regulatory domain %s; ignoring "
                    "country=%s", local->name, dev->otp_country, country);
            cf_send_warning(caph, buf);
        }

        free(country);
        country = strdup(dev->otp_country);
    } else if (country == NULL) {
        country = strdup("US");
    }

    if (country == NULL || (local->region = mm_s1g_region(country)) == NULL) {
        snprintf(msg, STATUS_MAX, "%s unknown country '%s'; supported: %s", local->name,
                country ? country : "", mm_s1g_countries());
        goto out;
    }

    if (fw_name != NULL)
        snprintf(fname, sizeof(fname), "%s", fw_name);
    else
        snprintf(fname, sizeof(fname), "mm8108%s-rl.bin", mm_chip_rev_string(dev->chip_id));

    /* linux-firmware names the firmware without the chip revision */
    if (!find_firmware(fw_dir, fname, fw_path, sizeof(fw_path)) &&
            (fw_name != NULL || !find_firmware(fw_dir, "mm8108.bin", fw_path, sizeof(fw_path)))) {
        if (find_other_fw_version(fw_path, sizeof(fw_path)))
            snprintf(msg, STATUS_MAX, "%s could not find firmware %s; %s is for another firmware "
                    "interface version, this driver needs v%u.  Download the firmware from "
                    "https://github.com/MorseMicro/morse-firmware and use the firmwaredir= option",
                    local->name, fname, fw_path, MM8108_FW_SEMVER_MAJOR);
        else
            snprintf(msg, STATUS_MAX, "%s could not find firmware %s; download it from "
                    "https://github.com/MorseMicro/morse-firmware and use the firmwaredir= option",
                    local->name, fname);
        goto out;
    }

    if (bcf_name != NULL) {
        if (!find_firmware(fw_dir, bcf_name, bcf_path, sizeof(bcf_path))) {
            snprintf(msg, STATUS_MAX, "%s could not find board config %s; download it from "
                    "https://github.com/MorseMicro/morse-firmware and use the firmwaredir= option",
                    local->name, bcf_name);
            goto out;
        }
    } else {
        /* The board type's own config, then the MM8108 reference module's that Kismet ships
         * (which the MM8108 board types in morse-firmware all use), and only then, on Linux,
         * the system's choice, as morse_driver would make it */
        static const char *reference[] = { "bcf_mf15457.bin", "bcf_mm8108_mf15457.bin" };
        char names[MM_BCF_MAX_NAMES][MM_BCF_NAME_LEN];
        size_t num_names = mm_bcf_default_names(dev, names), i;
        const char *chosen = NULL;

        if (dev->board_type != 0 && find_firmware(fw_dir, names[0], bcf_path, sizeof(bcf_path))) {
            chosen = names[0];
        } else {
            for (i = 0; i < sizeof(reference) / sizeof(reference[0]) && chosen == NULL; i++)
                if (find_firmware_kismet(fw_dir, reference[i], bcf_path, sizeof(bcf_path)))
                    chosen = reference[i];

            for (i = dev->board_type != 0 ? 1 : 0; i < num_names && chosen == NULL; i++)
                if (find_firmware_system(names[i], bcf_path, sizeof(bcf_path)))
                    chosen = names[i];
        }

        if (chosen == NULL) {
            snprintf(msg, STATUS_MAX, "%s could not find a board config for board type 0x%04x; "
                    "download them from https://github.com/MorseMicro/morse-firmware and use the "
                    "firmwaredir= option, or choose one with boardfile=", local->name,
                    dev->board_type);
            goto out;
        }

        /* Only the board type's own config is known to match the adapter */
        if (dev->board_type == 0 || chosen != names[0]) {
            if (dev->board_type == 0)
                snprintf(fname, sizeof(fname), "has no board type in OTP");
            else
                snprintf(fname, sizeof(fname), "board type 0x%04x is unknown", dev->board_type);

            snprintf(buf, sizeof(buf), "%s %s; using board config %s.  If the adapter needs a "
                    "different one, choose it with boardfile=", local->name, fname, chosen);
            cf_send_warning(caph, buf);
        }
    }

    boot.firmware_path = fw_path;
    boot.bcf_path = bcf_path;
    boot.country = local->region->country;

    if (mm_boot(dev, &boot) < 0 || mm_cmd_get_version(dev, version, sizeof(version)) < 0 ||
            mm_cmd_get_disabled_channels(dev, dis, sizeof(dis) / sizeof(dis[0]), &num_dis) < 0) {
        snprintf(msg, STATUS_MAX, "%s: %s", local->name, dev->errstr);
        goto out;
    }

    /* Every channel and width of the domain the board config allows */
    (*ret_interface)->channels = (char **) calloc(MM8108_MAX_CHANNELS, sizeof(char *));
    if ((*ret_interface)->channels == NULL) {
        snprintf(msg, STATUS_MAX, "out of memory");
        goto out;
    }

    for (size_t i = 0; i < local->region->num_channels &&
            (*ret_interface)->channels_len < MM8108_MAX_CHANNELS; i++) {
        const struct mm_s1g_channel *ch = &local->region->channels[i];

        if (!width_allowed(widths, ch->bw_mhz) || channel_disabled(ch, dis, num_dis))
            continue;

        snprintf(buf, sizeof(buf), "%uah", ch->channel);
        if (((*ret_interface)->channels[(*ret_interface)->channels_len] = strdup(buf)) != NULL)
            (*ret_interface)->channels_len++;
    }

    if ((*ret_interface)->channels_len == 0) {
        snprintf(msg, STATUS_MAX, "%s has no usable channels in %s", local->name,
                local->region->country);
        goto out;
    }

    (*ret_interface)->chanset = strdup((*ret_interface)->channels[0]);

    if (mm8108_start_monitor(dev) < 0 ||
            mm8108_tune(dev, mm_s1g_channel_lookup(local->region,
                    (unsigned int) strtoul((*ret_interface)->channels[0], NULL, 10))) < 0) {
        snprintf(msg, STATUS_MAX, "%s could not enter monitor mode: %s", local->name, dev->errstr);
        goto out;
    }

    if (dev->bcf_module[0] != 0)
        snprintf(buf, sizeof(buf), "%s (board 0x%04x %s, firmware %s)", mm_chip_name(dev->chip_id),
                dev->board_type, dev->bcf_module, version);
    else
        snprintf(buf, sizeof(buf), "%s (board 0x%04x, firmware %s)", mm_chip_name(dev->chip_id),
                dev->board_type, version);
    (*ret_interface)->hardware = strdup(buf);
    (*ret_interface)->capif = strdup(local->interface);

    /* The UUID follows the adapter MAC so it survives re-plugging */
    if ((*uuid = flag_dup(definition, "uuid")) == NULL) {
        snprintf(buf, sizeof(buf), "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
                adler32_csum((uint8_t *) "kismet_cap_mm8108_halow",
                    strlen("kismet_cap_mm8108_halow")) & 0xFFFFFFFF,
                dev->mac[0], dev->mac[1], dev->mac[2], dev->mac[3], dev->mac[4], dev->mac[5]);
        *uuid = strdup(buf);
    }

    {
        const char *fw_base = strrchr(fw_path, '/'), *bcf_base = strrchr(bcf_path, '/');

        snprintf(buf, sizeof(buf), "%s %s firmware %s (%s), board config %s%s%s%s, regulatory "
                "domain %s, %zu channels", local->name, mm_chip_name(dev->chip_id), version,
                fw_base ? fw_base + 1 : fw_path, bcf_base ? bcf_base + 1 : bcf_path,
                dev->bcf_module[0] ? " (" : "", dev->bcf_module, dev->bcf_module[0] ? ")" : "",
                local->region->country, (*ret_interface)->channels_len);
    }
    cf_send_message(caph, buf, MSGFLAG_INFO);

    *dlt = KDLT_IEEE802_11_RADIO;
    ret = 1;

out:
    pthread_mutex_unlock(&local->dev_lock);

    free(country);
    free(fw_dir);
    free(fw_name);
    free(bcf_name);
    free(widths);

    return ret;
}

void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;
    const struct mm_s1g_channel *ch;
    struct mm_s1g_channel *ret;
    char errstr[STATUS_MAX];
    unsigned long c;
    char *end;

    if (local->region == NULL || chanstr == NULL)
        return NULL;

    /* 27ah, or a bare channel number */
    errno = 0;
    c = strtoul(chanstr, &end, 10);

    if (errno != 0 || end == chanstr || (*end != 0 && strcasecmp(end, "ah") != 0) ||
            c > UINT16_MAX || (ch = mm_s1g_channel_lookup(local->region, (unsigned int) c)) == NULL) {
        snprintf(errstr, STATUS_MAX, "%s - '%s' is not an 802.11ah channel in %s", local->name,
                chanstr, local->region->country);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if ((ret = malloc(sizeof(*ret))) == NULL)
        return NULL;

    *ret = *ch;
    return ret;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;
    const struct mm_s1g_channel *ch = privchan;
    int r;

    if (ch == NULL)
        return 0;

    mm8108_lock_cmd(local);
    r = mm8108_tune(&local->dev, ch);
    if (r < 0)
        snprintf(msg, STATUS_MAX, "%s could not tune to channel %uah: %s", local->name,
                ch->channel, local->dev.errstr);
    pthread_mutex_unlock(&local->dev_lock);

    return r < 0 ? -1 : 1;
}

static int mm8108_send(local_mm8108_t *local, struct mm8108_qent *e) {
    int r;

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
    local_mm8108_t *local = (local_mm8108_t *) caph->userdata;
    struct mm8108_qent *batch, *e;
    char errstr[STATUS_MAX];
    uint64_t drops, reported_drops = 0;
    time_t last_drop_report = 0;
    bool error = false;
    int r;

    while (!error && caph->spindown == 0) {
        /* Let a pending command in */
        while (local->cmd_waiting)
            usleep(1000);

        pthread_mutex_lock(&local->dev_lock);
        r = mm8108_poll(&local->dev, 20);
        if (r < 0)
            snprintf(errstr, sizeof(errstr), "%s capture failed: %s", local->name,
                    local->dev.errstr);
        pthread_mutex_unlock(&local->dev_lock);

        if (r < 0) {
            cf_send_error(caph, 0, errstr);
            break;
        }

        pthread_mutex_lock(&local->q_lock);
        batch = local->qhead;
        local->qhead = local->qtail = NULL;
        local->qbytes = 0;
        drops = local->qdrops;
        pthread_mutex_unlock(&local->q_lock);

        for (e = batch; e != NULL && !error; e = e->next)
            if (mm8108_send(local, e) < 0)
                error = true;

        mm8108_queue_free(batch);

        if (drops != reported_drops && time(NULL) - last_drop_report >= 10) {
            snprintf(errstr, sizeof(errstr), "%s dropped %llu frames because Kismet could not "
                    "keep up", local->name, (unsigned long long) (drops - reported_drops));
            cf_send_warning(caph, errstr);
            reported_drops = drops;
            last_drop_report = time(NULL);
        }
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_mm8108_t local;
    kis_capture_handler_t *caph = cf_handler_init("mm8108");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    memset(&local, 0, sizeof(local));
    local.caph = caph;
    pthread_mutex_init(&local.dev_lock, NULL);
    pthread_mutex_init(&local.q_lock, NULL);

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

    /* Removes the monitor interface and resets the chip, then releases USB */
    pthread_mutex_lock(&local.dev_lock);
    if (local.dev_init) {
        mm8108_stop(&local.dev);
        mm8108_free(&local.dev);
    }
    pthread_mutex_unlock(&local.dev_lock);

    mm8108_queue_free(local.qhead);

    cf_handler_shutdown(caph);
    cf_handler_free(caph);

    return 1;
}
