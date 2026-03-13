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

/*
 * This datasource interfaces with the Radiacode geiger counter
 * https://www.radiacode.
 *
 * This datasource uses libusb to interface & requires a usb 
 * connection.
 *
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../capture_framework.h"
#include "../config.h"
#include "../simple_ringbuf_c.h"
#include "../kis_endian.h"

#include "wch_ble_analyzer.h"

#include <libusb-1.0/libusb.h>

#define BUFFER_SIZE 2048

/* arbitrary max number of wch devices we support on a single system; whenever
 * someone manages to break this limit we'll just increase it */
#define MAX_AGGREGATE_DEVICES       10

static const uint8_t adv_ch[3] = {37, 38, 39};

#ifndef KDLT_BTLE_RADIO
#define KDLT_BTLE_RADIO       256
#endif

/* DLT_BLUETOOTH_LE_LL_WITH_PHDR pseudo-header (10 bytes) plus aa_le component to make writing
 * packets efficiently simpler */
typedef struct {
    uint8_t  rf_channel;
    int8_t   signal_power;
    int8_t   noise_power;
    uint8_t  access_address_offenses;
    uint32_t reference_access_address;
    uint16_t flags;
    uint32_t aa_le;
} __attribute__((packed)) ble_phdr_with_aa_t;

typedef struct {
    wch_device_t *dev[3];
    size_t n_dev;
    uint8_t path[16];
} wch_aggregate_t;

typedef struct {
    libusb_context *usb_ctx;

    char *name;
    char *interface;

    wch_device_t *wch[3];
    size_t num_wch;

    uint8_t *bufs[3];

    unsigned int channel[3];

    kis_capture_handler_t *caph;
} local_wch_btle_t;

size_t aggregate_wch_devices(local_wch_btle_t *local, wch_aggregate_t *aggregate,
        wch_device_t *wch, int num_wch) {
    size_t n_agg = 0;
    int grouped_devices[MAX_MCU_DEVICES];

    libusb_device **list;
    ssize_t usb_cnt = 0;

    if (num_wch < 3) {
        return 0;
    }

    usb_cnt = libusb_get_device_list(local->usb_ctx, &list);

    if (usb_cnt <= 0) {
        return 0;
    }

    memset(aggregate, 0, sizeof(wch_aggregate_t) * MAX_AGGREGATE_DEVICES);
    memset(grouped_devices, 0, sizeof(int) * MAX_MCU_DEVICES);

    for (size_t i = 0; i < num_wch; i++) {
        for (size_t u = 0; u < usb_cnt; u++) {
            if (libusb_get_bus_number(list[u]) == wch[i].bus &&
                    libusb_get_device_address(list[u]) == wch[i].addr) {
                bool matched = false;

                uint8_t path[16];
                int n_path = 0;

                n_path = libusb_get_port_numbers(list[u], path, 16);

                if (n_path <= 1) {
                    continue;
                }

                for (size_t a = 0; a < n_agg; a++) {
                    if (memcmp(aggregate[a].path, path, sizeof(uint8_t) * (n_path - 1)) == 0) {
                        matched = true;

                        /* can't have more than 3 radios in 1 device */
                        if (aggregate[a].n_dev >= 3) {
                            continue;
                        }

                        aggregate[a].dev[aggregate[a].n_dev++] = &wch[i];
                        break;
                    }
                }

                if (matched) {
                    continue;
                }

                if (n_agg >= MAX_AGGREGATE_DEVICES) {
                    fprintf(stderr, "ERROR:  Too many WCH devices connected\n");
                    break;
                }

                memcpy(aggregate[n_agg].path, path, sizeof(uint8_t) * n_path);
                aggregate[n_agg].dev[0] = &wch[i];
                aggregate[n_agg].n_dev = 1;
                n_agg++;
            }
        }
    }

    libusb_free_device_list(list, 1);

    return n_agg;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno,
    char *definition, char *msg, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];
    char *device = NULL;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    int devno = 0;
    int busno = 0;

    wch_device_t wch_devs[MAX_MCU_DEVICES];
    int wch_devs_cnt = 0;

    wch_aggregate_t wch_aggregates[MAX_AGGREGATE_DEVICES];
    int wch_agg_cnt = 0;

    int x;

    local_wch_btle_t *local = (local_wch_btle_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strstr(interface, "wch-btle") != interface) {
        free(interface);
        return 0;
    }

    wch_devs_cnt = wch_find_devices(local->usb_ctx, wch_devs);

    if (wch_devs_cnt <= 0) {
        return 0;
    }

    bool matched = false;

    if (strstr(interface, "wch-btle-mcu") == interface) {
        /* open a single radio directly */

        x = sscanf(interface, "wch-btle-mcu-%d-%d", &busno, &devno);

        /* Look for interface-# */
        if (x != 2) {
            snprintf(msg, STATUS_MAX, "Expected wch-btle-mcu-[bus]-[device]");
            return 0;
        }

        for (size_t i = 0; i < wch_devs_cnt; i++) {
            if (wch_devs[i].bus == busno && wch_devs[i].addr == devno) {
                matched = true;
                break;
            }
        }
    } else {
        /* open an aggregate */
        x = sscanf(interface, "wch-btle-%d", &busno);
        devno = 0;

        /* Look for interface-# */
        if (x != 1) {
            snprintf(msg, STATUS_MAX, "Expected wch-btle-[number]");
            return 0;
        }

        wch_agg_cnt = aggregate_wch_devices(local, wch_aggregates, wch_devs, wch_devs_cnt);

        if (busno < wch_agg_cnt) {
            matched = true;
        }

    }

    if (!matched) {
        return 0;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_wch_ble_analyzer_pro",
                    strlen("kismet_cap_wch_ble_analyzer_pro")) & 0xFFFFFFFF, busno, devno);
        *uuid = strdup(errstr);
    }

    free(device);

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    typedef struct wch_list {
        char *device;
        struct wch_list *next;
    } wch_list_t;

    wch_list_t *devs = NULL;
    size_t num_devs = 0;

    char devname[32];
    unsigned int i;

    local_wch_btle_t *local = (local_wch_btle_t *) caph->userdata;

    wch_device_t wch_devs[MAX_MCU_DEVICES];
    int wch_devs_cnt = 0;

    wch_aggregate_t wch_aggregates[MAX_AGGREGATE_DEVICES];
    int wch_agg_cnt = 0;

    wch_devs_cnt = wch_find_devices(local->usb_ctx, wch_devs);

    if (wch_devs_cnt <= 0) {
        return 0;
    }

    wch_agg_cnt = aggregate_wch_devices(local, wch_aggregates, wch_devs, wch_devs_cnt);

    for (ssize_t i = 0; i < wch_agg_cnt; i++) {
        snprintf(devname, 32, "wch-btle-%lu", i);
        wch_list_t *d = (wch_list_t *) malloc(sizeof(wch_list_t));
        num_devs++;
        d->device = strdup(devname);
        d->next = devs;
        devs = d;
    }

    for (ssize_t i = 0; i < wch_devs_cnt; i++) {
        snprintf(devname, 32, "wch-btle-mcu-%u-%u",
                wch_devs[i].bus, wch_devs[i].addr);

        wch_list_t *d = (wch_list_t *) malloc(sizeof(wch_list_t));
        num_devs++;
        d->device = strdup(devname);
        d->next = devs;
        devs = d;
    }

    if (num_devs == 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces =
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    while (devs != NULL) {
        wch_list_t *td = devs->next;
        (*interfaces)[i] =
            (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        (*interfaces)[i]->interface = devs->device;
        (*interfaces)[i]->flags = NULL;
        (*interfaces)[i]->hardware = strdup("wch-btle");

        free(devs);
        devs = td;

        i++;
    }

    return num_devs;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
    char *msg, uint32_t *dlt, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {
    char *placeholder;
    int placeholder_len;
    char errstr[STATUS_MAX];

    int x;
    int busno = -1, devno = -1;

    wch_device_t wch_devs[MAX_MCU_DEVICES];
    int wch_devs_cnt = 0;

    wch_aggregate_t wch_aggregates[MAX_AGGREGATE_DEVICES];
    int wch_agg_cnt = 0;

    char cap_if[32];

    local_wch_btle_t *local = (local_wch_btle_t *) caph->userdata;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    local->interface = strndup(placeholder, placeholder_len);

    if (strstr(local->interface, "wch-btle") != local->interface) {
        free(local->interface);
        return 0;
    }

    wch_devs_cnt = wch_find_devices(local->usb_ctx, wch_devs);

    if (wch_devs_cnt <= 0) {
        return 0;
    }

    bool matched = false;

    if (strstr(local->interface, "wch-btle-mcu") == local->interface) {
        /* open a single radio directly */

        x = sscanf(local->interface, "wch-btle-mcu-%d-%d", &busno, &devno);

        /* Look for interface-# */
        if (x != 2) {
            snprintf(msg, STATUS_MAX, "Expected wch-btle-mcu-[bus]-[device]");
            return 0;
        }

        for (size_t i = 0; i < wch_devs_cnt; i++) {
            if (wch_devs[i].bus == busno && wch_devs[i].addr == devno) {
                matched = true;
                local->wch[0] = &wch_devs[i];
                local->num_wch = 1;

                snprintf(cap_if, 32, "wch-btle-mcu-%d-%d", busno, devno);

                break;
            }
        }

        snprintf(cap_if, 32, "wch-btle-mcu-%d-%d", busno, devno);
        (*ret_interface)->hardware = strdup("WCH BLE Analyzer MCU");
    } else {
        /* open an aggregate */
        x = sscanf(local->interface, "wch-btle-%d", &busno);
        devno = 0;

        /* Look for interface-# */
        if (x != 1) {
            snprintf(msg, STATUS_MAX, "Expected wch-btle-[number]");
            return 0;
        }

        wch_agg_cnt = aggregate_wch_devices(local, wch_aggregates, wch_devs, wch_devs_cnt);

        if (busno < wch_agg_cnt) {
            matched = true;

            for (size_t w = 0; w < wch_aggregates[busno].n_dev; w++) {
                local->wch[w] = wch_aggregates[busno].dev[w];
            }
            local->num_wch = wch_aggregates[busno].n_dev;

            snprintf(cap_if, 32, "wch-btle-%d", busno);
            (*ret_interface)->hardware = strdup("WCH BLE Analyzer Pro");
        }
    }

    if (!matched) {
        snprintf(msg, STATUS_MAX, "Unable to find WCH BTLE USB device");
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        local->name = strndup(placeholder, placeholder_len);
    } else {
        local->name = strdup(local->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_wch_ble_analyzer_pro",
                    strlen("kismet_cap_wch_ble_analyzer_pro")) & 0xFFFFFFFF, busno, devno);
        *uuid = strdup(errstr);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        char *tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%u", &(local->channel[0])) != 1) {
            snprintf(msg, STATUS_MAX, "Unable to parse channel, expected 0-39");
            free(tmp);
            return -1;
        }

        free(tmp);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "channel1", definition)) > 0) {
        char *tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%u", &(local->channel[0])) != 1) {
            snprintf(msg, STATUS_MAX, "Unable to parse channel1, expected 0-39");
            free(tmp);
            return -1;
        }

        free(tmp);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "channel2", definition)) > 0) {
        char *tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%u", &(local->channel[1])) != 1) {
            snprintf(msg, STATUS_MAX, "Unable to parse channel2, expected 0-39");
            free(tmp);
            return -1;
        }

        free(tmp);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "channel3", definition)) > 0) {
        char *tmp = strndup(placeholder, placeholder_len);

        if (sscanf(tmp, "%u", &(local->channel[2])) != 1) {
            snprintf(msg, STATUS_MAX, "Unable to parse channel3, expected 0-39");
            free(tmp);
            return -1;
        }

        free(tmp);
    }

    (*ret_interface)->capif = strdup(cap_if);

    // open device
    for (size_t i = 0; i < local->num_wch; i++) {
        int r = wch_open_device(local->wch[i]);
        if (r != 0) {
            snprintf(msg, STATUS_MAX, "Unable to open WCH radio %lu %d:%d: %s",
                    i, local->wch[i]->bus, local->wch[i]->addr, libusb_error_name(r));
            return -1;
        }

        local->bufs[i] = malloc(BULK_TRANSFER_SIZE);
        if (local->bufs[i] == NULL) {
            snprintf(msg, STATUS_MAX, "Unable to allocate buffer for radio %lu", i);
            return -1;
        }

        wch_capture_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.mode = MODE_BLE_MONITOR;
        cfg.phy = PHY_1M;
        cfg.channel = local->channel[i];
        cfg.ble_channel = local->channel[i];

        r = wch_start_capture(local->wch[i], &cfg);
        if (r != 0) {
            snprintf(msg, STATUS_MAX, "Unable to start MCU %lu %d:%d: %s",
                    i, local->wch[i]->bus, local->wch[i]->addr, libusb_error_name(r));
            return -1;
        }
    }

    return 1;
}

static uint8_t ble_ch_to_rf_ch(uint8_t ch) {
    if (ch == 37)
        return 0;
    if (ch == 38)
        return 12;
    if (ch == 39)
        return 39;
    if (ch <= 10)
        return ch + 1;
    return ch + 2;
}

static uint32_t ble_crc24(uint32_t init, const uint8_t *buf, int len) {
    uint32_t lfsr = init & 0xFFFFFF;
    for (int i = 0; i < len; i++) {
        uint8_t byte = buf[i];
        for (int j = 0; j < 8; j++) {
            int in = (byte ^ (int)lfsr) & 1;
            lfsr >>= 1;
            byte >>= 1;
            if (in)
                lfsr ^= 0xDA6000u;  /* reflected BLE polynomial */
        }
    }
    return lfsr;
}

static void on_packet(const wch_pkt_hdr_t *hdr, const uint8_t *pdu, int pdu_len, void *ctx) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) ctx;
    /* local_wch_btle_t *local = (local_wch_btle_t *) caph->userdata; */
    int ret;

    uint16_t flags = 0x0001 /* DEWHITENED */
                   | 0x0002 /* SIGPOWER_VALID */
                   | 0x0010; /* REF_AA_VALID */

    ble_phdr_with_aa_t ph = {
        .rf_channel = ble_ch_to_rf_ch(hdr->channel_index),
        .signal_power = (int8_t) hdr->rssi,
        .noise_power = (int8_t) 0x80,
        .access_address_offenses = 0,
        .reference_access_address = hdr->access_addr,
        .flags = flags,
        .aa_le = hdr->access_addr,
    };

    struct timeval tv;
    gettimeofday(&tv, NULL);

    uint32_t crc_val = ble_crc24(0x555555, pdu, pdu_len);
    uint8_t  crc[3] = {
        (uint8_t)(crc_val),
        (uint8_t)(crc_val >> 8),
        (uint8_t)(crc_val >> 16),
    };

    while (1) {
        if ((ret = cf_send_data_multi(caph, NULL, 0,
                        NULL, NULL, tv, KDLT_BTLE_RADIO,
                        sizeof(ble_phdr_with_aa_t), (uint8_t *) &ph,
                        pdu_len, pdu_len, (uint8_t *) pdu,
                        3, crc)) < 0) {
            cf_handler_spindown(caph);
        } else if (ret == 0) {
            cf_handler_wait_ringbuffer(caph);
            continue;
        } else {
            break;
        }
    }
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_wch_btle_t *local = (local_wch_btle_t *) caph->userdata;

#define DRAIN_POLL_MS  5
#define IDLE_WAIT_MS   100

    while (1) {
        bool any_data = false;

        if (caph->spindown) {
            break;
        }

        /* Phase 1: drain each MCU until its buffer is empty */
        for (int i = 0; i < local->num_wch && !caph->spindown; i++) {
            if (!local->wch[i]->is_open || !local->bufs[i])
                continue;
            for (;;) {
                int n = wch_read_packets(local->wch[i], local->bufs[i], on_packet, caph,
                                         DRAIN_POLL_MS);
                if (n > 0) {
                    any_data = true;
                    continue;
                }

                break;
            }
        }

        /* Phase 2: when all MCUs are idle, do a longer blocking wait
         * on each MCU to reduce CPU usage until traffic resumes. */
        if (!any_data && !caph->spindown) {
            for (int i = 0; i < local->num_wch && !caph->spindown; i++) {
                if (!local->wch[i]->is_open || !local->bufs[i])
                    continue;
                wch_read_packets(local->wch[i], local->bufs[i], on_packet, caph, IDLE_WAIT_MS);
            }
        }
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_wch_btle_t localrad = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .wch[0] = NULL,
        .wch[1] = NULL,
        .wch[2] = NULL,
        .num_wch = 0,
        .bufs[0] = NULL,
        .bufs[1] = NULL,
        .bufs[2] = NULL,
        .channel[0] = adv_ch[0],
        .channel[1] = adv_ch[1],
        .channel[2] = adv_ch[2],
    };

    int r;

    kis_capture_handler_t *caph = cf_handler_init("wch-ble-pro");

    if (caph == NULL) {
        fprintf(stderr,
            "FATAL: Could not allocate basic handler data, your system "
            "is very low on RAM or something is wrong.\n");
        return -1;
    }

    r = libusb_init(&localrad.usb_ctx);
    if (r < 0) {
        fprintf(stderr, "FATAL:  Could not initialize libusb\n");
        return -1;
    }

    localrad.caph = caph;

    cf_handler_set_userdata(caph, &localrad);
    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback); /**/
    cf_handler_set_capture_cb(caph, capture_thread);

    r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture by launching the remote loop */
    cf_handler_remote_capture(caph);

    /* Jail our ns */
    cf_jail_filesystem(caph);

    /* Strip our privs */
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    libusb_exit(localrad.usb_ctx);

    return 0;
}
