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
 * Derived from bladeRF project code,
 * Copyright (C) 2020 Nuand LLC
 */

/*
 * bladeRF wiphy capture
 *
 * This uses the bladeRF2 wiphy modem for 802.11 capture; this requires a
 * bladerf2 a9 and the wiphy rbf either flashed or available.
 *
 * this requires a very current libbladerf2.
 */

#define _GNU_SOURCE

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

#include <net/if.h>
#include <arpa/inet.h>

#include <ifaddrs.h>

#include <stdbool.h>

#include <time.h>

#include <fcntl.h>
#include <sys/stat.h>

#include "../config.h"
#include "../capture_framework.h"
#include "../wifi_ht_channels.h"

#include <libbladeRF.h>

#define MAX_PACKET_LEN  8192

#define DLT_IEEE802_11	        105	/* IEEE 802.11 wireless */
#define DLT_IEEE802_11_RADIO	127	/* 802.11 plus radiotap radio header */

struct bladeRF_wiphy_header_tx {
   uint16_t rsvd;
   uint16_t flags;
   uint16_t modulation;
   uint16_t bandwidth;
   uint16_t len;
   uint16_t rsvd2;
   uint32_t cookie;
};

struct bladeRF_wiphy_header_rx {
   uint16_t type;
   uint8_t  bandwidth;
   uint8_t  modulation;
   union {
      struct {
         uint16_t len;
         uint16_t rsvd2;
      };
      uint32_t cookie;
   };
   uint32_t rsvd3;
};

typedef struct {
    char *interface;
    char *name;

    /* Number of sequential errors setting channel */
    unsigned int seq_channel_failure;

    struct bladerf *bladeRF_dev;
    unsigned int last_freq;

    unsigned int bladerf_index;

} local_wifi_t;

/* Linux Wi-Fi Channels:
 *
 * Channel formats:
 *
 * XXW5         Channel/frequency XX, custom 5MHz channel
 * XXW10        Channel/frequency XX, custom 10MHz channel
 * XX           Channel/frequency XX, non-HT standard 20MHz channel
 */

/* Local interpretation of a channel; this lets us parse the string definitions
 * into a faster non-parsed version, once. */
typedef struct {
    unsigned int center_freq1;
} local_channel_t;

unsigned int wifi_chan_to_freq(unsigned int in_chan) {
    /* 802.11 channels to frequency; if it looks like a frequency, return as
     * pure frequency; derived from iwconfig */

    if (in_chan > 250)
        return in_chan;

    if (in_chan == 14)
        return 2484;
    else if (in_chan < 14)
        return 2407 + in_chan * 5;
    else if (in_chan >= 182 && in_chan <= 196)
        return 4000 + in_chan * 5;
    else
        return 5000 + in_chan * 5;

    return in_chan;
}

unsigned int wifi_freq_to_chan(unsigned int in_freq) {
    if (in_freq < 250)
        return in_freq;

    /* revamped from iw */
    if (in_freq == 2484)
        return 14;

    if (in_freq < 2484)
        return (in_freq - 2407) / 5;

    return in_freq / 5 - 1000;
}

/* Convert a string into a local interpretation; allocate ret_localchan.
 */
void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_channel_t *ret_localchan = NULL;
    unsigned int parsechan;
    int r;
    char errstr[STATUS_MAX];

    /* If we need t set a special mode for W5 and W10 parse it here,
     * right now we don't */

    r = sscanf(chanstr, "%u", &parsechan);

    if (r <= 0) {
        snprintf(errstr, STATUS_MAX, "unable to parse any channel information from "
                "channel string '%s'", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_ERROR);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    memset(ret_localchan, 0, sizeof(local_channel_t));

    if (r == 1) {
        (ret_localchan)->center_freq1 = parsechan;
        return ret_localchan;
    }

    return ret_localchan;
}

/* Convert a local interpretation of a channel back info a string;
 * 'chanstr' should hold at least STATUS_MAX characters; we'll never use
 * that many but it lets us do some cheaty stuff and re-use errstrs */
void local_channel_to_str(local_channel_t *chan, char *chanstr) {
    snprintf(chanstr, STATUS_MAX, "%u", chan->center_freq1);
}

/* Keep the expansion options for now in case we need them in a future firmware,
 * but the bladerf-wiphy doesn't work like that currently */
int populate_chanlist(kis_capture_handler_t *caph, char *interface, char *msg,
        unsigned int default_ht20, unsigned int expand_ht20,
        char ***chanlist, size_t *chanlist_sz) {
    size_t chan_sz = 0;
    unsigned int ci, cp;
    char conv_chan[16];

    for (ci = 0; ci < MAX_WIFI_HT_CHANNEL; ci++) {
        if (wifi_ht_channels[ci].chan == 0)
            continue;
        chan_sz++;
    }

    *chanlist = (char **) malloc(sizeof(char *) * chan_sz);

    cp = 0;
    for (ci = 0; ci < MAX_WIFI_HT_CHANNEL; ci++) {
        if (wifi_ht_channels[ci].chan == 0)
            continue;

        snprintf(conv_chan, 16, "%u", wifi_ht_channels[ci].chan);
        (*chanlist)[cp] = strdup(conv_chan);
        cp++;
    }

    *chanlist_sz = chan_sz;

    return 1;
}

/* Channel control callback; actually set a channel.  Determines if our
 * custom channel needs a VHT frequency set. */
int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan,
        char *msg) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    int r;

    if (privchan == NULL) {
        return 0;
    }

    if (local_wifi == NULL) {
        return 0;
    }

    if (local_wifi->bladeRF_dev == NULL) {
        return 0;
    }

    r = bladerf_set_frequency(local_wifi->bladeRF_dev, BLADERF_CHANNEL_RX(0),
            wifi_chan_to_freq(channel->center_freq1) * 1000UL * 1000UL);

    if (r != 0) {
        snprintf(msg, STATUS_MAX, "%s %s failed setting channel %u, error %d",
                    local_wifi->name, local_wifi->interface, channel->center_freq1, r);
                cf_send_message(caph, msg, MSGFLAG_ERROR);
                local_wifi->seq_channel_failure++;
    }

    local_wifi->last_freq = wifi_chan_to_freq(channel->center_freq1);

    return 1;
}


int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    int ret;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    unsigned int idx;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strstr(interface, "brf-wiphy-") != interface) {
        free(interface);
        return 0;
    }

    if (sscanf(interface, "brf-wiphy-%u", &idx) != 1) {
        free(interface);
        return 0;
    }

    /* For now just assume if it's a brf-wifphy-# interface, we can handle it;
     * we don't want to get into firmware loading at the probing stage accidentally */

    ret = populate_chanlist(caph, interface, errstr, 0, 0,
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));

    (*ret_interface)->hardware = strdup("bladeRF Wiphy");

    if (ret < 0) {
        free(interface);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name
         * and the mac address of the device */
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-00%04X",
                adler32_csum((unsigned char *) "kismet_cap_brf_wiphy",
                    strlen("kismet_cap_blader_wiphy")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) interface, strlen(interface)));
        *uuid = strdup(errstr);
    }

    free(interface);

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    /* Try to open the bladerf for monitoring */

    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;

    char *placeholder = NULL;
    int placeholder_len;

    char errstr[STATUS_MAX];
    char errstr2[STATUS_MAX];

    *uuid = NULL;
    *dlt = 0;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    int ret;

    char *localchanstr = NULL;
    local_channel_t *localchan = NULL;

    const int num_buffers = 4096;
    const int num_dwords_buffer = 4096 * 16;
    const int num_transfers = 16;
    const int stream_timeout = 10000000;
    const bladerf_sample_rate sample_rate = 20 * 1000 * 1000;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    local_wifi->interface = strndup(placeholder, placeholder_len);

    if (sscanf(local_wifi->interface, "brf-wiphy-%u", &local_wifi->bladerf_index) != 1) {
        snprintf(msg, STATUS_MAX, "Invalid bladeRF interface, expected brf-wiphy-N");
        free(local_wifi->interface);
        return -1;
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "name", definition)) > 0) {
        local_wifi->name = strndup(placeholder, placeholder_len);
    } else {
        local_wifi->name = strdup(local_wifi->interface);
    }

    /* Build an interface index parameter for now; in the future we should also
     * support serial number based */
    snprintf(errstr2, 1024, "*:instance=%u", local_wifi->bladerf_index);

    ret = bladerf_open(&local_wifi->bladeRF_dev, errstr2);
    if (ret != 0) {
        snprintf(msg, STATUS_MAX, "%s unable to open bladeRF interface: %d",
                local_wifi->name, ret);
        return -1;
    }

    ret = bladerf_sync_config(local_wifi->bladeRF_dev, BLADERF_RX_X1,
            BLADERF_FORMAT_PACKET_META, num_buffers, num_dwords_buffer,
            num_transfers, stream_timeout);
    if (ret != 0) {
        snprintf(msg, STATUS_MAX, "%s unable to configure bladeRF interface for "
                "wlan mode (%d); make sure you have the wiphy capable libbladerf2 "
                "library and have loaded the wlanxA9 FPGA firmware",
                local_wifi->name, ret);
        return -1;
    }

    ret = bladerf_set_sample_rate(local_wifi->bladeRF_dev, BLADERF_CHANNEL_RX(0),
            sample_rate, NULL);
    if (ret != 0) {
        snprintf(msg, STATUS_MAX, "%s unable to configure bladeRF interface sample "
                "rate: %d", local_wifi->name, ret);
        return -1;
    }

    ret = bladerf_enable_module(local_wifi->bladeRF_dev, BLADERF_MODULE_RX, true);
    if (ret != 0) {
        snprintf(msg, STATUS_MAX, "%s unable to configure bladeRF interface RX module: %d",
                local_wifi->name, ret);
        return -1;
    }

    bladerf_set_bias_tee(local_wifi->bladeRF_dev, BLADERF_CHANNEL_RX(0), true);
    bladerf_set_bias_tee(local_wifi->bladeRF_dev, BLADERF_CHANNEL_RX(1), true);

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name
     * and the mac address of the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-00%04X",
                adler32_csum((unsigned char *) "kismet_cap_brf_wiphy",
                    strlen("kismet_cap_blader_wiphy")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) local_wifi->interface,
                    strlen(local_wifi->interface)));
        *uuid = strdup(errstr);
    }


    ret = populate_chanlist(caph, local_wifi->interface, errstr, 0, 0,
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));
    if (ret < 0) {
        snprintf(msg, STATUS_MAX, "%s could not get list of channels from capture "
                "interface '%s': %s", local_wifi->name, local_wifi->interface, errstr);
        return -1;
    }

    (*ret_interface)->hardware = strdup("bladeRF Wiphy");

    *dlt = DLT_IEEE802_11;

    (*ret_interface)->capif = strdup(local_wifi->interface);

    if ((placeholder_len =
                cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);

        localchan =
            (local_channel_t *) chantranslate_callback(caph, localchanstr);

        free(localchanstr);

        if (localchan == NULL) {
            snprintf(msg, STATUS_MAX,
                    "%s %s could not parse channel= option provided in source "
                    "definition", local_wifi->name, local_wifi->interface);
            return -1;
        }

        local_channel_to_str(localchan, errstr);
        (*ret_interface)->chanset = strdup(errstr);

        snprintf(errstr, STATUS_MAX, "%s setting initial channel to %s",
                local_wifi->name, (*ret_interface)->chanset);
        cf_send_message(caph, errstr, MSGFLAG_INFO);

        if (chancontrol_callback(caph, 0, localchan, msg) < 0) {
            free(localchan);
            localchan = NULL;
            return -1;
        }
    }

    if (localchan != NULL) {
        free(localchan);
        localchan = NULL;
    }

    snprintf(errstr2, STATUS_MAX, "%s finished configuring, ready to capture",
            local_wifi->name);
    cf_send_message(caph, errstr2, MSGFLAG_INFO);

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {
    struct bladerf_devinfo *devices = NULL;

    char errstr[STATUS_MAX];

    int num_devs = 0;
    int i;

    num_devs = bladerf_get_device_list(&devices);

    if (num_devs <= 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces =
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    for (i = 0; i < num_devs; i++) {
        /* Allocate an interface */
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        snprintf(errstr, 1024, "brf-wiphy-%u", devices[i].instance);

        (*interfaces)[i]->interface = strdup(errstr);
        (*interfaces)[i]->flags = NULL;
        (*interfaces)[i]->hardware = strdup("bladeRF Wiphy");
    }

    bladerf_free_device_list(devices);

    return num_devs;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;

    char errstr[STATUS_MAX];

    uint8_t data[4096 * 16];
    struct bladeRF_wiphy_header_rx *bwh_r = (struct bladeRF_wiphy_header_rx *) data;

    struct timeval ts;

    int ret;

    memset(data, 0, 4096 * 16);

    bladerf_trim_dac_write(local_wifi->bladeRF_dev, 0x0EA8);

    while (1) {
        struct bladerf_metadata meta;

        memset(&meta, 0, sizeof(meta));

        bladerf_sync_rx(local_wifi->bladeRF_dev, data, 1000, &meta, 0);

        if (bwh_r->len <= 16)
            continue;

        gettimeofday(&ts, NULL);

        ret = cf_send_data(caph, NULL, 0,
                        NULL, NULL, ts, DLT_IEEE802_11,
                        bwh_r->len - 4, bwh_r->len - 4,
                        (uint8_t *) data + 16);

        if (ret < 0) {
            cf_send_error(caph, 0, "unable to send DATA frame");
            cf_handler_spindown(caph);
            break;
        } else if (ret == 0) {
            /* Go into a wait for the write buffer to get flushed */
            cf_handler_wait_ringbuffer(caph);
            continue;
        }
    }

    snprintf(errstr, STATUS_MAX, "%s interface '%s' closed: %d",
            local_wifi->name, local_wifi->interface, ret);
    cf_send_error(caph, 0, errstr);

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_wifi_t local_wifi = {
        .interface = NULL,
        .name = NULL,
        .seq_channel_failure = 0,
        .bladeRF_dev = NULL,
        .last_freq = 0,
        .bladerf_index = 0
    };

    /* fprintf(stderr, "CAPTURE_LINUX_WIFI launched on pid %d\n", getpid()); */

    kis_capture_handler_t *caph = cf_handler_init("bladerf-wiphy");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_wifi);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Set the translation cb */
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);

    /* Set the control cb */
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    /* Set a channel hop spacing of 4 to get the most out of 2.4 overlap;
     * it does nothing and hurts nothing on 5ghz */
    cf_handler_set_hop_shuffle_spacing(caph, 4);

    int r = cf_handler_parse_opts(caph, argc, argv);
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

    /* We're done - try to reset the networkmanager awareness of the interface */

    cf_handler_free(caph);

    return 1;
}

