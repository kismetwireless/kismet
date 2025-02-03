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
 * Hak5 Wi-Fi Coconut capture
 *
 * The Hak5 Wi-Fi Coconut is a USB device with 14 rt2800-based radios on
 * a series of hubs, designed to capture from all 14 channels simultaneous.
 *
 * In Kismet, this is presented as a single device reporting packets on 
 * all channels, using a basic radiotap header.
 *
 * The Wi-Fi Coconut enumeration code is derived from the Hak5 Wi-Fi Coconut
 * userspace tool.
 */

#define _GNU_SOURCE

#include <getopt.h>
#include <pthread.h>

#include <sched.h>

#include <string.h>

#include <unistd.h>
#include <errno.h>

#include <stdbool.h>

#include <time.h>

#include "../config.h"

#include "../capture_framework.h"

#ifdef SYS_LINUX
#define LIBWIFIUSERSPACE_EXCLUDE_TYPES
#endif
#include "userspace/userspace.h"
#include "wifi_coconut/wifi_coconut.h"
#include "libwifiuserspace/kernel/ieee80211_radiotap.h"

#define MAX_PACKET_LEN  8192

/* We always synthesize a radiotap header with signal data */
#define KDLT_IEEE802_11_RADIO	127

/* State tracking, put in userdata */
typedef struct {
    char *interface;
    char *name;

    bool verbose_diagnostics;
    int coconut_num;

    struct wifi_coconut *coconut;

    struct wifi_coconut_context *coconut_context;

    /* How many times have we looked for the coconut; allows us to do a timed look during
     * open and not spin forever */
    int search_iter;

    /* Coconut numbers in a list, and how many we found */
    unsigned int *coconut_list_numbers;
    unsigned int num_list_numbers;

    bool error;

    kis_capture_handler_t *caph;

} local_wifi_t;


int populate_chanlist(kis_capture_handler_t *caph, char *interface, char *msg, 
        char ***chanlist, size_t *chanlist_sz) {
    char conv_chan[16];
    unsigned int c;

    *chanlist_sz = 14;

    *chanlist = (char **) malloc(sizeof(char *) * 14);

    for (c = 0; c < 14; c++) {
        snprintf(conv_chan, 16, "%u", c + 1);
        (*chanlist)[c] = strdup(conv_chan);
    }

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

    unsigned int coconut_num = 0;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strstr(interface, "coconut") != interface) {
        free(interface);
        return 0;
    }

    /* look for coconut-X */
    ret = sscanf(interface, "coconut-%u", &coconut_num);
  
    /* Malformed somehow */
    if (ret != -1 && ret != 1) {
        return 0;
    }

    ret = populate_chanlist(caph, interface, errstr, 
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));

    (*ret_interface)->hardware = strdup("Hak5 Wi-Fi Coconut");

    free(interface);

    if (ret < 0)
        return 0;

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strdup(placeholder);
    } else {
        /* Make a fake uuid until we start actually opening them; this just lets us 
         * see if we can even try to probe this device */
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_hak5_coconut", 
                    strlen("kismet_cap_linux_wifi")) & 0xFFFFFFFF,
                coconut_num);
        *uuid = strdup(errstr);
    }

    return 1;
}

/* Callback for the coconut interface library */
int coconut_open_callback(struct wifi_coconut_context *coconut_context,
        void *cbaux, int state, int dev, struct wifi_coconut *coconuts) {
    local_wifi_t *local_wifi = (local_wifi_t *) cbaux;

    if (state == WIFI_COCONUT_SEARCH_STATE_NO_RADIOS || 
            state == WIFI_COCONUT_SEARCH_STATE_NO_COCONUT ||
            state == WIFI_COCONUT_SEARCH_STATE_MISMATCH ||
            state == WIFI_COCONUT_SEARCH_STATE_ERROR) {

        /* Allow up to 5 failures */
        if (local_wifi->search_iter++ < 5)
            return 0;

        /* Error out on open */
        return -1;
    }

    if (state == WIFI_COCONUT_SEARCH_STATE_DONE) {
        local_wifi->coconut = coconut_context->coconut;

        if (local_wifi->coconut_context->disable_leds) {
            for (unsigned int i = 0; i < 14; i++) {
                if (local_wifi->coconut->active_devices[i] == NULL)
                    continue;

                userspace_wifi_device_set_led(local_wifi->coconut_context->context, 
                        local_wifi->coconut->active_devices[i], false);
            }
            
        }
    }

    return 0;
}

int coconut_rx_packet(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        struct userspace_wifi_rx_signal *signal,
        unsigned char *data, unsigned int len) {

    local_wifi_t *local_wifi = (local_wifi_t *) context->local_data;

    int ret;

    struct timeval tv;

    typedef struct { 
        uint16_t version;
        uint16_t length;
        uint32_t bitmap;
        uint8_t flags;
        uint8_t pad0;
        uint16_t channel_freq;
        uint16_t channel_flags;
        uint8_t antsignal;
    } _rtap_hdr;

    typedef struct {
        _rtap_hdr hdr;
        uint8_t data[MAX_PACKET_LEN];
    } _rtap_packet;

    _rtap_packet rtap_packet = {
        .hdr = {
            .version = 0,
            .length = htole16(sizeof(_rtap_hdr)),
            .bitmap = htole32((1 << IEEE80211_RADIOTAP_FLAGS) | 
                    (1 << IEEE80211_RADIOTAP_CHANNEL) |
                    (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL)),
            .flags = 0,
            .channel_freq = htole16(ieee80211_channel_to_frequency(signal->channel, signal->band)),
            .channel_flags = 0,
            .antsignal = (uint8_t) signal->signal,
        },
    };

    if (len > MAX_PACKET_LEN)
        return 1;

    if (!signal->crc_valid)
        return 1;

    if (signal->short_gi)
        rtap_packet.hdr.flags |= IEEE80211_RADIOTAP_F_SHORTGI;

    if (signal->band == NL80211_BAND_2GHZ)
        rtap_packet.hdr.channel_flags |= IEEE80211_CHAN_2GHZ;
    else if (signal->band == NL80211_BAND_5GHZ)
        rtap_packet.hdr.channel_flags |= IEEE80211_CHAN_5GHZ;

    memcpy(rtap_packet.data, data, len);

    gettimeofday(&tv, NULL);

    while (1) {
        if ((ret = cf_send_data(local_wifi->caph, NULL, 0,
                        NULL, NULL, tv, KDLT_IEEE802_11_RADIO,
                        sizeof(_rtap_hdr) + len, sizeof(_rtap_hdr) + len, (uint8_t *) &rtap_packet)) < 0) {
            cf_send_error(local_wifi->caph, 0, "unable to send DATA frame");
            cf_handler_spindown(local_wifi->caph);
        } else if (ret == 0) {
            /* Go into a wait for the write buffer to get flushed */
            cf_handler_wait_ringbuffer(local_wifi->caph);
            continue;
        } else {
            break;
        }
    }

    return 1;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;

    start_wifi_coconut_capture(local_wifi->coconut_context);

    while (!local_wifi->error) {
        sleep(1);
    }

    cf_handler_spindown(caph);
}

void coconut_handle_error(const struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        const char *errstr, int errnum) {
    local_wifi_t *local_wifi = (local_wifi_t *) context->local_data;
    char msg[STATUS_MAX];

    snprintf(msg, STATUS_MAX, "%s encountered an error: %s", local_wifi->name, errstr);

    cf_send_error(local_wifi->caph, 0, msg);

    local_wifi->error = true;
}


int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    /*
     * Try to open a coconut and start monitoring it; we'll post a few status updates to
     * Kismet as we go; requires the coconut be present and openable by this user.
     * Synthesizes a UUID from the first device serial number in the coconut.
     */

    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;

    char *placeholder = NULL;
    int placeholder_len;
    
    char errstr[STATUS_MAX];

    *uuid = NULL;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    int ret;

    if (getuid() && geteuid() != 0) {
        snprintf(msg, STATUS_MAX, "Root required for opening raw USB devices, install as suid-root or run Kismet as root");
        return -1;
    }

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return -1;
    }

    local_wifi->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = 
                cf_find_flag(&placeholder, "name", definition)) > 0) {
        local_wifi->name = strndup(placeholder, placeholder_len);
    } else {
        local_wifi->name = strdup(local_wifi->interface);
    }


    /* Do we use verbose diagnostics? */
    if ((placeholder_len = 
                cf_find_flag(&placeholder, "verbose", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->verbose_diagnostics = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->verbose_diagnostics = 1;
        }
    }

    local_wifi->coconut_context = init_coconut_context();

    /* Allow disabling LEDs */
    if ((placeholder_len = 
                cf_find_flag(&placeholder, "disable_leds", definition)) > 0) {
        if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->coconut_context->disable_leds = 1;
            local_wifi->coconut_context->disable_blink = 1;
        }
    }

    userspace_wifi_init(&local_wifi->coconut_context->context);
    local_wifi->coconut_context->context->local_data = local_wifi;

    /* look for coconut-X */
    ret = sscanf(local_wifi->interface, "coconut-%d", &local_wifi->coconut_num);
  
    /* Malformed somehow */
    if (ret != -1 && ret != 1) {
        snprintf(msg, STATUS_MAX, "Malformed source; expected 'coconut' or 'coconut-N' for a "
                "specific coconut.");
        return -1;
    }

    local_wifi->coconut_context->coconut_number = local_wifi->coconut_num;

    /* Loop for a few times trying to open the desired device; brokered by the callback
     * return value */
    ret = coconut_search_and_open(local_wifi->coconut_context, true,
            local_wifi->coconut_context->coconut_number, 
            &coconut_open_callback, (void *) local_wifi);

    if (ret != WIFI_COCONUT_SEARCH_STATE_DONE) {
        snprintf(msg, STATUS_MAX, "%s could not open wifi coconut %s",
                local_wifi->name, local_wifi->interface);
        return -1;
    }

    /* Once we're able to iterate and find our device, synthesize a uuid unless the
     * user requested one */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strdup(placeholder);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_hak5_coconut", 
                    strlen("kismet_cap_linux_wifi")) & 0xFFFFFFFF,
                adler32_csum(local_wifi->coconut->first_usb_serial, 
                    strlen((const char *) local_wifi->coconut->first_usb_serial)));
        *uuid = strdup(errstr);
    }

    ret = populate_chanlist(caph, local_wifi->interface, errstr, 
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));
    if (ret < 0) {
        snprintf(msg, STATUS_MAX, "%s could not get list of channels for capture "
                "interface '%s': %s", local_wifi->name, local_wifi->interface, errstr);
        return -1;
    }

    (*ret_interface)->hardware = strdup("Hak5 Wi-Fi Coconut");

    *dlt = KDLT_IEEE802_11_RADIO;

    (*ret_interface)->capif = strdup(local_wifi->interface);

    userspace_wifi_set_packet_cb(local_wifi->coconut_context->context, &coconut_rx_packet);

    return 1;
}

/* Callback for the coconut interface library */
int coconut_list_callback(struct wifi_coconut_context *coconut_context,
        void *cbaux, int state, int dev, struct wifi_coconut *coconuts) {
    local_wifi_t *local_wifi = (local_wifi_t *) cbaux;
    struct wifi_coconut *coconut_iter = NULL;
    unsigned int i;

    /* Process the list of coconuts then fail before opening */
    if (state == WIFI_COCONUT_SEARCH_STATE_LIST) {
        local_wifi->num_list_numbers = 0;
        coconut_iter = coconuts;

        while (coconut_iter != NULL) {
            local_wifi->num_list_numbers++;
            coconut_iter = coconut_iter->next;
        }

        local_wifi->coconut_list_numbers = 
            (unsigned int *) malloc(sizeof(unsigned int) * local_wifi->num_list_numbers);

        coconut_iter = coconuts;
        i = 0;
        while (coconut_iter != NULL && i < local_wifi->num_list_numbers) {
            local_wifi->coconut_list_numbers[i] = coconut_iter->coconut_number;
            i++;
            coconut_iter = coconut_iter->next;
        }

        return -1;
    }

    return 0;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {
    char errstr[STATUS_MAX];

    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;

    local_wifi->coconut_context = init_coconut_context();
    userspace_wifi_init(&local_wifi->coconut_context->context);

    unsigned int i = 0;

    /* Do an open loop using the list callback and no wait */
    coconut_search_and_open(local_wifi->coconut_context, false,
            local_wifi->coconut_context->coconut_number, 
            &coconut_list_callback, (void *) local_wifi);

    if (local_wifi->num_list_numbers == 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces = 
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * 
                local_wifi->num_list_numbers);

    i = 0;

    for (i = 0; i < local_wifi->num_list_numbers; i++) {
        /* Allocate an interface */
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        snprintf(errstr, STATUS_MAX, "coconut-%u", local_wifi->coconut_list_numbers[i]);
        (*interfaces)[i]->interface = strdup(errstr);
        (*interfaces)[i]->hardware = strdup("Hak5 Wi-Fi Coconut");
    }

    free(local_wifi->coconut_list_numbers);

    return local_wifi->num_list_numbers;
}

int main(int argc, char *argv[]) {
    local_wifi_t local_wifi = {
        .interface = NULL,
        .name = NULL,
        .verbose_diagnostics = 0,
        .coconut_num = -1,
        .coconut = NULL,
        .coconut_context = NULL,
        .search_iter = 0,
        .coconut_list_numbers = NULL,
        .num_list_numbers = 0,
        .error = false,
        .caph = NULL,
    };

    kis_capture_handler_t *caph = cf_handler_init("hak5wificoconut");

    local_wifi.caph = caph;

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

    cf_handler_shutdown(caph);

    cf_handler_free(caph);

    return 1;
}

