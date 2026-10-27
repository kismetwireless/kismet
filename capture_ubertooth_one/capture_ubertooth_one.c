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
#include <sys/stat.h>
#include <dirent.h>

#include <unistd.h>
#include <errno.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <ifaddrs.h>

#include <stdbool.h>

#include <time.h>

#include <stdlib.h>

#include "../config.h"

#include "../capture_framework.h"

#ifdef HAVE_UBERTOOTH_UBERTOOTH_H
#include <ubertooth/ubertooth.h>
#else
#include <ubertooth.h>
#endif

#include <libusb.h>

#include "ubertooth_bredr.h"

#define MAX_PACKET_LEN  8192

#ifndef HAVE_LIBUBERTOOTH_UBERTOOTH_COUNT
unsigned ubertooth_count(void) {
    struct libusb_device **usb_list = NULL;
    struct libusb_context *ctx = NULL;
    struct libusb_device_descriptor desc;
    int usb_devs, i, r;
    unsigned uberteeth = 0;

    r = libusb_init(NULL);
    if (r < 0) {
        fprintf(stderr, "libusb_init failed (got 1.0?)\n");
        return -1;
    }

    usb_devs = libusb_get_device_list(ctx, &usb_list);

    for(i = 0 ; i < usb_devs ; ++i) {
        r = libusb_get_device_descriptor(usb_list[i], &desc);
        if(r < 0)
            fprintf(stderr, "couldn't get usb descriptor for dev #%d!\n", i);
        if ((desc.idVendor == TC13_VENDORID && desc.idProduct == TC13_PRODUCTID)
                || (desc.idVendor == U0_VENDORID && desc.idProduct == U0_PRODUCTID)
                || (desc.idVendor == U1_VENDORID && desc.idProduct == U1_PRODUCTID))
        {
            uberteeth++;
        }
    }

    libusb_free_device_list(usb_list,1);
    return uberteeth;
}
#endif

/* State tracking, put in userdata */
typedef struct {
    ubertooth_t *ut;
    int ubertooth_number;

    char *interface;
    char *name;

    pthread_mutex_t u1_mutex;

    unsigned int last_channel;
    time_t last_reset;

    /* Classic piconet survey instead of BTLE */
    int classic;
    u1_bredr_t bredr;

    /* The decoder belongs to the capture thread; a retune asks it to drop its history */
    int bredr_reset_pending;
} local_ubertooth_t;

/* Basic rate symbols over the bulk endpoint, 16 USB packets per read */
#define U1_BREDR_XFER       (PKT_LEN * 16)
#define U1_BREDR_TIMEOUT_MS 100
#define U1_BREDR_MAX_AC_ERR 2

/* ubertooth-rx's default, 2441MHz */
#define U1_BREDR_DEFAULT_FREQ   2441

/* Start receiving in the configured mode on the current channel; call with the lock held */
static int u1_start_rx(local_ubertooth_t *local_ubertooth) {
    if (local_ubertooth->classic) {
        local_ubertooth->bredr_reset_pending = 1;
        return cmd_rx_syms(local_ubertooth->ut->devh);
    }

    return cmd_btle_sniffing(local_ubertooth->ut->devh, false);
}

unsigned int u1_chan_to_freq(unsigned int in_chan) {
    if (in_chan == 37)
        return 2402;
    else if (in_chan == 38)
        return 2426;
    else if (in_chan == 39)
        return 2480;

    if (in_chan <= 10)
        return 2404 + (in_chan * 2);

    if (in_chan <= 36)
        return 2428 + ((in_chan - 11) * 2);

    return 0;
}

unsigned int u1_freq_to_chan(unsigned int in_freq) {
    if (in_freq % 2)
        return 0;

    if (in_freq == 2402)
        return 37;

    if (in_freq == 2426)
        return 38;

    if (in_freq == 2480)
        return 39;

    if (in_freq >= 2404 && in_freq < 2426) 
        return (in_freq - 2404) / 2;

    if (in_freq >= 2428 && in_freq < 2480)
        return ((in_freq - 2428) / 2) + 11;

    return 0;
}

/*
 * The U1 firmware likes to get 'funny'; perform a reset and reconfigure the
 * parameters
 */
int u1_reset_and_conf(kis_capture_handler_t *caph, char *errstr) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;

    int ret;
    int count = 0;

    pthread_mutex_lock(&local_ubertooth->u1_mutex);
    ret = cmd_reset(local_ubertooth->ut->devh);

    sleep(1);

    while (ubertooth_connect(local_ubertooth->ut, local_ubertooth->ubertooth_number) < 1) {
        count++;

        if (count > 5) {
            snprintf(errstr, STATUS_MAX, "%s could not connect to %s",
                    local_ubertooth->name, local_ubertooth->interface);
            pthread_mutex_unlock(&local_ubertooth->u1_mutex);
            return -1;
        }

        sleep(1);
    }

    ret = ubertooth_check_api(local_ubertooth->ut);
    if (ret < 0) {
        snprintf(errstr, STATUS_MAX, "%s API mismatch connecting to %s, make sure your "
                "libubertooth, libbtbb, and ubertooth firmware are all up to date.",
                local_ubertooth->name, local_ubertooth->interface);
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);
        return -1;
    }

    if (ret < 0) {
        snprintf(errstr, STATUS_MAX, "%s could not reset ubertooth-one device %s",
                local_ubertooth->name, local_ubertooth->interface);
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);
        return -1;
    }

    ret = cmd_set_modulation(local_ubertooth->ut->devh,
            local_ubertooth->classic ? MOD_BT_BASIC_RATE : MOD_BT_LOW_ENERGY);

    if (ret < 0) {
        snprintf(errstr, STATUS_MAX, "%s could not set ubertooth-one modulation on device %s",
                local_ubertooth->name, local_ubertooth->interface);
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);
        return -1;
    }

    ret = cmd_set_channel(local_ubertooth->ut->devh, local_ubertooth->last_channel);
    if (ret < 0) {
        snprintf(errstr, STATUS_MAX, "%s could not set ubertooth-one channel device %s",
                local_ubertooth->name, local_ubertooth->interface);
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);
        return -1;
    }

    ret = u1_start_rx(local_ubertooth);
    if (ret < 0) {
        snprintf(errstr, STATUS_MAX, "%s could not start ubertooth-one receiving on device %s",
                local_ubertooth->name, local_ubertooth->interface);
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);
        return -1;
    }

    local_ubertooth->last_reset = time(0);

    pthread_mutex_unlock(&local_ubertooth->u1_mutex);
    return 1;
}


/* Convert a string into a local interpretation (which is just frequency)
 */
void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;

    unsigned int *ret_localchan;
    unsigned int parsechan;
    int r;
    char errstr[STATUS_MAX];

    if ((r = sscanf(chanstr, "%u", &parsechan)) != 1) {
        snprintf(errstr, STATUS_MAX, "%s expected a numeric channel or frequency in MHz",
                local_ubertooth->name);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    /* Classic channels are every MHz from 2402 */
    if (local_ubertooth->classic) {
        if ((parsechan >= NUM_BREDR_CHANNELS && parsechan < 2402) || parsechan > 2480) {
            snprintf(errstr, STATUS_MAX, "%s expected a numeric classic channel (0-78) or "
                    "frequency in MHz (2402-2480)", local_ubertooth->name);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            return NULL;
        }

        ret_localchan = (unsigned int *) malloc(sizeof(unsigned int));
        if (ret_localchan == NULL)
            return NULL;

        *ret_localchan = parsechan < NUM_BREDR_CHANNELS ? 2402 + parsechan : parsechan;

        return ret_localchan;
    }

    if ((parsechan > 39 && parsechan < 2402) || parsechan > 2480 || 
            (parsechan > 39 && parsechan % 2)) {
        snprintf(errstr, STATUS_MAX, "%s expected a numeric channel (0-39) or frequency in "
                "MHz (2402-2480)", local_ubertooth->name);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (unsigned int *) malloc(sizeof(unsigned int));
    *ret_localchan = 0;

    if (parsechan <= 39)
        *ret_localchan = u1_chan_to_freq(parsechan);
    else
        *ret_localchan = parsechan;

    return ret_localchan;
}

int populate_chanlist(kis_capture_handler_t *caph, char *interface, char *msg, 
        char ***chanlist, size_t *chanlist_sz) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;

    /* Piconets hop across every channel, so one is enough to find them */
    if (local_ubertooth->classic) {
        *chanlist = (char **) malloc(sizeof(char *) * 1);
        (*chanlist)[0] = strdup("2441");
        *chanlist_sz = 1;
        return 1;
    }

    /* U1 firmware seems to crash even w/ 1s channel hopping, so only report channel 37
     * as supported for now */

    *chanlist = (char **) malloc(sizeof(char *) * 1);
    (*chanlist)[0] = strdup("37");
    *chanlist_sz = 1;

#if 0
    /* For now we allow 37, 38, and 39 */
    *chanlist = (char **) malloc(sizeof(char *) * 3);

    (*chanlist)[0] = strdup("37");
    (*chanlist)[1] = strdup("38");
    (*chanlist)[2] = strdup("39");

    *chanlist_sz = 3;
#endif

    return 1;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;
    int ret;
    int count = 0;

    if (privchan == NULL) {
        return 0;
    }

    unsigned int *channel = (unsigned int *) privchan;

    // fprintf(stderr, "channel %u\n", *channel);

    local_ubertooth->last_channel = *channel;

    while (count < 5) {
        pthread_mutex_lock(&local_ubertooth->u1_mutex);

        ret = cmd_stop(local_ubertooth->ut->devh);

        if (ret < 0) {
            pthread_mutex_unlock(&local_ubertooth->u1_mutex);
            count++;
            usleep(500);
            continue;
        }

        ret = cmd_set_channel(local_ubertooth->ut->devh, *channel);

        if (ret < 0) {
            pthread_mutex_unlock(&local_ubertooth->u1_mutex);
            count++;
            usleep(500);
            continue;
        }

        ret = u1_start_rx(local_ubertooth);

        if (ret < 0) {
            pthread_mutex_unlock(&local_ubertooth->u1_mutex);
            count++;
            usleep(500);
            continue;
        }

        pthread_mutex_unlock(&local_ubertooth->u1_mutex);
        break;
    }

    if (ret < 0) {
        ret = u1_reset_and_conf(caph, msg);

        if (ret < 0) {
            return ret;
        }

        pthread_mutex_lock(&local_ubertooth->u1_mutex);
        ret = cmd_set_channel(local_ubertooth->ut->devh, *channel);
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);
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

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    int u1_num = 0;
    int parse_num = 0;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    u1_num = ubertooth_count();

    /* is it an ubertooth? */
    if (strcmp("ubertooth", interface) == 0) {
        snprintf(msg, STATUS_MAX, "Didn't find an Ubertooth interface, skipping");
        parse_num = -1;
        free(interface);
        return 0;
    } else if ((ret = sscanf(interface, "ubertooth%u", &parse_num)) != 1) {
        if ((ret = sscanf(interface, "ubertooth-%u", &parse_num)) != 1) {
            snprintf(msg, STATUS_MAX, "Expected ubertoothX or ubertooth-X, skipping");
            free(interface);
            return 0;
        }
    }

    /* is it out of range? */
    if (parse_num > u1_num) {
        free(interface);
        return 0;
    }

    populate_chanlist(caph, interface, errstr, 
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));

    (*ret_interface)->hardware = strdup("ubertooth");

    free(interface);

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
         * and the mac address of the device */
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_ubertooth_one", 
                    strlen("kismet_cap_ubertooth_one")) & 0xFFFFFFFF,
                parse_num);
        *uuid = strdup(errstr);
    }

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;

    char *placeholder = NULL;
    int placeholder_len;
    
    char errstr[STATUS_MAX];

    *uuid = NULL;
    *dlt = 0;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    int ret;

    char *localchanstr = NULL;
    unsigned int *localchan = NULL;

    int ubertooth_number;
    int u1_num;

    /* Start processing the open */

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return -1;
    }

    local_ubertooth->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = 
                cf_find_flag(&placeholder, "name", definition)) > 0) {
        local_ubertooth->name = strndup(placeholder, placeholder_len);
    } else {
        local_ubertooth->name = strdup(local_ubertooth->interface);
    }

    u1_num = ubertooth_count();

    /* is it an ubertooth? */
    if (strcmp("ubertooth", local_ubertooth->interface) == 0) {
        ubertooth_number = -1;
    } else if ((ret = sscanf(local_ubertooth->interface, "ubertooth%u", &ubertooth_number)) != 1) {
        if ((ret = sscanf(local_ubertooth->interface, "ubertooth-%u", &ubertooth_number)) != 1) {
            snprintf(msg, STATUS_MAX, "%s could not parse ubertooth device from interface",
                    local_ubertooth->name);
            return -1;
        }
    }

    /* is it out of range? */
    if (ubertooth_number > u1_num) {
        snprintf(msg, STATUS_MAX, "%s could not find ubertooth %d (%d present)",
                local_ubertooth->name, ubertooth_number, u1_num);
        return -1;
    }

    local_ubertooth->ubertooth_number = ubertooth_number;

    if ((placeholder_len = cf_find_flag(&placeholder, "mode", definition)) > 0) {
        if (strncasecmp(placeholder, "classic", placeholder_len) == 0 && placeholder_len == 7) {
            local_ubertooth->classic = 1;
        } else if (strncasecmp(placeholder, "btle", placeholder_len) == 0 && placeholder_len == 4) {
            local_ubertooth->classic = 0;
        } else {
            snprintf(msg, STATUS_MAX, "%s unknown mode= option, expected 'btle' or 'classic'",
                    local_ubertooth->name);
            return -1;
        }
    }

    if (local_ubertooth->classic) {
        if (u1_bredr_init(&local_ubertooth->bredr, U1_BREDR_MAX_AC_ERR) < 0) {
            snprintf(msg, STATUS_MAX, "%s could not initialize libbtbb", local_ubertooth->name);
            return -1;
        }

        local_ubertooth->last_channel = U1_BREDR_DEFAULT_FREQ;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the mac address of the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_ubertooth_one", 
                    strlen("kismet_cap_ubertooth_one")) & 0xFFFFFFFF,
                ubertooth_number);
        *uuid = strdup(errstr);
    }

    local_ubertooth->ut = ubertooth_init();

    ret = ubertooth_connect(local_ubertooth->ut, ubertooth_number);
    if (ret < 0) {
        snprintf(msg, STATUS_MAX, "%s could not connect to %s",
                local_ubertooth->name, local_ubertooth->interface);
        return -1;
    }

    ret = ubertooth_check_api(local_ubertooth->ut);
    if (ret < 0) {
        snprintf(msg, STATUS_MAX, "%s API mismatch connecting to %s, make sure your "
                "libubertooth, libbtbb, and ubertooth firmware are all up to date.",
                local_ubertooth->name, local_ubertooth->interface);
        return -1;
    }

    (*ret_interface)->hardware = strdup("ubertooth");

    ret = populate_chanlist(caph, local_ubertooth->interface, errstr, 
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));

    /* BTLE is converted on the host; classic is sent as BR/EDR baseband */
    *dlt = local_ubertooth->classic ? U1_BREDR_DLT : 0;

    (*ret_interface)->capif = strdup(local_ubertooth->interface);

    /* Reset and configure */
    if (u1_reset_and_conf(caph, errstr) < 0) {
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);

        localchan = 
            (unsigned int *) chantranslate_callback(caph, localchanstr);

        free(localchanstr);

        if (localchan == NULL) {
            printf("invalid channel %s\n", placeholder);
            snprintf(msg, STATUS_MAX, 
                    "%s %s could not parse channel= option provided in source "
                    "definition", local_ubertooth->name, local_ubertooth->interface);
            return -1;
        }
    } else {
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = local_ubertooth->classic ? U1_BREDR_DEFAULT_FREQ : 2402;
    }

    snprintf(errstr, STATUS_MAX, "%d", *localchan);
    (*ret_interface)->chanset = strdup(errstr);

    snprintf(errstr, STATUS_MAX, "%s setting channel to %s", 
            local_ubertooth->name, (*ret_interface)->chanset);
    cf_send_message(caph, errstr, MSGFLAG_INFO);

    if (chancontrol_callback(caph, 0, localchan, msg) < 0) {
        free(localchan);
        return -1;
    }

    if (localchan != NULL)
        free(localchan);

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {
    char errstr[STATUS_MAX];

    size_t num_devs = 0;

    unsigned int i;

    num_devs = ubertooth_count();

    if (num_devs == 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces = 
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    for (i = 0; i < num_devs; i++) {
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        snprintf(errstr, STATUS_MAX, "ubertooth-%u", i);

        (*interfaces)[i]->interface = strdup(errstr);
        (*interfaces)[i]->hardware = strdup("ubertooth");
    }

    return num_devs;
}

static void bredr_emit(void *ctx, const usb_pkt_rx *rx, const uint8_t *frame, size_t frame_sz) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) ctx;
    struct timeval ts;
    int r;

    gettimeofday(&ts, NULL);

    while (1) {
        if ((r = cf_send_data(caph, NULL, 0, NULL, NULL, ts, U1_BREDR_DLT,
                        frame_sz, frame_sz, (uint8_t *) frame)) < 0) {
            cf_send_error(caph, 0, "unable to send DATA frame");
            cf_handler_spindown(caph);
            break;
        } else if (r == 0) {
            cf_handler_wait_ringbuffer(caph);
            continue;
        } else {
            break;
        }
    }
}

static void capture_thread_classic(kis_capture_handler_t *caph) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;
    uint8_t buf[U1_BREDR_XFER];
    usb_pkt_rx rx;
    int got, r, i, reset;

    while (!caph->spindown) {
        got = 0;

        pthread_mutex_lock(&local_ubertooth->u1_mutex);
        r = libusb_bulk_transfer(local_ubertooth->ut->devh, DATA_IN, buf, sizeof(buf),
                &got, U1_BREDR_TIMEOUT_MS);
        reset = local_ubertooth->bredr_reset_pending;
        local_ubertooth->bredr_reset_pending = 0;
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);

        if (reset)
            u1_bredr_reset(&local_ubertooth->bredr);

        if (r < 0 && r != LIBUSB_ERROR_TIMEOUT) {
            cf_send_error(caph, 0, "error receiving from Ubertooth One");
            break;
        }

        if (got < 0 || got > (int) sizeof(buf))
            continue;

        for (i = 0; i + PKT_LEN <= got; i += PKT_LEN) {
            memcpy(&rx, buf + i, sizeof(usb_pkt_rx));
            u1_bredr_feed(&local_ubertooth->bredr, &rx, bredr_emit, caph);
        }
    }

    cf_handler_spindown(caph);
}

void capture_thread(kis_capture_handler_t *caph) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;
    usb_pkt_rx rx;
    int r;
    struct timeval ts;
    char errstr[STATUS_MAX];
    int reset_due;

    if (local_ubertooth->classic) {
        capture_thread_classic(caph);
        return;
    }

    while (!caph->spindown) {
        pthread_mutex_lock(&local_ubertooth->u1_mutex);
        reset_due = time(0) - local_ubertooth->last_reset > 30;
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);

        if (reset_due && u1_reset_and_conf(caph, errstr) < 0) {
            cf_send_error(caph, 0, "error receiving from Ubertooth One");
            break;
        }

        pthread_mutex_lock(&local_ubertooth->u1_mutex);
        r = cmd_poll(local_ubertooth->ut->devh, &rx);
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);

        if (r < 0) {
            cf_send_error(caph, 0, "error receiving from Ubertooth One");
            break;
        }

        if (r == sizeof(usb_pkt_rx)) {
            gettimeofday(&ts, NULL);

            while (1) {
                if ((r = cf_send_data(caph, NULL, 0,
                                NULL, NULL, ts, 0,
                                sizeof(usb_pkt_rx),
                                sizeof(usb_pkt_rx), (unsigned char *) &rx)) < 0) {
                    cf_send_error(caph, 0, "unable to send DATA frame");
                    cf_handler_spindown(caph);
                    break;
                } else if (r == 0) {
                    /* Go into a wait for the write buffer to get flushed */
                    cf_handler_wait_ringbuffer(caph);
                    continue;
                } else {
                    break;
                }
            }
        }

        usleep(500);
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_ubertooth_t local_ubertooth = {
        .interface = NULL,
        .name = NULL,
        .ut = NULL,
        .u1_mutex = PTHREAD_MUTEX_INITIALIZER,
        .last_channel = 2402,
        .last_reset = 0,
        .classic = 0,
        .bredr_reset_pending = 0,
    };

    /* Clobber the USB debug settings because libubertooth sets it to be verbose */
    setenv("LIBUSB_DEBUG", "0", 1);

    kis_capture_handler_t *caph = cf_handler_init("ubertooth");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    /* Disable channel hopping */
    caph->max_channel_hop_rate = -1;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_ubertooth);

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

    cf_handler_free(caph);

    if (local_ubertooth.classic)
        u1_bredr_free(&local_ubertooth.bredr);

    return 1;
}

