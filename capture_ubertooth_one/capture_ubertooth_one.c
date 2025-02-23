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
} local_ubertooth_t;

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

    ret = cmd_set_modulation(local_ubertooth->ut->devh, MOD_BT_LOW_ENERGY);

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

    ret = cmd_btle_sniffing(local_ubertooth->ut->devh, false);
    if (ret < 0) {
        snprintf(errstr, STATUS_MAX, "%s could not set ubertooth-one btle sniffing on device %s",
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

        ret = cmd_btle_sniffing(local_ubertooth->ut->devh, false);

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
        parse_num = -1;
        free(interface);
        return 0;
    } else if ((ret = sscanf(interface, "ubertooth%u", &parse_num)) != 1) {
        if ((ret = sscanf(interface, "ubertooth-%u", &parse_num)) != 1) {
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

    /* we decode the DLT on the host */
    *dlt = 0;

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
        *localchan = 2402;
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

void capture_thread(kis_capture_handler_t *caph) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;
    usb_pkt_rx rx;
    int r;
    struct timeval ts;
    char errstr[STATUS_MAX];

    while (!caph->spindown) {
        pthread_mutex_lock(&local_ubertooth->u1_mutex);
        if (time(0) - local_ubertooth->last_reset > 30) {
            pthread_mutex_unlock(&local_ubertooth->u1_mutex);
            
            if (u1_reset_and_conf(caph, errstr) < 0) {
                cf_send_error(caph, 0, "error receiving from Ubertooth One");
                break;
            }
        }
        pthread_mutex_unlock(&local_ubertooth->u1_mutex);

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

    return 1;
}

