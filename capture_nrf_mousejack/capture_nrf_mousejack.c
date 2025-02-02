/*
  Derived from the Bastille Mousejack python code.
  While Kismet is generally licensed under the GPL2 license, this binary is
  derived from GPL3 code from Bastille, and as such, is under that license.
   
  Copyright (C) 2016 Bastille Networks
  Copyright (C) 2018 Mike Kershaw / dragorn@kismetwireless.net


  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define __GNU_SOURCE

#include <libusb-1.0/libusb.h>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "../config.h"

#include "mousejack.h"

#include "../capture_framework.h"

/* USB command timeout */
#define NRF_USB_TIMEOUT     2500

/* Unique instance data passed around by capframework */
typedef struct {
    libusb_context *libusb_ctx;
    libusb_device_handle *nrf_handle;

    unsigned int devno, busno;

    pthread_mutex_t usb_mutex;

    /* we don't want to do a channel query every data response, we just want to 
     * remember the last channel used */
    unsigned int channel;

    kis_capture_handler_t *caph;
} local_nrf_t;

/* Most basic of channel definitions */
typedef struct {
    unsigned int channel;
} local_channel_t;

int nrf_send_command_nb(kis_capture_handler_t *caph, uint8_t request, uint8_t *data, size_t len) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    uint8_t *cmdbuf = NULL;
    int actual_length;
    int r;

    cmdbuf = (uint8_t *) malloc(len + 1);
    cmdbuf[0] = request;

    if (len > 0) 
        memcpy(cmdbuf + 1, data, len);

    r = libusb_bulk_transfer(localnrf->nrf_handle, MOUSEJACK_USB_ENDPOINT_OUT,
            cmdbuf, len + 1, &actual_length, NRF_USB_TIMEOUT);

    free(cmdbuf);

    return r;
}

int nrf_send_command(kis_capture_handler_t *caph, uint8_t request, uint8_t *data, size_t len) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    int r;

    pthread_mutex_lock(&(localnrf->usb_mutex));

    r = nrf_send_command_nb(caph, request, data, len);

    pthread_mutex_unlock(&(localnrf->usb_mutex));

    return r;
}

int nrf_send_command_with_resp(kis_capture_handler_t *caph, uint8_t request, uint8_t *data,
        size_t len) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    int r;
    unsigned char rx_buf[64];
    int actual_length;

    pthread_mutex_lock(&(localnrf->usb_mutex));
    r = nrf_send_command_nb(caph, request, data, len);

    if (r < 0) {
        printf("command send failed\n");
        pthread_mutex_unlock(&(localnrf->usb_mutex));
        return r;
    }

    r = libusb_bulk_transfer(localnrf->nrf_handle, MOUSEJACK_USB_ENDPOINT_IN,
            rx_buf, 64, &actual_length, NRF_USB_TIMEOUT);

    pthread_mutex_unlock(&(localnrf->usb_mutex));

    return r;
}

int nrf_set_channel(kis_capture_handler_t *caph, uint8_t channel) {
    /* printf("channel %u\n", channel); */
    return nrf_send_command_with_resp(caph, MOUSEJACK_SET_CHANNEL, &channel, 1);
}

int nrf_enter_promisc_mode(kis_capture_handler_t *caph, uint8_t *prefix, size_t prefix_len) {
    unsigned char *prefix_buf = NULL;
    int r;

    if (prefix_len > 5)
        return -1;

    prefix_buf = (unsigned char *) malloc(prefix_len + 1);
    prefix_buf[0] = prefix_len;

    if (prefix_len > 0) {
        memcpy(prefix_buf + 1, prefix, prefix_len);
    }

    r = nrf_send_command_with_resp(caph, MOUSEJACK_ENTER_PROMISCUOUS_MODE, prefix_buf, prefix_len + 1);

    free(prefix_buf);

    return r;
}

int nrf_enter_sniffer_mode(kis_capture_handler_t *caph, uint8_t *address, size_t addr_len) {
    unsigned char *addr_buf = (unsigned char *) malloc(addr_len + 1);
    int r;

    addr_buf[0] = (uint8_t) addr_len;

    if (addr_len > 0)
        memcpy(addr_buf + 1, address, addr_len);

    r = nrf_send_command_with_resp(caph, MOUSEJACK_ENTER_SNIFFER_MODE, addr_buf, addr_len + 1);

    free(addr_buf);

    return r;
}

int nrf_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    int actual_len, r;

    pthread_mutex_lock(&(localnrf->usb_mutex));

    r = nrf_send_command_nb(caph, MOUSEJACK_RECEIVE_PAYLOAD, NULL, 0);
    r = libusb_bulk_transfer(localnrf->nrf_handle, MOUSEJACK_USB_ENDPOINT_IN,
            rx_buf, rx_max, &actual_len, NRF_USB_TIMEOUT);

    pthread_mutex_unlock(&(localnrf->usb_mutex));

    if (r < 0)
        return r;

    return actual_len;
}

int nrf_enable_pa(kis_capture_handler_t *caph) {
    return nrf_send_command_with_resp(caph, MOUSEJACK_ENABLE_LNA_PA, NULL, 0);
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    int x;
    int busno = -1, devno = -1;

    libusb_device **libusb_devs = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;

    int matched_device = 0;

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "mousejack") != interface) {
        free(interface);
        return 0;
    }

    /* Look for interface-bus-dev */
    x = sscanf(interface, "mousejack-%d-%d", &busno, &devno);

    free(interface);

    /* printf("probe matched %d\n", x); */

    /* If we don't have a valid busno/devno or malformed interface name */
    if (x != -1 && x != 2) {
        return 0;
    }

    libusb_devices_cnt = libusb_get_device_list(localnrf->libusb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        return 0;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == MOUSEJACK_USB_VENDOR && dev.idProduct == MOUSEJACK_USB_PRODUCT) {
            if (busno >= 0) {
                if (busno == libusb_get_bus_number(libusb_devs[i]) &&
                        devno == libusb_get_device_address(libusb_devs[i])) {
                    matched_device = 1;
                    break;
                }
            } else {
                matched_device = 1;
                busno = libusb_get_bus_number(libusb_devs[i]);
                devno = libusb_get_device_address(libusb_devs[i]);
                break;
            }
        }
    }

    libusb_free_device_list(libusb_devs, 1);


    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_nrf_mousejack", 
                    strlen("kismet_cap_nrf_mousejack")) & 0xFFFFFFFF,
                busno, devno);
        *uuid = strdup(errstr);
    }

    /* NRF supports 2-83 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 82);
    for (int i = 2; i < 84; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 2] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 82;

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {
    /* Basic list of devices */
    typedef struct nrf_list {
        char *device;
        struct nrf_list *next;
    } nrf_list_t; 

    nrf_list_t *devs = NULL;
    size_t num_devs = 0;

    libusb_device **libusb_devs = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;

    char devname[32];

    unsigned int i;

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    libusb_devices_cnt = libusb_get_device_list(localnrf->libusb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        return 0;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == MOUSEJACK_USB_VENDOR && dev.idProduct == MOUSEJACK_USB_PRODUCT) {
            snprintf(devname, 32, "mousejack-%u-%u",
                libusb_get_bus_number(libusb_devs[i]),
                libusb_get_device_address(libusb_devs[i]));

            nrf_list_t *d = (nrf_list_t *) malloc(sizeof(nrf_list_t));
            num_devs++;
            d->device = strdup(devname);
            d->next = devs;
            devs = d;
        }
    }
    libusb_free_device_list(libusb_devs, 1);

    if (num_devs == 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces = 
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    while (devs != NULL) {
        nrf_list_t *td = devs->next;
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        (*interfaces)[i]->interface = devs->device;
        (*interfaces)[i]->flags = NULL;
        (*interfaces)[i]->hardware = strdup("nrfmousejack");

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

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    int x;
    int busno = -1, devno = -1;

    libusb_device **libusb_devs = NULL;
    libusb_device *matched_dev = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;

    int matched_device = 0;
    char cap_if[32];

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "mousejack") != interface) {
        snprintf(msg, STATUS_MAX, "Unable to find mousejack interface"); 
        free(interface);
        return -1;
    }

    /* Look for interface-bus-dev */
    x = sscanf(interface, "mousejack-%d-%d", &busno, &devno);

    free(interface);

    /* If we don't have a valid busno/devno or malformed interface name */
    if (x != -1 && x != 2) {
        snprintf(msg, STATUS_MAX, "Malformed mousejack interface, expected 'mousejack' or "
                "'mousejack-bus#-dev#'"); 
        return -1;
    }

    libusb_devices_cnt = libusb_get_device_list(localnrf->libusb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        snprintf(msg, STATUS_MAX, "Unable to iterate USB devices"); 
        return -1;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == MOUSEJACK_USB_VENDOR && dev.idProduct == MOUSEJACK_USB_PRODUCT) {
            if (busno >= 0) {
                if (busno == libusb_get_bus_number(libusb_devs[i]) &&
                        devno == libusb_get_device_address(libusb_devs[i])) {
                    matched_device = 1;
                    matched_dev = libusb_devs[i];
                    break;
                }
            } else {
                matched_device = 1;
                busno = libusb_get_bus_number(libusb_devs[i]);
                devno = libusb_get_device_address(libusb_devs[i]);
                matched_dev = libusb_devs[i];
                break;
            }
        }
    }

    if (!matched_device) {
        snprintf(msg, STATUS_MAX, "Unable to find mousejack USB device");
        return -1;
    }

    libusb_free_device_list(libusb_devs, 1);

    snprintf(cap_if, 32, "mousejack-%u-%u", busno, devno);

    localnrf->devno = devno;
    localnrf->busno = busno;

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_nrf_mousejack", 
                    strlen("kismet_cap_nrf_mousejack")) & 0xFFFFFFFF,
                busno, devno);
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("nrfmousejack");

    /* NRF supports 2-83 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 82);
    for (int i = 2; i < 84; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 2] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 82;

    /* Try to open it */
    r = libusb_open(matched_dev, &localnrf->nrf_handle);
    if (r < 0) {
        snprintf(errstr, STATUS_MAX, "Unable to open mousejack USB interface: %s", 
                libusb_strerror((enum libusb_error) r));
        return -1;
    }

#if 0
    /* Try to reset it */
    r = libusb_reset_device(localnrf->nrf_handle);

    if (r < 0) {
        printf("reset failed\n");
        snprintf(errstr, STATUS_MAX, "Resetting USB device failed, continuing anyhow...");
    }
#endif

    /* Try to claim it */
    r = libusb_claim_interface(localnrf->nrf_handle, 0);
    if (r < 0) {
        if (r == LIBUSB_ERROR_BUSY) {
            /* Try to detach the kernel driver */
            r = libusb_detach_kernel_driver(localnrf->nrf_handle, 0);
            if (r < 0) {
                snprintf(errstr, STATUS_MAX, "Unable to open mousejack USB interface, and unable "
                        "to disconnect existing driver: %s", 
                        libusb_strerror((enum libusb_error) r));
                return -1;
            }
        } else {
            snprintf(errstr, STATUS_MAX, "Unable to open mousejack USB interface: %s",
                    libusb_strerror((enum libusb_error) r));
            return -1;
        }
    }

    libusb_set_configuration(localnrf->nrf_handle, 0);

    nrf_enter_promisc_mode(caph, NULL, 0);
    nrf_enable_pa(caph);

    return 1;
}

void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "unable to parse requested channel '%s'; nrf channels "
                "are from 2 to 83", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if (parsechan < 2 || parsechan > 83) {
        snprintf(errstr, STATUS_MAX, "unable to parse requested channel '%u'; nrf channels "
                "are from 2 to 83", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;

    return ret_localchan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan,
        char *msg) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;

    int r;

    if (privchan == NULL) {
        return 0;
    }

    r = nrf_set_channel(caph, channel->channel);

    if (r < 0)
        return -1;

    localnrf->channel = channel->channel;
   
    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    char errstr[STATUS_MAX];

    /* mousejack should be 6 bytes of response + payload so this should be plenty of 
     * space */
    uint8_t usb_buf[64];

    int buf_rx_len, r;

    while (1) {
        if (caph->spindown) {
            /* close usb */
            if (localnrf->nrf_handle) {
                libusb_close(localnrf->nrf_handle);
                localnrf->nrf_handle = NULL;
            }

            break;
        }

        buf_rx_len = nrf_receive_payload(caph, usb_buf, 64);

        if (buf_rx_len < 0) {
            snprintf(errstr, STATUS_MAX, "mousejack NRF interface 'mousejack-%u-%u' closed "
                    "unexpectedly", localnrf->busno, localnrf->devno);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        /* Skip runt packets caused by timeouts */
        if (buf_rx_len == 1)
            continue;

        /*
        if (buf_rx_len > 1) {
            fprintf(stderr, "mousejack saw %d ", buf_rx_len);

            for (int bb = 0; bb < buf_rx_len; bb++) {
                fprintf(stderr, "%02X ", usb_buf[bb] & 0xFF);
            }
            fprintf(stderr, "\n");
        }
        */

        while (1) {
            struct timeval tv;

            gettimeofday(&tv, NULL);

            if ((r = cf_send_data(caph, NULL, 0,
                            NULL, NULL, tv, 0,
                            buf_rx_len, buf_rx_len, usb_buf)) < 0) {
                cf_send_error(caph, 0, "unable to send DATA frame");
                cf_handler_spindown(caph);
            } else if (r == 0) {
                cf_handler_wait_ringbuffer(caph);
                continue;
            } else {
                break;
            }
        }
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_nrf_t localnrf = {
        .libusb_ctx = NULL,
        .nrf_handle = NULL,
        .caph = NULL,
    };

    pthread_mutex_init(&(localnrf.usb_mutex), NULL);

    kis_capture_handler_t *caph = cf_handler_init("nrfmousejack");
    int r;

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    r = libusb_init(&localnrf.libusb_ctx);
    if (r < 0) {
        return -1;
    }

    localnrf.caph = caph;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localnrf);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Channel callbacks */
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);

    /* Set the capture thread */
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

    libusb_exit(localnrf.libusb_ctx);

    return 0;
}

