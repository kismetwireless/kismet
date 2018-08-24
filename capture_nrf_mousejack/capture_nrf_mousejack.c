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

#include "../config.h"

#include "mousejack.h"

#include <libusb-1.0/libusb.h>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <dirent.h>

#include "../capture_framework.h"

/* Unique instance data passed around by capframework */
typedef struct {
    libusb_context *libusb_ctx;

    libusb_device_handle *nrf_handle;

    kis_capture_handler_t *caph;
} local_nrf_t;

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, KismetExternal__Command *frame,
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
    if (strstr(interface, "mousejack") != 0) {
        free(interface);
        return 0;
    }

    /* Look for interface-bus-dev */
    x = sscanf(interface, "mousejack-%d-%d", &busno, &devno);

    free(interface);

    /* If we don't have a valid busno/devno or malformed interface name */
    if (x != 0 && x != 2) {
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
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
            adler32_csum((unsigned char *) "kismet_cap_nrf_mousejack", 
                strlen("kismet_cap_nrf_mousejack")) & 0xFFFFFFFF,
            busno, devno);
    *uuid = strdup(errstr);
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
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
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
    if (strstr(interface, "mousejack") != 0) {
        snprintf(msg, STATUS_MAX, "Unable to find mousejack interface"); 
        free(interface);
        return -1;
    }

    /* Look for interface-bus-dev */
    x = sscanf(interface, "mousejack-%d-%d", &busno, &devno);

    free(interface);

    /* If we don't have a valid busno/devno or malformed interface name */
    if (x != 0 && x != 2) {
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


    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
            adler32_csum((unsigned char *) "kismet_cap_nrf_mousejack", 
                strlen("kismet_cap_nrf_mousejack")) & 0xFFFFFFFF,
            busno, devno);
    *uuid = strdup(errstr);

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("nrfmousejack");

    /* Try to open it */
    r = libusb_open(matched_dev, &localnrf->nrf_handle);
    if (r < 0) {
        snprintf(errstr, STATUS_MAX, "Unable to open mousejack USB interface: %s", 
                libusb_strerror((enum libusb_error) r));
        return -1;
    }

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

    libusb_set_configuration(localnrf->nrf_handle, 1);


    return 1;
}

int send_nrf_command(kis_capture_handler_t *caph, uint8_t request, uint8_t *data, size_t len) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    uint8_t *cmdbuf = NULL;

    if (len > 0) {
        cmdbuf = (uint8_t *) malloc(len);
        cmdbuf[0] = request;
        memcpy(cmdbuf + 1, data, len);

        libusb_wr
    } else {

    }
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    char errstr[STATUS_MAX];

    while (1) {
        if (caph->spindown) {
            /* close usb */

            break;
        }
    }
}

int main(int argc, char *argv[]) {
    local_nrf_t localnrf = {
        .libusb_ctx = NULL,
        .nrf_handle = NULL,
        .caph = NULL,
    };

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

    libusb_set_debug(localnrf.libusb_ctx, 3);

    localnrf.caph = caph;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localnrf);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
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

    libusb_exit(localnrf.libusb_ctx);

    return 0;
}

