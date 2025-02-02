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

#include "../config.h"

#include "ti_cc2531.h"

#include <libusb-1.0/libusb.h>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

#include "../capture_framework.h"

/* Unique instance data passed around by capframework */
#define TICC2531_RX_MAX         256
typedef struct {
    libusb_context *libusb_ctx;
    libusb_device_handle *ticc2531_handle;
    libusb_device *matched_dev; 

    unsigned int devno, busno;

    pthread_mutex_t usb_mutex;

    /* we don't want to do a channel query every data response, we just want to 
     * remember the last channel used */
    unsigned int channel;

    /* keep track of our errors so we can reset if needed */
    unsigned int error_ctr;

    /* keep track of the soft resets */
    unsigned int soft_reset;

    /* USB xfer */
    struct libusb_transfer *usbxfr;

    /* RX buffer */
    uint8_t rx_buf[TICC2531_RX_MAX];

    kis_capture_handler_t *caph;
} local_ticc2531_t;

#define TICC_USB_ERROR          -1
#define TICC_USB_UNRESPONSIVE   -5

/* Most basic of channel definitions */
typedef struct {
    unsigned int channel;
} local_channel_t;

int ticc2531_set_channel(kis_capture_handler_t *caph, uint8_t channel) {

    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;
    int ret;
    uint8_t data;

    /* two step channel process*/
    data = channel & 0xFF;

    ret = libusb_control_transfer(localticc2531->ticc2531_handle, TICC2531_DIR_OUT, TICC2531_SET_CHAN, 
            0x00, 0x00, &data, 1, TICC2531_TIMEOUT);

    if (ret < 0)
        return TICC_USB_UNRESPONSIVE;

    data = (channel >> 8) & 0xFF;

    ret = libusb_control_transfer(localticc2531->ticc2531_handle, TICC2531_DIR_OUT, TICC2531_SET_CHAN, 
            0x00, 0x01, &data, 1, TICC2531_TIMEOUT);

    if (ret < 0) {
        return TICC_USB_UNRESPONSIVE;
    }

    return ret;
}

int ticc2531_set_power(kis_capture_handler_t *caph,uint8_t power, int retries) {

    int ret;
    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;
    int i;

    /* set power */
    ret = libusb_control_transfer(localticc2531->ticc2531_handle, TICC2531_DIR_OUT, 
            TICC2531_SET_POWER, 0x00, power, NULL, 0, TICC2531_TIMEOUT);

    /* get power until it is the same as configured in set_power */
    for (i = 0; i < retries; i++) {
        uint8_t data;
        ret = libusb_control_transfer(localticc2531->ticc2531_handle, 0xC0, TICC2531_GET_POWER, 
                0x00, 0x00, &data, 1, TICC2531_TIMEOUT);

        if (ret < 0) {
            return ret;
        }

        if (data == power) {
            return 0;
        }
    }

    return ret;
}

int ticc2531_enter_promisc_mode(kis_capture_handler_t *caph) {

    int ret;
    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;

    ret = libusb_control_transfer(localticc2531->ticc2531_handle, TICC2531_DIR_OUT, 
            TICC2531_SET_START, 0x00, 0x00, NULL, 0, TICC2531_TIMEOUT);

    return ret;
}

int ticc2531_exit_promisc_mode(kis_capture_handler_t *caph) {

    int ret;
    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;

    ret = libusb_control_transfer(localticc2531->ticc2531_handle, TICC2531_DIR_OUT, 
            TICC2531_SET_END, 0x00, 0x00, NULL, 0, TICC2531_TIMEOUT);

    return ret;
}

int ticc2531_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;
    int actual_len, r;
   
    r = libusb_bulk_transfer(localticc2531->ticc2531_handle, TICC2531_DATA_EP, rx_buf, 
            rx_max, &actual_len, TICC2531_DATA_TIMEOUT);

    if (r < 0) {
        localticc2531->error_ctr++;
        if (localticc2531->error_ctr >= 5000) {
            pthread_mutex_unlock(&(localticc2531->usb_mutex));
            return TICC_USB_UNRESPONSIVE;
        } else {
            /*continue on for now*/
            pthread_mutex_unlock(&(localticc2531->usb_mutex));
            return 1;
        }
    }

    localticc2531->soft_reset = 0; /*we got something valid so reset*/    
    localticc2531->error_ctr = 0; /*we got something valid so reset*/

    return actual_len;
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
    int num_device = 0;

    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "ticc2531") != interface) {
        free(interface);
        return 0;
    }

    /* Look for interface-bus-dev */
    x = sscanf(interface, "ticc2531-%d-%d", &busno, &devno);

    if (x != 2) {
        busno = -1;
        x = sscanf(interface, "ticc2531-%d", &devno);

        if (x != 1)
            devno = -1;
    }

    free(interface);

    /* If we don't have a valid busno/devno or malformed interface name */
    if (busno == -1 && devno == -1)
        return 0;

    pthread_mutex_lock(&(localticc2531->usb_mutex));

    libusb_devices_cnt = libusb_get_device_list(localticc2531->libusb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        pthread_mutex_unlock(&(localticc2531->usb_mutex));
        return 0;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == TICC2531_USB_VENDOR && dev.idProduct == TICC2531_USB_PRODUCT) {
            if (busno >= 0) {
                if (busno == libusb_get_bus_number(libusb_devs[i]) &&
                        devno == libusb_get_device_address(libusb_devs[i])) {
                    matched_device = 1;
                    break;
                }
            } else {
                if (num_device == devno) {
                    matched_device = 1;
                    busno = libusb_get_bus_number(libusb_devs[i]);
                    devno = libusb_get_device_address(libusb_devs[i]);
                    break;
                }

                num_device++;
            }
        }
    }

    libusb_free_device_list(libusb_devs, 1);
    pthread_mutex_unlock(&(localticc2531->usb_mutex));

    if (!matched_device) {
        return 0;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_ti_cc2531", 
                    strlen("kismet_cap_ti_cc2531")) & 0xFFFFFFFF,
                busno, devno);
        *uuid = strdup(errstr);
    }

    /* TI CC 2531 supports 11-26 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 16);
    for (int i = 11; i < 27; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 11] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 16;
    
    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    /* Basic list of devices */
    typedef struct ticc2531_list {
        char *device;
        struct ticc2531_list *next;
    } ticc2531_list_t;

    ticc2531_list_t *devs = NULL;
    size_t num_devs = 0;
    libusb_device **libusb_devs = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;
    char devname[32];
    unsigned int i;

    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;
    pthread_mutex_lock(&(localticc2531->usb_mutex));
    libusb_devices_cnt = libusb_get_device_list(localticc2531->libusb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        pthread_mutex_unlock(&(localticc2531->usb_mutex));
        return 0;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == TICC2531_USB_VENDOR && dev.idProduct == TICC2531_USB_PRODUCT) {
            snprintf(devname, 32, "ticc2531-%u-%u", libusb_get_bus_number(libusb_devs[i]),
                     libusb_get_device_address(libusb_devs[i]));

            ticc2531_list_t *d = (ticc2531_list_t *) malloc(sizeof(ticc2531_list_t));
            num_devs++;
            d->device = strdup(devname);
            d->next = devs;
            devs = d;
        }
    }

    libusb_free_device_list(libusb_devs, 1);
    pthread_mutex_unlock(&(localticc2531->usb_mutex));

    if (num_devs == 0) {
        *interfaces = NULL;
        pthread_mutex_unlock(&(localticc2531->usb_mutex));
        return 0;
    }

    *interfaces =
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    while (devs != NULL) {
        ticc2531_list_t *td = devs->next;
        (*interfaces)[i] =
            (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        (*interfaces)[i]->interface = devs->device;
        (*interfaces)[i]->flags = NULL;
        (*interfaces)[i]->hardware = strdup("ticc2531");

        free(devs);
        devs = td;

        i++;
    }

    pthread_mutex_unlock(&(localticc2531->usb_mutex));

    return num_devs;
}

void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "1 unable to parse requested channel '%s'; ticc2531 channels "
                "are from 11 to 26", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if (parsechan > 26 || parsechan < 11) {
        snprintf(errstr, STATUS_MAX, "2 unable to parse requested channel '%u'; ticc2531 channels "
                "are from 11 to 26", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;
    return ret_localchan;
}

int open_usb_device(kis_capture_handler_t *caph, char *errstr) {
    int r;
    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;

    pthread_mutex_lock(&(localticc2531->usb_mutex));

    /* Try to open it */
    r = libusb_open(localticc2531->matched_dev, &localticc2531->ticc2531_handle);

    localticc2531->error_ctr = 0;

    if (r < 0) {
        snprintf(errstr, STATUS_MAX, "Unable to open ticc2531 USB interface: %s", 
                libusb_strerror((enum libusb_error) r));
        pthread_mutex_unlock(&(localticc2531->usb_mutex));
        return -1;
    }

    if (libusb_kernel_driver_active(localticc2531->ticc2531_handle, 0)) {
        r = libusb_detach_kernel_driver(localticc2531->ticc2531_handle, 0); 

        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "Unable to open ticc2531 USB interface, "
                    "could not disconnect kernel drivers: %s",
                    libusb_strerror((enum libusb_error) r));
            pthread_mutex_unlock(&(localticc2531->usb_mutex));
            return -1;
        }
    }

    /* config */
    r = libusb_set_configuration(localticc2531->ticc2531_handle, 1);
    if (r < 0) {
        snprintf(errstr, STATUS_MAX,
                 "Unable to open ticc2531 USB interface; could not set USB configuration.  Has "
                 "your device been flashed with the sniffer firmware?");
        pthread_mutex_unlock(&(localticc2531->usb_mutex));
        return -1;
    }

    /* Try to claim it */
    r = libusb_claim_interface(localticc2531->ticc2531_handle, 0);
    if (r < 0) {
        if (r == LIBUSB_ERROR_BUSY) {
            /* Try to detach the kernel driver */
            r = libusb_detach_kernel_driver(localticc2531->ticc2531_handle, 0);
            if (r < 0) {
                snprintf(errstr, STATUS_MAX, "Unable to open ticc2531 USB interface, and unable "
                        "to disconnect existing driver: %s", 
                        libusb_strerror((enum libusb_error) r));
                pthread_mutex_unlock(&(localticc2531->usb_mutex));
                return -1;
            }
        } else {
            snprintf(errstr, STATUS_MAX, "Unable to open ticc2531 USB interface: %s",
                    libusb_strerror((enum libusb_error) r));
            pthread_mutex_unlock(&(localticc2531->usb_mutex));
            return -1;
        }
    }

    ticc2531_set_power(caph, 0x04, TICC2531_POWER_RETRIES);

    ticc2531_set_channel(caph, localticc2531->channel);

    ticc2531_enter_promisc_mode(caph);

    pthread_mutex_unlock(&(localticc2531->usb_mutex));

    return 1;
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
    ssize_t libusb_devices_cnt = 0;
    int r;

    int matched_device = 0;
    int num_device = 0;

    char cap_if[32];
    
    ssize_t i;

    char *localchanstr = NULL;
    unsigned int *localchan = NULL;

    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "ticc2531") != interface) {
        snprintf(msg, STATUS_MAX, "Unable to find ti cc2531 interface"); 
        free(interface);
        return -1;
    }

    /* Look for interface-bus-dev */
    x = sscanf(interface, "ticc2531-%d-%d", &busno, &devno);

    /* Look for interface-# */
    if (x != 2) {
        busno = -1;
        x = sscanf(interface, "ticc2531-%d", &devno);

        if (x != 1)
            devno = -1;
    }

    free(interface);

    /* If we don't have a valid busno/devno or malformed interface name */
    if (devno == -1 && busno == -1) {
        snprintf(msg, STATUS_MAX, "Malformed ticc2531 interface, expected 'ticc2531' or "
                "'ticc2531-bus#-dev#'"); 
        return -1;
    }

    pthread_mutex_lock(&(localticc2531->usb_mutex));
    libusb_devices_cnt = libusb_get_device_list(localticc2531->libusb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        snprintf(msg, STATUS_MAX, "Unable to iterate USB devices"); 
        pthread_mutex_unlock(&(localticc2531->usb_mutex));
        return -1;
    }
    
    for (i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == TICC2531_USB_VENDOR && dev.idProduct == TICC2531_USB_PRODUCT) {
            if (busno >= 0) {
                if (busno == libusb_get_bus_number(libusb_devs[i]) &&
                        devno == libusb_get_device_address(libusb_devs[i])) {
                    matched_device = 1;
                    localticc2531->matched_dev = libusb_devs[i];
                    break;
                }
            } else {
                if (num_device == devno) {
                    matched_device = 1;
                    busno = libusb_get_bus_number(libusb_devs[i]);
                    devno = libusb_get_device_address(libusb_devs[i]);
                    localticc2531->matched_dev = libusb_devs[i];
                    break;
                }

                num_device++;
            }
        }
    }

    if (!matched_device) {
        pthread_mutex_unlock(&(localticc2531->usb_mutex));
        snprintf(msg, STATUS_MAX, "Unable to find ticc2531 USB device");
        return -1;
    }

    libusb_free_device_list(libusb_devs, 1);

    snprintf(cap_if, 32, "ticc2531-%u-%u", busno, devno);

    // try pulling the channel
    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = atoi(localchanstr); 
        free(localchanstr);

        if (localchan == NULL) {
            snprintf(msg, STATUS_MAX,
                    "ticc2531 could not parse channel= option provided in source "
                    "definition");
            pthread_mutex_unlock(&(localticc2531->usb_mutex));
            return -1;
        }
    } else {
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = 11;
    }


    localticc2531->devno = devno;
    localticc2531->busno = busno;

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_ti_cc2531", 
                    strlen("kismet_cap_ti_cc2531")) & 0xFFFFFFFF,
                busno, devno);
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("ticc2531");

    /* TI CC 2531 supports 11-26 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 16);
    for (int i = 11; i < 27; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 11] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 16;

    localticc2531->channel = *localchan;

    pthread_mutex_unlock(&(localticc2531->usb_mutex));

    /* Try to open it */
    r = open_usb_device(caph, msg);

    if (r < 0)
        return -1;

    return 1;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    int r;

    char errstr[STATUS_MAX];
    char open_errstr[STATUS_MAX];

    if (privchan == NULL) {
        return 0;
    }
   
    if (localticc2531->ticc2531_handle == NULL) {
        pthread_mutex_unlock(&(localticc2531->usb_mutex));
        return 0;
    }

    ticc2531_exit_promisc_mode(caph);

    r = ticc2531_set_channel(caph, channel->channel);

    if (r == TICC_USB_UNRESPONSIVE) {
        snprintf(errstr, STATUS_MAX, "TI CC 2531 interface 'ticc2531-%u-%u' channel unable to be set"
        ", re-opening the datasource as a precaution", 
                localticc2531->busno, localticc2531->devno);

        cf_send_warning(caph, errstr);

        /* close usb */
        pthread_mutex_lock(&(localticc2531->usb_mutex));
        if (localticc2531->ticc2531_handle) {
            libusb_close(localticc2531->ticc2531_handle);
            localticc2531->ticc2531_handle = NULL;
        }
        pthread_mutex_unlock(&(localticc2531->usb_mutex));

        if (open_usb_device(caph, open_errstr) < 0) {
            snprintf(errstr, STATUS_MAX, "TI CC 2531 interface 'ticc2531-%u-%u' could not be "
                    "re-opened: %s", localticc2531->busno, localticc2531->devno, open_errstr);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
        }
        return 1;
    }

    localticc2531->channel = channel->channel;

    ticc2531_enter_promisc_mode(caph);

    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_ticc2531_t *localticc2531 = (local_ticc2531_t *) caph->userdata;
    char errstr[STATUS_MAX];
    char open_errstr[STATUS_MAX];

    uint8_t usb_buf[256];

    int buf_rx_len, r;

    while (1) {
        if (caph->spindown) {
            /* close usb */
            if (localticc2531->ticc2531_handle) {
                libusb_close(localticc2531->ticc2531_handle);
                localticc2531->ticc2531_handle = NULL;
            }

            break;
        }

        buf_rx_len = ticc2531_receive_payload(caph, usb_buf, 256);

        if (buf_rx_len < 0) {
            if (buf_rx_len == TICC_USB_UNRESPONSIVE) {
                snprintf(errstr, STATUS_MAX, "TI CC 2531 interface 'ticc2531-%u-%u' has not seen "
                        "any data in a prolonged period of time; sometimes the device "
                        "sniffer firmware crashes, re-opening the datasource as a precaution", 
                        localticc2531->busno, localticc2531->devno);

                cf_send_warning(caph, errstr);

                /* close usb */
                pthread_mutex_lock(&(localticc2531->usb_mutex));
                if (localticc2531->ticc2531_handle) {
                    libusb_close(localticc2531->ticc2531_handle);
                    localticc2531->ticc2531_handle = NULL;
                }
                pthread_mutex_unlock(&(localticc2531->usb_mutex));

                if (open_usb_device(caph, open_errstr) < 0) {
                    snprintf(errstr, STATUS_MAX, "TI CC 2531 interface 'ticc2531-%u-%u' could not be "
                            "re-opened: %s", localticc2531->busno, localticc2531->devno, open_errstr);
                    cf_send_error(caph, 0, errstr);
                    cf_handler_spindown(caph);
                    break;
                }

                continue;

            } else {
                snprintf(errstr, STATUS_MAX, "TI CC 2531 interface 'ticc2531-%u-%u' closed "
                        "unexpectedly", localticc2531->busno, localticc2531->devno);
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }
        }

        /* Skip runt packets caused by timeouts */
        if (buf_rx_len == 1)
            continue;

        /* the devices look to report a 4 byte counter/heartbeat, skip it */
        if (buf_rx_len <= 7)
            continue;

        if(usb_buf[0] != 0x00) {
            //printf("invalid 2531 packet?\n");
            continue;
        }

        /* insert the channel into the packet header*/
        usb_buf[2] = (uint8_t)localticc2531->channel;

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
    local_ticc2531_t localticc2531 = {
        .libusb_ctx = NULL,
        .ticc2531_handle = NULL,
        .matched_dev = NULL,
        .caph = NULL,
        .error_ctr = 0,
        .soft_reset = 0,
        .usbxfr = NULL,
    };

    pthread_mutex_init(&(localticc2531.usb_mutex), NULL);

    kis_capture_handler_t *caph = cf_handler_init("ticc2531");
    int r;

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    r = libusb_init(&localticc2531.libusb_ctx);
    if (r < 0) {
        return -1;
    }

    localticc2531.caph = caph;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localticc2531);

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

    libusb_exit(localticc2531.libusb_ctx);
    
    return 0;
}

