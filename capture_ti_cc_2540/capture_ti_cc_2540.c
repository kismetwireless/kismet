
#include "../config.h"

#include "ti_cc2540.h"

#include <libusb-1.0/libusb.h>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "../capture_framework.h"

/* USB command timeout */
#define TICC2540_USB_TIMEOUT     1000

/* Unique instance data passed around by capframework */
typedef struct {
    libusb_context *libusb_ctx;
    libusb_device_handle *ticc2540_handle;

    unsigned int devno, busno;

    pthread_mutex_t usb_mutex;

    /* we don't want to do a channel query every data response, we just want to 
     * remember the last channel used */
    unsigned int channel;

    kis_capture_handler_t *caph;
} local_ticc2540_t;

/* Most basic of channel definitions */
typedef struct {
    unsigned int channel;
} local_channel_t;

int ticc2540_set_channel(kis_capture_handler_t *caph, uint8_t channel) {
    /* printf("channel %u\n", channel); */
printf("ticc2540_set_channel channel:%u\n",channel);
    local_ticc2540_t *localticc2540 = (local_ticc2540_t *) caph->userdata;

    int ret;
    uint8_t data;

    data = channel & 0xFF;
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    ret = libusb_control_transfer(localticc2540->ticc2540_handle, TICC2540_DIR_OUT, TICC2540_SET_CHAN, 0x00, 0x00, &data, 1, TICC2540_TIMEOUT);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));
    if (ret < 0)
    {
        printf("setting channel (LSB) failed!\n");
        return ret;
    }
    data = (channel >> 8) & 0xFF;
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    ret = libusb_control_transfer(localticc2540->ticc2540_handle, TICC2540_DIR_OUT, TICC2540_SET_CHAN, 0x00, 0x01, &data, 1, TICC2540_TIMEOUT);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));
    if (ret < 0)
    {
        printf("setting channel (LSB) failed!\n");
        return ret;
    }
printf("ticc2540_set_channel return\n");
    return ret;
}///mutex inside

int ticc2540_set_power(kis_capture_handler_t *caph,uint8_t power, int retries) {
printf("ticc2540_set_power\n");
    int ret;
    local_ticc2540_t *localticc2540 = (local_ticc2540_t *) caph->userdata;
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    // set power
    ret = libusb_control_transfer(localticc2540->ticc2540_handle, TICC2540_DIR_OUT, TICC2540_SET_POWER, 0x00, power, NULL, 0, TICC2540_TIMEOUT);
    // get power until it is the same as configured in set_power
    int i;
    for (i = 0; i < retries; i++)
    {
        uint8_t data;
        ret = libusb_control_transfer(localticc2540->ticc2540_handle, 0xC0, TICC2540_GET_POWER, 0x00, 0x00, &data, 1, TICC2540_TIMEOUT);
        if (ret < 0)
        {
            pthread_mutex_unlock(&(localticc2540->usb_mutex));
            return ret;
        }
        if (data == power)
        {
            pthread_mutex_unlock(&(localticc2540->usb_mutex));
            return 0;
        }
    }
    pthread_mutex_unlock(&(localticc2540->usb_mutex));
printf("ticc2540_set_power ret:%d return\n",ret);
    return ret;
}//mutex inside

int ticc2540_enter_promisc_mode(kis_capture_handler_t *caph) {
printf("ticc2540_enter_promisc_mode\n");
    int ret;
    local_ticc2540_t *localticc2540 = (local_ticc2540_t *) caph->userdata;
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    ret = libusb_control_transfer(localticc2540->ticc2540_handle, TICC2540_DIR_OUT, TICC2540_SET_START, 0x00, 0x00, NULL, 0, TICC2540_TIMEOUT);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));
printf("ticc2540_enter_promisc_mode ret:%d return\n",ret);
    return ret;
}//mutex inside

int ticc2540_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
printf("ticc2540_receive_payload\n");
    local_ticc2540_t *localticc2540 = (local_ticc2540_t *) caph->userdata;
    int actual_len, r;
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    r = libusb_bulk_transfer(localticc2540->ticc2540_handle, TICC2540_DATA_EP, rx_buf, rx_max, &actual_len, TICC2540_TIMEOUT);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));
printf("ticc2540_receive_payload return r:%d\n",r);

    if(r == LIBUSB_ERROR_TIMEOUT)
        r = 1;

    if (r < 0)
        return r;

    return actual_len;
}//mutex inside

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
   
printf("probe_callback\n");
 
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

    local_ticc2540_t *localticc2540 = (local_ticc2540_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    printf("Look for the interface type\n");
    if (strstr(interface, "ticc2540") != interface) {
        free(interface);
        return 0;
    }

    /* Look for interface-bus-dev */
    printf("Look for interface-bus-dev\n");
    x = sscanf(interface, "ticc2540-%d-%d", &busno, &devno);
    printf("free interface\n");
    free(interface);

    printf("probe matched %d\n", x);

    /* If we don't have a valid busno/devno or malformed interface name */
    if (x != -1 && x != 2) {
        return 0;
    }
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    libusb_devices_cnt = libusb_get_device_list(localticc2540->libusb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        return 0;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == TICC2540_USB_VENDOR && dev.idProduct == TICC2540_USB_PRODUCT) {
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
    printf("libusb_free_device_list\n");
    libusb_free_device_list(libusb_devs, 1);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
            adler32_csum((unsigned char *) "kismet_cap_ti_cc2540", 
                strlen("kismet_cap_ti_cc2540")) & 0xFFFFFFFF,
            busno, devno);
    *uuid = strdup(errstr);

    printf("%s\n",errstr);

    /* TI CC 2540 supports 37-39 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 4);
    for (int i = 37; i < 40; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 37] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 3;
    printf("probe_callback return\n");
    return 1;
}/////mutex inside

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {
    /* Basic list of devices */
    typedef struct ticc2540_list {
        char *device;
        struct ticc2540_list *next;
    } ticc2540_list_t; 

printf("list_callback\n");

    ticc2540_list_t *devs = NULL;
    size_t num_devs = 0;

    libusb_device **libusb_devs = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;

    char devname[32];

    unsigned int i;

    local_ticc2540_t *localticc2540 = (local_ticc2540_t *) caph->userdata;
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    libusb_devices_cnt = libusb_get_device_list(localticc2540->libusb_ctx, &libusb_devs);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));
    if (libusb_devices_cnt < 0) {
        return 0;
    }
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == TICC2540_USB_VENDOR && dev.idProduct == TICC2540_USB_PRODUCT) {
            snprintf(devname, 32, "ticc2540-%u-%u",
                libusb_get_bus_number(libusb_devs[i]),
                libusb_get_device_address(libusb_devs[i]));

            ticc2540_list_t *d = (ticc2540_list_t *) malloc(sizeof(ticc2540_list_t));
            num_devs++;
            d->device = strdup(devname);
            d->next = devs;
            devs = d;
        }
    }
    libusb_free_device_list(libusb_devs, 1);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));
    if (num_devs == 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces = 
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    while (devs != NULL) {
        ticc2540_list_t *td = devs->next;
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        (*interfaces)[i]->interface = devs->device;
        (*interfaces)[i]->flags = NULL;
        (*interfaces)[i]->hardware = strdup("ticc2540");

        free(devs);
        devs = td;

        i++;
    }
printf("list_callback return\n");
    return num_devs;
}///mutex inside

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    printf("open_callback\n");

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

    local_ticc2540_t *localticc2540 = (local_ticc2540_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    printf("Look for the interface type\n");
    if (strstr(interface, "ticc2540") != interface) {
        snprintf(msg, STATUS_MAX, "Unable to find ti cc2540 interface"); 
        free(interface);
        return -1;
    }

    /* Look for interface-bus-dev */
    printf("Look for interface-bus-dev\n");
    x = sscanf(interface, "ticc2540-%d-%d", &busno, &devno);

    free(interface);

    /* If we don't have a valid busno/devno or malformed interface name */
    if (x != -1 && x != 2) {
        snprintf(msg, STATUS_MAX, "Malformed ticc2540 interface, expected 'ticc2540' or "
                "'ticc2540-bus#-dev#'"); 
        return -1;
    }
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    libusb_devices_cnt = libusb_get_device_list(localticc2540->libusb_ctx, &libusb_devs);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));
    if (libusb_devices_cnt < 0) {
        snprintf(msg, STATUS_MAX, "Unable to iterate USB devices"); 
        return -1;
    }
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == TICC2540_USB_VENDOR && dev.idProduct == TICC2540_USB_PRODUCT) {
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
        snprintf(msg, STATUS_MAX, "Unable to find ticc2540 USB device");
        return -1;
    }

    libusb_free_device_list(libusb_devs, 1);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));

    snprintf(cap_if, 32, "ticc2540-%u-%u", busno, devno);

    localticc2540->devno = devno;
    localticc2540->busno = busno;

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
            adler32_csum((unsigned char *) "kismet_cap_ti_cc2540", 
                strlen("kismet_cap_ti_cc2540")) & 0xFFFFFFFF,
            busno, devno);
    *uuid = strdup(errstr);

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("ticc2540");

    /* BTLE supports 37-39 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 4);
    for (int i = 37; i < 40; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 37] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 3;

    pthread_mutex_lock(&(localticc2540->usb_mutex));
    /* Try to open it */
    r = libusb_open(matched_dev, &localticc2540->ticc2540_handle);
    pthread_mutex_unlock(&(localticc2540->usb_mutex));
    if (r < 0) {
        snprintf(errstr, STATUS_MAX, "Unable to open ticc2540 USB interface: %s", 
                libusb_strerror((enum libusb_error) r));
        pthread_mutex_unlock(&(localticc2540->usb_mutex));
        return -1;
    }
    pthread_mutex_lock(&(localticc2540->usb_mutex));
    printf("Check if kernel driver attached\n");
    if(libusb_kernel_driver_active(localticc2540->ticc2540_handle, 0))
    {
        printf("detach driver\n");
        r = libusb_detach_kernel_driver(localticc2540->ticc2540_handle, 0); // detach driver
        assert(r == 0);
    }

    /* Try to claim it */
    r = libusb_claim_interface(localticc2540->ticc2540_handle, 0);
    if (r < 0) {
        if (r == LIBUSB_ERROR_BUSY) {
            /* Try to detach the kernel driver */
            r = libusb_detach_kernel_driver(localticc2540->ticc2540_handle, 0);
            if (r < 0) {
                snprintf(errstr, STATUS_MAX, "Unable to open ticc2540 USB interface, and unable "
                        "to disconnect existing driver: %s", 
                        libusb_strerror((enum libusb_error) r));
                pthread_mutex_unlock(&(localticc2540->usb_mutex));
                return -1;
            }
        } else {
            snprintf(errstr, STATUS_MAX, "Unable to open ticc2540 USB interface: %s",
                    libusb_strerror((enum libusb_error) r));
            pthread_mutex_unlock(&(localticc2540->usb_mutex));
            return -1;
        }
    }
    printf("libusb_claim_interface r:%d\n",r);

    printf("libusb_set_configuration\n");
    r = libusb_set_configuration(localticc2540->ticc2540_handle, -1);
    printf("libusb_set_configuration r:%d\n",r);
    assert(r < 0);

    // read ident
    printf("read ident\n");
    uint8_t ident[32];
    int ret;
    printf("libusb_control_transfer\n"); 
    ret = libusb_control_transfer(localticc2540->ticc2540_handle, TICC2540_DIR_IN, TICC2540_GET_IDENT, 0x00, 0x00, ident, sizeof(ident), TICC2540_TIMEOUT);
    printf("print out\n");
    if (ret > 0)
    {
        printf("IDENT:");
        for (int i = 0; i < ret; i++)
            printf(" %02X", ident[i]);
        printf("\n");
    }
    printf("pthread_mutex_unlock\n");
    pthread_mutex_unlock(&(localticc2540->usb_mutex));

    printf("ticc2540_set_power\n");
    ticc2540_set_power(caph,0x04, TICC2540_POWER_RETRIES);

    ticc2540_enter_promisc_mode(caph);
printf("open_callback return\n");
    return 1;
}///mutex inside

void *chantranslate_callback(kis_capture_handler_t *caph, char *chanstr) {
printf("chantranslate_callback\n");
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "1 unable to parse requested channel '%s'; ticc2540 channels "
                "are from 37 to 39", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if (parsechan > 39 || parsechan < 37) {
        snprintf(errstr, STATUS_MAX, "2 unable to parse requested channel '%u'; ticc2540 channels "
                "are from 37 to 39", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;
printf("chantranslate_callback return\n");
    return ret_localchan;
}///

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan,
        char *msg) {
    local_ticc2540_t *localticc2540 = (local_ticc2540_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
printf("chancontrol_callback\n");
    int r;

    if (privchan == NULL) {
        return 0;
    }

    r = ticc2540_set_channel(caph, channel->channel);

printf("chancontrol_callback return r:%d\n",r);

    if (r < 0)
        return -1;

    localticc2540->channel = channel->channel;
   
    return 1;
}///

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_ticc2540_t *localticc2540 = (local_ticc2540_t *) caph->userdata;
printf("capture_thread\n");
    char errstr[STATUS_MAX];

    uint8_t usb_buf[256];

    int buf_rx_len, r;

    while (1) {
        if (caph->spindown) {
            /* close usb */
            if (localticc2540->ticc2540_handle) {
                libusb_close(localticc2540->ticc2540_handle);
                localticc2540->ticc2540_handle = NULL;
            }

            break;
        }
        printf("ticc2540_receive_payload\n");
        buf_rx_len = ticc2540_receive_payload(caph, usb_buf, 256);
        printf("ticc2540_receive_payload buf_rx_len:%d\n",buf_rx_len);
        if (buf_rx_len < 0) {
            snprintf(errstr, STATUS_MAX, "TI CC 2540 interface 'ticc2540-%u-%u' closed "
                    "unexpectedly", localticc2540->busno, localticc2540->devno);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        /* Skip runt packets caused by timeouts */
        if (buf_rx_len == 1)
            continue;

        //the devices look to report a 4 byte counter/heartbeat, skip it
        if(buf_rx_len <= 7)
            continue;

        /**/
        if (buf_rx_len > 1) {
            fprintf(stderr, "ti cc 2540 saw %d ", buf_rx_len);

            for (int bb = 0; bb < buf_rx_len; bb++) {
                fprintf(stderr, "%02X ", usb_buf[bb] & 0xFF);
            }
            fprintf(stderr, "\n");
        }
        /**/

        while (1) {
            struct timeval tv;

            gettimeofday(&tv, NULL);

            if ((r = cf_send_data(caph,
                            NULL, NULL, NULL,
                            tv,
                            0,
                            buf_rx_len, usb_buf)) < 0) {
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
printf("capture_thread return\n");
}///

int main(int argc, char *argv[]) {
    local_ticc2540_t localticc2540 = {
        .libusb_ctx = NULL,
        .ticc2540_handle = NULL,
        .caph = NULL,
    };

    pthread_mutex_init(&(localticc2540.usb_mutex), NULL);

    kis_capture_handler_t *caph = cf_handler_init("ticc2540");
    int r;

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    r = libusb_init(&localticc2540.libusb_ctx);
    if (r < 0) {
        return -1;
    }

    libusb_set_debug(localticc2540.libusb_ctx, 3);

    localticc2540.caph = caph;

    /* Set the local data ptr */
    printf("Set the local data ptr\n");
    cf_handler_set_userdata(caph, &localticc2540);

    /* Set the callback for opening  */
    printf("Set the callback for opening\n");
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    printf("Set the callback for probing an interface\n");
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    printf("Set the list callback\n");
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Channel callbacks */
    printf("Channel callbacks\n");
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);

    /* Set the capture thread */
    printf("Set the capture thread\n");
    cf_handler_set_capture_cb(caph, capture_thread);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture by launching the remote loop */
    printf("Support remote capture by launching the remote loop\n");
    cf_handler_remote_capture(caph);

    /* Jail our ns */
    printf("Jail our ns\n");
    cf_jail_filesystem(caph);

    /* Strip our privs */
    printf("Strip our privs\n");
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);
    printf("libusb_exit\n");
    libusb_exit(localticc2540.libusb_ctx);
    
    printf("main return\n");
    return 0;
}

