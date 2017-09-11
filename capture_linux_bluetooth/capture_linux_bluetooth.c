/*
    This file is part of Kismet

    Copyright (C) 2017 Mike Kershaw / Dragorn

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

    Based on the bluez-5.46 client/ code
    Copyright (C) 2012  Intel Corporation. All rights reserved.

    Based on the Blue-Z stack code,

    Copyright (C) 2000-2001  Qualcomm Incorporated
    Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
    Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>

    and used under the GPL2 license

    Controls a linux bluetooth interface in bluez via dbus and hci sockets
*/

/* https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/device-api.txt */

/* Bluetooth devices are sent as complete device records in a custom
 * capsource packet:
 *
 * LINUXBTDEVICE
 * A complete bluetooth device record as reported over the dbus channel
 *
 * KV Pairs:
 * GPS (optional)
 * SIGNAL 
 * BTDEVICE
 *
 * KV BTDEVICE
 * Bluetooth device record KV.
 *
 * Content:
 *
 * Msgpack packed dictionary containing the following:
 * "address": (string) String mac address of the device
 * "name": (string) String name of the device, as advertised (optional)
 * "uuid_vec": Vetor of string UUIDs (optional)
 * "tv_sec": (uint64_t) Unix timestamp second component
 * "tv_usec": (uint64_t) Unix timestamp microsecond component
 * "txpower": (int) Transmit power, if advertised (optional)
 * "addrtype": (uint) Address type
 *
 */

#include "../config.h"

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

#include "mgmtlib/bluetooth.h"
#include "mgmtlib/hci.h"
#include "mgmtlib/mgmt.h"

#include "linux_bt_rfkill.h"

#include "../simple_datasource_proto.h"
#include "../simple_ringbuf_c.h"
#include "../capture_framework.h"

/* Unique instance data passed around by capframework */
typedef struct {
    /* Target interface */
    char *bt_interface;
    char *bt_interface_str_address;

    /* Raw (inverse) bdaddress */
    uint8_t bt_interface_address[6];

    /* bluez management interface socket */
    int mgmt_fd;
    unsigned int devid;

    /* Read ringbuf */
    kis_simple_ringbuf_t *read_rbuf;

    /* Scanning type */
    uint8_t scan_type;

    kis_capture_handler_t *caph;
} local_bluetooth_t;

#define SCAN_TYPE_BREDR (1 << BDADDR_BREDR)
#define SCAN_TYPE_LE ((1 << BDADDR_LE_PUBLIC) | (1 << BDADDR_LE_RANDOM))
#define SCAN_TYPE_DUAL (SCAN_TYPE_BREDR | SCAN_TYPE_LE)

/* Outbound commands */
typedef struct {
    uint16_t opcode;
    uint16_t index;
    uint16_t length;
    uint8_t param[0];
} bluez_mgmt_command_t;

/* Convert an address to a string; string must hold at least 18 bytes */
#define BDADDR_STR_LEN      18

static char *eir_get_name(const uint8_t *eir, uint16_t eir_len);
static unsigned int eir_get_flags(const uint8_t *eir, uint16_t eir_len);
void bdaddr_to_string(const uint8_t *bdaddr, char *str);

/* Encode a BTDEVICE KV pair */
simple_cap_proto_kv_t *encode_kv_btdevice(struct mgmt_ev_device_found *dev) {
    const char *key_address = "address";
    const char *key_name = "name";
    const char *key_uuid_vec = "uuid_vec";
    const char *key_tv_sec = "tv_sec";
    const char *key_tv_usec = "tv_usec";
    const char *key_txpower = "txpower";
    const char *key_type = "type";

    char address[BDADDR_STR_LEN];
    char *name;

    uint16_t eirlen;

    simple_cap_proto_kv_t *kv;
    size_t content_sz;

    struct timeval tv;

    /* Address, 2 time fields, type are always sent */
    size_t num_fields = 4;

    /* Extract the name from EIR */
    eirlen = le16toh(dev->eir_len);
    name = eir_get_name(dev->eir, eirlen);

    bdaddr_to_string(dev->addr.bdaddr.b, address);

    if (name != NULL)
        num_fields++;

    /* We don't get these, yet, from the mgmtsock */
    /*
    if (g_dbus_proxy_get_property(proxy, "UUIDs", &iter))
        num_fields++;

    if (g_dbus_proxy_get_property(proxy, "TxPower", &iter))
        num_fields++;
    */

    msgpuck_buffer_t *puckbuffer;

    size_t initial_sz = num_fields * 32;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL)
        return NULL;

    mp_b_encode_map(puckbuffer, num_fields);

    /* Always encode address and timestamp */
    mp_b_encode_str(puckbuffer, key_address, strlen(key_address));
    mp_b_encode_str(puckbuffer, address, strlen(address));

    gettimeofday(&tv, NULL);

    mp_b_encode_str(puckbuffer, key_tv_sec, strlen(key_tv_sec));
    mp_b_encode_uint(puckbuffer, tv.tv_sec);

    mp_b_encode_str(puckbuffer, key_tv_usec, strlen(key_tv_usec));
    mp_b_encode_uint(puckbuffer, tv.tv_usec);

    mp_b_encode_str(puckbuffer, key_type, strlen(key_type));
    mp_b_encode_uint(puckbuffer, dev->addr.type);

    if (name != NULL) {
        mp_b_encode_str(puckbuffer, key_name, strlen(key_name));
        mp_b_encode_str(puckbuffer, name, strlen(name));
        free(name);
    }

    /*
    if (g_dbus_proxy_get_property(proxy, "TxPower", &iter)) {
        dbus_message_iter_get_basic(&iter, &txpower);

        mp_b_encode_str(puckbuffer, key_txpower, strlen(key_txpower));
        mp_b_encode_int(puckbuffer, txpower);
    }

    if (g_dbus_proxy_get_property(proxy, "UUIDs", &iter)) {
        int uuid_sz = 0;

        dbus_message_iter_recurse(&iter, &value);
        while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_STRING) {
            uuid_sz++;
            dbus_message_iter_next(&value);
        }

        if (uuid_sz > 0) {
            mp_b_encode_str(puckbuffer, key_uuid_vec, strlen(key_uuid_vec));
            mp_b_encode_array(puckbuffer, uuid_sz);

            dbus_message_iter_recurse(&iter, &value);
            while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_STRING) {
                const char *uuid;

                dbus_message_iter_get_basic(&value, &uuid);

                mp_b_encode_str(puckbuffer, uuid, strlen(uuid));

                dbus_message_iter_next(&value);
            }
        }
    }
    */

    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL) {
        mp_b_free_buffer(puckbuffer);
        return NULL;
    }

    snprintf(kv->header.key, 16, "%.16s", "BTDEVICE");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;
}

int cf_send_btdevice(local_bluetooth_t *localbt, struct mgmt_ev_device_found *dev) {
    size_t num_kvs = 2;

    simple_cap_proto_kv_t **kv_pairs;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    kv_pairs[0] = encode_kv_btdevice(dev);
    
    if (kv_pairs[0] == NULL) {
        free(kv_pairs);
        return -1;
    }

    kv_pairs[1] = encode_kv_signal(dev->rssi, 0, 0, 0, 0.0f, NULL, 0.0f);
    if (kv_pairs[1] == NULL) {
        free(kv_pairs[0]);
        free(kv_pairs);
        return -1;
    }

    return cf_stream_packet(localbt->caph, "LINUXBTDEVICE", kv_pairs, 2);
}

void bdaddr_to_string(const uint8_t *bdaddr, char *str) {
    snprintf(str, 18, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
            bdaddr[5], bdaddr[4], bdaddr[3],
            bdaddr[2], bdaddr[1], bdaddr[0]);
}

/* Connect to the bluez management system */
int mgmt_connect() {
    int fd;
    struct sockaddr_hci addr;

    if ((fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 
                    BTPROTO_HCI)) < 0) {
        return -errno;
    }

    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = HCI_DEV_NONE;
    addr.hci_channel = HCI_CHANNEL_CONTROL;

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }
    
    return fd;
}

/* Write a request to the management socket ringbuffer, serviced by the
 * select() loop */
int mgmt_write_request(int mgmt_fd, uint16_t opcode, uint16_t index, 
        uint16_t length, const void *param) {
    bluez_mgmt_command_t *cmd;
    size_t pksz = sizeof(bluez_mgmt_command_t) + length;
    ssize_t written_sz;

    if (opcode == 0) {
        return -1;
    }

    if (length > 0 && param == NULL) {
        return -1;
    }

    cmd = (bluez_mgmt_command_t *) malloc(pksz);

    cmd->opcode = htole16(opcode);
    cmd->index = htole16(index);
    cmd->length = htole16(length);

    if (length != 0 && param != NULL) {
        memcpy(cmd->param, param, length);
    }

    if ((written_sz = send(mgmt_fd, cmd, pksz, 0)) < 0) {
        fprintf(stderr, "FATAL - Failed to send to mgmt sock %d: %s\n",
                mgmt_fd, strerror(errno));
        free(cmd);
        exit(1);
    }

    free(cmd);

    return 1;
}

/* Initiate finding a device */
int cmd_start_discovery(local_bluetooth_t *localbt) {
    struct mgmt_cp_start_discovery cp;

    memset(&cp, 0, sizeof(cp));
    cp.type = localbt->scan_type;

    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_START_DISCOVERY, 
            localbt->devid, sizeof(cp), &cp);
}

/* Probe the controller */
int cmd_get_controller_info(local_bluetooth_t *localbt) {
    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_READ_INFO, localbt->devid, 0, NULL);
}

int cmd_enable_controller(local_bluetooth_t *localbt) {
    uint8_t val = 0x1;

    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_SET_POWERED, localbt->devid, 
            sizeof(val), &val);
}

/* Handle controller info response */
void resp_controller_info(local_bluetooth_t *localbt, uint8_t status, uint16_t len, 
        const void *param) {
    const struct mgmt_rp_read_info *rp = (struct mgmt_rp_read_info *) param;
    char bdaddr[BDADDR_STR_LEN];

    if (len < sizeof(struct mgmt_rp_read_info)) {
        return;
    }

    bdaddr_to_string(rp->bdaddr.b, bdaddr);

    /* Figure out if we support BDR/EDR and BTLE */
    if (!(rp->supported_settings & MGMT_SETTING_BREDR)) {
        localbt->scan_type &= ~SCAN_TYPE_BREDR;
    }

    if (!(rp->supported_settings & MGMT_SETTING_LE)) {
        localbt->scan_type &= ~SCAN_TYPE_LE;
    }

    /* Is it currently powered? */
    if (!(rp->current_settings & MGMT_SETTING_POWERED)) {
        /* If the interface is off, turn it on */
        cmd_enable_controller(localbt);
    } else {
        /* If the interface is on, start scanning */
        cmd_start_discovery(localbt);
    }
}

void resp_controller_power(local_bluetooth_t *localbt, uint8_t status, uint16_t len,
        const void *param) {
    uint32_t *settings = (uint32_t *) param;
    char errstr[STATUS_MAX];

    if (len < sizeof(uint32_t)) {
        return;
    }

    if (*settings & MGMT_SETTING_POWERED) {
        /* Initiate scanning mode */
        cmd_start_discovery(localbt);
    } else {
        snprintf(errstr, STATUS_MAX, "Interface %s failed to power on",
                localbt->bt_interface);
        cf_send_error(localbt->caph, errstr);
        return;
    }
}

void evt_controller_discovering(local_bluetooth_t *localbt, uint16_t len, const void *param) {
    struct mgmt_ev_discovering *dsc = (struct mgmt_ev_discovering *) param;

    if (len < sizeof(struct mgmt_ev_discovering)) {
        return;
    }

    if (!dsc->discovering) {
        cmd_start_discovery(localbt);
    }

}

static char *eir_get_name(const uint8_t *eir, uint16_t eir_len) {
    uint8_t parsed = 0;

    if (eir_len < 2)
        return NULL;

    while (parsed < eir_len - 1) {
        uint8_t field_len = eir[0];

        if (field_len == 0)
            break;

        parsed += field_len + 1;

        if (parsed > eir_len)
            break;

        /* Check for short of complete name */
        if (eir[1] == 0x09 || eir[1] == 0x08)
            return strndup((char *) &eir[2], field_len - 1);

        eir += field_len + 1;
    }

    return NULL;
}

static unsigned int eir_get_flags(const uint8_t *eir, uint16_t eir_len) {
    uint8_t parsed = 0;

    if (eir_len < 2)
        return 0;

    while (parsed < eir_len - 1) {
        uint8_t field_len = eir[0];

        if (field_len == 0)
            break;

        parsed += field_len + 1;

        if (parsed > eir_len)
            break;

        /* Check for flags */
        if (eir[1] == 0x01)
            return eir[2];

        eir += field_len + 1;
    }

    return 0;
}

/* Actual device found in scan trigger */
void evt_device_found(local_bluetooth_t *localbt, uint16_t len, const void *param) {
    struct mgmt_ev_device_found *dev = (struct mgmt_ev_device_found *) param;

    if (len < sizeof(struct mgmt_ev_device_found)) {
        return;
    }

    cf_send_btdevice(localbt, dev);
}

void handle_mgmt_response(local_bluetooth_t *localbt) {
    /* Top-level command */
    bluez_mgmt_command_t *evt;

    /* Buffer loading sizes */
    size_t bufsz;
    size_t peekedsz;

    /* Interpreted codes from response */
    uint16_t ropcode;
    uint16_t rlength;
    uint16_t rindex;

    /* Nested records */
    struct mgmt_ev_cmd_complete *crec;
    struct mgmt_ev_cmd_status *cstat;

    /* caph */
    char errstr[STATUS_MAX];

    while ((bufsz = kis_simple_ringbuf_used(localbt->read_rbuf)) >= 
            sizeof(bluez_mgmt_command_t)) {
        evt = (bluez_mgmt_command_t *) malloc(bufsz);

        if ((peekedsz = kis_simple_ringbuf_peek(localbt->read_rbuf, (void *) evt, bufsz)) < 
                sizeof(bluez_mgmt_command_t)) {
            free(evt);
            return;
        }

        ropcode = le16toh(evt->opcode);
        rindex = le16toh(evt->index);
        rlength = le16toh(evt->length);

        if (rlength + sizeof(bluez_mgmt_command_t) > peekedsz) {
            free(evt);
            return;
        }

        /* Consume this object from the buffer */
        kis_simple_ringbuf_read(localbt->read_rbuf, NULL, 
                sizeof(bluez_mgmt_command_t) + rlength);

        /* Ignore events not for us */
        if (rindex != localbt->devid) {
            continue;
        }

        if (ropcode == MGMT_EV_CMD_COMPLETE) {
            if (rlength < sizeof(struct mgmt_ev_cmd_complete)) {
                free(evt);
                continue;
            }

            crec = (struct mgmt_ev_cmd_complete *) evt->param;

            ropcode = le16toh(crec->opcode);

            /* Handle the different opcodes */
            switch (ropcode) {
                case MGMT_OP_READ_INFO:
                    resp_controller_info(localbt, crec->status, 
                            rlength - sizeof(struct mgmt_ev_cmd_complete),
                            crec->data);
                    break;
                case MGMT_OP_SET_POWERED:
                    resp_controller_power(localbt, crec->status,
                            rlength - sizeof(struct mgmt_ev_cmd_complete),
                            crec->data);
                    break;
                default:
                    break;
            }
        } else if (ropcode == MGMT_EV_CMD_STATUS) {
            /* fprintf(stderr, "DEBUG - command status hci%u len %u\n", rindex, rlength); */
        } else {
            switch (ropcode) {
                case MGMT_EV_DISCOVERING:
                    evt_controller_discovering(localbt, 
                            rlength - sizeof(bluez_mgmt_command_t),
                            evt->param);
                    break;
                case MGMT_EV_DEVICE_FOUND:
                    evt_device_found(localbt,
                            rlength - sizeof(bluez_mgmt_command_t),
                            evt->param);
                    break;
                case MGMT_EV_INDEX_REMOVED:
                    /* we only get here if rindex matches, so we know our own 
                     * device got removed */
                    snprintf(errstr, STATUS_MAX, 
                            "Bluetooth interface hci%u was removed", rindex);
                    cf_send_error(localbt->caph, errstr);
                    break;

                default:
                    break;
            }
        }

        /* Dump the temp object */
        free(evt);
    }
}


int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, simple_cap_proto_frame_t *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    uint8_t hwaddr[6];

    int hci_sock;
    int devid;
    static struct hci_dev_info di;

    int x;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (sscanf(interface, "hci%u", &devid) != 1) {
        free(interface);
        return 0;
    }

    if ((hci_sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
        free(interface);
        return 0;
    }

    di.dev_id = devid;

    if (ioctl(hci_sock, HCIGETDEVINFO, (void *) &di)) {
        free(interface);
        return 0;
    }

    free(interface);
    close(hci_sock);

    for (x = 0; x < 6; x++)
        hwaddr[5 - x] = di.bdaddr.b[x];

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the mac address of the device */
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
            adler32_csum((unsigned char *) "kismet_cap_linux_bluetooth", 
                strlen("kismet_cap_linux_bluetooth")) & 0xFFFFFFFF,
            hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
            hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
    *uuid = strdup(errstr);
    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, char ***interfaces, char ***flags) {
    DIR *devdir;
    struct dirent *devfile;

    /* Basic list of devices */
    typedef struct bt_list {
        char *device;
        char *flags;
        struct bt_list *next;
    } bt_list_t; 

    bt_list_t *devs = NULL;
    size_t num_devs = 0;

    unsigned int i;

    if ((devdir = opendir("/sys/class/bluetooth/")) == NULL) {
        /* Not an error, just nothing to do */
        *interfaces = NULL;
        *flags = NULL;
        return 0;
    }

    /* Look at the files in the sys dir and see if they're wi-fi */
    while ((devfile = readdir(devdir)) != NULL) {
        /* AFAIK every hciX device in the /sys/class/bluetooth dir is a bluetooth
         * controller */
        unsigned int idx;
        if (sscanf(devfile->d_name, "hci%u", &idx) == 1) {
            bt_list_t *d = (bt_list_t *) malloc(sizeof(bt_list_t));
            num_devs++;
            d->device = strdup(devfile->d_name);
            d->flags = NULL;
            d->next = devs;
            devs = d;
        }
    }

    closedir(devdir);

    if (num_devs == 0) {
        *interfaces = NULL;
        *flags = NULL;
        return 0;
    }

    *interfaces = (char **) malloc(sizeof(char *) * num_devs);
    *flags = (char **) malloc(sizeof(char *) * num_devs);

    i = 0;

    while (devs != NULL) {
        bt_list_t *td = devs->next;
        (*interfaces)[i] = devs->device;
        (*flags)[i] = devs->flags;

        free(devs);
        devs = td;

        i++;
    }

    return num_devs;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, simple_cap_proto_frame_t *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    uint8_t hwaddr[6];
    char textaddr[18];

    int hci_sock;
    int devid;
    static struct hci_dev_info di;

    int x;

    local_bluetooth_t *localbt = (local_bluetooth_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (sscanf(interface, "hci%u", &devid) != 1) {
        snprintf(msg, STATUS_MAX, "Unable to parse device id");
        free(interface);
        return 0;
    }

    if ((hci_sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
        snprintf(msg, STATUS_MAX, "Unable to connect HCI socket: %s",
                strerror(errno));
        free(interface);
        return 0;
    }

    di.dev_id = devid;
    localbt->devid = devid;

    if (ioctl(hci_sock, HCIGETDEVINFO, (void *) &di)) {
        snprintf(msg, STATUS_MAX, "Unable to get device info: %s", 
                strerror(errno));
        free(interface);
        return 0;
    }

    if (localbt->bt_interface != NULL)
        free(localbt->bt_interface);
    localbt->bt_interface = strdup(interface);

    free(interface);
    close(hci_sock);

    for (x = 0; x < 6; x++)
        hwaddr[5 - x] = di.bdaddr.b[x];

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the mac address of the device */
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
            adler32_csum((unsigned char *) "kismet_cap_linux_bluetooth", 
                strlen("kismet_cap_linux_bluetooth")) & 0xFFFFFFFF,
            hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
            hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
    *uuid = strdup(errstr);

    snprintf(textaddr, 18, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
            di.bdaddr.b[5], di.bdaddr.b[4], di.bdaddr.b[3],
            di.bdaddr.b[2], di.bdaddr.b[1], di.bdaddr.b[0]);

    if (localbt->bt_interface_str_address != NULL)
        free(localbt->bt_interface_str_address);

    memcpy(localbt->bt_interface_address, di.bdaddr.b, 6);
    localbt->bt_interface_str_address = strdup(textaddr);

    if (linux_sys_get_bt_rfkill(localbt->bt_interface, LINUX_BT_RFKILL_TYPE_HARD)) {
        snprintf(msg, STATUS_MAX, "Bluetooth interface %s is hard blocked by rfkill, "
                "check your physical radio switch", localbt->bt_interface);
        return -1;
    }

    if (linux_sys_get_bt_rfkill(localbt->bt_interface, LINUX_BT_RFKILL_TYPE_SOFT)) {
        if (linux_sys_clear_bt_rfkill(localbt->bt_interface) < 0) {
            snprintf(msg, STATUS_MAX, "Bluetooth interface %s is soft blocked by rfkill, "
                    "and we were unable to unblock it", localbt->bt_interface);
            return -1;
        } else {
            snprintf(errstr, STATUS_MAX, "Bluetooth interface %s was blocked by "
                    "rfkill, activated it", localbt->bt_interface);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
        }
    }

    (*ret_interface)->capif = strdup(localbt->bt_interface);

    if (localbt->mgmt_fd > 0)
        close(localbt->mgmt_fd);

    if ((localbt->mgmt_fd = mgmt_connect()) < 0) {
        snprintf(errstr, STATUS_MAX, "Could not connect to kernel bluez management socket: %s",
                strerror(-(localbt->mgmt_fd)));
        return -1;
    }

    /* Set up our ringbuffers */
    if (localbt->read_rbuf)
        kis_simple_ringbuf_free(localbt->read_rbuf);

    localbt->read_rbuf = kis_simple_ringbuf_create(4096);

    if (localbt->read_rbuf == NULL) {
        snprintf(errstr, STATUS_MAX, "Could not allocate ringbuffers");
        close(localbt->mgmt_fd);
        return -1;
    }

    cmd_get_controller_info(localbt);

    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_bluetooth_t *localbt = (local_bluetooth_t *) caph->userdata;

    /* Ringbuffer and select mgmt stuff */
    fd_set rset;
    struct timeval tm;
    char errstr[STATUS_MAX];

    while (1) {
        if (caph->spindown) {
            close(localbt->mgmt_fd);
            localbt->mgmt_fd = -1;

            kis_simple_ringbuf_free(localbt->read_rbuf);
            localbt->read_rbuf = NULL;
            break;
        }

        FD_ZERO(&rset);

        tm.tv_sec = 0;
        tm.tv_usec = 100000;

        /* Always set read buffer */
        FD_SET(localbt->mgmt_fd, &rset);

        if (select(localbt->mgmt_fd + 1, &rset, NULL, NULL, &tm) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                fprintf(stderr, "FATAL: Select failed %s\n", strerror(errno));
                exit(1);
            }

            continue;
        }

        if (FD_ISSET(localbt->mgmt_fd, &rset)) {
            while (kis_simple_ringbuf_available(localbt->read_rbuf)) {
                ssize_t amt_read;
                size_t amt_buffered;
                uint8_t rbuf[512];

                if ((amt_read = read(localbt->mgmt_fd, rbuf, 512)) <= 0) {
                    if (errno != EINTR && errno != EAGAIN) {
                        snprintf(errstr, STATUS_MAX, "Failed to read from "
                                "management socket: %s", strerror(errno));
                        cf_send_error(caph, errstr);
                        break;
                    } else {
                        break;
                    }
                }

                amt_buffered = kis_simple_ringbuf_write(localbt->read_rbuf, rbuf, amt_read);

                if ((ssize_t) amt_buffered != amt_read) {
                    snprintf(errstr, STATUS_MAX, "Failed to put management data into buffer");
                    cf_send_error(caph, errstr);
                    break;
                }

                handle_mgmt_response(localbt);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    local_bluetooth_t localbt = {
        .bt_interface = NULL,
        .bt_interface_str_address = NULL,
        .devid = 0,
        .mgmt_fd = 0,
        .read_rbuf = NULL,
        .scan_type = SCAN_TYPE_DUAL,
        .caph = NULL,
    };

    kis_capture_handler_t *caph = cf_handler_init("linuxbluetooth");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localbt.caph = caph;

    /* Jail our ns */
    if (cf_jail_filesystem(caph) < 1) {
        fprintf(stderr, "DEBUG - Couldn't jail filesystem\n");
    }

    /* Strip our privs */
    if (cf_drop_most_caps(caph) < 1) {
        fprintf(stderr, "DEBUG - Didn't drop some privs\n");
    }

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localbt);

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

    cf_handler_loop(caph);

    return 0;
}

