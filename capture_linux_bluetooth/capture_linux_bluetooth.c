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
 * capsource packet, using the bluetooth protobuf entry
 */

#include "../config.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/signalfd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>

#include "mgmtlib/bluetooth.h"
#include "mgmtlib/hci.h"
#include "mgmtlib/hci_lib.h"
#include "mgmtlib/mgmt.h"

#include "linux_bt_rfkill.h"
#include "bt_probe.h"

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

    /* Controller is discovering, and when we last tried to set it up */
    int discovering;
    time_t last_setup;

    /* Active probing, see bt_probe.h.  The settings change from the command thread
     * under probe_mutex; everything else belongs to the capture thread */
    pthread_mutex_t probe_mutex;
    bt_probe_mode_t probe_mode;
    unsigned int probe_interval;
    int probe_status_dirty;

    bt_probe_state_t *probe;
    int hci_fd;

    /* The probe in flight; the have_ flags are 1 read, -1 refused, 0 waiting */
    int probe_active;
    bt_probe_target_t probe_target;
    time_t probe_start;
    int probe_le_ext;
    int probe_tried_ext;
    int probe_connected;
    uint16_t probe_handle;
    int probe_have_version, probe_have_features;
    uint8_t probe_version;
    uint16_t probe_manuf, probe_subversion;
    uint8_t probe_features[8];

    unsigned long probes_done;
    time_t probe_last_end;
    time_t probe_last_status;

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
static char *eir_get_uuids_json(const uint8_t *eir, uint16_t eir_len);
static void eir_get_manuf(const uint8_t *eir, uint16_t eir_len,
        char **out_company_id_hex, char **out_data_hex);
static char *eir_get_service_data_json(const uint8_t *eir, uint16_t eir_len);
static int eir_get_txpower(const uint8_t *eir, uint16_t eir_len, int8_t *out_txpower);
static const uint8_t *eir_get_field(const uint8_t *eir, uint16_t eir_len, uint8_t type,
        uint8_t data_len);
static void probe_device_found(local_bluetooth_t *localbt, struct mgmt_ev_device_found *dev);
void bdaddr_to_string(const uint8_t *bdaddr, char *str);

int cf_send_btjson(local_bluetooth_t *localbt, struct mgmt_ev_device_found *dev) {
    /* Room for the raw EIR as hex alongside the fields pulled out of it */
    char json[16384];
    char *eir_hex;

    char address[BDADDR_STR_LEN];
    char *name, *safe_name = NULL;
    char *uuids_json;
    char *service_data_json;
    char *manuf_company_id_hex, *manuf_data_hex;
    char txpower_json[8];
    unsigned int i;
    char class_json[16];
    char appearance_json[8];
    const uint8_t *field;
    int8_t txpower;
    uint16_t eirlen;

    int r;

    struct timeval tv;

    gettimeofday(&tv, 0);

    /* convert the address */
    bdaddr_to_string(dev->addr.bdaddr.b, address);

    /* Extract the name from EIR */
    eirlen = le16toh(dev->eir_len);
    name = eir_get_name(dev->eir, eirlen);

    if (name != NULL)
        safe_name = json_sanitize_string(name);

    if (safe_name == NULL)
        safe_name = strdup("");

    /* Same EIR buffer works for both classic and LE scans; no need to
     * branch on dev->addr.type here. */
    uuids_json = eir_get_uuids_json(dev->eir, eirlen);
    service_data_json = eir_get_service_data_json(dev->eir, eirlen);
    eir_get_manuf(dev->eir, eirlen, &manuf_company_id_hex, &manuf_data_hex);

    if (eir_get_txpower(dev->eir, eirlen, &txpower))
        snprintf(txpower_json, sizeof(txpower_json), "%d", txpower);
    else
        snprintf(txpower_json, sizeof(txpower_json), "null");

    /* Class of device (BR/EDR, the kernel adds it from the inquiry result) and
     * appearance, both little endian */
    if ((field = eir_get_field(dev->eir, eirlen, 0x0D, 3)) != NULL)
        snprintf(class_json, sizeof(class_json), "%u",
                (unsigned int) field[0] | ((unsigned int) field[1] << 8) |
                ((unsigned int) field[2] << 16));
    else
        snprintf(class_json, sizeof(class_json), "null");

    if ((field = eir_get_field(dev->eir, eirlen, 0x19, 2)) != NULL)
        snprintf(appearance_json, sizeof(appearance_json), "%u",
                (unsigned int) field[0] | ((unsigned int) field[1] << 8));
    else
        snprintf(appearance_json, sizeof(appearance_json), "null");

    /* All of the EIR for the server to decode, unless it's implausibly long */
    eir_hex = (char *) malloc((size_t) (eirlen <= 2048 ? eirlen : 0) * 2 + 1);
    if (eir_hex == NULL) {
        free(uuids_json);
        free(service_data_json);
        free(manuf_company_id_hex);
        free(manuf_data_hex);
        if (safe_name != name)
            free(safe_name);
        free(name);
        return -1;
    }

    eir_hex[0] = '\0';
    if (eirlen <= 2048)
        for (i = 0; i < eirlen; i++)
            snprintf(eir_hex + i * 2, 3, "%02x", dev->eir[i]);

    r = snprintf(json, sizeof(json), "{"
            "\"addr\": \"%s\","
            "\"name\": \"%s\","
            "\"type\": %u,"
            "\"connectable\": %u,"
            "\"service_uuids\": %s,"
            "\"service_data\": %s,"
            "\"manuf_company_id\": \"%s\","
            "\"manuf_data\": \"%s\","
            "\"txpower\": %s,"
            "\"class\": %s,"
            "\"appearance\": %s,"
            "\"eir\": \"%s\""
            "}",
            address, safe_name, dev->addr.type, (dev->flags & 0x04) ? 0 : 1,
            uuids_json,
            service_data_json,
            manuf_company_id_hex != NULL ? manuf_company_id_hex : "",
            manuf_data_hex != NULL ? manuf_data_hex : "",
            txpower_json, class_json, appearance_json, eir_hex);

    free(eir_hex);

    if (safe_name != name) {
        free(safe_name);
    }

    if (name != NULL) {
        free(name);
    }

    free(uuids_json);
    free(service_data_json);
    if (manuf_company_id_hex != NULL)
        free(manuf_company_id_hex);
    if (manuf_data_hex != NULL)
        free(manuf_data_hex);

    /* A truncated report isn't valid JSON */
    if (r < 0 || (size_t) r >= sizeof(json))
        return 0;

    /* Pass RSSI from management event to Kismet via signal params */
    struct cf_params_signal sig;
    memset(&sig, 0, sizeof(sig));
    sig.signal_dbm = (int8_t) dev->rssi;
    sig.freq_khz = 2400000;

    while (1) {
        if ((r = cf_send_json(localbt->caph, NULL, 0, &sig, NULL, tv, "linuxbthci", json)) < 0) {
            cf_send_error(localbt->caph, 0, "unable to send JSON frame");
            cf_handler_spindown(localbt->caph);
            break;
        } else if (r == 0) {
            cf_handler_wait_ringbuffer(localbt->caph);
        } else {
            break;
        }
    }

    return 0;
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

    if (cmd == NULL)
        return -1;

    cmd->opcode = htole16(opcode);
    cmd->index = htole16(index);
    cmd->length = htole16(length);

    if (length != 0 && param != NULL) {
        memcpy(cmd->param, param, length);
    }

    /* the socket is non-blocking; a failed command is retried by the setup loop */
    if ((written_sz = send(mgmt_fd, cmd, pksz, 0)) < 0) {
        fprintf(stderr, "ERROR - Failed to send to mgmt sock %d: %s\n",
                mgmt_fd, strerror(errno));
        free(cmd);
        return -1;
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

/* Enable BREDR */
int cmd_enable_bredr(local_bluetooth_t *localbt) {
    uint8_t val = 0x01;

    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_SET_BREDR, localbt->devid,
            sizeof(val), &val);
}

/* Enable BTLE */
int cmd_enable_btle(local_bluetooth_t *localbt) {
    uint8_t val = 0x01;

    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_SET_LE, localbt->devid,
            sizeof(val), &val);
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

    uint32_t current, supported;

    if (len < sizeof(struct mgmt_rp_read_info)) {
        return;
    }

    bdaddr_to_string(rp->bdaddr.b, bdaddr);

    current = le32toh(rp->current_settings);
    supported = le32toh(rp->supported_settings);

    /* Figure out if we support BDR/EDR and BTLE */
    if (!(supported & MGMT_SETTING_BREDR)) {
        localbt->scan_type &= ~SCAN_TYPE_BREDR;
    }

    if (!(supported & MGMT_SETTING_LE)) {
        localbt->scan_type &= ~SCAN_TYPE_LE;
    }

    /* Is BREDR enabled? If not, turn it on */
    if ((supported & MGMT_SETTING_BREDR) && !(current & MGMT_SETTING_BREDR)) {
        cmd_enable_bredr(localbt);
        return;
    }

    /* Is BLE enabled? If not, turn it on */
    if ((supported & MGMT_SETTING_LE) && !(current & MGMT_SETTING_LE)) {
        cmd_enable_btle(localbt);
        return;
    }

    /* Is it currently powered? */
    if (!(current & MGMT_SETTING_POWERED)) {
        /* If the interface is off, turn it on */
        cmd_enable_controller(localbt);
        return;
    }

    /* If the interface is on, start scanning */
    cmd_start_discovery(localbt);
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
        cf_send_error(localbt->caph, 0, errstr);
        return;
    }
}

void evt_controller_discovering(local_bluetooth_t *localbt, uint16_t len, const void *param) {
    struct mgmt_ev_discovering *dsc = (struct mgmt_ev_discovering *) param;

    if (len < sizeof(struct mgmt_ev_discovering)) {
        return;
    }

    localbt->discovering = dsc->discovering;

    if (!dsc->discovering) {
        cmd_start_discovery(localbt);
    }

}

static char *eir_get_name(const uint8_t *eir, uint16_t eir_len) {
    uint16_t parsed = 0;

    if (eir_len < 2)
        return NULL;

    while (parsed < eir_len - 1) {
        uint16_t field_len = eir[0];

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

/* Builds a JSON array of every 16/32/128-bit service UUID (AD types
 * 0x02-0x07) found in an EIR/AD buffer. Returns a malloc'd string the
 * caller must free ("[]" if none found or eir_len too short). */
static char *eir_get_uuids_json(const uint8_t *eir, uint16_t eir_len) {
    uint16_t parsed = 0;
    char *out = malloc(4096);
    size_t out_pos = 0;
    int first = 1;
    /* Longest entry (comma + quoted dashed 128-bit uuid) is 39 bytes;
     * checked before every write so out_pos can never pass what snprintf
     * actually wrote, even with LE Extended Advertising's larger AD data. */
    const size_t max_entry = 40;

    out[out_pos++] = '[';

    if (eir_len >= 2) {
        while (parsed < eir_len - 1) {
            uint8_t field_len = eir[0];
            uint8_t ad_type;
            const uint8_t *payload;
            uint8_t payload_len;
            int i;

            if (field_len == 0)
                break;

            parsed += field_len + 1;
            if (parsed > eir_len)
                break;

            ad_type = eir[1];
            payload = eir + 2;
            payload_len = field_len - 1;

            if (ad_type == 0x02 || ad_type == 0x03) {
                for (i = 0; i + 2 <= payload_len; i += 2) {
                    uint16_t val;
                    if (out_pos + max_entry >= 4096)
                        goto done;
                    val = payload[i] | ((uint16_t) payload[i + 1] << 8);
                    out_pos += snprintf(out + out_pos, 4096 - out_pos,
                            "%s\"%04x\"", first ? "" : ",", val);
                    first = 0;
                }
            } else if (ad_type == 0x04 || ad_type == 0x05) {
                for (i = 0; i + 4 <= payload_len; i += 4) {
                    uint32_t val;
                    if (out_pos + max_entry >= 4096)
                        goto done;
                    val = payload[i] | ((uint32_t) payload[i + 1] << 8) |
                        ((uint32_t) payload[i + 2] << 16) | ((uint32_t) payload[i + 3] << 24);
                    out_pos += snprintf(out + out_pos, 4096 - out_pos,
                            "%s\"%08x\"", first ? "" : ",", val);
                    first = 0;
                }
            } else if (ad_type == 0x06 || ad_type == 0x07) {
                /* 128-bit UUIDs are on-air little-endian; reverse then
                 * dash into RFC 4122 canonical form. */
                for (i = 0; i + 16 <= payload_len; i += 16) {
                    char hex[33];
                    int b;
                    if (out_pos + max_entry >= 4096)
                        goto done;
                    for (b = 0; b < 16; b++)
                        snprintf(hex + b * 2, 3, "%02x", payload[i + 15 - b]);
                    out_pos += snprintf(out + out_pos, 4096 - out_pos,
                            "%s\"%.8s-%.4s-%.4s-%.4s-%.12s\"",
                            first ? "" : ",", hex, hex + 8, hex + 12, hex + 16, hex + 20);
                    first = 0;
                }
            }

            eir += field_len + 1;
        }
    }

done:
    if (out_pos < 4095)
        out[out_pos++] = ']';
    out[out_pos] = '\0';

    return out;
}

/* Extracts Manufacturer Specific Data (AD type 0xFF) from an EIR/AD
 * buffer: first 2 bytes are the little-endian company ID, the rest is
 * the payload. *out_company_id_hex and *out_data_hex are malloc'd strings
 * the caller must free, both NULL if none found. Only the first match is
 * used; a device practically never sends more than one. */
static void eir_get_manuf(const uint8_t *eir, uint16_t eir_len,
        char **out_company_id_hex, char **out_data_hex) {
    uint16_t parsed = 0;

    *out_company_id_hex = NULL;
    *out_data_hex = NULL;

    if (eir_len < 2)
        return;

    while (parsed < eir_len - 1) {
        uint8_t field_len = eir[0];

        if (field_len == 0)
            break;

        parsed += field_len + 1;
        if (parsed > eir_len)
            break;

        if (eir[1] == 0xFF && field_len >= 3) {
            uint16_t company_id = eir[2] | ((uint16_t) eir[3] << 8);
            size_t payload_len = field_len - 3;
            char *company_hex = malloc(5);
            char *data_hex = malloc(payload_len * 2 + 1);
            size_t i;

            snprintf(company_hex, 5, "%04x", company_id);
            for (i = 0; i < payload_len; i++)
                snprintf(data_hex + i * 2, 3, "%02x", eir[4 + i]);
            data_hex[payload_len * 2] = '\0';

            *out_company_id_hex = company_hex;
            *out_data_hex = data_hex;
            return;
        }

        eir += field_len + 1;
    }
}

/* The TX Power Level record, the radiated power in dBm; returns 1 if present */
static int eir_get_txpower(const uint8_t *eir, uint16_t eir_len, int8_t *out_txpower) {
    uint16_t parsed = 0;

    while (parsed + 2 <= eir_len) {
        uint8_t field_len = eir[parsed];

        if (field_len == 0 || parsed + 1 + field_len > eir_len)
            break;

        if (eir[parsed + 1] == 0x0A && field_len == 2) {
            *out_txpower = (int8_t) eir[parsed + 2];
            return 1;
        }

        parsed += field_len + 1;
    }

    return 0;
}

/* The data of the first EIR record of a type, when it has exactly data_len bytes */
static const uint8_t *eir_get_field(const uint8_t *eir, uint16_t eir_len, uint8_t type,
        uint8_t data_len) {
    uint16_t parsed = 0;

    while (parsed + 2 <= eir_len) {
        uint8_t field_len = eir[parsed];

        if (field_len == 0 || parsed + 1 + field_len > eir_len)
            break;

        if (eir[parsed + 1] == type)
            return field_len == data_len + 1 ? &eir[parsed + 2] : NULL;

        parsed += field_len + 1;
    }

    return NULL;
}

/* 16-bit UUID service data records (such as Remote ID) as a JSON array of hex
 * strings, each the UUID followed by the data */
static char *eir_get_service_data_json(const uint8_t *eir, uint16_t eir_len) {
    /* Worst case every byte becomes 2 hex chars, plus quoting and commas */
    size_t bufsz = (size_t) eir_len * 4 + 3;
    char *ret = malloc(bufsz);
    size_t pos = 0;
    uint16_t parsed = 0;
    int first = 1;

    if (ret == NULL)
        return strdup("[]");

    ret[pos++] = '[';

    while (eir_len >= 2 && parsed < eir_len - 1) {
        uint8_t field_len = eir[0];
        size_t i;

        if (field_len == 0)
            break;

        parsed += field_len + 1;
        if (parsed > eir_len)
            break;

        if (eir[1] == 0x16 && field_len >= 3) {
            if (!first)
                ret[pos++] = ',';
            first = 0;

            ret[pos++] = '"';
            for (i = 0; i < (size_t) field_len - 1; i++) {
                snprintf(ret + pos, 3, "%02x", eir[2 + i]);
                pos += 2;
            }
            ret[pos++] = '"';
        }

        eir += field_len + 1;
    }

    ret[pos++] = ']';
    ret[pos] = '\0';

    return ret;
}

/* Actual device found in scan trigger */
void evt_device_found(local_bluetooth_t *localbt, uint16_t len, const void *param) {
    struct mgmt_ev_device_found *dev = (struct mgmt_ev_device_found *) param;

    if (len < sizeof(struct mgmt_ev_device_found)) {
        return;
    }

    /* The EIR data has to fit in the event */
    if (le16toh(dev->eir_len) > len - sizeof(struct mgmt_ev_device_found)) {
        return;
    }

    cf_send_btjson(localbt, dev);

    probe_device_found(localbt, dev);
}

/* Active probing.  Names are left to the kernel: answering its confirm-name
 * request with "not known" makes it resolve the name after the inquiry, and the
 * result comes back as another device found event.  Version and features need
 * a connection, made over a raw HCI socket one device at a time. */

#define PROBE_CONNECT_TIMEOUT 10
#define PROBE_TIMEOUT 20
#define PROBE_GAP 2
#define PROBE_STATUS_INTERVAL 30

#define HCI_OP(ogf, ocf) ((uint16_t) (((ogf) << 10) | (ocf)))
#define OP_CREATE_CONN          HCI_OP(0x01, 0x0005)
#define OP_DISCONNECT           HCI_OP(0x01, 0x0006)
#define OP_CREATE_CONN_CANCEL   HCI_OP(0x01, 0x0008)
#define OP_READ_REMOTE_FEATURES HCI_OP(0x01, 0x001B)
#define OP_READ_REMOTE_VERSION  HCI_OP(0x01, 0x001D)
#define OP_LE_CREATE_CONN       HCI_OP(0x08, 0x000D)
#define OP_LE_CREATE_CONN_CANCEL HCI_OP(0x08, 0x000E)
#define OP_LE_READ_REMOTE_FEATURES HCI_OP(0x08, 0x0016)
#define OP_LE_EXT_CREATE_CONN   HCI_OP(0x08, 0x0043)

static void probe_get_settings(local_bluetooth_t *localbt, bt_probe_mode_t *mode,
        unsigned int *interval) {
    pthread_mutex_lock(&localbt->probe_mutex);
    *mode = localbt->probe_mode;
    *interval = localbt->probe_interval;
    pthread_mutex_unlock(&localbt->probe_mutex);
}

static int probe_hci_cmd(local_bluetooth_t *localbt, uint16_t opcode, const uint8_t *param,
        uint8_t plen) {
    uint8_t buf[4 + 255];

    if (localbt->hci_fd < 0)
        return -1;

    buf[0] = HCI_COMMAND_PKT;
    buf[1] = opcode & 0xFF;
    buf[2] = (opcode >> 8) & 0xFF;
    buf[3] = plen;
    if (plen > 0)
        memcpy(buf + 4, param, plen);

    if (write(localbt->hci_fd, buf, 4 + (size_t) plen) != 4 + (ssize_t) plen)
        return -1;

    return 0;
}

static void probe_hci_close(local_bluetooth_t *localbt) {
    if (localbt->hci_fd >= 0)
        close(localbt->hci_fd);
    localbt->hci_fd = -1;
}

static int probe_hci_open(local_bluetooth_t *localbt) {
    struct sockaddr_hci addr;
    struct hci_filter flt;
    char errstr[STATUS_MAX];
    int fd;

    if ((fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, BTPROTO_HCI)) < 0) {
        snprintf(errstr, STATUS_MAX, "%s could not open an HCI socket for probing: %s",
                localbt->bt_interface, strerror(errno));
        cf_send_message(localbt->caph, errstr, MSGFLAG_ERROR);
        return -1;
    }

    memset(&flt, 0, sizeof(flt));
    hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
    hci_filter_set_event(EVT_CONN_COMPLETE, &flt);
    hci_filter_set_event(EVT_DISCONN_COMPLETE, &flt);
    hci_filter_set_event(EVT_READ_REMOTE_FEATURES_COMPLETE, &flt);
    hci_filter_set_event(EVT_READ_REMOTE_VERSION_COMPLETE, &flt);
    hci_filter_set_event(EVT_CMD_STATUS, &flt);
    hci_filter_set_event(EVT_LE_META_EVENT, &flt);

    if (setsockopt(fd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        snprintf(errstr, STATUS_MAX, "%s could not filter the HCI probing socket: %s",
                localbt->bt_interface, strerror(errno));
        cf_send_message(localbt->caph, errstr, MSGFLAG_ERROR);
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = localbt->devid;
    addr.hci_channel = HCI_CHANNEL_RAW;

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        snprintf(errstr, STATUS_MAX, "%s could not bind the HCI probing socket: %s",
                localbt->bt_interface, strerror(errno));
        cf_send_message(localbt->caph, errstr, MSGFLAG_ERROR);
        close(fd);
        return -1;
    }

    localbt->hci_fd = fd;

    return 0;
}

static void probe_send_json(local_bluetooth_t *localbt, const char *type, const char *json) {
    struct timeval tv;
    int r;

    gettimeofday(&tv, 0);

    while (1) {
        if ((r = cf_send_json(localbt->caph, NULL, 0, NULL, NULL, tv, type, json)) < 0) {
            cf_send_error(localbt->caph, 0, "unable to send JSON frame");
            cf_handler_spindown(localbt->caph);
            break;
        } else if (r == 0) {
            cf_handler_wait_ringbuffer(localbt->caph);
        } else {
            break;
        }
    }
}

static void probe_send_status(local_bluetooth_t *localbt) {
    bt_probe_mode_t mode;
    unsigned int interval;
    char json[256];

    probe_get_settings(localbt, &mode, &interval);

    snprintf(json, sizeof(json), "{"
            "\"probe\": \"%s\","
            "\"probe_interval\": %u,"
            "\"probes\": %lu,"
            "\"queued\": %u,"
            "\"last_probe\": %lu"
            "}",
            bt_probe_mode_str(mode), interval, localbt->probes_done,
            localbt->probe != NULL ? localbt->probe->q_len : 0,
            (unsigned long) localbt->probe_last_end);

    probe_send_json(localbt, "linuxbtprobe", json);

    localbt->probe_last_status = time(0);
}

static void probe_send_result(local_bluetooth_t *localbt) {
    char json[512];
    char address[BDADDR_STR_LEN];
    char version[96] = "";
    char features[64] = "";

    if (localbt->probe_have_version != 1 && localbt->probe_have_features != 1)
        return;

    bdaddr_to_string(localbt->probe_target.addr, address);

    if (localbt->probe_have_version == 1)
        snprintf(version, sizeof(version),
                "\"lmp_version\": %u, \"lmp_manufacturer\": %u, \"lmp_subversion\": %u,",
                localbt->probe_version, localbt->probe_manuf, localbt->probe_subversion);

    if (localbt->probe_have_features == 1)
        snprintf(features, sizeof(features),
                "\"%s\": \"%02x%02x%02x%02x%02x%02x%02x%02x\",",
                localbt->probe_target.type == BDADDR_BREDR ? "lmp_features" : "le_features",
                localbt->probe_features[0], localbt->probe_features[1],
                localbt->probe_features[2], localbt->probe_features[3],
                localbt->probe_features[4], localbt->probe_features[5],
                localbt->probe_features[6], localbt->probe_features[7]);

    snprintf(json, sizeof(json), "{"
            "\"addr\": \"%s\","
            "\"type\": %u,"
            "%s%s"
            "\"probed\": 1"
            "}",
            address, localbt->probe_target.type, version, features);

    probe_send_json(localbt, "linuxbthci", json);
}

static void probe_finish(local_bluetooth_t *localbt) {
    uint8_t p[3];

    if (!localbt->probe_active)
        return;

    if (localbt->probe_connected) {
        p[0] = localbt->probe_handle & 0xFF;
        p[1] = (localbt->probe_handle >> 8) & 0x0F;
        p[2] = 0x13;
        probe_hci_cmd(localbt, OP_DISCONNECT, p, 3);
    }

    probe_send_result(localbt);

    localbt->probe_active = 0;
    localbt->probe_connected = 0;
    localbt->probe_last_end = time(0);
    localbt->probes_done++;
}

/* Give up on the probe in flight: cancel the connection attempt or drop the link */
static void probe_abort(local_bluetooth_t *localbt) {
    if (!localbt->probe_active)
        return;

    if (!localbt->probe_connected) {
        if (localbt->probe_target.type == BDADDR_BREDR)
            probe_hci_cmd(localbt, OP_CREATE_CONN_CANCEL, localbt->probe_target.addr, 6);
        else
            probe_hci_cmd(localbt, OP_LE_CREATE_CONN_CANCEL, NULL, 0);
    }

    probe_finish(localbt);
}

static int probe_le_connect(local_bluetooth_t *localbt) {
    uint8_t p[26];
    uint8_t peer_type = localbt->probe_target.type == BDADDR_LE_RANDOM ? 1 : 0;

    if (!localbt->probe_le_ext) {
        /* scan interval and window 60 ms, connection interval 30-50 ms, timeout 5 s */
        p[0] = 0x60; p[1] = 0x00;
        p[2] = 0x60; p[3] = 0x00;
        p[4] = 0x00;
        p[5] = peer_type;
        memcpy(p + 6, localbt->probe_target.addr, 6);
        p[12] = 0x00;
        p[13] = 0x18; p[14] = 0x00;
        p[15] = 0x28; p[16] = 0x00;
        p[17] = 0x00; p[18] = 0x00;
        p[19] = 0xF4; p[20] = 0x01;
        p[21] = 0x00; p[22] = 0x00;
        p[23] = 0x00; p[24] = 0x00;
        return probe_hci_cmd(localbt, OP_LE_CREATE_CONN, p, 25);
    }

    /* Controllers driven with the extended commands refuse the legacy one */
    p[0] = 0x00;
    p[1] = 0x00;
    p[2] = peer_type;
    memcpy(p + 3, localbt->probe_target.addr, 6);
    p[9] = 0x01;
    p[10] = 0x60; p[11] = 0x00;
    p[12] = 0x60; p[13] = 0x00;
    p[14] = 0x18; p[15] = 0x00;
    p[16] = 0x28; p[17] = 0x00;
    p[18] = 0x00; p[19] = 0x00;
    p[20] = 0xF4; p[21] = 0x01;
    p[22] = 0x00; p[23] = 0x00;
    p[24] = 0x00; p[25] = 0x00;
    return probe_hci_cmd(localbt, OP_LE_EXT_CREATE_CONN, p, 26);
}

static void probe_start(local_bluetooth_t *localbt, const bt_probe_target_t *t) {
    uint8_t p[13];
    int r;

    localbt->probe_target = *t;
    localbt->probe_active = 1;
    localbt->probe_start = time(0);
    localbt->probe_connected = 0;
    localbt->probe_tried_ext = localbt->probe_le_ext;
    localbt->probe_have_version = 0;
    localbt->probe_have_features = 0;

    if (t->type == BDADDR_BREDR) {
        memcpy(p, t->addr, 6);
        /* DM1/DH1/DM3/DH3/DM5/DH5, page scan mode R2, allow role switch */
        p[6] = 0x18; p[7] = 0xCC;
        p[8] = 0x02;
        p[9] = 0x00;
        p[10] = 0x00; p[11] = 0x00;
        p[12] = 0x01;
        r = probe_hci_cmd(localbt, OP_CREATE_CONN, p, 13);
    } else {
        r = probe_le_connect(localbt);
    }

    if (r < 0)
        probe_finish(localbt);
}

static void probe_connected(local_bluetooth_t *localbt, uint16_t handle) {
    uint8_t p[2];

    localbt->probe_connected = 1;
    localbt->probe_handle = handle & 0x0FFF;

    p[0] = localbt->probe_handle & 0xFF;
    p[1] = (localbt->probe_handle >> 8) & 0x0F;

    probe_hci_cmd(localbt, OP_READ_REMOTE_VERSION, p, 2);

    if (localbt->probe_target.type == BDADDR_BREDR)
        probe_hci_cmd(localbt, OP_READ_REMOTE_FEATURES, p, 2);
    else
        probe_hci_cmd(localbt, OP_LE_READ_REMOTE_FEATURES, p, 2);
}

/* Both reads answered, either way */
static void probe_check_done(local_bluetooth_t *localbt) {
    if (localbt->probe_have_version != 0 && localbt->probe_have_features != 0)
        probe_finish(localbt);
}

static uint16_t ev_le16(const uint8_t *p) {
    return (uint16_t) (p[0] | (p[1] << 8));
}

/* One HCI event: its code and parameters */
static void probe_handle_event(local_bluetooth_t *localbt, uint8_t code, const uint8_t *ev,
        size_t len) {
    uint16_t handle, opcode;

    if (!localbt->probe_active)
        return;

    switch (code) {
        case EVT_CMD_STATUS:
            /* status, credits, opcode */
            if (len < 4 || ev[0] == 0)
                return;
            opcode = ev_le16(ev + 2);
            if (opcode == OP_LE_CREATE_CONN && !localbt->probe_tried_ext &&
                    (ev[0] == 0x01 || ev[0] == 0x0C)) {
                localbt->probe_le_ext = 1;
                localbt->probe_tried_ext = 1;
                if (probe_le_connect(localbt) < 0)
                    probe_finish(localbt);
                return;
            }
            if (opcode == OP_CREATE_CONN || opcode == OP_LE_CREATE_CONN ||
                    opcode == OP_LE_EXT_CREATE_CONN)
                probe_finish(localbt);
            return;

        case EVT_CONN_COMPLETE:
            /* status, handle, address, link type, encryption */
            if (len < 11 || localbt->probe_target.type != BDADDR_BREDR ||
                    localbt->probe_connected ||
                    memcmp(ev + 3, localbt->probe_target.addr, 6) != 0)
                return;
            if (ev[0] != 0) {
                probe_finish(localbt);
                return;
            }
            probe_connected(localbt, ev_le16(ev + 1));
            return;

        case EVT_LE_META_EVENT:
            if (len < 1)
                return;
            /* connection complete and enhanced connection complete share the head:
             * subevent, status, handle, role, peer type, peer address */
            if ((ev[0] == 0x01 && len >= 19) || (ev[0] == 0x0A && len >= 31)) {
                if (localbt->probe_target.type == BDADDR_BREDR || localbt->probe_connected ||
                        memcmp(ev + 6, localbt->probe_target.addr, 6) != 0)
                    return;
                if (ev[1] != 0) {
                    probe_finish(localbt);
                    return;
                }
                probe_connected(localbt, ev_le16(ev + 2));
                return;
            }
            /* LE read remote features complete: subevent, status, handle, features */
            if (ev[0] == 0x04 && len >= 12) {
                handle = ev_le16(ev + 2) & 0x0FFF;
                if (!localbt->probe_connected || handle != localbt->probe_handle)
                    return;
                if (ev[1] == 0) {
                    memcpy(localbt->probe_features, ev + 4, 8);
                    localbt->probe_have_features = 1;
                } else {
                    localbt->probe_have_features = -1;
                }
                probe_check_done(localbt);
            }
            return;

        case EVT_READ_REMOTE_VERSION_COMPLETE:
            /* status, handle, version, manufacturer, subversion */
            if (len < 8)
                return;
            handle = ev_le16(ev + 1) & 0x0FFF;
            if (!localbt->probe_connected || handle != localbt->probe_handle)
                return;
            if (ev[0] == 0) {
                localbt->probe_version = ev[3];
                localbt->probe_manuf = ev_le16(ev + 4);
                localbt->probe_subversion = ev_le16(ev + 6);
                localbt->probe_have_version = 1;
            } else {
                localbt->probe_have_version = -1;
            }
            probe_check_done(localbt);
            return;

        case EVT_READ_REMOTE_FEATURES_COMPLETE:
            /* status, handle, features */
            if (len < 11)
                return;
            handle = ev_le16(ev + 1) & 0x0FFF;
            if (!localbt->probe_connected || handle != localbt->probe_handle)
                return;
            if (ev[0] == 0) {
                memcpy(localbt->probe_features, ev + 3, 8);
                localbt->probe_have_features = 1;
            } else {
                localbt->probe_have_features = -1;
            }
            probe_check_done(localbt);
            return;

        case EVT_DISCONN_COMPLETE:
            /* status, handle, reason */
            if (len < 3)
                return;
            handle = ev_le16(ev + 1) & 0x0FFF;
            if (localbt->probe_connected && handle == localbt->probe_handle) {
                localbt->probe_connected = 0;
                probe_finish(localbt);
            }
            return;
    }
}

/* Each read of the raw socket is one packet: type, event code, length, parameters */
static void probe_read_hci(local_bluetooth_t *localbt) {
    uint8_t buf[260];
    ssize_t r;

    while (localbt->hci_fd >= 0) {
        r = read(localbt->hci_fd, buf, sizeof(buf));

        if (r < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                char errstr[STATUS_MAX];
                snprintf(errstr, STATUS_MAX, "%s HCI probing socket failed: %s",
                        localbt->bt_interface, strerror(errno));
                cf_send_message(localbt->caph, errstr, MSGFLAG_ERROR);
                localbt->probe_connected = 0;
                probe_finish(localbt);
                probe_hci_close(localbt);
            }
            return;
        }

        if (r == 0)
            return;

        if (r < 3 || buf[0] != HCI_EVENT_PKT || (size_t) buf[2] > (size_t) r - 3)
            continue;

        probe_handle_event(localbt, buf[1], buf + 3, buf[2]);
    }
}

/* Called from the capture loop on every pass */
static void probe_service(local_bluetooth_t *localbt) {
    bt_probe_mode_t mode;
    unsigned int interval;
    bt_probe_target_t t;
    time_t now = time(0);
    int dirty;

    pthread_mutex_lock(&localbt->probe_mutex);
    mode = localbt->probe_mode;
    interval = localbt->probe_interval;
    dirty = localbt->probe_status_dirty;
    localbt->probe_status_dirty = 0;
    pthread_mutex_unlock(&localbt->probe_mutex);
    (void) interval;

    if (mode != BT_PROBE_INFO) {
        probe_abort(localbt);
        if (localbt->probe != NULL)
            bt_probe_flush(localbt->probe);
        probe_hci_close(localbt);
    } else if (localbt->hci_fd < 0 &&
            (dirty || now - localbt->probe_last_status >= PROBE_STATUS_INTERVAL)) {
        /* a failed open is retried at the status interval, not on every pass */
        probe_hci_open(localbt);
    }

    if (localbt->probe_active) {
        if (now - localbt->probe_start >= PROBE_TIMEOUT ||
                (!localbt->probe_connected && now - localbt->probe_start >= PROBE_CONNECT_TIMEOUT))
            probe_abort(localbt);
    } else if (mode == BT_PROBE_INFO && localbt->hci_fd >= 0 && localbt->probe != NULL &&
            now - localbt->probe_last_end >= PROBE_GAP && bt_probe_next(localbt->probe, &t)) {
        probe_start(localbt, &t);
    }

    if (dirty || now - localbt->probe_last_status >= PROBE_STATUS_INTERVAL)
        probe_send_status(localbt);
}

static void probe_device_found(local_bluetooth_t *localbt, struct mgmt_ev_device_found *dev) {
    bt_probe_mode_t mode;
    unsigned int interval;
    uint32_t flags = le32toh(dev->flags);
    struct mgmt_cp_confirm_name cp;
    char *name;

    probe_get_settings(localbt, &mode, &interval);

    if (mode == BT_PROBE_OFF || localbt->probe == NULL)
        return;

    /* The kernel waits for an answer before resolving the name of a classic device */
    if (flags & MGMT_DEV_FOUND_CONFIRM_NAME) {
        name = eir_get_name(dev->eir, le16toh(dev->eir_len));

        memset(&cp, 0, sizeof(cp));
        cp.addr = dev->addr;
        cp.name_known = name != NULL ||
            !bt_probe_offer_name(localbt->probe, dev->addr.bdaddr.b, time(0), interval);

        free(name);

        mgmt_write_request(localbt->mgmt_fd, MGMT_OP_CONFIRM_NAME, localbt->devid,
                sizeof(cp), &cp);
    }

    if (mode == BT_PROBE_INFO && !(flags & MGMT_DEV_FOUND_NOT_CONNECTABLE) &&
            dev->addr.type <= BDADDR_LE_RANDOM)
        bt_probe_offer(localbt->probe, dev->addr.bdaddr.b, dev->addr.type, time(0), interval);
}

static void *probe_chantranslate(kis_capture_handler_t *caph, const char *chanstr) {
    bt_probe_setting_t *s = (bt_probe_setting_t *) malloc(sizeof(bt_probe_setting_t));
    (void) caph;

    if (s != NULL)
        bt_probe_parse_setting(chanstr, s);

    return s;
}

/* Runtime probing settings arrive as set_channel strings.  As with the cell
 * sources, every outcome returns 0: a positive return records the setting as the
 * source's channel and replays it after a reopen, and a negative one tears the
 * source down.  The status report shows what was applied. */
static int probe_chancontrol(kis_capture_handler_t *caph, uint32_t seqno, void *privchan,
        char *msg) {
    local_bluetooth_t *localbt = (local_bluetooth_t *) caph->userdata;
    bt_probe_setting_t *s = (bt_probe_setting_t *) privchan;
    (void) seqno;

    if (s == NULL) {
        snprintf(msg, STATUS_MAX, "linuxbluetooth: out of memory parsing the setting");
        return 0;
    }

    switch (s->result) {
        case BT_PROBE_SET_OK:
            break;
        case BT_PROBE_SET_UNKNOWN_KEY:
            snprintf(msg, STATUS_MAX, "%s: unknown setting; use probe=off|name|info or "
                    "probe_interval=<seconds>", localbt->bt_interface);
            cf_send_message(caph, msg, MSGFLAG_ERROR);
            return 0;
        case BT_PROBE_SET_BAD_VALUE:
            snprintf(msg, STATUS_MAX, "%s: bad value; probe takes off, name or info, and "
                    "probe_interval %u to %u seconds", localbt->bt_interface,
                    BT_PROBE_INTERVAL_MIN, BT_PROBE_INTERVAL_MAX);
            cf_send_message(caph, msg, MSGFLAG_ERROR);
            return 0;
        default:
            snprintf(msg, STATUS_MAX, "%s has no channels; its settings are "
                    "probe=off|name|info and probe_interval=<seconds>", localbt->bt_interface);
            cf_send_message(caph, msg, MSGFLAG_ERROR);
            return 0;
    }

    pthread_mutex_lock(&localbt->probe_mutex);
    if (s->has_mode)
        localbt->probe_mode = s->mode;
    if (s->has_interval)
        localbt->probe_interval = s->interval;
    localbt->probe_status_dirty = 1;
    pthread_mutex_unlock(&localbt->probe_mutex);

    if (s->has_mode)
        snprintf(msg, STATUS_MAX, "%s active probing: %s", localbt->bt_interface,
                bt_probe_mode_str(s->mode));
    else
        snprintf(msg, STATUS_MAX, "%s probes each device at most every %u seconds",
                localbt->bt_interface, s->interval);
    cf_send_message(caph, msg, MSGFLAG_INFO);

    return 0;
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
            free(evt);
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
                case MGMT_OP_START_DISCOVERY:
                    if (crec->status == 0x0A) {
                        break;
                    } else if (crec->status != 0) {
                        snprintf(errstr, STATUS_MAX,
                                "Bluetooth interface hci%u discovery failed", rindex);
                        cf_send_error(localbt->caph, 0, errstr);
                    }
                    break;
                case MGMT_OP_SET_BREDR:
                    if (crec->status != 0) {
                        snprintf(errstr, STATUS_MAX,
                                "Bluetooth interface hci%u enabling BREDR failed", rindex);
                        cf_send_error(localbt->caph, 0, errstr);
                    }

                    cmd_get_controller_info(localbt);
                    break;
                case MGMT_OP_SET_LE:
                    if (crec->status != 0) {
                        snprintf(errstr, STATUS_MAX,
                                "Bluetooth interface hci%u enabling LE failed", rindex);
                        cf_send_error(localbt->caph, 0, errstr);
                    }

                    cmd_get_controller_info(localbt);
                    break;
                default:
                    break;
            }
        } else if (ropcode == MGMT_EV_CMD_STATUS) {
            /* fprintf(stderr, "DEBUG - command status hci%u len %u\n", rindex, rlength); */
        } else {
            switch (ropcode) {
                case MGMT_EV_DISCOVERING:
                    evt_controller_discovering(localbt, rlength, evt->param);
                    break;
                case MGMT_EV_DEVICE_FOUND:
                    evt_device_found(localbt, rlength, evt->param);
                    break;
                case MGMT_EV_INDEX_REMOVED:
                    /* we only get here if rindex matches, so we know our own
                     * device got removed; a USB reset removes and re-adds it */
                    snprintf(errstr, STATUS_MAX,
                            "Bluetooth interface hci%u was removed, waiting for it to "
                            "return", rindex);
                    cf_send_message(localbt->caph, errstr, MSGFLAG_ERROR);
                    localbt->discovering = 0;
                    break;
                case MGMT_EV_INDEX_ADDED:
                    snprintf(errstr, STATUS_MAX,
                            "Bluetooth interface hci%u returned, restarting discovery",
                            rindex);
                    cf_send_message(localbt->caph, errstr, MSGFLAG_INFO);
                    cmd_get_controller_info(localbt);
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
        char *msg, char **uuid,
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
        snprintf(msg, STATUS_MAX, "Expected hciX interface, skipping");
        free(interface);
        return 0;
    }

    if ((hci_sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
        snprintf(msg, STATUS_MAX, "Unable to create a Bluetooth HCI socket to %s", interface);
        free(interface);
        return 0;
    }

    di.dev_id = devid;

    if (ioctl(hci_sock, HCIGETDEVINFO, (void *) &di)) {
        snprintf(msg, STATUS_MAX, "Unable to fetch Bluetooth device info from %s", interface);
        free(interface);
        close(hci_sock);
        return 0;
    }

    free(interface);
    close(hci_sock);

    for (x = 0; x < 6; x++)
        hwaddr[5 - x] = di.bdaddr.b[x];

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name
     * and the mac address of the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
                adler32_csum((unsigned char *) "kismet_cap_linux_bluetooth",
                    strlen("kismet_cap_linux_bluetooth")) & 0xFFFFFFFF,
                hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
                hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
        *uuid = strdup(errstr);
    }

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {
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
        return 0;
    }

    /* Look at the files in the sys dir and see if they're wi-fi */
    while ((devfile = readdir(devdir)) != NULL) {
        /* Skip aliased bluetooth controllers with hcix:y */
        unsigned int idx, idy;
        if (sscanf(devfile->d_name, "hci%u:%u", &idx, &idy) == 1) {
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
        return 0;
    }

    *interfaces =
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    while (devs != NULL) {
        bt_list_t *td = devs->next;
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        (*interfaces)[i]->interface = devs->device;
        (*interfaces)[i]->flags = devs->flags;
        (*interfaces)[i]->hardware = strdup("linuxhci");

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
        close(hci_sock);
        return 0;
    }

    if (localbt->bt_interface != NULL)
        free(localbt->bt_interface);

    char ifrename[64];
    snprintf(ifrename, 64, "hci%u", localbt->devid);
    localbt->bt_interface = strdup(ifrename);

    free(interface);
    close(hci_sock);

    for (x = 0; x < 6; x++)
        hwaddr[5 - x] = di.bdaddr.b[x];

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name
     * and the mac address of the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
                adler32_csum((unsigned char *) "kismet_cap_linux_bluetooth",
                    strlen("kismet_cap_linux_bluetooth")) & 0xFFFFFFFF,
                hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
                hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
        *uuid = strdup(errstr);
    }

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
    (*ret_interface)->hardware = strdup("linuxhci");

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

    localbt->discovering = 0;
    localbt->last_setup = time(0);

    /* Probing is off unless the source line asks for it */
    {
        bt_probe_mode_t mode = BT_PROBE_OFF;
        unsigned int interval = BT_PROBE_INTERVAL_DEFAULT;

        if ((placeholder_len = cf_find_flag(&placeholder, "probe", definition)) > 0 &&
                !bt_probe_parse_mode(placeholder, placeholder_len, &mode)) {
            snprintf(msg, STATUS_MAX, "Invalid probe= option, expected off, name or info");
            return -1;
        }

        if ((placeholder_len = cf_find_flag(&placeholder, "probe_interval", definition)) > 0 &&
                !bt_probe_parse_interval(placeholder, placeholder_len, &interval)) {
            snprintf(msg, STATUS_MAX, "Invalid probe_interval= option, expected %u to %u "
                    "seconds", BT_PROBE_INTERVAL_MIN, BT_PROBE_INTERVAL_MAX);
            return -1;
        }

        if (localbt->probe == NULL &&
                (localbt->probe = (bt_probe_state_t *) malloc(sizeof(bt_probe_state_t))) == NULL) {
            snprintf(msg, STATUS_MAX, "Could not allocate probing state");
            return -1;
        }

        bt_probe_state_init(localbt->probe);

        pthread_mutex_lock(&localbt->probe_mutex);
        localbt->probe_mode = mode;
        localbt->probe_interval = interval;
        localbt->probe_status_dirty = 1;
        pthread_mutex_unlock(&localbt->probe_mutex);

        localbt->probe_active = 0;
        localbt->probe_connected = 0;
        localbt->probe_le_ext = 0;
        localbt->probe_last_end = 0;
        localbt->probe_last_status = 0;
        localbt->probes_done = 0;
        probe_hci_close(localbt);
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
            /* Drop the link or cancel the attempt, but report nothing while shutting down */
            localbt->probe_have_version = 0;
            localbt->probe_have_features = 0;
            probe_abort(localbt);
            probe_hci_close(localbt);

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

        if (localbt->hci_fd >= 0)
            FD_SET(localbt->hci_fd, &rset);

        if (select((localbt->hci_fd > localbt->mgmt_fd ? localbt->hci_fd : localbt->mgmt_fd) + 1,
                    &rset, NULL, NULL, &tm) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                snprintf(errstr, STATUS_MAX, "%s select failed: %s",
                        localbt->bt_interface, strerror(errno));
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                continue;
            }

            continue;
        }

        /* Setup can lose a race with bluetoothd after a controller reset (a busy
         * power or discovery command), so redo it until the controller is discovering */
        if (!localbt->discovering && time(0) - localbt->last_setup >= 2) {
            localbt->last_setup = time(0);
            cmd_get_controller_info(localbt);
        }

        if (localbt->hci_fd >= 0 && FD_ISSET(localbt->hci_fd, &rset))
            probe_read_hci(localbt);

        probe_service(localbt);

        if (FD_ISSET(localbt->mgmt_fd, &rset)) {
            while (kis_simple_ringbuf_available(localbt->read_rbuf)) {
                ssize_t amt_read;
                size_t amt_buffered;
                uint8_t rbuf[512];

                if ((amt_read = read(localbt->mgmt_fd, rbuf, 512)) <= 0) {
                    if (errno != EINTR && errno != EAGAIN) {
                        snprintf(errstr, STATUS_MAX, "Failed to read from "
                                "management socket: %s", strerror(errno));
                        cf_send_error(caph, 0, errstr);
                        break;
                    } else {
                        break;
                    }
                }

                amt_buffered = kis_simple_ringbuf_write(localbt->read_rbuf, rbuf, amt_read);

                if ((ssize_t) amt_buffered != amt_read) {
                    snprintf(errstr, STATUS_MAX, "Failed to put management data into buffer");
                    cf_send_error(caph, 0, errstr);
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
        .discovering = 0,
        .last_setup = 0,
        .probe_mutex = PTHREAD_MUTEX_INITIALIZER,
        .probe_mode = BT_PROBE_OFF,
        .probe_interval = BT_PROBE_INTERVAL_DEFAULT,
        .probe = NULL,
        .hci_fd = -1,
        .caph = NULL,
    };

    kis_capture_handler_t *caph = cf_handler_init("linuxbluetooth");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localbt.caph = caph;

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

    /* Runtime probing settings arrive as channel changes */
    cf_handler_set_chantranslate_cb(caph, probe_chantranslate);
    cf_handler_set_chancontrol_cb(caph, probe_chancontrol);

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

    return 0;
}
