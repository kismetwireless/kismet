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

    and the bluez-5.46 gdbus code

    Copyright (C) 2004-2011  Marcel Holtmann <marcel@holtmann.org>


    Controls a linux bluetooth interface in bluez via dbus and hci sockets
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

#include <glib.h>

#include "gdbus/gdbus.h"

#include "bluetooth.h"
#include "hci.h"

#include "linux_bt_rfkill.h"

#include "../simple_datasource_proto.h"
#include "../capture_framework.h"

/* Unique instance data passed around by capframework */
typedef struct {
    /* Target interface */
    char *bt_interface;
    char *bt_interface_address;

    /* Are we already in the middle of issuing a command? */
    int state_powering_on;
    int state_scanning_on;

    kis_capture_handler_t *caph;
} local_bluetooth_t;

/* Command data passed around during instance events */
typedef struct {
    /* Local state reference */
    local_bluetooth_t *localbt;

    /* Dbus proxy object */
    GDBusProxy *proxy;
} local_command_t;

/* Figure out if a given adapter is powered on */
static dbus_bool_t dbus_adapter_is_powered(GDBusProxy *proxy) {
    DBusMessageIter iter;
    dbus_bool_t iter_bool;

    /* Make sure the interface is powered on */
    if (!g_dbus_proxy_get_property(proxy, "Powered", &iter)) {
        /* We'll throw an error later when we try to turn it on */
        return FALSE;
    }

    dbus_message_iter_get_basic(&iter, &iter_bool);
    return iter_bool;
}

/* Figure out if a given adapter is scanning */
static dbus_bool_t dbus_adapter_is_scanning(GDBusProxy *proxy) {
    DBusMessageIter iter;
    dbus_bool_t iter_bool;

    /* Make sure the interface is powered on */
    if (!g_dbus_proxy_get_property(proxy, "Discovering", &iter)) {
        /* We'll throw an error later when we try to turn it on */
        return FALSE;
    }

    dbus_message_iter_get_basic(&iter, &iter_bool);

    return iter_bool;
}

/* Scan command callback */
static void dbus_adapter_scan_reply(DBusMessage *message, void *user_data) {
    DBusError error;
    local_command_t *cmd = (local_command_t *) user_data;
    char errstr[STATUS_MAX];

    dbus_error_init(&error);

    cmd->localbt->state_scanning_on = 0;

    if (dbus_set_error_from_message(&error, message) == TRUE) {
        snprintf(errstr, STATUS_MAX, "Unable to turn on scanning - %s: %s",
                error.name, error.message);
        cf_send_error(cmd->localbt->caph, errstr);
    }
}

static void dbus_initiate_adapter_scan(local_command_t *cmd) {
    const char *method = "StartDiscovery";

    if (cmd->localbt->state_scanning_on) {
        return;
    }

    cmd->localbt->state_scanning_on = 1;

    if (g_dbus_proxy_method_call(cmd->proxy, method, NULL,
                dbus_adapter_scan_reply, cmd, NULL) == FALSE) {
        cf_send_error(cmd->localbt->caph, "Unable to turn on discovery mode");
        return;
    }
}

static void dbus_adapter_poweron_reply(const DBusError *error, void *user_data) {
    local_command_t *cmd = (local_command_t *) user_data;
    char errstr[STATUS_MAX];

    cmd->localbt->state_powering_on = 0;

    if (dbus_error_is_set(error)) {
        snprintf(errstr, STATUS_MAX, "Unable to turn on interface power - %s:%s",
                error->name, error->message);
        cf_send_error(cmd->localbt->caph, errstr);
        return;
    }

    /* Do we need to enable scanning mode?  We probably do */
    if (!dbus_adapter_is_scanning(cmd->proxy)) {
        dbus_initiate_adapter_scan(cmd);
    }
}

static void dbus_initiate_adapter_poweron(local_command_t *cmd) {
    dbus_bool_t powered = TRUE;
    char errstr[STATUS_MAX];

    if (cmd->localbt->state_powering_on) {
        return;
    }

    cmd->localbt->state_powering_on = 1;

    if (g_dbus_proxy_set_property_basic(cmd->proxy, "Powered", DBUS_TYPE_BOOLEAN, &powered,
                dbus_adapter_poweron_reply, cmd, NULL) == FALSE) {
        snprintf(errstr, STATUS_MAX, "Unable to turn on interface power");
        cf_send_error(cmd->localbt->caph, errstr);
    }
}

/* Called when devices change; grab info about the device and print it out */
static void dbus_bt_device(GDBusProxy *proxy) {
    DBusMessageIter iter;

    const char *name = NULL;
    const char *address = NULL;
    dbus_int16_t rssi = 0;

    if (g_dbus_proxy_get_property(proxy, "Address", &iter))
        dbus_message_iter_get_basic(&iter, &address);

    if (g_dbus_proxy_get_property(proxy, "Name", &iter))
        dbus_message_iter_get_basic(&iter, &name);

    if (g_dbus_proxy_get_property(proxy, "RSSI", &iter))
        dbus_message_iter_get_basic(&iter, &rssi);

    fprintf(stderr, "DEVICE - %s (%s) %d\n", address, name, rssi);
}

/* Called whenever a dbus entity is connected (specifically, adapter and 
 * device) */
static void dbus_proxy_added(GDBusProxy *proxy, void *user_data) {
    const char *interface;
    DBusMessageIter iter;
    const char *address;
    local_bluetooth_t *localbt = (local_bluetooth_t *) user_data;
    local_command_t cmd = {
        .localbt = localbt,
        .proxy = proxy,
    };

    interface = g_dbus_proxy_get_interface(proxy);

    if (!strcmp(interface, "org.bluez.Device1")) {
        dbus_bt_device(proxy);
    } else if (!strcmp(interface, "org.bluez.Adapter1")) {
        /* We've been notified there's a new adapter; we need to compare it to our
         * desired adapter, see if it has scan enabled, and enable scan if it
         * doesn't
         */

        /* Fetch address */
        if (g_dbus_proxy_get_property(proxy, "Address", &iter)) {
            dbus_message_iter_get_basic(&iter, &address);

            /* Compare to the address we extracted for the hciX */
            if (strcmp(address, localbt->bt_interface_address)) {
                return;
            }

            /* See if adapter is powered on; if not, power it on, we'll enable
             * scanning in the poweron completion */
            if (!dbus_adapter_is_powered(proxy)) {
                dbus_initiate_adapter_poweron(&cmd);
                return;
            } 

            /* See if adapter is already scanning; if not, enable scanning */
            if (!dbus_adapter_is_scanning(proxy)) {
                dbus_initiate_adapter_scan(&cmd);
            }
        }
    }
}

/* Called when an entity is removed; if we lose our primary adapter we're
 * going to have a bad time */
static void dbus_proxy_removed(GDBusProxy *proxy, void *user_data) {
    const char *interface;
    DBusMessageIter iter;
    const char *address;
    local_bluetooth_t *localbt = (local_bluetooth_t *) user_data;
    char errstr[STATUS_MAX];

    interface = g_dbus_proxy_get_interface(proxy);

    if (!strcmp(interface, "org.bluez.Adapter1")) {
        /* Fetch address */
        if (g_dbus_proxy_get_property(proxy, "Address", &iter)) {
            dbus_message_iter_get_basic(&iter, &address);

            /* Compare to the address we extracted for the hciX */
            if (strcmp(address, localbt->bt_interface_address)) {
                return;
            }

            snprintf(errstr, STATUS_MAX, "Bluetooth interface removed");
            cf_send_error(localbt->caph, errstr);
            return;
        }
    }
}

static void dbus_property_changed(GDBusProxy *proxy, const char *name,
        DBusMessageIter *iter, void *user_data) {
    const char *interface;
    local_bluetooth_t *localbt = (local_bluetooth_t *) user_data;
    local_command_t cmd = {
        .localbt = localbt,
        .proxy = proxy,
    };

    interface = g_dbus_proxy_get_interface(proxy);

    if (!strcmp(interface, "org.bluez.Device1")) {
        /* Shove devices at the device handler directly */
        dbus_bt_device(proxy);
    } else if (!strcmp(interface, "org.bluez.Adapter1")) {
        /* If the adapter changed, maybe we need to inventory its state */
        DBusMessageIter addr_iter;

        if (g_dbus_proxy_get_property(proxy, "Address", &addr_iter) == TRUE) {
            const char *address;

            dbus_message_iter_get_basic(&addr_iter, &address);

            /* Is this the adapter we care about? */
            if (strcmp(address, localbt->bt_interface_address)) {
                return;
            }

            /* See if adapter is powered on; if not, power it on, we'll enable
             * scanning in the poweron completion */
            if (!dbus_adapter_is_powered(proxy)) {
                dbus_initiate_adapter_poweron(&cmd);
                return;
            } 

            /* See if adapter is already scanning; if not, enable scanning */
            if (!dbus_adapter_is_scanning(proxy)) {
                dbus_initiate_adapter_scan(&cmd);
                return;
            }
        }
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

    if (ioctl(hci_sock, HCIGETDEVINFO, (void *) &di)) {
        snprintf(msg, STATUS_MAX, "Unable to get device info: %s", 
                strerror(errno));
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

    if (localbt->bt_interface_address != NULL)
        free(localbt->bt_interface_address);
    localbt->bt_interface_address = strdup(textaddr);

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

    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_bluetooth_t *localbt = (local_bluetooth_t *) caph->userdata;
    GDBusClient *client;

    static GMainLoop *main_loop;
    static DBusConnection *dbus_connection;

    main_loop = g_main_loop_new(NULL, FALSE);
    dbus_connection = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);
    g_dbus_attach_object_manager(dbus_connection);

    client = g_dbus_client_new(dbus_connection, "org.bluez", "/org/bluez");

    g_dbus_client_set_proxy_handlers(client, dbus_proxy_added, 
            dbus_proxy_removed, dbus_property_changed, localbt);

    g_main_loop_run(main_loop);

    g_dbus_client_unref(client);
    dbus_connection_unref(dbus_connection);
    g_main_loop_unref(main_loop);
}

int main(int argc, char *argv[]) {
    local_bluetooth_t localbt = {
        .bt_interface = NULL,
        .bt_interface_address = NULL,
        .state_powering_on = 0,
        .state_scanning_on = 0,
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

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_loop(caph);

    return 0;
}

