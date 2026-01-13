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

#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <rtl-sdr.h>
#include <zlib.h>

#include "../capture_framework.h"
#include "../simple_ringbuf_c.h"

typedef struct {
    cf_ipc_t *ipc_433;

    /* Unlocked by the ipc callback if the process terminates, otherwise
     * we handle forwarding the JSON data during the data available callback
     * loop
     */
    pthread_cond_t rtl433_valid_cond;
    pthread_mutex_t rtl433_valid_cond_mutex;

    unsigned long freq;

    char *name;

    /* Argv list */
    char **rtl_argv;
} local_rtl433_t;

unsigned long human_to_hz(const char *in_str, unsigned int in_len) {
    char *fixedstr = NULL;
    char scale[5];
    double f;
    int r;

    if (in_len == 0)
        return 0;

    fixedstr = strndup(in_str, in_len);

    r = sscanf(fixedstr, "%lf%4s", &f, scale);

    if (r == 2) {
        if (strcasecmp("mhz", scale) == 0) {
            free(fixedstr);
            return f * 1000 * 1000;
        } else if (strcasecmp("khz", scale) == 0) {
            free(fixedstr);
            return f * 1000;
        } else if (strcasecmp("hz", scale) == 0) {
            free(fixedstr);
            return f;
        }
    } else if (r == 1) {
        free(fixedstr);
        return f;
    }

    if (fixedstr != NULL)
        free(fixedstr);

    return 0;
}

int find_rtl_by_subinterface(char *subinterface) {
    char manuf[256];
    char product[256];
    char serial[256];

    int subif_as_sn_only = 0;
    int subif_as_int = -1;

    int n = rtlsdr_get_device_count();
    int i, r;

    if (subinterface == NULL) {
        return -1;
    }

    /* look for an optional rtl433-sn-XYZ for solving serial collisions */
    if (strlen(subinterface) > 3 && strncmp(subinterface, "sn-", 3) == 0) {
        subinterface += 3;
        subif_as_sn_only = 1;
    }

    for (i = 0; i < n; i++) {
        r = rtlsdr_get_device_usb_strings(i, manuf, product, serial);

        if (r != 0)
            continue;

        if (strcmp(serial, subinterface) == 0) {
            return i;
        }
    }

    if (!subif_as_sn_only && sscanf(subinterface, "%d", &subif_as_int) == 1) {
        if (subif_as_int >= 0 && subif_as_int < n) {
            return subif_as_int;
        }
    }

    return -1;
}

int ipc_handle_rx(kis_capture_handler_t *caph, cf_ipc_t *ipc, uint32_t read_sz) {
    local_rtl433_t *local433 = (local_rtl433_t *) caph->userdata;
    ssize_t newline = 0;
    size_t peeked_sz = 0;
    char *buf;
    int fail = 0;
    struct timeval tv;
    char errstr[STATUS_MAX];
    int r;

    /*
     * Blindly repackage the output per-line and send it to Kismet.  We don't bother
     * parsing to see if it's actually JSON here because then we'd need a C JSON
     * library, etc, when we can just send it to Kismet and let it ignore it if it's
     * no good.
     *
     * We DO NOT go into a loop waiting for the output tcp/ipc buffer to flush as we're
     * being called as part of the main IO thread.
     */

    while (!fail) {
        /* Exit w/out error */
        newline = kis_simple_ringbuf_search_byte(ipc->in_ringbuf, '\n');
        if (newline <= 0) {
            break;
        }

        peeked_sz = kis_simple_ringbuf_peek_zc(ipc->in_ringbuf, (void **) &buf, newline);

        if (peeked_sz < newline) {
            snprintf(errstr, STATUS_MAX, "%s unable to fetch rtl_433 data from buffer", local433->name);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
            fail = 1;
            break;
        }

        buf[newline] = '\0';
        gettimeofday(&tv, NULL);

        /*
         * Since we're part of the core IO loop, not a capture thread, we need to
         * just fail if the tx buffer is full.
         *
         * Since rtl433 json RX is pretty slow, this shouldn't be a major problem
         */
        r = cf_send_json(caph, NULL, 0, NULL, NULL, tv, "RTL433", (char *) buf);
        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "%s unable to send JSON frame to Kismet", local433->name);
            fprintf(stderr, "%s", errstr);
            cf_send_error(caph, 0, errstr);
            fail = 1;
            break;
        }

        kis_simple_ringbuf_peek_free(ipc->in_ringbuf, buf);
        kis_simple_ringbuf_read(ipc->in_ringbuf, NULL, newline + 1);

        continue;
    }

    if (fail) {
        /* Unlock the capture thread and die */
        pthread_cond_broadcast(&local433->rtl433_valid_cond);
        cf_handler_spindown(caph);
    }

    return 0;
}

void ipc_handle_terminate(kis_capture_handler_t *caph, cf_ipc_t *ipc, int rc) {
    local_rtl433_t *local433 = (local_rtl433_t *) caph->userdata;
    pthread_cond_broadcast(&local433->rtl433_valid_cond);
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    unsigned int num_radios = rtlsdr_get_device_count();
    int i;
    char buf[256];

    *interfaces =
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) *
                num_radios);

    for (i = 0; i < num_radios; i++) {
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));
        snprintf(buf, 256, "rtl433-%u", i);
        (*interfaces)[i]->interface = strdup(buf);
        (*interfaces)[i]->hardware = strdup("rtlsdr");
    }

    return num_radios;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char *subinterface;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

	int matched_device = 0;
	int num_device = 0;

    char manuf_buf[256];
    char product_buf[256];
    char serial_buf[256];

    char buf[STATUS_MAX];

    if (!cf_ipc_find_exec(caph, "rtl_433")) {
        snprintf(msg, STATUS_MAX, "rtl_433 binary not installed");
        return 0;
    }

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for:
     * rtl433
     * rtl433-[serial]
     * rtl433-[0, 1, 2, 3...]
     */

    /* Look for the interface type */
    if (strstr(interface, "rtl433") != interface) {
        free(interface);
        return 0;
    }

    /* Alias 'rtl433' to 'rtl433-0' */
    if (strlen(interface) == strlen("rtl433")) {
        matched_device = 1;
        num_device = 0;
    } else {
        subinterface = strstr(interface, "-");
        if (subinterface == NULL) {
            free(interface);
            snprintf(msg, STATUS_MAX, "Unable to parse rtl433 interface in definition");
            return 0;
        }

        num_device = find_rtl_by_subinterface(subinterface + 1);
        if (num_device >= 0)
            matched_device = 1;
    }

    if (matched_device == 0 || num_device < 0) {
        free(interface);
        snprintf(msg, STATUS_MAX, "Unable to find rtl433 device");
        return 0;
    }

    free(interface);
    interface = NULL;

    snprintf(buf, STATUS_MAX, "rtl433-%d", num_device);
    (*ret_interface)->capif = strdup(buf);
    (*ret_interface)->hardware = strdup("rtlsdr");

    if (rtlsdr_get_device_usb_strings(num_device, manuf_buf, product_buf, serial_buf) != 0) {
        snprintf(msg, STATUS_MAX, "Unable to find rtl433 device");
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        uint32_t hash;

        snprintf(buf, STATUS_MAX, "%s%s%s", manuf_buf, product_buf, serial_buf);
        hash = adler32_csum((unsigned char *) buf, strlen(buf));

        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                adler32_csum((unsigned char *) "kismet_cap_sdr_rtl433",
                    strlen("kismet_cap_sdr_rtl433")) & 0xFFFFFFFF,
                hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char *subinterface;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

	int matched_device = 0;
	int num_device = 0;

    char manuf_buf[256];
    char product_buf[256];
    char serial_buf[256];

    char buf[STATUS_MAX];

    // rtl_433 -F json -M level -d X -f Y [additional]
    unsigned int num_args = 9;

    // Channel, if any
    char *channel = NULL;
    unsigned int channel_len = 0;

    unsigned int n = 0;

    local_rtl433_t *local433 = (local_rtl433_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "rtl433") != interface) {
        free(interface);
        return 0;
    }

    /* Alias 'rtl433' to 'rtl433-0' */
    if (strlen(interface) == strlen("rtl433")) {
        matched_device = 1;
        num_device = 0;
    } else {
        subinterface = strstr(interface, "-");
        if (subinterface == NULL) {
            free(interface);
            snprintf(msg, STATUS_MAX, "Unable to parse rtl433 interface in definition");
            return 0;
        }

        num_device = find_rtl_by_subinterface(subinterface + 1);
        if (num_device >= 0)
            matched_device = 1;
    }

    if (matched_device == 0 || num_device < 0) {
        free(interface);
        snprintf(msg, STATUS_MAX, "Unable to find rtl433 device");
        return 0;
    }

    free(interface);
    interface = NULL;

    snprintf(buf, STATUS_MAX, "rtl433-%d", num_device);
    local433->name = strdup(buf);
    (*ret_interface)->capif = strdup(buf);
    (*ret_interface)->hardware = strdup("rtlsdr");

    if (rtlsdr_get_device_usb_strings(num_device, manuf_buf, product_buf, serial_buf) != 0) {
        snprintf(msg, STATUS_MAX, "Unable to find rtl433 device");
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        uint32_t hash;

        snprintf(buf, STATUS_MAX, "%s%s%s", manuf_buf, product_buf, serial_buf);
        hash = adler32_csum((unsigned char *) buf, strlen(buf));

        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                adler32_csum((unsigned char *) "kismet_cap_sdr_rtl433",
                    strlen("kismet_cap_sdr_rtl433")) & 0xFFFFFFFF,
                hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    channel_len = cf_find_flag(&channel, "channel", definition);
    if (channel_len > 0) {
        local433->freq = human_to_hz(channel, channel_len);
    } else {
        channel_len = cf_find_flag(&channel, "frequency", definition);
        if (channel_len > 0) {
            local433->freq = human_to_hz(channel, channel_len);
        }
    }

    if (local433->freq == 0) {
        snprintf(msg, STATUS_MAX, "Invalid channel / frequency, expected nnn, nnnHz, nnnKhz, or nnnMhz");
        return -1;
    }

    (*ret_interface)->channels = (char **) malloc(sizeof(char *));
    snprintf(buf, STATUS_MAX, "%4.6fMHz", (float) local433->freq / 1000.0f / 1000.0f);
    (*ret_interface)->channels[0] = strdup(buf);
    (*ret_interface)->channels_len = 1;

    snprintf(buf, STATUS_MAX, "%lu", local433->freq);

    /* Aggregate any additional arguments and add to num_args */

    local433->rtl_argv = (char **) malloc(sizeof(char *) * (num_args + 1));

    n = 0;
    local433->rtl_argv[n++] = strdup("rtl_433");
    local433->rtl_argv[n++] = strdup("-d");
    snprintf(buf, STATUS_MAX, "%u", num_device);
    local433->rtl_argv[n++] = strdup(buf);
    local433->rtl_argv[n++] = strdup("-F");
    local433->rtl_argv[n++] = strdup("json");
    local433->rtl_argv[n++] = strdup("-M");
    local433->rtl_argv[n++] = strdup("level");
    local433->rtl_argv[n++] = strdup("-f");
    snprintf(buf, STATUS_MAX, "%lu", local433->freq);
    local433->rtl_argv[n++] = strdup(buf);

    /* Add any other future arguments */

    /* Terminating null on argv */
    local433->rtl_argv[n] = NULL;

    /* We can't open the interface if rtl_433 isn't found */
    if (!cf_ipc_find_exec(caph, "rtl_433")) {
        snprintf(msg, STATUS_MAX, "kismet_cap_sdr_rtl433 could not find rtl_433 binary in path.  Make sure it is installed.");
        return -1;
    }

    /* Try to launch directly */
    if ((local433->ipc_433 = cf_ipc_exec(caph, num_args, local433->rtl_argv)) == NULL) {
        snprintf(msg, STATUS_MAX, "kismet_cap_sdr_rtl433 failed to launch the rtl_433 tool");
        return -1;
    }

    /* Set up the data and termination handlers */
    cf_ipc_set_rx(caph, local433->ipc_433, ipc_handle_rx);
    cf_ipc_set_term(caph, local433->ipc_433, ipc_handle_terminate);

    /* Remember the IPC for polling */
    cf_ipc_add_process(caph, local433->ipc_433);

    return 1;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_rtl433_t *local433 = (local_rtl433_t *) caph->userdata;

    wrap_cond_wait(&local433->rtl433_valid_cond,
            &local433->rtl433_valid_cond_mutex);
    pthread_mutex_unlock(&local433->rtl433_valid_cond_mutex);

}

int main(int argc, char *argv[]) {
    local_rtl433_t local433 = {
        .ipc_433 = NULL,
        .freq = 433920000,
        .name = NULL,
       .rtl_argv = NULL,
    };

    kis_capture_handler_t *caph = cf_handler_init("rtl433");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    pthread_cond_init(&local433.rtl433_valid_cond, NULL);
    pthread_mutex_init(&local433.rtl433_valid_cond_mutex, NULL);

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local433);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* No channel callbacks needed since we only allow setting channel on open */

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

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
