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

/*
 * Kismet datasource for legacy (pre-2006-optional-PHY) 900MHz IEEE 802.15.4
 * BPSK Zigbee, received via an RTL-SDR.
 *
 * Follows the same shape as capture_sdr_rtl433_v2.c: the Kismet-facing glue
 * here is plain C per capture_framework.c conventions, and the actual RF
 * demodulation is delegated to a spawned subprocess (zigbee900_live_rx.py,
 * a GNU Radio flowgraph + custom decode block) via cf_ipc, exactly like
 * rtl433_v2 spawns the separate rtl_433 binary and forwards its output.
 *
 * Unlike rtl433 (which fixes its frequency at spawn time; "no channel
 * callbacks needed since we only allow setting channel on open"), this
 * source supports live channel hopping: chancontrol_callback writes a
 * "CHANNEL <n>\n" line into the ipc child's stdin ring buffer, which the
 * running zigbee900_live_rx.py process reads and retunes to immediately,
 * without restarting. Note: GNU Radio flowgraph startup is far too slow to
 * respawn per hop at Kismet's normal hopping cadence.
 *
 * The RF chain, chip-mapping tables (IEEE Std 802.15.4-2006 clause 6.6),
 * and packet framing were validated separately: against the primary-source
 * standard text, against a real over-the-air capture from a Freaklabs
 * 328P/900MHz transmitter (55 frames, 0% loss, CRC-valid), and via offline
 * unit tests of the dedup/false-positive logic (2026-07-30).
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "../capture_framework.h"
#include "../config.h"

#define LINKTYPE_IEEE802_15_4_NOFCS     230
#define LINKTYPE_IEEE802_15_4           195

#define ZIGBEE900_MIN_CHANNEL 1
#define ZIGBEE900_MAX_CHANNEL 10

/* Overridable via a "script=" source option; this default assumes the
 * script has been installed alongside the capture helper. */
#define DEFAULT_SCRIPT_PATH "/usr/share/kismet/zigbee900/zigbee900_live_rx.py"

#define MAX_PSDU_BYTES 127
#define MAX_LINE_LEN (16 + MAX_PSDU_BYTES * 2 + 8)   /* "PSDU NN <hex>\n" plus slack */

typedef struct {
    char *name;
    char *interface;
    char *script_path;

    unsigned int channel;

    cf_ipc_t *ipc;

    pthread_cond_t ipc_valid_cond;
    pthread_mutex_t ipc_valid_cond_mutex;

    kis_capture_handler_t *caph;
} local_zigbee900_t;

typedef struct {
    unsigned int channel;
} local_channel_t;

/* Forward declarations: open_callback registers these before their
 * definitions appear later in this file. */
int ipc_handle_rx(kis_capture_handler_t *caph, cf_ipc_t *ipc, uint32_t read_sz);
void ipc_handle_terminate(kis_capture_handler_t *caph, cf_ipc_t *ipc, int rc);
int ipc_handle_err(kis_capture_handler_t *caph, cf_ipc_t *ipc, uint32_t read_sz);

/* Decode a hex string (even length, no separators) into a byte buffer.
 * Returns the decoded length, or -1 on malformed input. */
int hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_max) {
    size_t i;
    unsigned int byte;

    if (hex_len % 2 != 0)
        return -1;

    if (hex_len / 2 > out_max)
        return -1;

    for (i = 0; i < hex_len / 2; i++) {
        if (sscanf(hex + i * 2, "%2x", &byte) != 1)
            return -1;
        out[i] = (uint8_t) byte;
    }

    return (int) (hex_len / 2);
}

void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "unable to parse channel; zigbee900 channels are integers 1-10");
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if (parsechan < ZIGBEE900_MIN_CHANNEL || parsechan > ZIGBEE900_MAX_CHANNEL) {
        snprintf(errstr, STATUS_MAX, "zigbee900 channel %u out of range (%d-%d)",
                 parsechan, ZIGBEE900_MIN_CHANNEL, ZIGBEE900_MAX_CHANNEL);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;

    return ret_localchan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_zigbee900_t *local900 = (local_zigbee900_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    char cmd[32];
    int len;
    char errstr[STATUS_MAX];

    if (privchan == NULL)
        return 0;

    if (local900->ipc == NULL || !local900->ipc->running) {
        snprintf(errstr, STATUS_MAX, "%s decoder process is not running, can't set channel",
                 local900->name);
        cf_send_warning(caph, errstr);
        return 1;
    }

    len = snprintf(cmd, sizeof(cmd), "CHANNEL %u\n", channel->channel);

    pthread_mutex_lock(&(local900->ipc->out_ringbuf_lock));
    if (kis_simple_ringbuf_available(local900->ipc->out_ringbuf) < (size_t) len) {
        pthread_mutex_unlock(&(local900->ipc->out_ringbuf_lock));
        snprintf(errstr, STATUS_MAX, "%s failed to queue channel command, buffer full",
                 local900->name);
        cf_send_warning(caph, errstr);
        return 1;
    }
    kis_simple_ringbuf_write(local900->ipc->out_ringbuf, cmd, (size_t) len);
    pthread_mutex_unlock(&(local900->ipc->out_ringbuf_lock));

    local900->channel = channel->channel;

    return 1;
}

/* Build the "1".."10" channel list used by both probe and open */
void build_channel_list(cf_params_interface_t **ret_interface) {
    int i;
    char chstr[3];

    (*ret_interface)->channels =
        (char **) malloc(sizeof(char *) * (ZIGBEE900_MAX_CHANNEL - ZIGBEE900_MIN_CHANNEL + 1));

    for (i = ZIGBEE900_MIN_CHANNEL; i <= ZIGBEE900_MAX_CHANNEL; i++) {
        snprintf(chstr, sizeof(chstr), "%d", i);
        (*ret_interface)->channels[i - ZIGBEE900_MIN_CHANNEL] = strdup(chstr);
    }

    (*ret_interface)->channels_len = ZIGBEE900_MAX_CHANNEL - ZIGBEE900_MIN_CHANNEL + 1;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *definition, char *msg, char **uuid,
        cf_params_interface_t **ret_interface, cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char *script_path = NULL;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if (!cf_ipc_find_exec(caph, "python3")) {
        snprintf(msg, STATUS_MAX, "zigbee900sdr requires python3, not found in path");
        return 0;
    }

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strstr(interface, "zigbee900sdr") != interface) {
        snprintf(msg, STATUS_MAX, "Didn't find a zigbee900sdr interface, skipping");
        free(interface);
        return 0;
    }

    free(interface);

    if ((placeholder_len = cf_find_flag(&placeholder, "script", definition)) > 0) {
        script_path = strndup(placeholder, placeholder_len);
    } else {
        script_path = strdup(DEFAULT_SCRIPT_PATH);
    }

    if (access(script_path, R_OK | X_OK) != 0) {
        snprintf(msg, STATUS_MAX, "zigbee900sdr script not found or not executable: %s (%s); "
                 "override with script= in the source definition", script_path, strerror(errno));
        free(script_path);
        return 0;
    }

    free(script_path);

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-000000000000",
                adler32_csum((unsigned char *) "kismet_cap_sdr_zigbee900",
                    strlen("kismet_cap_sdr_zigbee900")) & 0xFFFFFFFF);
        *uuid = strdup(errstr);
    }

    build_channel_list(ret_interface);

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface, cf_params_spectrum_t **ret_spectrum) {

    local_zigbee900_t *local900 = (local_zigbee900_t *) caph->userdata;

    char *placeholder;
    int placeholder_len;
    char errstr[STATUS_MAX];
    unsigned int initial_channel = ZIGBEE900_MIN_CHANNEL;

    char *argv[4];
    char chan_str[8];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if (!cf_ipc_find_exec(caph, "python3")) {
        snprintf(msg, STATUS_MAX, "zigbee900sdr requires python3, not found in path");
        return -1;
    }

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    local900->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        local900->name = strndup(placeholder, placeholder_len);
    } else {
        local900->name = strdup(local900->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "script", definition)) > 0) {
        local900->script_path = strndup(placeholder, placeholder_len);
    } else {
        local900->script_path = strdup(DEFAULT_SCRIPT_PATH);
    }

    if (access(local900->script_path, R_OK | X_OK) != 0) {
        snprintf(msg, STATUS_MAX, "%s script not found or not executable: %s (%s)",
                 local900->name, local900->script_path, strerror(errno));
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        if (sscanf(placeholder, "%u", &initial_channel) != 1 ||
                initial_channel < ZIGBEE900_MIN_CHANNEL || initial_channel > ZIGBEE900_MAX_CHANNEL) {
            snprintf(msg, STATUS_MAX, "%s invalid initial channel in source definition",
                     local900->name);
            return -1;
        }
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-000000000000",
                adler32_csum((unsigned char *) "kismet_cap_sdr_zigbee900",
                    strlen("kismet_cap_sdr_zigbee900")) & 0xFFFFFFFF);
        *uuid = strdup(errstr);
    }

    snprintf(chan_str, sizeof(chan_str), "%u", initial_channel);

    argv[0] = local900->script_path;
    argv[1] = chan_str;
    argv[2] = NULL;

    if ((local900->ipc = cf_ipc_exec(caph, 2, argv)) == NULL) {
        snprintf(msg, STATUS_MAX, "%s failed to launch %s", local900->name, local900->script_path);
        return -1;
    }

    cf_ipc_set_rx(caph, local900->ipc, ipc_handle_rx);
    cf_ipc_set_term(caph, local900->ipc, ipc_handle_terminate);
    /* No public setter for the stderr callback exists in capture_framework.h,
     * but the cf_ipc_t struct itself is fully exposed, so assign it directly;
     * this is the only way to see zigbee900_live_rx.py's diagnostic
     * output (READY/RETUNED/ERROR lines). Otherwise it's silently
     * discarded (framework clears err_ringbuf when err_callback is NULL). */
    local900->ipc->err_callback = ipc_handle_err;
    cf_ipc_add_process(caph, local900->ipc);

    local900->channel = initial_channel;

    build_channel_list(ret_interface);

    /* Kismet's phy_802154 dissector (phy_802154.cc) only creates device-tracker
     * entries for KDLT_IEEE802_15_4_NOFCS or _TAP; plain LINKTYPE_IEEE802_15_4
     * (195, "with FCS") is silently dropped before device creation even though
     * cf_send_data()/num_packets still count it fine. Our decoder already
     * strips the trailing 2-byte FCS before emitting PSDU (data) lines (it only
     * used the FCS to validate CRC), so NOFCS is the correct match. */
    *dlt = LINKTYPE_IEEE802_15_4_NOFCS;

    return 1;
}

int ipc_handle_rx(kis_capture_handler_t *caph, cf_ipc_t *ipc, uint32_t read_sz) {
    local_zigbee900_t *local900 = (local_zigbee900_t *) caph->userdata;
    ssize_t newline;
    size_t peeked_sz;
    char *buf;
    char errstr[STATUS_MAX];
    unsigned int line_channel;
    char hexbuf[MAX_PSDU_BYTES * 2 + 1];
    uint8_t pkt[MAX_PSDU_BYTES];
    int pkt_len;
    struct timeval tv;
    int matched;

    while (1) {
        newline = kis_simple_ringbuf_search_byte(ipc->in_ringbuf, '\n');
        if (newline <= 0)
            break;

        peeked_sz = kis_simple_ringbuf_peek_zc(ipc->in_ringbuf, (void **) &buf, newline);
        if (peeked_sz < (size_t) newline) {
            kis_simple_ringbuf_peek_free(ipc->in_ringbuf, buf);
            break;
        }

        buf[newline] = '\0';

        matched = 0;
        if (strncmp(buf, "PSDU ", 5) == 0) {
            if (sscanf(buf + 5, "%u %127s", &line_channel, hexbuf) == 2) {
                pkt_len = hex_decode(hexbuf, strlen(hexbuf), pkt, sizeof(pkt));
                if (pkt_len > 0) {
                    gettimeofday(&tv, NULL);
                    if (cf_send_data(caph, NULL, 0, NULL, NULL, tv,
                                LINKTYPE_IEEE802_15_4_NOFCS, pkt_len, pkt_len, pkt) < 0) {
                        snprintf(errstr, STATUS_MAX,
                                "%s unable to send packet to Kismet server", local900->name);
                        cf_send_error(caph, 0, errstr);
                    }
                    matched = 1;
                }
            }
        }

        (void) matched;   /* non-matching lines (READY/RETUNED/ERROR on stderr,
                             or malformed stdout) are silently ignored here;
                             they don't indicate a fault by themselves */

        kis_simple_ringbuf_peek_free(ipc->in_ringbuf, buf);
        kis_simple_ringbuf_read(ipc->in_ringbuf, NULL, newline + 1);
    }

    return 0;
}

int ipc_handle_err(kis_capture_handler_t *caph, cf_ipc_t *ipc, uint32_t read_sz) {
    local_zigbee900_t *local900 = (local_zigbee900_t *) caph->userdata;
    ssize_t newline;
    size_t peeked_sz;
    char *buf;

    while (1) {
        newline = kis_simple_ringbuf_search_byte(ipc->err_ringbuf, '\n');
        if (newline <= 0)
            break;

        peeked_sz = kis_simple_ringbuf_peek_zc(ipc->err_ringbuf, (void **) &buf, newline);
        if (peeked_sz < (size_t) newline) {
            kis_simple_ringbuf_peek_free(ipc->err_ringbuf, buf);
            break;
        }

        buf[newline] = '\0';
        fprintf(stderr, "%s decoder stderr: %s\n", local900->name, buf);
        fflush(stderr);

        kis_simple_ringbuf_peek_free(ipc->err_ringbuf, buf);
        kis_simple_ringbuf_read(ipc->err_ringbuf, NULL, newline + 1);
    }

    return 0;
}

void ipc_handle_terminate(kis_capture_handler_t *caph, cf_ipc_t *ipc, int rc) {
    local_zigbee900_t *local900 = (local_zigbee900_t *) caph->userdata;
    char errstr[STATUS_MAX];

    snprintf(errstr, STATUS_MAX, "%s decoder process exited unexpectedly (code %d)",
             local900->name, rc);
    cf_send_error(caph, 0, errstr);

    wrap_cond_signal(&local900->ipc_valid_cond, &local900->ipc_valid_cond_mutex);
}

/* Dummy capture thread, uses the same pattern as capture_sdr_rtl433_v2.c:
 * real data arrives via ipc_handle_rx from the framework's own IO loop, not
 * from this thread. Only exists to give the framework a capture thread
 * to run, and wakes up (letting the process exit cleanly) if the spawned
 * decoder process dies. */
void capture_thread(kis_capture_handler_t *caph) {
    local_zigbee900_t *local900 = (local_zigbee900_t *) caph->userdata;

    wrap_cond_wait(&local900->ipc_valid_cond, &local900->ipc_valid_cond_mutex);
}

int main(int argc, char *argv[]) {
    local_zigbee900_t local900 = {
        .name = NULL,
        .interface = NULL,
        .script_path = NULL,
        .channel = ZIGBEE900_MIN_CHANNEL,
        .ipc = NULL,
    };

    kis_capture_handler_t *caph = cf_handler_init("zigbee900sdr");

    if (caph == NULL) {
        fprintf(stderr,
            "FATAL: Could not allocate basic handler data, your system "
            "is very low on RAM or something is wrong.\n");
        return -1;
    }

    pthread_cond_init(&local900.ipc_valid_cond, NULL);
    pthread_mutex_init(&local900.ipc_valid_cond_mutex, NULL);

    local900.caph = caph;

    cf_handler_set_userdata(caph, &local900);

    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);

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
