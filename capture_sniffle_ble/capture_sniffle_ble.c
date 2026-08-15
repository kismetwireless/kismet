#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "../capture_framework.h"
#include "../config.h"

// This helper talks Sniffle's (https://github.com/nccgroup/Sniffle) own
// serial wire protocol directly; it only handles the serial framing and
// specific command sequence needed for passive advertising-channel scans.
// It forwards Sniffle's own raw 0x10 (PacketMessage) message body
// close to verbatim via cf_send_data. All of the actual BLE pseudoheader
// construction, channel remapping, and CRC-flag handling happens
// server-side in datasource_sniffle_ble.cc's handle_rx_data_content(),
// mirroring exactly how datasource_nrf_51822.cc/capture_nrf_51822.c split
// the same work.
//
// Wire protocol summary (see sniffle_hw.py for the authoritative source):
//   Every command and response is base64-encoded, CRLF-terminated, one
//   message per line. The first decoded byte is a self-referential word
//   count and the second decoded byte is a message type; the rest is the
//   message body.
//
// Command bytes (opcode, payload) sent to configure passive scanning on a
// single primary advertising channel, matching setup_sniffer(mode=
// PASSIVE_SCAN) in sniffle_hw.py exactly, in the same order it issues them:
//   0x18 '@'                                  -- cmd_marker, sync (sent once at connect, before setup)
//   0x10 chan,aa(4 LE),phy,crci(4 LE)          -- cmd_chan_aa_phy
//   0x12 rssi_min                             -- cmd_rssi
//   0x11 0x00                                 -- cmd_pause_done(false)
//   0x15 0x00                                 -- cmd_follow(false) -- PASSIVE_SCAN, not CONN_FOLLOW
//   0x16 0x00                                 -- cmd_auxadv(false)
//   0x13                                      -- cmd_mac() with no target (no payload)
//   0x26 0x01                                 -- cmd_crc_valid(true)
//   0x27 txpower                              -- cmd_tx_power
//   0x21                                      -- cmd_interval_preload([]) (no payload)
//   0x23 phy_preload                          -- cmd_phy_preload(PHY_2M)

#define BUFFER_SIZE 4096

#ifndef D_BAUDRATE
#define D_BAUDRATE B2000000  // Sniffle's own default, per sniffle_hw.py (CP2102N dongles)
#endif

#ifndef B9600
#define B9600 9600
#endif
#ifndef B19200
#define B19200 19200
#endif
#ifndef B38400
#define B38400 38400
#endif
#ifndef B57600
#define B57600 57600
#endif
#ifndef B115200
#define B115200 115200
#endif
#ifndef B230400
#define B230400 230400
#endif
#ifndef B460800
#define B460800 460800
#endif
#ifndef B500000
#define B500000 500000
#endif
#ifndef B576000
#define B576000 576000
#endif
#ifndef B921600
#define B921600 921600
#endif
#ifndef B1000000
#define B1000000 1000000
#endif
#ifndef B1152000
#define B1152000 1152000
#endif
#ifndef B1500000
#define B1500000 1500000
#endif
#ifndef B2000000
#define B2000000 2000000
#endif
#ifndef B2500000
#define B2500000 2500000
#endif
#ifndef B3000000
#define B3000000 3000000
#endif
#ifndef B3500000
#define B3500000 3500000
#endif
#ifndef B4000000
#define B4000000 4000000
#endif


// BLE constants, from Sniffle's python_cli/sniffle/constants.py
#define BLE_ADV_AA      0x8E89BED6
#define BLE_ADV_CRCI    0x555555

#define PHY_1M          0
#define PHY_2M          1
#define PHY_CODED_S8    2
#define PHY_CODED_S2    3

// Matches datasource_sniffle_ble.h
#ifndef KDLT_BTLE_RADIO
#define KDLT_BTLE_RADIO 256
#endif

/* Unique instance data passed around by capframework */
typedef struct {
    pthread_mutex_t serial_mutex;

    struct termios oldtio, newtio;

    int fd;

    char *name;
    char *interface;

    int channel; // primary advertising channel: 37, 38, or 39

    speed_t baudrate;

    kis_capture_handler_t *caph;
} local_sniffle_t;

int get_baud(int baud) {
    switch (baud) {
        case 9600: return B9600;
        case 19200: return B19200;
        case 38400: return B38400;
        case 57600: return B57600;
        case 115200: return B115200;
        case 230400: return B230400;
        case 460800: return B460800;
        case 500000: return B500000;
        case 576000: return B576000;
        case 921600: return B921600;
        case 1000000: return B1000000;
        case 1152000: return B1152000;
        case 1500000: return B1500000;
        case 2000000: return B2000000;
        case 2500000: return B2500000;
        case 3000000: return B3000000;
        case 3500000: return B3500000;
        case 4000000: return B4000000;
        default: return -1;
    }
}

/* ---- Minimal standard base64 codec (Sniffle's protocol requires no
 * variant/URL-safe alphabet, just plain RFC 4648 with '=' padding) ---- */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(const uint8_t *in, int in_len, char *out) {
    int i, j;
    for (i = 0, j = 0; i < in_len; i += 3) {
        uint32_t oa = in[i];
        uint32_t ob = (i + 1) < in_len ? in[i + 1] : 0;
        uint32_t oc = (i + 2) < in_len ? in[i + 2] : 0;
        uint32_t triple = (oa << 16) | (ob << 8) | oc;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i + 1) < in_len ? b64_table[(triple >> 6) & 0x3F] : '=';
        out[j++] = (i + 2) < in_len ? b64_table[triple & 0x3F] : '=';
    }
    return j;
}

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decode exactly 4 base64 chars into up to 3 bytes. Returns number of
 * valid output bytes (1-3), or -1 on error. */
static int b64_decode_quad(const char *in, uint8_t *out) {
    int vals[4];
    int pad = 0;

    for (int k = 0; k < 4; k++) {
        if (in[k] == '=') {
            vals[k] = 0;
            pad++;
        } else {
            vals[k] = b64_decode_char(in[k]);
            if (vals[k] < 0)
                return -1;
        }
    }

    out[0] = (uint8_t) ((vals[0] << 2) | (vals[1] >> 4));
    out[1] = (uint8_t) (((vals[1] & 0xF) << 4) | (vals[2] >> 2));
    out[2] = (uint8_t) (((vals[2] & 0x3) << 6) | vals[3]);

    return 3 - pad;
}

/* Decode a full CRLF-stripped base64 line. Returns total decoded length,
 * or -1 on malformed input (not a multiple of 4 base64 chars, or an
 * invalid character). */
static int b64_decode_line(const char *line, int line_len, uint8_t *out, int out_bufsize) {
    int decoded_len = 0;
    int i;

    if (line_len % 4 != 0)
        return -1;

    for (i = 0; i < line_len; i += 4) {
        uint8_t tmp[3];
        int n = b64_decode_quad(line + i, tmp);
        if (n < 0)
            return -1;
        if (decoded_len + n > out_bufsize)
            return -1;
        memcpy(out + decoded_len, tmp, n);
        decoded_len += n;
    }

    return decoded_len;
}

/* ---- Sniffle command protocol ---- */

/* cmd_bytes[0] is the opcode; cmd_bytes[1..] is the payload, matching
 * sniffle_hw.py's _send_cmd(cmd_byte_list) exactly (b0 = ceil((len+1)/3)
 * self-referential word count, prepended, whole thing base64+CRLF). */
static void sniffle_send_cmd(local_sniffle_t *localsniffle, const uint8_t *cmd_bytes, int cmd_len) {
    uint8_t full[64];
    char encoded[128];
    int full_len, enc_len;

    if (cmd_len + 1 > (int) sizeof(full))
        return; // shouldn't happen -- every command we send is well under this

    full[0] = (uint8_t) ((cmd_len + 1 + 2) / 3); // b0, matches Python's (len(cmd_byte_list)+3)//3
    memcpy(full + 1, cmd_bytes, cmd_len);
    full_len = cmd_len + 1;

    enc_len = b64_encode(full, full_len, encoded);
    encoded[enc_len++] = '\r';
    encoded[enc_len++] = '\n';

    pthread_mutex_lock(&(localsniffle->serial_mutex));
    write(localsniffle->fd, encoded, enc_len);
    pthread_mutex_unlock(&(localsniffle->serial_mutex));
}

/* Configure Sniffle for passive advertising-channel scanning on a single
 * channel, matching setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, chan=...)
 * in sniffle_hw.py exactly, command-for-command and in the same order. */
static void sniffle_setup_passive_scan(local_sniffle_t *localsniffle) {
    uint8_t cmd[16];

    // cmd_marker(b'@') - sync, sent once at connect (matches SniffleHW.__init__)
    cmd[0] = 0x18; cmd[1] = '@';
    sniffle_send_cmd(localsniffle, cmd, 2);

    // cmd_chan_aa_phy(chan, BLE_ADV_AA, PHY_1M, BLE_ADV_CRCI)
    // pack("<BLBL", chan, aa, phy, crci) - 1 + 4 + 1 + 4 = 10 bytes
    cmd[0] = 0x10;
    cmd[1] = (uint8_t) localsniffle->channel;
    cmd[2] = (uint8_t) (BLE_ADV_AA & 0xFF);
    cmd[3] = (uint8_t) ((BLE_ADV_AA >> 8) & 0xFF);
    cmd[4] = (uint8_t) ((BLE_ADV_AA >> 16) & 0xFF);
    cmd[5] = (uint8_t) ((BLE_ADV_AA >> 24) & 0xFF);
    cmd[6] = PHY_1M;
    cmd[7] = (uint8_t) (BLE_ADV_CRCI & 0xFF);
    cmd[8] = (uint8_t) ((BLE_ADV_CRCI >> 8) & 0xFF);
    cmd[9] = (uint8_t) ((BLE_ADV_CRCI >> 16) & 0xFF);
    cmd[10] = (uint8_t) ((BLE_ADV_CRCI >> 24) & 0xFF);
    sniffle_send_cmd(localsniffle, cmd, 11);

    // cmd_rssi(-128) - no minimum RSSI filter
    cmd[0] = 0x12; cmd[1] = (uint8_t) (-128 & 0xFF);
    sniffle_send_cmd(localsniffle, cmd, 2);

    // cmd_pause_done(false)
    cmd[0] = 0x11; cmd[1] = 0x00;
    sniffle_send_cmd(localsniffle, cmd, 2);

    // cmd_follow(false) - PASSIVE_SCAN, not CONN_FOLLOW
    cmd[0] = 0x15; cmd[1] = 0x00;
    sniffle_send_cmd(localsniffle, cmd, 2);

    // cmd_auxadv(false)
    cmd[0] = 0x16; cmd[1] = 0x00;
    sniffle_send_cmd(localsniffle, cmd, 2);

    // cmd_mac() - no target MAC/IRK, no payload
    cmd[0] = 0x13;
    sniffle_send_cmd(localsniffle, cmd, 1);

    // cmd_crc_valid(true)
    cmd[0] = 0x26; cmd[1] = 0x01;
    sniffle_send_cmd(localsniffle, cmd, 2);

    // cmd_tx_power(5) - matches setup_sniffer's own default
    cmd[0] = 0x27; cmd[1] = 0x05;
    sniffle_send_cmd(localsniffle, cmd, 2);

    // cmd_interval_preload([]) - no pairs, no payload
    cmd[0] = 0x21;
    sniffle_send_cmd(localsniffle, cmd, 1);

    // cmd_phy_preload(PHY_2M) - matches setup_sniffer's own default
    cmd[0] = 0x23; cmd[1] = PHY_2M;
    sniffle_send_cmd(localsniffle, cmd, 2);

    // No cmd_scan()/random_addr() - those are ACTIVE_SCAN-only, not used here
}

/* Read one CRLF-terminated line from the serial port (excluding the CRLF).
 * Returns line length, 0 on a blank/ignorable read, or -1 on error/closed. */
static int sniffle_readline(kis_capture_handler_t *caph, int fd, char *buf, int bufsize) {
    int pos = 0;

    while (pos < bufsize - 1) {
        if (*(volatile int *) &caph->spindown)
            return -1;

        char c;
        int r = read(fd, &c, 1);

        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            return -1;
        }

        if (r == 0)
            continue; // VTIME timeout with nothing read, just retry

        if (c == '\n') {
            if (pos > 0 && buf[pos - 1] == '\r')
                pos--;
            return pos;
        }

        buf[pos++] = (uint8_t) c;
    }

    return -1; // line too long, treat as desync
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno,
    char *definition, char *msg, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];
    char *device = NULL;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strstr(interface, "sniffle_ble") != interface) {
        snprintf(msg, STATUS_MAX, "Expected a 'sniffle_ble' interface, not matching");
        free(interface);
        return 0;
    }

    free(interface);

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_sniffle_ble",
                strlen("kismet_cap_sniffle_ble")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    free(device);

    // Primary advertising channels only -- this datasource doesn't hop
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);
    for (int i = 37; i < 40; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 37] = strdup(chstr);
    }
    (*ret_interface)->channels_len = 3;

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
    char *msg, uint32_t *dlt, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {

    char *placeholder;
    int placeholder_len;
    char *device = NULL;
    char errstr[STATUS_MAX];
    char *localbaudratestr = NULL;

    local_sniffle_t *localsniffle = (local_sniffle_t *) caph->userdata;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    localsniffle->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localsniffle->name = strndup(placeholder, placeholder_len);
    } else {
        localsniffle->name = strdup(localsniffle->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX,
            "%s expected device= path to serial device in definition", localsniffle->name);
        return -1;
    }

    // Primary advertising channel to listen on - default 37, matching
    // Sniffle's own CLI default. Only 37/38/39 are meaningful; anything
    // else is rejected up front rather than silently mis-mapped later in
    // datasource_sniffle_ble.cc.
    localsniffle->channel = 37;
    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        char *chanstr = strndup(placeholder, placeholder_len);
        int chan = atoi(chanstr);
        free(chanstr);
        if (chan < 37 || chan > 39) {
            snprintf(msg, STATUS_MAX,
                "%s channel= must be 37, 38, or 39 (primary advertising channels only)",
                localsniffle->name);
            return -1;
        }
        localsniffle->channel = chan;
    }

    // Baud rate: Sniffle's own default (2,000,000) works for CP2102N based dongles
    if ((placeholder_len = cf_find_flag(&placeholder, "baud", definition)) > 0) {
        localbaudratestr = strndup(placeholder, placeholder_len);
        int req_baud = atoi(localbaudratestr);
        free(localbaudratestr);
        int b = get_baud(req_baud);
        if (b < 0) {
            snprintf(msg, STATUS_MAX, "%s unsupported baud= value", localsniffle->name);
            return -1;
        }
        localsniffle->baudrate = b;
    } else {
        localsniffle->baudrate = D_BAUDRATE;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_sniffle_ble",
                strlen("kismet_cap_sniffle_ble")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    pthread_mutex_lock(&localsniffle->serial_mutex);

    localsniffle->fd = open(device, O_RDWR | O_NOCTTY);

    if (localsniffle->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
            localsniffle->name, strerror(errno));
        pthread_mutex_unlock(&(localsniffle->serial_mutex));
        free(device);
        return -1;
    }

    free(device);

    tcgetattr(localsniffle->fd, &localsniffle->oldtio);
    localsniffle->newtio = localsniffle->oldtio;

    cfmakeraw(&localsniffle->newtio);

    cfsetispeed(&localsniffle->newtio, localsniffle->baudrate);
    cfsetospeed(&localsniffle->newtio, localsniffle->baudrate);

    localsniffle->newtio.c_cflag |= (CLOCAL | CREAD | CS8);
    localsniffle->newtio.c_cflag &= ~(PARENB | PARODD | CSTOPB | CRTSCTS);
    localsniffle->newtio.c_iflag |= IGNPAR;

    // Short read timeout, no minimum - matches capture_nrf_51822.c's approach,
    // needed so sniffle_readline() can check caph->spindown between bytes
    // rather than blocking forever if the dongle stops talking.
    localsniffle->newtio.c_cc[VMIN] = 0;
    localsniffle->newtio.c_cc[VTIME] = 1;

    if (tcsetattr(localsniffle->fd, TCSANOW, &localsniffle->newtio) < 0) {
        snprintf(msg, STATUS_MAX, "%s tcsetattr failed - %s",
            localsniffle->name, strerror(errno));
        pthread_mutex_unlock(&(localsniffle->serial_mutex));
        return -1;
    }

    tcflush(localsniffle->fd, TCIFLUSH);

    pthread_mutex_unlock(&(localsniffle->serial_mutex));

    // Configure Sniffle for passive scanning on the requested channel
    sniffle_setup_passive_scan(localsniffle);

    *dlt = KDLT_BTLE_RADIO;

    return 1;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_sniffle_t *localsniffle = (local_sniffle_t *) caph->userdata;

    char line[BUFFER_SIZE];
    uint8_t decoded[BUFFER_SIZE];
    char errstr[STATUS_MAX];

    while (1) {
        if (*(volatile int *) &caph->spindown) {
            tcsetattr(localsniffle->fd, TCSANOW, &localsniffle->oldtio);
            break;
        }

        int line_len = sniffle_readline(caph, localsniffle->fd, line, sizeof(line));

        if (line_len < 0) {
            // Either spindown or a real read error/closed device; either
            // way there's nothing more useful to do in this loop iteration
            if (*(volatile int *) &caph->spindown)
                break;
            snprintf(errstr, STATUS_MAX, "%s error reading from serial device",
                localsniffle->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (line_len < 4)
            continue; // blank/too-short line, not a real message

        int decoded_len = b64_decode_line(line, line_len, decoded, sizeof(decoded));

        if (decoded_len < 2)
            continue; // malformed or too short to contain a message type byte

        uint8_t msgtype = decoded[1];

        // Only 0x10 (PacketMessage) matters for Kismet - 0x11 (debug text),
        // 0x12 (marker), 0x13 (state), 0x14 (version/measurement) are all
        // ignored here, same as this datasource has no use for them.
        if (msgtype != 0x10)
            continue;

        uint8_t *body = decoded + 2;
        int body_len = decoded_len - 2;

        if (body_len <= 0)
            continue;

        struct timeval tv;
        gettimeofday(&tv, NULL);

        while (1) {
            int r = cf_send_data(caph, NULL, 0, NULL, NULL, tv, 0,
                    (uint32_t) body_len, (uint32_t) body_len, body);

            if (r < 0) {
                cf_send_error(caph, 0, "unable to send DATA frame");
                cf_handler_spindown(caph);
                break;
            } else if (r == 0) {
                cf_handler_wait_ringbuffer(caph);
                continue;
            } else {
                break;
            }
        }
    }
}

int main(int argc, char *argv[]) {
    local_sniffle_t localsniffle = {
        .name = NULL,
        .interface = NULL,
        .channel = 37,
        .baudrate = D_BAUDRATE,
    };

    pthread_mutex_init(&localsniffle.serial_mutex, NULL);

    kis_capture_handler_t *caph = cf_handler_init("sniffle_ble");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Unable to initialize capture framework\n");
        return -1;
    }

    localsniffle.caph = caph;

    cf_handler_set_userdata(caph, &localsniffle);

    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_capture_cb(caph, capture_thread);

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_remote_capture(caph);

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    return 0;
}
