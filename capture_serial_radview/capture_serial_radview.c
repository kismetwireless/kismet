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
 * This datasource interfaces with the radview geiger counter:
 * https://www.radviewdetection.com/
 *
 * The radview outputs a CPS and a spectral value as raw digital and analog 
 * 5 volt signals, and must be combined with something like an Arduino to 
 * turn the signals into usable data.
 *
 * Included is an Arduino sketch for 5v IO compatible arduino devices which 
 * outputs JSON over serial in a format expected by this capture code.
 *
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "../capture_framework.h"
#include "../config.h"
#include "../simple_ringbuf_c.h"

#include "serial_radview.h"

#define BUFFER_SIZE 2048

#if defined(SYS_OPENBSD)
#define MODEMDEVICE "/dev/cuaU0"
#else
#define MODEMDEVICE "/dev/ttyUSB0"
#endif

#ifndef CRTSCTS
#define CRTSCTS 020000000000 /*should be defined but isn't with the C99*/
#endif

/* Unique instance data passed around by capframework */
typedef struct {
    pthread_mutex_t serial_mutex;

    struct termios oldtio, newtio;

    int fd;

    char *name;
    char *interface;

    speed_t baudrate;

    kis_simple_ringbuf_t *serial_ringbuf;

    kis_capture_handler_t *caph;
} local_radview_t;

/* Convert to a typed baudrate */
int get_baud(int baud) {
    switch (baud) {
        case 9600:
            return B9600;
        case 19200:
            return B19200;
        case 38400:
            return B38400;
        case 57600:
            return B57600;
        case 115200:
            return B115200;
        case 230400:
            return B230400;
        case 460800:
            return B460800;
        case 500000:
            return B500000;
        case 576000:
            return B576000;
        case 921600:
            return B921600;
        case 1000000:
            return B1000000;
        case 1152000:
            return B1152000;
        case 1500000:
            return B1500000;
        case 2000000:
            return B2000000;
        case 2500000:
            return B2500000;
        case 3000000:
            return B3000000;
        case 3500000:
            return B3500000;
        case 4000000:
            return B4000000;
        default:
            return -1;
    }
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

    /* Look for the interface type */
    if (strstr(interface, "radview") != interface) {
        free(interface);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "Radview requires a device= field in the capture "
                "definition with a path to the serial device");
        return 0;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_serial_radview",
                strlen("kismet_cap_serial_radview")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    free(device);

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
    unsigned int *localbaudrate = NULL;

    local_radview_t *localrad = (local_radview_t *) caph->userdata;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    localrad->interface = strndup(placeholder, placeholder_len);

    if (strstr(localrad->interface, "radview") != localrad->interface) {
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localrad->name = strndup(placeholder, placeholder_len);
    } else {
        localrad->name = strdup(localrad->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX,
            "%s requires a device= field in the capture definition with a path to the serial device",
            localrad->name);
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "baudrate", definition)) > 0) {
        localbaudratestr = strndup(placeholder, placeholder_len);
        localbaudrate = (unsigned int *) malloc(sizeof(unsigned int));

        *localbaudrate = atoi(localbaudratestr);

        free(localbaudratestr);
        localbaudratestr = NULL;

        if (localbaudrate == NULL) {
            snprintf(msg, STATUS_MAX,
                "radview could not parse baudrate= option provided in source "
                "definition");
            return -1;
        }

        localrad->baudrate = get_baud(*localbaudrate);

        free(localbaudrate);
        localbaudrate = NULL;
    } else {
        localrad->baudrate = D_BAUDRATE;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_serial_radview",
                strlen("kismet_cap_serial_radview")) &
                0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    localrad->fd = open(device, O_RDWR | O_NOCTTY);

    if (localrad->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
            localrad->name, strerror(errno));
        return -1;
    }

    tcgetattr(localrad->fd, &localrad->oldtio); 
    bzero(&localrad->newtio, sizeof(localrad->newtio));

    /* set the baud rate and flags */
#if defined(SYS_OPENBSD)
    localrad->newtio.c_cflag = CRTSCTS | CS8 | CLOCAL | CREAD;
    cfsetspeed(&localrad->newtio, localrad->baudrate);
#else
    localrad->newtio.c_cflag =
        localrad->baudrate | CRTSCTS | CS8 | CLOCAL | CREAD;
#endif

    /* ignore parity errors */
    localrad->newtio.c_iflag = IGNPAR;

    /* raw output */
    localrad->newtio.c_oflag = 0;

    /* newtio.c_lflag = ICANON; */
    localrad->newtio.c_cc[VTIME] = 5; // 0.5 seconds
    localrad->newtio.c_cc[VMIN] = 0;

    /* flush and set up */
    if (tcsetattr(localrad->fd, TCSANOW, &localrad->newtio)) {
        snprintf(msg, STATUS_MAX, "%s failed to set serial device options - %s",
                 localrad->name, strerror(errno));
        return -1;
    }

    if (tcflush(localrad->fd, TCIFLUSH)) {
        snprintf(msg, STATUS_MAX, "%s failed to flush serial device - %s",
                 localrad->name, strerror(errno));
        return -1;
    }

    free(device);

    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_radview_t *localrad = (local_radview_t *) caph->userdata;

    ssize_t amt_read;
    size_t maxread = 0;
    uint8_t *buf;
    size_t buf_avail;
    size_t peeked_sz;

    char errstr[STATUS_MAX];

    while (1) {
        if (caph->spindown) {
            break;
        }

        buf_avail = kis_simple_ringbuf_available(localrad->serial_ringbuf);

        if (buf_avail == 0) {
            snprintf(errstr, STATUS_MAX, "%s serial read buffer full; possibly incorrect radview "
                    "firmware; expected JSON records.", localrad->name);
            /* printf("DEBUG: %s\n", errstr); */
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
            break;
        }

        maxread = kis_simple_ringbuf_reserve_zcopy(localrad->serial_ringbuf, (void **) &buf, buf_avail);
        amt_read = read(localrad->fd, buf, maxread);

        if (amt_read <= 0) {
            kis_simple_ringbuf_commit(localrad->serial_ringbuf, buf, 0);

            if (errno && errno != EINTR && errno != EAGAIN) {
                snprintf(errstr, STATUS_MAX, "%s serial port error: %s", localrad->name,
                        strerror(errno));
                /* printf("DEBUG: %s\n", errstr); */
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
                break;
            }
        } else {
            kis_simple_ringbuf_commit(localrad->serial_ringbuf, buf, amt_read);

            /* Search for newlines, return json record */
            ssize_t newline = 0;
            int fail = 0;
            struct timeval tv;
            int r;

            while (1) {
                newline = kis_simple_ringbuf_search_byte(localrad->serial_ringbuf, '\n');
                if (newline <= 0)
                    break;

                peeked_sz = kis_simple_ringbuf_peek_zc(localrad->serial_ringbuf, (void **) &buf, newline);

                if (peeked_sz < newline) {
                    snprintf(errstr, STATUS_MAX, "%s unable to fetch output from buffer.", localrad->name);
                    /* printf("DEBUG: %s\n", errstr); */
                    cf_send_message(caph, errstr, MSGFLAG_ERROR);
                    fail = 1;
                    break;
                }

                buf[newline] = '\0';

                gettimeofday(&tv, NULL);

                while (1) {
                    r = cf_send_json(caph, NULL, 0, NULL, NULL, tv, "radview", (char *) buf);

                    if (r < 0) {
                        snprintf(errstr, STATUS_MAX, "%s unable to send JSON frame.", localrad->name);
                        fprintf(stderr, "%s", errstr);
                        cf_send_error(caph, 0, errstr);
                        fail = 1;
                        break;
                    } else if (r == 0) {
                        cf_handler_wait_ringbuffer(caph);
                        continue;
                    } else {
                        break;
                    }
                }

                kis_simple_ringbuf_peek_free(localrad->serial_ringbuf, buf);
                kis_simple_ringbuf_read(localrad->serial_ringbuf, NULL, newline + 1);

                continue;
            }

            if (fail) {
                break;
            }
        }
    }

    /* set the port back to normal */
    tcsetattr(localrad->fd, TCSANOW, &localrad->oldtio);
    close(localrad->fd);

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_radview_t localrad = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .fd = -1,
        .serial_ringbuf = NULL,
    };

    kis_capture_handler_t *caph = cf_handler_init("radview");

    if (caph == NULL) {
        fprintf(stderr,
            "FATAL: Could not allocate basic handler data, your system "
            "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localrad.serial_ringbuf = kis_simple_ringbuf_create(8192); 

    localrad.caph = caph;

    cf_handler_set_userdata(caph, &localrad);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback); /**/
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
