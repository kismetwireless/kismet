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
#include "nrf_51822.h"

#define BUFFER_SIZE 256

#if defined(SYS_OPENBSD)
#define MODEMDEVICE "/dev/cuaU0"
#else
#define MODEMDEVICE "/dev/ttyUSB0"
#endif

#ifndef CRTSCTS
#define CRTSCTS 020000000000 /*should be defined but isn't with the C99*/
#endif

#define CHECK_BIT(var, pos) ((var) & (1 << (pos)))

/* Unique instance data passed around by capframework */
typedef struct {
    pthread_mutex_t serial_mutex;

    struct termios oldtio, newtio;

    int fd;

    char *name;
    char *interface;

    speed_t baudrate;

    // we will keep a counter of empty length packets
    unsigned int error_ctr;
    unsigned int ping_ctr;

    kis_capture_handler_t *caph;
} local_nrf_t;

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

bool ping_check(kis_capture_handler_t *caph) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    /**
    PING_REQ = 0x0D
    PING_RESP = 0x0E
    **/
    uint8_t buf[BUFFER_SIZE-1];
    buf[0] = 0x0D;
    uint16_t ctr = 0;
    int8_t res = 0;
    int8_t resp_len = 1;
    bool found = false;
    pthread_mutex_lock(&(localnrf->serial_mutex));

    /* lets flush the buffer */
    tcflush(localnrf->fd, TCIOFLUSH);
    /* we are transmitting something */
    res = write(localnrf->fd, buf, 1);
    if (res < 0) {
        found = false;
    }
    if (resp_len > 0) {
        /* looking for a response */
        while (ctr < 5000) {
            usleep(25);
            memset(buf, 0x00, sizeof(buf));
            found = false;
            res = read(localnrf->fd, buf, BUFFER_SIZE-1);
            /* currently if we get something back that is fine and continue */
            if (res > 0) {
                found = true;
                break;
            }
            ctr++;
        }
    }
    pthread_mutex_unlock(&(localnrf->serial_mutex));
    return found;
}

int nrf_receive_payload(
    kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    int actual_len = 0;

    pthread_mutex_lock(&(localnrf->serial_mutex));
    actual_len = read(localnrf->fd, rx_buf, rx_max);
    pthread_mutex_unlock(&(localnrf->serial_mutex));

    if (actual_len == 0) {
        localnrf->error_ctr++;
        if (localnrf->error_ctr > 1000000) {
            // try to send a ping packet to verify we are actually talking to
            // the correct device
            if (ping_check(caph)) {
                localnrf->error_ctr = 0;
                localnrf->ping_ctr = 0;
            } else {
                // we have an error, or possibly the incorrect serial port
                localnrf->ping_ctr++;
                if (localnrf->ping_ctr > 1000000) {
                    return -1;
                }
            }
        }
    } else {
        localnrf->error_ctr = 0;
        localnrf->ping_ctr = 0;
    }

    return actual_len;
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
    if (strstr(interface, "nrf51822") != interface) {
        free(interface);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) >
        0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX,
            "Expected device= path to serial device in definition");
        return 0;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) >
        0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_nrf_51822",
                strlen("kismet_cap_nrf_51822")) &
                0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    /* TI CC 2540 supports 37-39 */
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
    unsigned int *localbaudrate = NULL;

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    localnrf->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) >
        0) {
        localnrf->name = strndup(placeholder, placeholder_len);
    } else {
        localnrf->name = strdup(localnrf->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) >
        0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX,
            "%s expected device= path to serial device in definition",
            localnrf->name);
        return -1;
    }

    // try and find the baudrate
    if ((placeholder_len = cf_find_flag(&placeholder, "baudrate", definition)) >
        0) {
        localbaudratestr = strndup(placeholder, placeholder_len);
        localbaudrate = (unsigned int *) malloc(sizeof(unsigned int));
        *localbaudrate = atoi(localbaudratestr);
        free(localbaudratestr);

        if (localbaudrate == NULL) {
            snprintf(msg, STATUS_MAX,
                "nrf51822 could not parse baudrate= option provided in source "
                "definition");
            return -1;
        }
        // better way of doing this?
        localnrf->baudrate = get_baud(*localbaudrate);
    } else {
        localnrf->baudrate = D_BAUDRATE;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) >
        0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_nrf_51822",
                strlen("kismet_cap_nrf_51822")) &
                0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    /* open for r/w but no tty */
    localnrf->fd = open(device, O_RDWR | O_NOCTTY);

    if (localnrf->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
            localnrf->name, strerror(errno));
        return -1;
    }

    tcgetattr(localnrf->fd,
        &localnrf->oldtio); /* save current serial port settings */
    bzero(&localnrf->newtio,
        sizeof(localnrf->newtio)); /* clear struct for new port settings */

    /* set the baud rate and flags */
#if defined(SYS_OPENBSD)
    localnrf->newtio.c_cflag = CRTSCTS | CS8 | CLOCAL | CREAD;
    cfsetspeed(&localnrf->newtio, localnrf->baudrate);
#else
    localnrf->newtio.c_cflag =
        localnrf->baudrate | CRTSCTS | CS8 | CLOCAL | CREAD;
#endif

    /* ignore parity errors */
    localnrf->newtio.c_iflag = IGNPAR;

    /* raw output */
    localnrf->newtio.c_oflag = 0;

    /* newtio.c_lflag = ICANON; */
    localnrf->newtio.c_cc[VTIME] = 5; // 0.5 seconds
    localnrf->newtio.c_cc[VMIN] = 0;

    /* flush and set up */
    if (tcsetattr(localnrf->fd, TCSANOW, &localnrf->newtio)) {
        snprintf(msg, STATUS_MAX, "%s failed to set serial device options - %s",
                 localnrf->name, strerror(errno));
        return -1;
    }

    if (tcflush(localnrf->fd, TCIFLUSH)) {
        snprintf(msg, STATUS_MAX, "%s failed to flush serial device - %s",
                 localnrf->name, strerror(errno));
        return -1;
    }

    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    char errstr[STATUS_MAX];
    uint8_t buf[BUFFER_SIZE];
    int buf_rx_len = 0;
    unsigned char pkt[BUFFER_SIZE-1];
    memset(pkt, 0x00, sizeof(pkt));

    int pkt_start = 0;
    int hdr_len = 0;
    int pkt_len = 0;
    /* int pld_ctr = 0; */
    int pkt_ctr = 0;
    bool valid_pkt = false;

    int r = 0;

    while (1) {
        if (caph->spindown) {
            /* set the port back to normal */
            tcsetattr(localnrf->fd, TCSANOW, &localnrf->oldtio);
            break;
        }

        valid_pkt = false;
	memset(buf, 0, sizeof(buf));
        buf_rx_len = nrf_receive_payload(caph, buf, BUFFER_SIZE);

        if (buf_rx_len < 0) {
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (buf_rx_len > 0 ) {
	    if (buf[0] == SLIP_START && buf[buf_rx_len - 1] != SLIP_END) {
		while(buf[buf_rx_len - 1] != SLIP_END && buf_rx_len < BUFFER_SIZE)
		{
		    int size_read = 0, size_to_read = BUFFER_SIZE - buf_rx_len;
                    size_read = nrf_receive_payload(caph, &buf[buf_rx_len], size_to_read);
		    buf_rx_len += size_read;
		}
	    }
        }

        /* multiple packets can be returned at the same time.
         * I had tried passing it all to the data source, but
         * that caused some issues. It was easier to break them
         * apart here and send along to the data source.
         */
        /* do some parsing or validation */

        if (buf[0] == SLIP_START && buf[buf_rx_len - 1] == SLIP_END) {
            for (int xp = 0; xp < buf_rx_len; xp++) {
                if ((buf[xp] == SLIP_START && xp == 0) ||
                    (buf[xp] == SLIP_START && buf[xp - 1] == SLIP_END)) {
                    pkt_start = xp;
                    xp++;
                    /* check the protocol version */
                    if (buf[pkt_start + 3] == 0x01) {
                        hdr_len = buf[pkt_start + 1];
                        pkt_len = buf[pkt_start + 2];
                    } else if (buf[pkt_start + 3] == 0x02 ||
                        buf[pkt_start + 3] == 0x03) {
                        hdr_len = 0x06;
                        pkt_len = buf[pkt_start + 1];
                    }
                }

                /* check the packet_type from the header */
                if (buf[pkt_start + 6] == EVENT_PACKET_DATA ||
                        (buf[pkt_start + 3] == 0x03 &&
                         buf[pkt_start + 6] == EVENT_PACKET_ADVERTISING)) {
                    valid_pkt = true;
                    /* pld_ctr = 0; */
                    pkt_ctr = 0;
                    memset(pkt, 0x00, sizeof(pkt));

                    for (int hctr = (pkt_start + 1 + hdr_len);
                         hctr < (pkt_len + pkt_start + 1 + hdr_len); hctr++) {
                        xp++;
                        pkt[pkt_ctr] = buf[hctr];
                        pkt_ctr++;
                    }
                }

                /* send the packet along */
                if (pkt_ctr > 0 && valid_pkt) {
                    while (1) {
                        struct timeval tv;

                        gettimeofday(&tv, NULL);

                        if ((r = cf_send_data(caph, NULL, 0,
                                        NULL, NULL, tv, 0,
                                        pkt_ctr, pkt_ctr, pkt)) < 0) {
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
            }
        }
    }
    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_nrf_t localnrf = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .fd = -1,
    };

    kis_capture_handler_t *caph = cf_handler_init("nrf51822");

    if (caph == NULL) {
        fprintf(stderr,
            "FATAL: Could not allocate basic handler data, your system "
            "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localnrf.caph = caph;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localnrf);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    /**/ cf_handler_set_probe_cb(caph, probe_callback); /**/

    /* Set the list callback */
    /* cf_handler_set_listdevices_cb(caph, list_callback); */

    /* Channel callbacks */
    /* cf_handler_set_chantranslate_cb(caph, chantranslate_callback); */
    /* cf_handler_set_chancontrol_cb(caph, chancontrol_callback); */

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
