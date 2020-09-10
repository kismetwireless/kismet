#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#include "../config.h"

#include "nrf_51822.h"

#include "../capture_framework.h"

#include "nrf_51822.h"

#define MODEMDEVICE "/dev/ttyUSB0"

#ifndef CRTSCTS
#define CRTSCTS  020000000000 /*should be defined but isn't with the C99*/
#endif

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

/* Unique instance data passed around by capframework */
typedef struct {
    pthread_mutex_t serial_mutex;

    struct termios oldtio, newtio;

    int fd;

    char *name;
    char *interface;

    kis_capture_handler_t *caph;
} local_nrf_t;

int nrf_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    int actual_len = 0;

    actual_len = read(localnrf->fd,rx_buf,rx_max);
    return actual_len;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, KismetExternal__Command *frame,
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

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        return 0;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_nrf_51822", 
                    strlen("kismet_cap_nrf_51822")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device,
                    strlen(device)));
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
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    char *placeholder;
    int placeholder_len;
    char *device = NULL;
    char errstr[STATUS_MAX];

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return -1;
    }

    localnrf->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localnrf->name = strndup(placeholder, placeholder_len);
    } else {
        localnrf->name = strdup(localnrf->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "%s expected device= path to serial device in definition",
                localnrf->name);
        return -1;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the serial device */

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_nrf_51822", 
                    strlen("kismet_cap_nrf_51822")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device,
                    strlen(device)));
        *uuid = strdup(errstr);
    }

    /* open for r/w but no tty */
    localnrf->fd = open(device, O_RDWR | O_NOCTTY );

    if (localnrf->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
                localnrf->name, strerror(errno));
        return -1;
    }

    tcgetattr(localnrf->fd,&localnrf->oldtio); /* save current serial port settings */
    bzero(&localnrf->newtio, sizeof(localnrf->newtio)); /* clear struct for new port settings */

    /* set the baud rate and flags */
    localnrf->newtio.c_cflag = BAUDRATE | CRTSCTS | CS8 | CLOCAL | CREAD;

    /* ignore parity errors */
    localnrf->newtio.c_iflag = IGNPAR;

    /* raw output */
    localnrf->newtio.c_oflag = 0;

    /* newtio.c_lflag = ICANON; */

    /* flush and set up */
    tcflush(localnrf->fd, TCIFLUSH);
    tcsetattr(localnrf->fd, TCSANOW, &localnrf->newtio);

    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    char errstr[STATUS_MAX];
    uint8_t buf[256];
    int buf_rx_len = 0;
    unsigned char pkt[255];memset(pkt,0x00,255);

    int pkt_start = 0;
    int hdr_len = 0;
    int pkt_len = 0;
    /* int pld_ctr = 0; */
    int pkt_ctr = 0;
    bool valid_pkt = false;

    int r = 0;

    while(1) {
        if (caph->spindown) {
            /* set the port back to normal */
            tcsetattr(localnrf->fd,TCSANOW,&localnrf->oldtio);
            break;
        }

        valid_pkt = false;
        buf_rx_len = nrf_receive_payload(caph, buf, 256);

        if (buf_rx_len < 0) {
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        /* multiple packets can be returned at the same time.
         * I had tried passing it all to the data source, but
         * that caused some issues. It was easier to break them
         * apart here and send along to the data source.
         */
        /* do some parsing or validation */

        if(buf[0] == 0xAB && buf[buf_rx_len-1] == 0xBC) {
            for(int xp=0;xp<buf_rx_len;xp++) {
                if((buf[xp] == 0xAB && xp == 0) || (buf[xp] == 0xAB && buf[xp-1] == 0xBC)) {
                    pkt_start = xp;xp++;
                    hdr_len = buf[pkt_start+1];
                    pkt_len = buf[pkt_start+2];
                }

                /* check the packet_type from the header */
                if (buf[pkt_start+6] == 0x06) {
                    valid_pkt = true;
                    /* pld_ctr = 0; */
                    pkt_ctr = 0;
                    memset(pkt,0x00,255);

                    for (int hctr = (pkt_start + 1 + hdr_len); 
                            hctr < (pkt_len + pkt_start + 1 + hdr_len); hctr++) {
                        xp++;
                        pkt[pkt_ctr] = buf[hctr]; pkt_ctr++;
                    }
                }

                /* send the packet along */
                if (pkt_ctr > 0 && valid_pkt) {
                    while (1) {
                        struct timeval tv;

                        gettimeofday(&tv, NULL);

                        if ((r = cf_send_data(caph,
                                        NULL, NULL, NULL,
                                        tv,
                                        0,
                                        pkt_ctr, pkt)) < 0) {
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
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
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

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
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

    return 0;
}
