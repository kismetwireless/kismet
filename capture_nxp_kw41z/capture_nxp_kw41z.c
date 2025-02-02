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

#define _GNU_SOURCE

#include "../config.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#include "nxp_kw41z.h"

#include "../capture_framework.h"

#ifndef CRTSCTS
#define CRTSCTS 020000000000 /*should be defined but isn't with the C99*/
#endif


int nxp_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max);

/* Unique instance data passed around by capframework */
typedef struct {
    pthread_mutex_t serial_mutex;

    struct termios oldtio, newtio;

    int fd;

    unsigned int channel;
    unsigned int prevchannel;
    char *name;
    char *interface;
    
    bool ready;

    kis_capture_handler_t *caph;
} local_nxp_t;

/* Most basic of channel definitions */
typedef struct {
    unsigned int channel;
} local_channel_t;

bool checksum(uint8_t *payload, uint8_t len) {
    uint8_t chk = 0;
    uint8_t checksum = payload[len - 1];
    chk = payload[1];

    for (int xp = 2; xp < len - 1; xp++) {
        chk ^= payload[xp];
    }

    return checksum == chk;
}

int nxp_write_cmd(kis_capture_handler_t *caph, uint8_t *tx_buf, size_t tx_len, uint8_t *resp,
                  size_t resp_len, uint8_t *rx_buf, size_t rx_max) {

    uint8_t buf[255];
    uint16_t ctr = 0;
    int8_t res = 0;
    bool found = false;
    local_nxp_t *localnxp = (local_nxp_t *) caph->userdata;
    pthread_mutex_lock(&(localnxp->serial_mutex));

    if (tx_len > 0) {
        /* lets flush the buffer */
        tcflush(localnxp->fd, TCIOFLUSH);
        /* we are transmitting something */
	    res = write(localnxp->fd, tx_buf, tx_len);
        if (res < 0) {
            return res;
        }
        if (resp_len > 0) {
            /* looking for a response */
            while (ctr < 5000) {
                usleep(25);
                memset(buf,0x00,255);
                found = false;
                res = read(localnxp->fd, buf, 255);
                /* currently if we get something back that is fine and continue */
                if (res > 0 && memcmp(buf, resp, resp_len) == 0) {
                    found = true;
                    break;
                } else if (res > 0) {
                    if (buf[0] == 0x02) {
                        /* we got something from the device */
                        res = -1;  // we fell through
                        tcflush(localnxp->fd,TCIOFLUSH);
                        break;
                    }
                }
                ctr++;
            }
            if (!found) {
                res = -1;  // we fell through
            }
        } else {
            res = 1;  // no response requested
        }
    } else if (rx_max > 0) {
        res = read(localnxp->fd, rx_buf, rx_max);
	    if (res < 0) {
            usleep(25);
            res = 0;
        }
    }

    pthread_mutex_unlock(&(localnxp->serial_mutex));
    return res;
}

int nxp_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
    return nxp_write_cmd(caph, NULL, 0, NULL, 0, rx_buf, rx_max);
}

int nxp_reset(kis_capture_handler_t *caph) {
    uint8_t cmd_1[6] = {0x02, 0xA3, 0x08, 0x00, 0x00, 0xAB};
    uint8_t buf[256];

    nxp_write_cmd(caph, cmd_1, 6, NULL, 0, NULL, 0);
    usleep(100);
    /* lets do some reads, to maybe clear the buffer */
    for (int i = 0; i < 10; i++) 
        nxp_receive_payload(caph, buf, 256);

    return 1;
}

int nxp_enter_promisc_mode(kis_capture_handler_t *caph, uint8_t chan) {
    /* first byte is header, last byte is checksum
     * checksum is basic xor of other bits
     * for these we can just used precomputed packets
     */
    int res = 0;
    if (chan < 30) {
        uint8_t cmd_1[14] = {0x02, 0x85, 0x09, 0x08, 0x00, 0x52, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD6};
        uint8_t rep_1[8] = {0x02, 0x84, 0x0D, 0x02, 0x00, 0x00, 0x52, 0xD9};
        res = nxp_write_cmd(caph, cmd_1, 14, rep_1, 8, NULL, 0);
        if (res < 0)
            return res;

        uint8_t cmd_2[14] = {0x02, 0x85, 0x09, 0x08, 0x00, 0x21, 0x0B,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAE};
        uint8_t rep_2[8] = {0x02, 0x84, 0x0D, 0x02, 0x00, 0x00, 0x21, 0xAA};

        /* channel */
        cmd_2[6] = chan;

        if (chan == 12)
            cmd_2[13] = 0xA9;
        else if (chan == 13)
            cmd_2[13] = 0xA8;
        else if (chan == 14)
            cmd_2[13] = 0xAB;
        else if (chan == 15)
            cmd_2[13] = 0xAA;
        else if (chan == 16)
            cmd_2[13] = 0xB5;
        else if (chan == 17)
            cmd_2[13] = 0xB4;
        else if (chan == 18)
            cmd_2[13] = 0xB7;
        else if (chan == 19)
            cmd_2[13] = 0xB6;
        else if (chan == 20)
            cmd_2[13] = 0xB1;
        else if (chan == 21)
            cmd_2[13] = 0xB0;
        else if (chan == 22)
            cmd_2[13] = 0xB3;
        else if (chan == 23)
            cmd_2[13] = 0xB2;
        else if (chan == 24)
            cmd_2[13] = 0xBD;
        else if (chan == 25)
            cmd_2[13] = 0xBC;
        else if (chan == 26)
            cmd_2[13] = 0xBF;

        res = nxp_write_cmd(caph, cmd_2, 14, rep_2, 8, NULL, 0);
        if (res < 0)
            return res;

        uint8_t cmd_3[14] = {0x02, 0x85, 0x09, 0x08, 0x00, 0x51, 0x01,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4};
        uint8_t rep_3[8] = {0x02, 0x84, 0x0D, 0x02, 0x00, 0x00, 0x51, 0xDA};
        res = nxp_write_cmd(caph, cmd_3, 14, rep_3, 8, NULL, 0);
        if (res < 0)
            return res;

        uint8_t cmd_4[14] = {0x02, 0x85, 0x09, 0x08, 0x00, 0x52, 0x01,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD7};
        uint8_t rep_4[8] = {0x02, 0x84, 0x0D, 0x02, 0x00, 0x00, 0x52, 0xD9};
        res = nxp_write_cmd(caph, cmd_4, 14, rep_4, 8, NULL, 0);
        if (res < 0)
            return res;
    } else {
        /* bluetooth */
        uint8_t cmd_1[6] = {0x02, 0x52, 0x00, 0x00, 0x00, 0x52};
        uint8_t rep_1[6] = {0x02, 0x52, 0x02, 0x00, 0x00, 0x50};
        res = nxp_write_cmd(caph, cmd_1, 6, rep_1, 6, NULL, 0);
        if (res < 0)
            return res;

        uint8_t cmd_2[7] = {0x02, 0x4E, 0x00, 0x01, 0x00, 0x00, 0x4F};
        uint8_t rep_2[7] = {0x02, 0x4E, 0x80, 0x01, 0x00, 0x00, 0xCF};
        res = nxp_write_cmd(caph, cmd_2, 7, rep_2, 7, NULL, 0);
        if (res < 0)
            return res;

        /* chan 37 by default */
        uint8_t cmd_3[7] = {0x02, 0x4E, 0x02, 0x01, 0x00, 0x01, 0x4C};
        uint8_t rep_3[7] = {0x02, 0x4E, 0x82, 0x01, 0x00, 0x00, 0xCD};
        if (chan == 38) {
            cmd_3[5] = 0x02;
            cmd_3[6] = 0x4F;
        }
        if (chan == 39) {
            cmd_3[5] = 0x04;
            cmd_3[6] = 0x49;
        }

        res = nxp_write_cmd(caph, cmd_3, 7, rep_3, 7, NULL, 0);
        if (res < 0) return res;

        uint8_t cmd_4[7] = {0x02, 0x4E, 0x01, 0x01, 0x00, 0x00, 0x4E};
        uint8_t rep_4[7] = {0x02, 0x4E, 0x81, 0x01, 0x00, 0x00, 0xCE};
        res = nxp_write_cmd(caph, cmd_4, 7, rep_4, 7, NULL, 0);

        if (res < 0)
            return res;

        uint8_t cmd_5[7] = {0x02, 0x4E, 0x00, 0x01, 0x00, 0x01, 0x4E};
        uint8_t rep_5[7] = {0x02, 0x4E, 0x80, 0x01, 0x00, 0x00, 0xCF};
        res = nxp_write_cmd(caph, cmd_5, 7, rep_5, 7, NULL, 0);
        if (res < 0)
            return res;
    }

    return res;
}

int nxp_write_cmd_retry(kis_capture_handler_t *caph, uint8_t *tx_buf, size_t tx_len,
                        uint8_t *resp, size_t resp_len, uint8_t *rx_buf, size_t rx_max) {
    int ret = 0;
    int retries = 3;
    int reset = 0;

    while (retries > 0) {
        ret = nxp_write_cmd(caph,tx_buf,tx_len,resp,resp_len,rx_buf,rx_max);

        if (ret >= 0) {
            usleep(50);
            break;
        }

        usleep(100);
        retries--;

        if (retries == 0 && reset == 0) {
            retries = 3;
            reset = 1;
            nxp_reset(caph);
            usleep(200);
        }
    }

    return ret;
}

int nxp_exit_promisc_mode(kis_capture_handler_t *caph) {
    uint8_t cmd[7] = {0x02, 0x4E, 0x00, 0x01, 0x00, 0x00, 0x4F};
    uint8_t rep[7] = {0x02, 0x4E, 0x80, 0x01, 0x00, 0x00, 0xCF};
    int res = 0;

    res = nxp_write_cmd_retry(caph, cmd, 7, rep, 7, NULL, 0);

    return res;
}

int nxp_set_channel(kis_capture_handler_t *caph, uint8_t channel) {
    int res = 0;

    res = nxp_exit_promisc_mode(caph);

    if (res < 0) 
        return res;

    res = nxp_enter_promisc_mode(caph, channel);

    return res;
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

    char cap_if[32];

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "nxp_kw41z") != interface) {
        free(interface);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        return 0;
    }

    snprintf(cap_if, 32, "nxp_kw41z-%012X", adler32_csum((unsigned char *) device, strlen(device)));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_nxp_kw41z",
                    strlen("kismet_cap_nxp_kw41z")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("nxp_kw41z");

    /* NXP KW41Z supports 11-26 for zigbee and 37-39 for ble */
    char chstr[4];
    int ctr = 0;

    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);
    for (int i = 37; i < 40; i++) {
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[ctr] = strdup(chstr);
        ctr++;
    }

    (*ret_interface)->channels_len = 3;// 19

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    char *placeholder;
    int placeholder_len;
    char *device = NULL;
    char *phy = NULL;
    char errstr[STATUS_MAX];
    int res = 0;

    local_nxp_t *localnxp = (local_nxp_t *) caph->userdata;

    *ret_interface = cf_params_interface_new();

    char cap_if[32];

    char *localchanstr = NULL;
    unsigned int *localchan = NULL;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return -1;
    }

    localnxp->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localnxp->name = strndup(placeholder, placeholder_len);
    } else {
        localnxp->name = strdup(localnxp->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "%s expected device= path to serial device in definition",
                localnxp->name);
        return -1;
    }

    // try to pull the phy
    if ((placeholder_len = cf_find_flag(&placeholder, "phy", definition)) > 0) {
        phy = strndup(placeholder, placeholder_len);
    } else {
        phy = strdup("any");
    }

    // try pulling the channel
    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = atoi(localchanstr); 
        free(localchanstr);

        if (localchan == NULL) {
            snprintf(msg, STATUS_MAX,
                    "nxp kw41z could not parse channel= option provided in source "
                    "definition");
            return -1;
        }
    } else {
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = 11;
    }
    
    snprintf(cap_if, 32, "nxp_kw41z-%012X",adler32_csum((unsigned char *) device, strlen(device)));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_nxp_kw41z", 
                    strlen("kismet_cap_nxp_kw41z")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device,
                    strlen(device)));
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("nxp_kw41z");

    /* NXP KW41Z supports 11-26 for zigbee and 37-39 for ble */
    char chstr[4];
    int ctr = 0;
    if (strcmp(phy, "btle") == 0) {
        (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);

        for (int i = 37; i < 40; i++) {
            snprintf(chstr, 4, "%d", i);
            (*ret_interface)->channels[ctr] = strdup(chstr);
            ctr++;
        }

        (*ret_interface)->channels_len = 3;
        if (*localchan < 37) {
            *localchan = 37;
        }
    }
    else if (strcmp(phy, "zigbee") == 0) {
        (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 16);

        for (int i = 11; i < 27; i++) {
            snprintf(chstr, 4, "%d", i);
            (*ret_interface)->channels[ctr] = strdup(chstr);
            ctr++;
        }

        (*ret_interface)->channels_len = 16;
        if (*localchan > 26) {
            *localchan = 11;
        }
    } else {
        (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 19);

        for (int i = 11; i < 27; i++) {
            snprintf(chstr, 4, "%d", i);
            (*ret_interface)->channels[ctr] = strdup(chstr);
            ctr++;
        }

        for (int i = 37; i < 40; i++) {
            snprintf(chstr, 4, "%d", i);
            (*ret_interface)->channels[ctr] = strdup(chstr);
            ctr++;
        }

        (*ret_interface)->channels_len = 19;
    }

    pthread_mutex_lock(&(localnxp->serial_mutex));
    /* open for r/w but no tty */
    localnxp->fd = open(device, O_RDWR | O_NOCTTY);

    if (localnxp->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
                localnxp->name, strerror(errno));
        return -1;
    }

    tcgetattr(localnxp->fd,&localnxp->oldtio); /* save current serial port settings */
    bzero(&localnxp->newtio, sizeof(localnxp->newtio)); /* clear struct for new port settings */

    /* set the baud rate and flags */
    localnxp->newtio.c_cflag = BAUDRATE | CRTSCTS | CS8 | CLOCAL | CREAD;

    /* ignore parity errors */
    localnxp->newtio.c_iflag = IGNPAR;

    /* raw output */
    localnxp->newtio.c_oflag = 0;

    /* newtio.c_lflag = ICANON; */

    localnxp->newtio.c_lflag &= ~ICANON; /* Set non-canonical mode */
    localnxp->newtio.c_cc[VTIME] = 1; /* Set timeout in deciseconds */

    /* flush and set up */
    tcflush(localnxp->fd, TCIFLUSH);
    tcsetattr(localnxp->fd, TCSANOW, &localnxp->newtio);

    pthread_mutex_unlock(&(localnxp->serial_mutex));
   
    localnxp->ready = false;
 
    /* nxp_reset(caph); */

    res = nxp_exit_promisc_mode(caph);
    if (res < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to send NXP exit_promisc command (%d)\n", localnxp->name, res);
        return -1;
    }

    res = nxp_enter_promisc_mode(caph, *localchan);
    if (res < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to send NXP enter_promisc command (%d)\n", localnxp->name, res);
        return -1;
    }

    localnxp->channel = *localchan;

    localnxp->ready = true;

    return 1;
}

void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "1 unable to parse requested channel '%s'; nxp kw41z channels "
                "are from 11 to 26 and 37 to 39", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    /* if (parsechan > 39 || parsechan < 37) { */
    if (parsechan > 39 || parsechan < 11) {
        snprintf(errstr, STATUS_MAX, "2 unable to parse requested channel '%u'; nxp kw41z channels "
                "are from 11 to 26 and 37 to 39", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;
    return ret_localchan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_nxp_t *localnxp = (local_nxp_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    int r;

    if (privchan == NULL) {
        return 0;
    }
    /* crossing the phy layer */
    if ( (localnxp->prevchannel >= 37 && localnxp->prevchannel <= 39) &&
       (channel->channel >= 11 && channel->channel <= 26) ) {
        localnxp->ready = false;
        nxp_reset(caph);
        pthread_mutex_lock(&(localnxp->serial_mutex));
        // clear the buffer
        tcflush(localnxp->fd, TCIOFLUSH);
        usleep(350);
        tcflush(localnxp->fd, TCIOFLUSH);
        pthread_mutex_unlock(&(localnxp->serial_mutex));
        localnxp->ready = true;
    }

    if (localnxp->ready == true) {
        localnxp->ready = false;
        r = nxp_set_channel(caph, channel->channel);
        if (r <= 0) {
            localnxp->ready = false;
            nxp_reset(caph);
            // clear the buffer
            pthread_mutex_lock(&(localnxp->serial_mutex));
            tcflush(localnxp->fd, TCIOFLUSH);
            usleep(350);
            tcflush(localnxp->fd, TCIOFLUSH);
            pthread_mutex_unlock(&(localnxp->serial_mutex));
            r = 1;
            localnxp->ready = true;
        } else {
            pthread_mutex_lock(&(localnxp->serial_mutex));
            tcflush(localnxp->fd, TCIOFLUSH);
            pthread_mutex_unlock(&(localnxp->serial_mutex));
            localnxp->ready = true;
            localnxp->prevchannel = channel->channel;
        }
    } else {
	    r = 0;
    }

    return r;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_nxp_t *localnxp = (local_nxp_t *) caph->userdata;

    char errstr[STATUS_MAX];
    uint8_t buf[256];
    int buf_rx_len = 0;
    int r = 0;

    while (1) {
        if (caph->spindown) {
            nxp_exit_promisc_mode(caph);
            /* set the port back to normal */
            pthread_mutex_lock(&(localnxp->serial_mutex));
            tcsetattr(localnxp->fd, TCSANOW, &localnxp->oldtio);
            pthread_mutex_unlock(&(localnxp->serial_mutex));
            break;
        }
        buf_rx_len = 0;
        if (localnxp->ready) {
            memset(buf,0x00,256);
            buf_rx_len = nxp_receive_payload(caph, buf, 256);
            if (buf_rx_len < 0) {
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }
        }
        //check the checksum
        if (!checksum(buf,buf_rx_len)) {
            //printf("bad checksum\n");
            buf_rx_len = 0;
        }
        if (buf_rx_len > 0) {
            //printf("channel:%d prevchannel:%d\n",(uint8_t)localnxp->channel,(uint8_t)localnxp->prevchannel);
            /* btle channel is part of the packet, zigbee is not*/
            if((uint8_t)localnxp->prevchannel == 0){
                if((uint8_t)localnxp->channel >= 11 && (uint8_t)localnxp->channel <= 26) {
                    buf[4] = (uint8_t)localnxp->channel;
                }
            }
            else {
                if((uint8_t)localnxp->prevchannel >= 11 && (uint8_t)localnxp->prevchannel <= 26) {
                    buf[4] = (uint8_t)localnxp->prevchannel;
                }
            }

            while (1) {
                struct timeval tv;

                gettimeofday(&tv, NULL);

                if ((r = cf_send_data(caph, NULL, 0,
                                NULL, NULL, tv, 0,
                                buf_rx_len, buf_rx_len, buf)) < 0) {
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
    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_nxp_t localnxp = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .fd = -1,
        .ready = false,
        .prevchannel = 0,
    };

    pthread_mutex_init(&(localnxp.serial_mutex), NULL);

    kis_capture_handler_t *caph = cf_handler_init("nxp_kw41z");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localnxp.caph = caph;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localnxp);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    /* cf_handler_set_listdevices_cb(caph, list_callback); */

    /* Channel callbacks */
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback); 

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

