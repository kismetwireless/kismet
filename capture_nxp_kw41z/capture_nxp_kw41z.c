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
#define CRTSCTS  020000000000 /*should be defined but isn't with the C99*/
#endif

/* Unique instance data passed around by capframework */
typedef struct {

    pthread_mutex_t serial_mutex;

    struct termios oldtio,newtio;

    int fd;

    unsigned int channel;

    char *name;
    char *interface;

    kis_capture_handler_t *caph;
} local_nxp_t;

/* Most basic of channel definitions */
typedef struct {
    unsigned int channel;
} local_channel_t;

int nxp_write_cmd(kis_capture_handler_t *caph, uint8_t *tx_buf, size_t tx_len, uint8_t *resp, size_t resp_len, uint8_t *rx_buf, size_t rx_max)
{
    uint8_t buf[255];
    uint16_t ctr = 0;
    uint8_t res = 0;
    bool found = false;
    local_nxp_t *localnxp = (local_nxp_t *) caph->userdata;
    pthread_mutex_lock(&(localnxp->serial_mutex));

    if(tx_len > 0) {

     // we are transmitting something
        write(localnxp->fd,tx_buf,tx_len);
        if(resp_len > 0) {
	    // looking for a response
            while(ctr < 5000) {
		    usleep(10);
                res = read(localnxp->fd,buf,255);
                // currently if we get something back that is fine and continue
		// if needed we can look for a specific response
                if(memcmp(buf,resp,resp_len) == 0)
	        {
		    found = true;
		    break; 
		}
                if(res > 0) {
                    break;
                }
                ctr++;
            }
            if(!found)
            return -1;// we fell through
        }
    }
    else if(rx_max > 0) {
        res = read(localnxp->fd,rx_buf,rx_max);
    }
    pthread_mutex_unlock(&(localnxp->serial_mutex));
    return res;
}

int nxp_reset(kis_capture_handler_t *caph)
{
    uint8_t cmd_1[6] = {0x02,0xA3,0x08,0x00,0x00,0xAB};
    nxp_write_cmd(caph,cmd_1,6,NULL,0,NULL,0);
    return 1;
}

int nxp_enter_promisc_mode(kis_capture_handler_t *caph, uint8_t chan)
{
    // first byte is header, last byte is checksum
    // checksum is basic xor of other bits
    // for these we can jsut used precomputed packets

    // bluetooth
    uint8_t cmd_1[6] = {0x02,0x52,0x00,0x00,0x00,0x52};
    uint8_t rep_1[6] = {0x02,0x52,0x02,0x00,0x00,0x50};
    nxp_write_cmd(caph,cmd_1,6,rep_1,6,NULL,0);

    uint8_t cmd_2[7] = {0x02,0x4E,0x00,0x01,0x00,0x00,0x4F};
    uint8_t rep_2[7] = {0x02,0x4E,0x80,0x01,0x00,0x00,0xCF};
    nxp_write_cmd(caph,cmd_2,7,rep_2,7,NULL,0);

    // chan 37 by default
    uint8_t cmd_3[7] = {0x02,0x4E,0x02,0x01,0x00,0x01,0x4C};
    uint8_t rep_3[7] = {0x02,0x4E,0x01,0x01,0x00,0x00,0x4E};
    if (chan == 38) {
    cmd_3[5] = 0x02; cmd_3[6] = 0x4F;}
    if(chan == 39) {
    cmd_3[5] = 0x04; cmd_3[6] = 0x49;}

    nxp_write_cmd(caph,cmd_3,7,NULL,0,NULL,0);

    uint8_t cmd_4[7] = {0x02,0x4E,0x01,0x01,0x00,0x00,0x4E};
    uint8_t rep_4[7] = {0x02,0x4E,0x80,0x01,0x00,0x00,0xCF};
    nxp_write_cmd(caph,cmd_4,7,rep_4,7,NULL,0);

    uint8_t cmd_5[7] = {0x02,0x4E,0x00,0x01,0x00,0x01,0x4E};
    // uint8_t rep_5[7] = {0x02,0x4E,0x80,0x01,0x00,0x00,0xCF};
    nxp_write_cmd(caph,cmd_5,7,NULL,0,NULL,0);

    return 1;
}

int nxp_exit_promisc_mode(kis_capture_handler_t *caph)
{
    uint8_t cmd[7] = {0x02,0x4E,0x00,0x01,0x00,0x00,0x4F};
    uint8_t rep[7] = {0x02,0x4E,0x80,0x01,0x00,0x00,0xCF};
    nxp_write_cmd(caph,cmd,7,rep,7,NULL,0);
    return 1;
}

int nxp_set_channel(kis_capture_handler_t *caph, uint8_t channel)
{
    nxp_exit_promisc_mode(caph);
    nxp_enter_promisc_mode(caph,channel);

    return 1;
}

int nxp_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
    
    int res = nxp_write_cmd(caph,NULL,0,NULL,0,rx_buf,rx_max);

    return res;
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

    /* NXP KW41Z supports 37-39 for ble */
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

    local_nxp_t *localnxp = (local_nxp_t *) caph->userdata;

    *ret_interface = cf_params_interface_new();

    char cap_if[32];

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

    /* NXP KW41Z supports 37-39 for ble */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);
    for (int i = 37; i < 40; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 37] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 3;

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

    /* flush and set up */
    tcflush(localnxp->fd, TCIFLUSH);
    tcsetattr(localnxp->fd, TCSANOW, &localnxp->newtio);

    pthread_mutex_unlock(&(localnxp->serial_mutex));
    
    //nxp_reset(caph);
    
    nxp_exit_promisc_mode(caph);
    nxp_enter_promisc_mode(caph,37);

    return 1;
}

void *chantranslate_callback(kis_capture_handler_t *caph, char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "1 unable to parse requested channel '%s'; ticc2540 channels "
                "are from 37 to 39", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if (parsechan > 39 || parsechan < 37) {
        snprintf(errstr, STATUS_MAX, "2 unable to parse requested channel '%u'; ticc2540 channels "
                "are from 37 to 39", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;
    return ret_localchan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {

    local_channel_t *channel = (local_channel_t *) privchan;
    int r;

    if (privchan == NULL) {
        return 0;
    }

    r = nxp_set_channel(caph, channel->channel);
    
    return r;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {

    local_nxp_t *localnxp = (local_nxp_t *) caph->userdata;

    char errstr[STATUS_MAX];
    uint8_t buf[256];
    int buf_rx_len = 0;
    int r = 0;

    while(1) {
	    if(caph->spindown) {
            nxp_exit_promisc_mode(caph);
            /* set the port back to normal */
            pthread_mutex_lock(&(localnxp->serial_mutex));
            tcsetattr(localnxp->fd,TCSANOW,&localnxp->oldtio);
            pthread_mutex_unlock(&(localnxp->serial_mutex));
            break;
	    }
            buf_rx_len = nxp_receive_payload(caph, buf, 256);
            if (buf_rx_len < 0) {
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }

            if(buf_rx_len > 0)
            while (1) {
                struct timeval tv;

                gettimeofday(&tv, NULL);

                if ((r = cf_send_data(caph,
                                NULL, NULL, NULL,
                                tv,
                                0,
                                buf_rx_len, buf)) < 0) {
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
    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_nxp_t localnxp = {
        .caph = NULL,
	.name = NULL,
        .interface = NULL,
        .fd = -1,
    };

    pthread_mutex_init(&(localnxp.serial_mutex), NULL);

    kis_capture_handler_t *caph = cf_handler_init("nxp_kw41z");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localnxp.caph = caph;

    /* Limit channel hop rate since it requires multiple usb commands */
    // caph->max_channel_hop_rate = 30;// 30 seconds

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

