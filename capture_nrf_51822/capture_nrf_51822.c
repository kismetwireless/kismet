
#include "../config.h"

#include "nrf_51822.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#include "../capture_framework.h"

volatile int STOP=FALSE;

#define MODEMDEVICE "/dev/ttyUSB0"
# define CRTSCTS  020000000000 /*should be defined but isn't with the C99*/

/* Unique instance data passed around by capframework */
typedef struct {

    pthread_mutex_t serial_mutex;

    struct termios oldtio,newtio;

    int fd;

    kis_capture_handler_t *caph;
} local_nrf_t;

int nrf_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
//printf("nrf_receive_payload\n");
    
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    int actual_len = 0;

    actual_len = read(localnrf->fd,rx_buf,rx_max);
//printf("nrf_receive_payload close\n");
    return actual_len;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
 
printf("probe_callback\n");

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    int x;

     int r;

    int matched_device = 0;

    local_nrf_t *localnrf51822 = (local_nrf_t *) caph->userdata;

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

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
            adler32_csum((unsigned char *) "kismet_cap_nrf_51822", 
                strlen("kismet_cap_nrf_51822")) & 0xFFFFFFFF,
            1, 1);
    *uuid = strdup(errstr);

    /* TI CC 2540 supports 37-39 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);
    for (int i = 37; i < 40; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 37] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 3;

printf("probe_callback close\n");

    return 1;
}/////mutex inside

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

printf("open_callback\n");

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    /* open for r/w but no tty */
    printf("open the serial\n");
    localnrf->fd = open(MODEMDEVICE, O_RDWR | O_NOCTTY );
    printf("post open fc:%d\n",localnrf->fd);
    if (localnrf->fd <0) {perror(MODEMDEVICE); exit(-1); }
    printf("continue on\n");
    tcgetattr(localnrf->fd,&localnrf->oldtio); /* save current serial port settings */
    bzero(&localnrf->newtio, sizeof(localnrf->newtio)); /* clear struct for new port settings */

    /* set the baud rate and flags */
    localnrf->newtio.c_cflag = BAUDRATE | CRTSCTS | CS8 | CLOCAL | CREAD;

    /* ignore parity errors */
    localnrf->newtio.c_iflag = IGNPAR;// | ICRNL;

    /* raw output */
    localnrf->newtio.c_oflag = 0;

    /* newtio.c_lflag = ICANON; */

    /* flush and set up */
    tcflush(localnrf->fd, TCIFLUSH);
    tcsetattr(localnrf->fd,TCSANOW,&localnrf->newtio);

printf("open_callback close\n");

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
    int pld_ctr = 0;
    int pkt_ctr = 0;

    int r=0;

    while(1) {
	    if(caph->spindown) {
		/* set the port back to normal */
                tcsetattr(localnrf->fd,TCSANOW,&localnrf->oldtio);
		break;
	    }

        buf_rx_len = nrf_receive_payload(caph, buf, 256);
        if (buf_rx_len < 0) {
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        //printf("buf_rx_len:%d\n",buf_rx_len);

        /* do some parsing or validation */

	if(buf[0] == 0xAB && buf[buf_rx_len-1] == 0xBC)
	{

for(int xp=0;xp<buf_rx_len;xp++)
{
//      printf("xp:%d\n",xp);
        if(
        (buf[xp] == 0xAB && xp == 0)
        || (buf[xp] == 0xAB && buf[xp-1] == 0xBC)
        )
        {
                //printf("start of new packet\n");
                pkt_start = xp;xp++;
                hdr_len = buf[pkt_start+1];
                pkt_len = buf[pkt_start+2];
                //printf("header length:%02X - %d\n",hdr_len,hdr_len);
                //printf("payload length:%02X - %d\n",pkt_len,pkt_len);
        }
        /*
        printf(" HEADER \n");
        for(int hctr=(pkt_start+1);hctr<(hdr_len+pkt_start+1);hctr++)
        {
                printf("%02X ",buf[hctr]);xp++;
        }
        printf("\n");
        */
        pld_ctr = 0;
        pkt_ctr = 0;
        memset(pkt,0x00,255);
        //printf(" PAYLOAD \n");
        for(int hctr=(pkt_start+1+hdr_len);hctr<(pkt_len+pkt_start+1+hdr_len);hctr++)
        {
                //printf("%02X ",buf[hctr]);xp++;
                pld_ctr++;
                if(pld_ctr > 10 && pld_ctr != 17)//there is a pad at 17....
                {
                        pkt[pkt_ctr] = buf[hctr]; pkt_ctr++;
                }
        }
        //printf("\n");

        //send the packet along
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
/*
for(int xp=0;xp<buf_rx_len;xp++)
{
        printf("%02X ",buf[xp]);
}
*/
	}

    }
    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_nrf_t localnrf = {
        .caph = NULL,
    };

    kis_capture_handler_t *caph = cf_handler_init("nrf51822");
    //int r;

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localnrf.caph = caph;

    printf("nrf51822 main\n");

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

