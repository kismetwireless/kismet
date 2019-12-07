
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
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    int actual_len = 0;

    actual_len = read(localnrf->fd,rx_buf,rx_max);

    return actual_len;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    /* open for r/w but no tty */
    localnrf->fd = open(MODEMDEVICE, O_RDWR | O_NOCTTY );
    if (localnrf->fd <0) {perror(MODEMDEVICE); exit(-1); }

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
                printf("start of new packet\n");
                pkt_start = xp;xp++;
                hdr_len = buf[pkt_start+1];
                pkt_len = buf[pkt_start+2];
                printf("header length:%02X - %d\n",hdr_len,hdr_len);
                printf("payload length:%02X - %d\n",pkt_len,pkt_len);
        }

        printf(" HEADER \n");
        for(int hctr=(pkt_start+1);hctr<(hdr_len+pkt_start+1);hctr++)
        {
                printf("%02X ",buf[hctr]);xp++;
        }
        printf("\n");

        pld_ctr = 0;
        pkt_ctr = 0;
        memset(pkt,0x00,255);
        printf(" PAYLOAD \n");
        for(int hctr=(pkt_start+1+hdr_len);hctr<(pkt_len+pkt_start+1+hdr_len);hctr++)
        {
                printf("%02X ",buf[hctr]);xp++;
                pld_ctr++;
                if(pld_ctr > 10 && pld_ctr != 17)//there is a pad at 17....
                {
                        pkt[pkt_ctr] = buf[hctr]; pkt_ctr++;
                }
        }
        printf("\n");

}
for(int xp=0;xp<buf_rx_len;xp++)
{
        printf("%02X ",buf[xp]);
}

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

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localnrf);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    /* cf_handler_set_probe_cb(caph, probe_callback); */

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

