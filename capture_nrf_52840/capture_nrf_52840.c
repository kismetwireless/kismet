
#include "../config.h"

#include "nrf_52840.h"

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

#define MODEMDEVICE "/dev/ttyACM0"
#define CRTSCTS  020000000000 /*should be defined but isn't with the C99*/

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

/* Unique instance data passed around by capframework */
typedef struct {

    pthread_mutex_t serial_mutex;

    struct termios oldtio,newtio;

    int fd;

    unsigned int channel;

    char *name;
    char *interface;

    /* flag to let use know when we are ready to capture */
    bool ready;

    kis_capture_handler_t *caph;
} local_nrf_t;

/* Most basic of channel definitions */
typedef struct {
    unsigned int channel;
} local_channel_t;

int nrf_write_cmd(kis_capture_handler_t *caph, uint8_t *tx_buf, size_t tx_len)
{
    /*
     * receive
     * sleep
     * channel x
     */
    uint8_t buf[255];
    uint8_t res = 0;
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
pthread_mutex_lock(&(localnrf->serial_mutex));
    //printf("write the command:%s\n",tx_buf);
    write(localnrf->fd,tx_buf,tx_len);
    //printf("look for a response\n");
    res = read(localnrf->fd,buf,255);
    //printf("res:%d buf:%s\n",res,buf);
pthread_mutex_unlock(&(localnrf->serial_mutex));
    return 1;
}

int nrf_enter_promisc_mode(kis_capture_handler_t *caph)
{
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    localnrf->ready = false;
    //write receive
    //printf("write receive\n");
    nrf_write_cmd(caph,"receive\r\n\r\n",strlen("receive\r\n\r\n"));
    localnrf->ready = true;
    //printf("ready:%d\n",localnrf->ready);
    return 1;
}

int nrf_exit_promisc_mode(kis_capture_handler_t *caph)
{
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    //write sleep
    //printf("write sleep\n");
    nrf_write_cmd(caph,"sleep\r\n\r\n",strlen("sleep\r\n\r\n"));
    localnrf->ready = false;
    //printf("ready:%d\n",localnrf->ready);
    return 1;
}

int nrf_set_channel(kis_capture_handler_t *caph, uint8_t channel)
{
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    nrf_exit_promisc_mode(caph);
    //printf("nrf52840 channel:%d\n",channel);
    uint8_t ch[16];
    sprintf(ch,"channel %d\r\n\r\n",channel);
    nrf_write_cmd(caph,ch,strlen(ch));
    nrf_enter_promisc_mode(caph);
    //printf("ready:%d\n",localnrf->ready);
    return 1;
}

int nrf_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
//printf("nrf_receive_payload\n");
    
    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    unsigned char buf[256];memset(buf,0x00,256);
    unsigned char pkt[256];memset(pkt,0x00,256);
    int actual_len = 0;
    bool endofpkt=false;
    int pkt_ctr = 0;
    int res = 0;
    unsigned int loop_ctr = 0;

    while(1) {
pthread_mutex_lock(&(localnrf->serial_mutex));
	    res = read(localnrf->fd,buf,255);
pthread_mutex_unlock(&(localnrf->serial_mutex));
	    if(res > 0)
	    {
                loop_ctr = 0;
                //printf("payload-- %s:%d\n", buf, res);
                for(int xp = 0;xp < res;xp++)
                {
                        if(buf[xp] == 'r'
                        && buf[xp+1] == 'e'
                        && buf[xp+2] == 'c'
                        )
                        {
                                memset(pkt,0x00,256);
                                pkt_ctr = 0;//start over
                        }

                        pkt[pkt_ctr] = buf[xp];
                        pkt_ctr++;
                        if(pkt_ctr > 254)
                                break;
                        if(strstr((char*)pkt,"received:") > 0
                        && strstr((char*)pkt,"power:") > 0
                        && strstr((char*)pkt,"lqi:") > 0
                        && strstr((char*)pkt,"time:") > 0
                        )
                        {
                                //printf("pkt:%s\n",pkt);
                                endofpkt = true;
                                //pkt_ctr = 0;
                                //memset(pkt,0x00,256);
                                break;
                        }
		}
	        if(pkt_ctr > 0 && endofpkt)
        	{
			for(int xp=0;xp<pkt_ctr;xp++)
				rx_buf[xp] = pkt[xp];
			actual_len = pkt_ctr;
			break;
		}
	    }
	    else
	    {
		    loop_ctr++;
		    if(loop_ctr > 10000)
			    break;
	    }
    }


//printf("nrf_receive_payload close\n");
    return actual_len;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

//printf("probe_callback\n");

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
    if (strstr(interface, "nrf52840") != interface) {
        free(interface);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        return 0;
    }

    snprintf(cap_if, 32, "nrf52840-%12X",adler32_csum((unsigned char *) device, strlen(device)));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%12X",
                adler32_csum((unsigned char *) "kismet_cap_nrf_52840", 
                    strlen("kismet_cap_nrf_52840")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device,
                    strlen(device)));
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("nrf52840");

    /* nRF 52840 supports 11-26 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 16);
    for (int i = 11; i < 27; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 11] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 16;

    return 1;
}/////mutex inside

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
//printf("open_callback\n");

    char *placeholder;
    int placeholder_len;
    char *device = NULL;
    char errstr[STATUS_MAX];

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    *ret_interface = cf_params_interface_new();

    char cap_if[32];

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

    snprintf(cap_if, 32, "nrf52840-%12X",adler32_csum((unsigned char *) device, strlen(device)));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%12X",
                adler32_csum((unsigned char *) "kismet_cap_nrf_52840", 
                    strlen("kismet_cap_nrf_52840")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device,
                    strlen(device)));
        *uuid = strdup(errstr);
    }
//printf("open_callback set channels\n");

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("nrf52840");

    /* nRF 52840 supports 11 - 26*/
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 16);
    for (int i = 11; i < 27; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 11] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 16;

//printf("set mutex and try to open\n");

    pthread_mutex_lock(&(localnrf->serial_mutex));
    /* open for r/w but no tty */
    localnrf->fd = open(device, O_RDWR | O_NOCTTY );

    if (localnrf->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
                localnrf->name, strerror(errno));
//printf("failed to open serial device\n");

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

pthread_mutex_unlock(&(localnrf->serial_mutex));
//printf("serial mutex end\n");

    //printf("set channel and start listening\n");
    nrf_set_channel(caph, 11);

    return 1;
}

void *chantranslate_callback(kis_capture_handler_t *caph, char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "1 unable to parse requested channel '%s'; nRF52840 channels "
                "are from 11 to 26", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if (parsechan > 26 || parsechan < 11) {
        snprintf(errstr, STATUS_MAX, "2 unable to parse requested channel '%u'; nRF52840 channels "
                "are from 11 to 26", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;
    return ret_localchan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    int r;

    //printf("calling nrf_set_channel\n");

    if (privchan == NULL) {
        return 0;
    }

    nrf_set_channel(caph, channel->channel);
    
    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {

    local_nrf_t *localnrf = (local_nrf_t *) caph->userdata;

    char errstr[STATUS_MAX];
    uint8_t buf[256];
    int buf_rx_len = 0;
    int r = 0;

    while(1) {
	    if(caph->spindown) {
		nrf_exit_promisc_mode(caph);
		/* set the port back to normal */
pthread_mutex_lock(&(localnrf->serial_mutex));
                tcsetattr(localnrf->fd,TCSANOW,&localnrf->oldtio);
pthread_mutex_unlock(&(localnrf->serial_mutex));
		break;
	    }
if(localnrf->ready)
{
        buf_rx_len = nrf_receive_payload(caph, buf, 256);
        if (buf_rx_len < 0) {
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        //send the packet along
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

    kis_capture_handler_t *caph = cf_handler_init("nrf52840");
    //int r;

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localnrf.caph = caph;

    //printf("nrf52840 main\n");

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localnrf);

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

