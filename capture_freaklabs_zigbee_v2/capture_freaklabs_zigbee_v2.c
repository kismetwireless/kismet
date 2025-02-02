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
#include "capture_freaklabs_zigbee_v2.h"

#define BUFFER_SIZE 256

#if defined(SYS_OPENBSD)
#define MODEMDEVICE "/dev/cuaU0"
#else
#define MODEMDEVICE "/dev/ttyUSB0"
#endif

#ifndef CRTSCTS
#define CRTSCTS 020000000000 /*should be defined but isn't with the C99*/
#endif

#define LINKTYPE_IEEE802_15_4_NOFCS     230
#define LINKTYPE_IEEE802_15_4           195

#define FZ_CMD_FRAME        0x00
#define FZ_CMD_CHANNEL      0x01
#define FZ_CMD_GET_CHANNEL  0x81
#define FZ_CMD_SET_CHANNEL  0x82
#define FZ_PROTO_VERSION    1

const uint8_t magic_legacy[] = {0x53, 0x6E, 0x69, 0x66};
const uint8_t magic[] = {0xC1, 0x1F, 0xFE, 0x72};

typedef struct {
    speed_t baudrate;
    struct termios oldtio, newtio;
    int fd;

    char *name;
    char *interface;

    int band;

    uint8_t channel;

    kis_capture_handler_t *caph;
} local_freaklabs_t;

typedef struct {
    unsigned int channel;
} local_channel_t;

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

int write_command(kis_capture_handler_t *caph, local_freaklabs_t *freak, uint8_t *cmd,
                  size_t len) {
    char errstr[STATUS_MAX];
    ssize_t fz_cmd_len;

    typedef struct {
        uint8_t cmd_magic[sizeof(magic)];
        uint8_t version;
        uint8_t cmd[0];
    } __attribute__((packed)) fz_cmd;

    fz_cmd *zcmd = NULL;

    fz_cmd_len = sizeof(fz_cmd) + len;

    zcmd = (fz_cmd *) malloc(fz_cmd_len);
    memcpy(zcmd->cmd_magic, magic, sizeof(magic));
    zcmd->version = 1;
    memcpy(zcmd->cmd, cmd, len);

    if (write(freak->fd, (unsigned char *) zcmd, fz_cmd_len) != fz_cmd_len) {
        snprintf(errstr, STATUS_MAX, "%s failed to send command - %s",
                 freak->name, strerror(errno));
        cf_send_error(caph, 0, errstr);
        cf_handler_spindown(caph);
        return -1;
    }

    return 1;
}

int set_channel(kis_capture_handler_t *caph, local_freaklabs_t *freak, uint8_t channel) {
    int r;

    typedef struct {
        uint8_t cmd;
        uint8_t pad;
        uint8_t channel;
    } __attribute__((packed)) fz_channel;

    fz_channel zchan;

    zchan.cmd = FZ_CMD_SET_CHANNEL;
    zchan.pad = 1;
    zchan.channel = channel;

    /* The freaklabs takes 150uS to set the channel and return; the channel 
     * assignment result gets set during the main read loop so currently 
     * we blindly set the channel and wait for the hw to accept it and 
     * update the channel there */

    r = write_command(caph, freak, (uint8_t *) &zchan, sizeof(fz_channel));

    return r;
}

uint8_t get_channel(kis_capture_handler_t *caph, local_freaklabs_t *freak) {
    int r;
    uint8_t get_chan = FZ_CMD_GET_CHANNEL;

    r = write_command(caph, freak, &get_chan, 1);

    return r;
}


void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    printf("translate %s\n", chanstr);

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "unable to parse channel; freaklabs channels are integers");
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;

    return ret_localchan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_freaklabs_t *localfreak = (local_freaklabs_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;

    char errstr[STATUS_MAX];

    if (privchan == NULL) {
        return 0;
    }

    if ((localfreak->band == 0 && channel->channel != 0) ||
            (localfreak->band == 1 && (channel == 0 || channel->channel >= 11)) ||
            (localfreak->band == 2 && (channel->channel < 11 || channel->channel > 26))) {
        snprintf(errstr, STATUS_MAX, "invalid channel for this freaklabs device (%u not in band %u)", channel->channel, localfreak->band);
        cf_send_warning(caph, errstr);
        return 1;
    }

    if (set_channel(caph, localfreak, channel->channel) < 0) {
        snprintf(errstr, STATUS_MAX, "failed to set channel %u", channel->channel);
        cf_send_warning(caph, errstr);
        return 1;
    }

    localfreak->channel = channel->channel;

    return 1;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno,
    char *definition, char *msg, char **uuid,
    cf_params_interface_t **ret_interface, cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];
    char *device = NULL;

    /* 0: 800mhz (0)
     * 1: 900mhz (1-10)
     * 2: 2.4ghz (11-27)
     */
    int band = 2;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "freaklabs") != interface) {
        free(interface);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX,
            "Expected device= path to serial device in definition");
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "band", definition)) > 0) {
       if (strncmp(placeholder, "800", placeholder_len) == 0) {
           band = 0;
       }  else if (strncmp(placeholder, "900", placeholder_len) == 0) {
           band = 1;
       } else if (strncmp(placeholder, "2400", placeholder_len) == 0) {
           band = 2;
       }
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_freaklabs_zigbee",
                strlen("kismet_cap_freaklabs_zigbee")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    int n_chans = 0;
    int s_chan = 0;

    if (band == 0) {
        n_chans = 1;
        s_chan = 0;
    } else if (band == 1) {
        n_chans = 10;
        s_chan = 1;
    } else if (band == 2) {
        n_chans = 16;
        s_chan = 11;
    }

    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * n_chans);
    for (int i = s_chan; i < n_chans - s_chan; i++) {
        char chstr[3];
        snprintf(chstr, 3, "%d", i);
        (*ret_interface)->channels[i - s_chan] = strdup(chstr);
    }

    (*ret_interface)->channels_len = n_chans;

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
    char *msg, uint32_t *dlt, char **uuid,
    cf_params_interface_t **ret_interface, cf_params_spectrum_t **ret_spectrum) {

    local_freaklabs_t *localfreak = (local_freaklabs_t *) caph->userdata;

    char *placeholder;
    int placeholder_len;
    char *device = NULL;
    char errstr[STATUS_MAX];

    char *localbaudratestr = NULL;
    unsigned int *localbaudrate = NULL;

    /* 0: 800mhz
     * 1: 900mhz (0-11)
     * 2: 2.4ghz (11-27)
     */
    int band = 2;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    localfreak->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localfreak->name = strndup(placeholder, placeholder_len);
    } else {
        localfreak->name = strdup(localfreak->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "%s expected device= path to serial device in definition", localfreak->name);
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "baudrate", definition)) > 0) {
        localbaudratestr = strndup(placeholder, placeholder_len);
        localbaudrate = (unsigned int *) malloc(sizeof(unsigned int));
        *localbaudrate = atoi(localbaudratestr);
        free(localbaudratestr);

        if (localbaudrate == NULL) {
            snprintf(msg, STATUS_MAX, "%s could not parse baudrate option "
                                      "provided in source definition", localfreak->name);
            return -1;
        }

        localfreak->baudrate = get_baud(*localbaudrate);

        free(localbaudrate);
    } else {
        localfreak->baudrate = D_BAUDRATE;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "band", definition)) > 0) {
        if (strncmp(placeholder, "800", placeholder_len) == 0) {
            band = 0;
        }  else if (strncmp(placeholder, "900", placeholder_len) == 0) {
            band = 1;
        } else if (strncmp(placeholder, "2400", placeholder_len) == 0) {
            band = 2;
        }
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_freaklabs_zigbee",
                strlen("kismet_cap_freaklabs_zigbee")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    /* open for r/w but no tty */
    localfreak->fd = open(device, O_RDWR | O_NOCTTY);

    if (localfreak->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s", localfreak->name, strerror(errno));
        return -1;
    }

    tcgetattr(localfreak->fd, &localfreak->oldtio);
    bzero(&localfreak->newtio, sizeof(localfreak->newtio));

    /* Set up raw IO */
    localfreak->newtio.c_cflag |= CLOCAL;
    localfreak->newtio.c_cflag |= CREAD;

    localfreak->newtio.c_cflag &= ~ECHO;
    localfreak->newtio.c_cflag &= ~ECHOE;

    localfreak->newtio.c_cflag &= ~PARENB;
    localfreak->newtio.c_cflag &= ~CSTOPB;
    localfreak->newtio.c_cflag &= ~CSIZE;
    localfreak->newtio.c_cflag |= CS8;

    localfreak->newtio.c_oflag = 0;

    localfreak->newtio.c_cc[VTIME] = 10;
    localfreak->newtio.c_cc[VMIN] = 0;

    cfsetspeed(&localfreak->newtio, localfreak->baudrate);

    /* flush and set up */
    if (tcsetattr(localfreak->fd, TCSANOW, &localfreak->newtio)) {
        snprintf(msg, STATUS_MAX, "%s failed to set serial device options - %s",
                 localfreak->name, strerror(errno));
        return -1;
    }

    if (tcflush(localfreak->fd, TCIOFLUSH)) {
        snprintf(msg, STATUS_MAX, "%s failed to flush serial device - %s",
                 localfreak->name, strerror(errno));
        return -1;
    }

    int n_chans = 0;
    int s_chan = 0;

    if (band == 0) {
        n_chans = 1;
        s_chan = 0;
    } else if (band == 1) {
        n_chans = 10;
        s_chan = 1;
    } else if (band == 2) {
        n_chans = 16;
        s_chan = 11;
    }

    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * n_chans);
    for (int i = s_chan; i < s_chan + n_chans; i++) {
        char chstr[3];
        snprintf(chstr, 3, "%d", i);
        (*ret_interface)->channels[i - s_chan] = strdup(chstr);
    }

    (*ret_interface)->channels_len = n_chans;

    localfreak->band = band;

    return 1;
}

/* Work around serial port oddness and keep spinning reading from the serial 
 * device until we get the amount of data we want or until it errors out. */
int spin_read(int fd, uint8_t *buf, size_t len) {
    size_t read_so_far = 0;
    int r;

    while (read_so_far < len) {
        r = read(fd, buf + read_so_far, len - read_so_far);

        if (r < 0) {
            return r;
        }

        read_so_far += r;
    }
  
    return read_so_far;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_freaklabs_t *localfreak = (local_freaklabs_t *) caph->userdata;

    char errstr[STATUS_MAX];

    typedef struct {
        uint8_t magic[4];
        uint8_t version;
    } __attribute__((packed)) fz_hdr;

    typedef struct {
        uint8_t cmd;
        uint8_t val;
    } __attribute__((packed)) fz_cmd_hdr;

    uint8_t buf[BUFFER_SIZE];
    fz_hdr *hdr = (fz_hdr *) buf;
    fz_cmd_hdr *cmd_hdr = (fz_cmd_hdr *) buf;

    uint8_t pkt_len = 0;

    ssize_t r = 0;

    while (1) {
        pkt_len = 0;

        if (caph->spindown) {
            break;
        }

        r = spin_read(localfreak->fd, buf, sizeof(fz_hdr));

        if (r < 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - error reading from serial: %s",
                     localfreak->name, strerror(errno));
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (r == 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection closed", localfreak->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (r < sizeof(fz_hdr)) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection failed to read full header", localfreak->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        /* Silently skip ahead if there's no magic */
        if (memcmp(hdr->magic, magic, 4) != 0 && memcmp(hdr->magic, magic_legacy, 4) != 0) {
            continue;
        }

        if (hdr->version != 1) {
            /* Legacy packet format from contiki sniffer */
            pkt_len = hdr->version;
        } else {
            /* two-byte header of command and length */
            r = spin_read(localfreak->fd, buf, sizeof(fz_cmd_hdr));

            if (r < 0) {
                snprintf(errstr, BUFFER_SIZE, "%s - error reading from serial: %s",
                         localfreak->name, strerror(errno));
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }

            if (r == 0) {
                snprintf(errstr, BUFFER_SIZE, "%s - serial connection closed", localfreak->name);
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }

            if (r < sizeof(fz_hdr)) {
                snprintf(errstr, BUFFER_SIZE, "%s - serial connection failed to read full header", localfreak->name);
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }

            if (cmd_hdr->cmd == FZ_CMD_CHANNEL) {
                localfreak->channel = cmd_hdr->val;
            } else if (cmd_hdr->cmd == FZ_CMD_FRAME) {
                pkt_len = cmd_hdr->val;
            }

            /* Other frame types get ignored */
        }

        if (pkt_len == 0) {
            continue;
        }

        /* Read into packet buffer; buffer is always big enough to hold a uint8 length so no extra checks */
        r = spin_read(localfreak->fd, buf, pkt_len);

        if (r < 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - error reading from serial: %s",
                     localfreak->name, strerror(errno));
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (r == 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection closed", localfreak->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (r < pkt_len) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection failed to read full header", localfreak->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }


        while (1) {
            struct timeval tv;
            gettimeofday(&tv, NULL);

            if ((r = cf_send_data(caph, NULL, 0,
                            NULL, NULL, tv, 0,
                            pkt_len, pkt_len, buf)) < 0) {
                snprintf(errstr, BUFFER_SIZE, "%s - unable to send packet to Kismet server", localfreak->name);
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
            } else if (r == 0) {
                cf_handler_wait_ringbuffer(caph);
                continue;
            } else {
                break;
            }
        }
    }

    /* set the port back to normal */
    tcsetattr(localfreak->fd, TCSANOW, &localfreak->oldtio);

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_freaklabs_t localfreak = {
        .baudrate = B57600,
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .fd = -1,
        .channel = 0,
    };

    kis_capture_handler_t *caph = cf_handler_init("freaklabszigbee");

    if (caph == NULL) {
        fprintf(stderr,
            "FATAL: Could not allocate basic handler data, your system "
            "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localfreak.caph = caph;

    cf_handler_set_userdata(caph, &localfreak);

    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
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
