//Usage: sudo ./kismet_cap_ti_cc_2531  --source=catsniffer:device=/dev/ttyACM0 --connect localhost:3501 --tcp --disable-retry

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>

#include "../capture_framework.h"
#include "../config.h"
#include "catsniffer_zigbee.h"

#define BUFFER_SIZE 256

#if defined(SYS_OPENBSD)
#define MODEMDEVICE "/dev/cuaU0"
#else
#define MODEMDEVICE "/dev/ttyACM0"
#endif

#ifndef CRTSCTS
#define CRTSCTS 020000000000 /*should be defined but isn't with the C99*/
#endif

#define LINKTYPE_IEEE802_15_4_NOFCS     230
#define LINKTYPE_IEEE802_15_4           195

#ifndef KDLT_IEEE802_15_4_TAP
#define KDLT_IEEE802_15_4_TAP             283 
#endif

#define FZ_CMD_FRAME        0x00
#define FZ_CMD_CHANNEL      0x01
#define FZ_CMD_GET_CHANNEL  0x81
#define FZ_CMD_SET_CHANNEL  0x45
#define FZ_PROTO_VERSION    1

#define CHANNEL_COUNT 16
#define START_CHANNEL 11
#define BASE_FREQUENCY 2405
#define SOF 0x5340
#define PACKET_EOF 0x4540
#define COMMAND_SET_CHANNEL 0x45
#define PAYLOAD_LENGTH 0x0004

uint8_t channel_commands[CHANNEL_COUNT][12];

/* const uint8_t magic[] = {0x40, 0x53, 0xc0}; */ /*frame start followed by data frame indicator */
const uint8_t magic[] = {0x40, 0x53}; /*frame start */

typedef struct {
    speed_t baudrate;
    struct termios oldtio, newtio;
    int fd;

    char *name;
    char *interface;

    int band;

    uint8_t channel;

    kis_capture_handler_t *caph;
} local_catsniffer_t;

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

// Function to calculate the Frame Check Sequence (FCS)
uint8_t calculate_fcs(uint8_t *dataBuffer, uint16_t length) {
    uint32_t result = 0;
    for (int i = 0; i < length; i++) {
        result += dataBuffer[i];
    }
    return (result & 0xFF);
}

// Function to generate channel commands
void generate_channel_commands() {
    for (int i = 0; i < CHANNEL_COUNT; i++) {
        uint8_t channel = START_CHANNEL + i;
        uint16_t frequency = BASE_FREQUENCY + (channel - START_CHANNEL) * 5;
        uint8_t *packet = channel_commands[i];

        // Start of Frame
        packet[0] = (SOF & 0xFF);        // 0x40
        packet[1] = (SOF >> 8) & 0xFF;   // 0x53

        // Command Type
        packet[2] = COMMAND_SET_CHANNEL; // 0x45

        // Payload Length
        packet[3] = (PAYLOAD_LENGTH & 0xFF);      // 0x04
        packet[4] = (PAYLOAD_LENGTH >> 8) & 0xFF; // 0x00

        // Frequency (little-endian)
        packet[5] = frequency & 0xFF;           // Low byte of frequency
        packet[6] = (frequency >> 8) & 0xFF;    // High byte of frequency

        // Fractional Frequency (set to 0x0000)
        packet[7] = 0x00;
        packet[8] = 0x00;

        // Calculate FCS
        packet[9] = calculate_fcs(&packet[2], 7); // FCS calculation excludes SOF and EOF

        // End of Frame
        packet[10] = (PACKET_EOF & 0xFF);       // 0x40
        packet[11] = (PACKET_EOF >> 8) & 0xFF;  // 0x45

        // Optional: Print the command packet for debugging
        printf("Channel %d command: {", channel);
        for (int j = 0; j < 12; j++) {
            printf("0x%02x", packet[j]);
            if (j < 11) {
                printf(", ");
            }
        }
        printf("}\n");
    }
}

int write_command(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer, uint8_t *cmd, size_t len) {
    char errstr[STATUS_MAX];
    ssize_t fz_cmd_len;

    fz_cmd_len = len;

    if (write(catsniffer->fd, (unsigned char *) cmd, fz_cmd_len) != fz_cmd_len) {
        snprintf(errstr, STATUS_MAX, "%s failed to send command - %s", catsniffer->name, strerror(errno));
        cf_send_error(caph, 0, errstr);
        cf_handler_spindown(caph);
        return -1;
    }

    return 1;
}

int send_initialization_command(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer) {
    static const uint8_t init_command[] = {0x40, 0x53, 0x40, 0x00, 0x00, 0x40, 0x40, 0x45};
    return write_command(caph, catsniffer, (uint8_t *)init_command, sizeof(init_command));
}

int send_stop_command(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer) {
    static const uint8_t stop_command[] = {0x40, 0x53, 0x42, 0x00, 0x00, 0x42, 0x40, 0x45};
    return write_command(caph, catsniffer, (uint8_t *)stop_command, sizeof(stop_command));
}

int send_phy_configuration_command(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer) {
    static const uint8_t phy_command[] = {0x40, 0x53, 0x47, 0x01, 0x00, 0x12, 0x5a, 0x40, 0x45};
    return write_command(caph, catsniffer, (uint8_t *)phy_command, sizeof(phy_command));
}

int send_start_command(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer) {
    static const uint8_t start_command[] = {0x40, 0x53, 0x41, 0x00, 0x00, 0x41, 0x40, 0x45};
    return write_command(caph, catsniffer, (uint8_t *)start_command, sizeof(start_command));
}

uint8_t get_channel(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer) {
    int r;
    uint8_t get_chan = FZ_CMD_GET_CHANNEL;

    r = write_command(caph, catsniffer, &get_chan, 1);

    return r;
}

int init_interface(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer) {
    int r;

    // Print the file descriptor to the console
    printf("init_interface: TTY file descriptor is %d.\n", catsniffer->fd);
    
    // First, send the stop command
    printf("init_interface: Sending stop command.\n");
    r = send_stop_command(caph, catsniffer);
    if (r < 0) {
        printf("init_interface: Failed to send stop command. Error code: %d.\n", r);
        return r;
    }
    printf("init_interface: Stop command sent successfully.\n");

    // Then, send the initialization command
    printf("init_interface: Sending initialization command.\n");
    r = send_initialization_command(caph, catsniffer);
    if (r < 0) {
        printf("init_interface: Failed to send initialization command. Error code: %d.\n", r);
        return r;
    }
    printf("init_interface: Initialization command sent successfully.\n");

    // Then, send the PHY configuration command
    printf("init_interface: Sending PHY configuration command.\n");
    r = send_phy_configuration_command(caph, catsniffer);
    if (r < 0) {
        printf("init_interface: Failed to send PHY configuration command. Error code: %d.\n", r);
        return r;
    }
    printf("init_interface: PHY configuration command sent successfully.\n");

    return 0;
}

int set_channel(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer, uint8_t channel) {
    int r;

    printf("set_channel: Attempting to set channel to %u.\n", channel);

    // First, send the stop command
    printf("set_channel: Sending stop command.\n");
    r = send_stop_command(caph, catsniffer);
    if (r < 0) {
        return r;
    }
    
    // Then, send the initialization command
    printf("init_interface: Sending initialization command.\n");
    r = send_initialization_command(caph, catsniffer);
    if (r < 0) {
        printf("init_interface: Failed to send initialization command. Error code: %d.\n", r);
        return r;
    }
    printf("init_interface: Initialization command sent successfully.\n");
    //Leaving this array definition for reference
    // Now send the channel-specific command
    /*static const uint8_t channel_commands[16][12] = {
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x65, 0x09, 0x00, 0x00, 0xb7, 0x40, 0x45}, // Channel 11
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x6a, 0x09, 0x00, 0x00, 0xbc, 0x40, 0x45}, // Channel 12
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x6f, 0x09, 0x00, 0x00, 0xc1, 0x40, 0x45}, // Channel 13
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x74, 0x09, 0x00, 0x00, 0xc6, 0x40, 0x45}, // Channel 14
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x79, 0x09, 0x00, 0x00, 0xcb, 0x40, 0x45}, // Channel 15
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x7e, 0x09, 0x00, 0x00, 0xd0, 0x40, 0x45}, // Channel 16
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x83, 0x09, 0x00, 0x00, 0xd5, 0x40, 0x45}, // Channel 17
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x88, 0x09, 0x00, 0x00, 0xda, 0x40, 0x45}, // Channel 18
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x8d, 0x09, 0x00, 0x00, 0xdf, 0x40, 0x45}, // Channel 19
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x92, 0x09, 0x00, 0x00, 0xe4, 0x40, 0x45}, // Channel 20
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x97, 0x09, 0x00, 0x00, 0xe9, 0x40, 0x45}, // Channel 21
        {0x40, 0x53, 0x45, 0x04, 0x00, 0x9c, 0x09, 0x00, 0x00, 0xee, 0x40, 0x45}, // Channel 22
        {0x40, 0x53, 0x45, 0x04, 0x00, 0xa1, 0x09, 0x00, 0x00, 0xf3, 0x40, 0x45}, // Channel 23
        {0x40, 0x53, 0x45, 0x04, 0x00, 0xa6, 0x09, 0x00, 0x00, 0xf8, 0x40, 0x45}, // Channel 24
        {0x40, 0x53, 0x45, 0x04, 0x00, 0xab, 0x09, 0x00, 0x00, 0xfd, 0x40, 0x45}, // Channel 25
        {0x40, 0x53, 0x45, 0x04, 0x00, 0xb0, 0x09, 0x00, 0x00, 0x02, 0x40, 0x45}  // Channel 26
    };*/ //Bypassing this for now; using dynamic generation at startup

    if (channel < 11 || channel > 26) {
        return -1; // Invalid channel
    }

    int channel_index = channel - START_CHANNEL;
    const uint8_t *command = channel_commands[channel_index];    
    // Adjust channel to zero-based index
    //int channel_index = channel - 11;
    //const uint8_t *command = channel_commands[channel_index];
    size_t command_len = sizeof(channel_commands[channel_index]);

    //Debug
    printf("Channel command for channel %d:\n", channel);
    for (size_t i = 0; i < command_len; i++) {
        printf("%02X ", command[i]);  // Print each byte as a two-digit hexadecimal number
    }
    printf("\n");  // Newline after printing all bytes
	
    printf("set_channel: Sending channel configuration command.\n");
    r = write_command(caph, catsniffer, (uint8_t *)command, command_len);
    if (r < 0) {
        return r;
    }

    // Finally, send the start command
    printf("set_channel: Sending start command.\n");
    r = send_start_command(caph, catsniffer);

    return r;
}


void *chantranslate_callback(kis_capture_handler_t *caph, char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    printf("translate %s\n", chanstr);

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "unable to parse channel; channels are integers");
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;

    return ret_localchan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_catsniffer_t *localcatsniffer = (local_catsniffer_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;

    char errstr[STATUS_MAX];

    if (privchan == NULL) {
        return 0;
    }

    if ((localcatsniffer->band == 0 && channel->channel != 0) ||
            (localcatsniffer->band == 1 && (channel == 0 || channel->channel >= 11)) ||
            (localcatsniffer->band == 2 && (channel->channel < 11 || channel->channel > 26))) {
        snprintf(errstr, STATUS_MAX, "invalid channel for this device (%u not in band %u)", channel->channel, localcatsniffer->band);
        cf_send_warning(caph, errstr);
        return 1;
    }

    if (set_channel(caph, localcatsniffer, channel->channel) < 0) {
        snprintf(errstr, STATUS_MAX, "failed to set channel %u", channel->channel);
        cf_send_warning(caph, errstr);
        return 1;
    }

    localcatsniffer->channel = channel->channel;

    return 1;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno,
    char *definition, char *msg, char **uuid, KismetExternal__Command *frame,
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
    printf("Definition string: %s\n", definition);
    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "catsniffer") != interface) {
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
            adler32_csum((unsigned char *) "kismet_cap_catsniffer_zigbee",
                strlen("kismet_cap_catsniffer_zigbee")) & 0xFFFFFFFF,
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
    char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
    cf_params_interface_t **ret_interface, cf_params_spectrum_t **ret_spectrum) {

    local_catsniffer_t *localcatsniffer = (local_catsniffer_t *) caph->userdata;

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

    localcatsniffer->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localcatsniffer->name = strndup(placeholder, placeholder_len);
    } else {
        localcatsniffer->name = strdup(localcatsniffer->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "%s expected device= path to serial device in definition", localcatsniffer->name);
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "baudrate", definition)) > 0) {
        localbaudratestr = strndup(placeholder, placeholder_len);
        localbaudrate = (unsigned int *) malloc(sizeof(unsigned int));
        *localbaudrate = atoi(localbaudratestr);
        free(localbaudratestr);

        if (localbaudrate == NULL) {
            snprintf(msg, STATUS_MAX, "%s could not parse baudrate option "
                                      "provided in source definition", localcatsniffer->name);
            return -1;
        }

        localcatsniffer->baudrate = get_baud(*localbaudrate);

        free(localbaudrate);
    } else {
        localcatsniffer->baudrate = D_BAUDRATE;
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
            adler32_csum((unsigned char *) "kismet_cap_catsniffer_zigbee",
                strlen("kismet_cap_catsniffer_zigbee")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    /* open for r/w but no tty */
    localcatsniffer->fd = open(device, O_RDWR | O_NOCTTY);

    if (localcatsniffer->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s", localcatsniffer->name, strerror(errno));
        return -1;
    }

    tcgetattr(localcatsniffer->fd, &localcatsniffer->oldtio);
    bzero(&localcatsniffer->newtio, sizeof(localcatsniffer->newtio));

    /* Set up raw IO */
    localcatsniffer->newtio.c_cflag |= CLOCAL;
    localcatsniffer->newtio.c_cflag |= CREAD;

    localcatsniffer->newtio.c_cflag &= ~ECHO;
    localcatsniffer->newtio.c_cflag &= ~ECHOE;

    localcatsniffer->newtio.c_cflag &= ~PARENB;
    localcatsniffer->newtio.c_cflag &= ~CSTOPB;
    localcatsniffer->newtio.c_cflag &= ~CSIZE;
    localcatsniffer->newtio.c_cflag |= CS8;

    localcatsniffer->newtio.c_oflag = 0;

    localcatsniffer->newtio.c_cc[VTIME] = 10;
    localcatsniffer->newtio.c_cc[VMIN] = 0;

    cfsetspeed(&localcatsniffer->newtio, localcatsniffer->baudrate);

    /* flush and set up */
    if (tcsetattr(localcatsniffer->fd, TCSANOW, &localcatsniffer->newtio)) {
        snprintf(msg, STATUS_MAX, "%s failed to set serial device options - %s",
                 localcatsniffer->name, strerror(errno));
        return -1;
    }

    if (tcflush(localcatsniffer->fd, TCIOFLUSH)) {
        snprintf(msg, STATUS_MAX, "%s failed to flush serial device - %s",
                 localcatsniffer->name, strerror(errno));
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

    localcatsniffer->band = band;

    // Generate the channel commands at the start
    printf("Generating channel commands.\n");
    generate_channel_commands();
    
    printf("main: Initializing interface.\n");
    int result = init_interface(caph, localcatsniffer);
    if (result < 0) {
        fprintf(stderr, "main: Failed to initialize interface. Exiting.\n");
        return result;
    }
    
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
    local_catsniffer_t *localcatsniffer = (local_catsniffer_t *) caph->userdata;

    char errstr[STATUS_MAX];

    typedef struct {
        uint8_t magic[2];
        uint8_t type;
        uint8_t pkt_len;
    } __attribute__((packed)) fz_hdr;

    uint8_t buf[BUFFER_SIZE];
    uint8_t send_buf[BUFFER_SIZE + 1];  // Extra byte for channel
    uint8_t fragment_buf[BUFFER_SIZE];
    int fragment_len = 0;
    fz_hdr *hdr = (fz_hdr *) buf;

    ssize_t r = 0;

    while (1) {
        if (caph->spindown) {
            break;
        }

        // Read the header
        r = spin_read(localcatsniffer->fd, buf, sizeof(fz_hdr));

        if (r < 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - error reading from serial: %s",
                     localcatsniffer->name, strerror(errno));
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (r == 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection closed", localcatsniffer->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (r < sizeof(fz_hdr)) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection failed to read full header", localcatsniffer->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        // Check the magic bytes
        if (memcmp(hdr->magic, magic, 2) != 0) {
            continue;  // Skip if magic bytes don't match
        }

        // Check if the packet type is 0xC0 (data packet)
        if (hdr->type != 0xC0) {
            continue;  // Skip if not a data packet
        }

        // Use pkt_len to determine the length of the packet and add 3 bytes for FCS and end-of-frame
        uint8_t pkt_len = hdr->pkt_len + 3;

        if (pkt_len == 0 || pkt_len > BUFFER_SIZE - sizeof(fz_hdr)) {
            continue;  // Skip if packet length is zero or exceeds buffer size
        }

        // Read the remainder of the packet
        r = spin_read(localcatsniffer->fd, buf + sizeof(fz_hdr), pkt_len);

        if (r < 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - error reading from serial: %s",
                     localcatsniffer->name, strerror(errno));
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (r == 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection closed", localcatsniffer->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (r < pkt_len) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection failed to read full packet", localcatsniffer->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        // Validate the end of frame bytes
        if (buf[sizeof(fz_hdr) + pkt_len - 2] != 0x40 || buf[sizeof(fz_hdr) + pkt_len - 1] != 0x45) {
            // If the last two bytes are not 0x40 0x45, search for a new frame starting with 0x40 0x53
            for (int i = 0; i < pkt_len - 1; i++) {
                if (buf[sizeof(fz_hdr) + i] == 0x40 && buf[sizeof(fz_hdr) + i + 1] == 0x53) {
                    // Found the start of a new fragment
                    fragment_len = pkt_len - i;
                    if (fragment_len > BUFFER_SIZE) {
                        fragment_len = BUFFER_SIZE;  // Prevent overflow
                    }
                    memcpy(fragment_buf, buf + sizeof(fz_hdr) + i, fragment_len);

                    // Continue reading from the TTY until 0x40 0x45 is detected
                    while (fragment_len < BUFFER_SIZE) {
                        r = spin_read(localcatsniffer->fd, buf, BUFFER_SIZE);
                        if (r <= 0) break;  // Handle errors or EOF

                        int copy_len = BUFFER_SIZE - fragment_len;
                        if (r < copy_len) {
                            copy_len = r;  // Copy only as much as was read
                        }
                        memcpy(fragment_buf + fragment_len, buf, copy_len);
                        fragment_len += copy_len;

                        if (fragment_buf[fragment_len - 2] == 0x40 && fragment_buf[fragment_len - 1] == 0x45) {
                            // Full packet received
                            break;
                        }
                    }

                    // Validate the reconstructed packet length
                    uint8_t new_pkt_len = fragment_buf[2];
                    if (new_pkt_len != fragment_len - 4) {
                        fragment_len = 0;  // Discard invalid packet
                        continue;
                    }

                    // Process the valid packet
                    printf("Reassembled frame (%d bytes): ", fragment_len);
                    for (int j = 0; j < fragment_len; j++) {
                        printf("%02X ", fragment_buf[j]);
                    }
                    printf("\n");
                    break;
                }
            }
            continue;
        }

        // Prepend the channel byte to the buffer
        send_buf[0] = localcatsniffer->channel;
        memcpy(send_buf + 1, buf, pkt_len + sizeof(fz_hdr));

        // Debugging: Print the received packet with the prepended channel to the console
        printf("Received frame with channel (%lu bytes): ", pkt_len + sizeof(fz_hdr) + 1);
        for (int i = 0; i < pkt_len + sizeof(fz_hdr) + 1; i++) {
            printf("%02X ", send_buf[i]);
        }
        printf("\n");

        // Process the received data packet (send to Kismet, etc.)
        while (1) {
            struct timeval tv;
            gettimeofday(&tv, NULL);

            // Send the entire buffer with the channel byte prepended
            if ((r = cf_send_data(caph, NULL, NULL, NULL, tv, 0, pkt_len + sizeof(fz_hdr) + 1, send_buf)) < 0) {
                snprintf(errstr, BUFFER_SIZE, "%s - unable to send packet to Kismet server", localcatsniffer->name);
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;  // Exit on error
            } else if (r == 0) {
                cf_handler_wait_ringbuffer(caph);
                continue;
            } else {
                break;  // Break the loop after successfully processing a packet
            }
        }
    }

    // Reset the TTY to its original settings
    tcsetattr(localcatsniffer->fd, TCSANOW, &localcatsniffer->oldtio);

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    
    // Record start time
    time_t epoch_start_time;
    epoch_start_time = time(NULL);
    //time_t start_time;
    //struct tm * local_time;
    //char start_time_str[100];
    
    //time(&start_time);
    //local_time = localtime(&start_time);
    //strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", local_time);
    //printf("Start time: %s\n", start_time_str);
    
    printf("Initializing local_catsniffer_t structure.\n");
    local_catsniffer_t localcatsniffer = {
        .baudrate = B115200,
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .fd = -1,
        .channel = 0,
    };

    printf("Calling cf_handler_init(\"catsniffer\").\n");
    kis_capture_handler_t *caph = cf_handler_init("catsniffer_zigbee");

    if (caph == NULL) {
        fprintf(stderr,
                "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    printf("Assigning caph to localcatsniffer.caph.\n");
    localcatsniffer.caph = caph;

    printf("Calling cf_handler_set_userdata(caph, &localcatsniffer).\n");
    cf_handler_set_userdata(caph, &localcatsniffer);

    printf("Setting callback functions.\n");
    printf("-> cf_handler_set_open_cb(caph, open_callback).\n");
    cf_handler_set_open_cb(caph, open_callback);

    printf("-> cf_handler_set_probe_cb(caph, probe_callback).\n");
    cf_handler_set_probe_cb(caph, probe_callback);

    printf("-> cf_handler_set_chantranslate_cb(caph, chantranslate_callback).\n");
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);

    printf("-> cf_handler_set_chancontrol_cb(caph, chancontrol_callback).\n");
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);

    printf("Setting capture thread callback.\n");
    printf("-> cf_handler_set_capture_cb(caph, capture_thread).\n");
    cf_handler_set_capture_cb(caph, capture_thread);

    printf("Parsing command-line options.\n");
    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        printf("Invalid options provided. Displaying help.\n");
        cf_print_help(caph, argv[0]);
        return -1;
    }

    printf("Starting remote capture loop.\n");
    cf_handler_remote_capture(caph);

    printf("Applying filesystem jail.\n");
    cf_jail_filesystem(caph);

    printf("Dropping unnecessary capabilities.\n");
    cf_drop_most_caps(caph);
    
    printf("Entering main handler loop.\n");
    cf_handler_loop(caph);

    time_t epoch_end_time;
    epoch_end_time = time(NULL);
    
    double time_diff = difftime(epoch_end_time, epoch_start_time);
    
    printf("Total runtime: %.f seconds\n", time_diff);
    //time_t end_time;
    //char end_time_str[100];
    
    //time(&end_time);
    //local_time = localtime(&end_time);
    //strftime(end_time_str, sizeof(end_time_str), "%Y-%m-%d %H:%M:%S", local_time);
    //printf("End time: %s\n", end_time_str);

    // Calculate and print total runtime
    //double total_runtime = difftime(end_time, start_time);
    //printf("Total runtime: %.2f seconds\n", total_runtime);
    
    printf("Exiting program.\n");
    return 0;
}
