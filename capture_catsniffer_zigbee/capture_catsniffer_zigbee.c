//Usage: sudo ./kismet_cap_catsniffer_zigbee  --source=catsniffer_zigbee:device=/dev/ttyACM0 --connect localhost:3501 --tcp --disable-retry

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

#include "../protobuf_c_1005000/kismet.pb-c.h"
#include "../protobuf_c_1005000/datasource.pb-c.h"

#if defined(__linux__)
#include <endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htole16 OSSwapHostToLittleInt16
#define htole32 OSSwapHostToLittleInt32
#else
#include <sys/endian.h>
#endif

#include "../tap_802_15_4.h"

#ifndef kis_htole16
#define kis_htole16 htole16
#endif
#ifndef kis_htole32
#define kis_htole32 htole32
#endif

#define BUFFER_SIZE 256

#if defined(SYS_OPENBSD)
#define MODEMDEVICE "/dev/cuaU0"
#else
#define MODEMDEVICE "/dev/ttyACM0"
#endif

#ifndef CRTSCTS
#define CRTSCTS 020000000000
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

/* ------------------------------------------------------------------------- */
/* [TAP] Minimal packed 802.15.4 TAP header used by Kismet & Wireshark, with
 * three TLVs: FCS present (0), RSSI (dBm), channel (11..26).
 * We keep it local to the capture tool to avoid include path friction.
 */
#ifndef CATSNIFFER_TAP_LOCAL_DEF
#define CATSNIFFER_TAP_LOCAL_DEF
#pragma pack(push, 1)
typedef struct {
    uint16_t type;    /* LE (Little-Endian) */
    uint16_t length;  /* LE; byte-count for the value field (logical length) */
    uint32_t value;   /* LE; we store the value in the low bytes */
} _tap_tlv;

#pragma pack(pop)
#endif
/* ------------------------------------------------------------------------- */

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
    //printf("init_interface: TTY file descriptor is %d.\n", catsniffer->fd);

    // First, send the stop command
    //printf("init_interface: Sending stop command.\n");
    r = send_stop_command(caph, catsniffer);
    if (r < 0) {
        printf("init_interface: Failed to send stop command. Error code: %d.\n", r);
        return r;
    }
    //printf("init_interface: Stop command sent successfully.\n");

    // Then, send the initialization command
    //printf("init_interface: Sending initialization command.\n");
    r = send_initialization_command(caph, catsniffer);
    if (r < 0) {
        printf("init_interface: Failed to send initialization command. Error code: %d.\n", r);
        return r;
    }
    //printf("init_interface: Initialization command sent successfully.\n");

    // Then, send the PHY configuration command
    //printf("init_interface: Sending PHY configuration command.\n");
    r = send_phy_configuration_command(caph, catsniffer);
    if (r < 0) {
        printf("init_interface: Failed to send PHY configuration command. Error code: %d.\n", r);
        return r;
    }
    //printf("init_interface: PHY configuration command sent successfully.\n");

    return 0;
}

int set_channel(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer, uint8_t channel) {
    int r;

    //printf("set_channel: Attempting to set channel to %u.\n", channel); //Debug

    // First, send the stop command
    //printf("set_channel: Sending stop command.\n"); //Debug
    r = send_stop_command(caph, catsniffer);
    if (r < 0) {
        return r;
    }

    // Then, send the initialization command
    //printf("init_interface: Sending initialization command.\n"); //Debug
    r = send_initialization_command(caph, catsniffer);
    if (r < 0) {
        printf("init_interface: Failed to send initialization command. Error code: %d.\n", r);
        return r;
    }

    if (channel < 11 || channel > 26) {
        return -1; // Invalid channel
    }

    int channel_index = channel - START_CHANNEL;
    const uint8_t *command = channel_commands[channel_index];
    size_t command_len = sizeof(channel_commands[channel_index]);

    r = write_command(caph, catsniffer, (uint8_t *)command, command_len);
    if (r < 0) {
        return r;
    }

    // Finally, send the start command
    r = send_start_command(caph, catsniffer);

    return r;
}

// Translate user channel string -> driver-specific channel object
void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    // printf("translate %s\n", chanstr); //Debug

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "unable to parse channel; channels are integers");
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    //Range checks by band for stricter validation:
    local_catsniffer_t *lc = (local_catsniffer_t *)caph->userdata;
    if ((lc->band == 0 && parsechan != 0) ||
        (lc->band == 1 && (parsechan < 1 || parsechan > 10)) ||
        (lc->band == 2 && (parsechan < 11 || parsechan > 26))) {
        snprintf(errstr, STATUS_MAX, "channel %u out of range for current band", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    if (!ret_localchan) {
        cf_send_message(caph, "out of memory creating channel object", MSGFLAG_ERROR);
        return NULL;
    }

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
    char *definition, char *msg, char **uuid,
    cf_params_interface_t **ret_interface, cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;
    char *interface = NULL;
    char errstr[STATUS_MAX];
    char *device = NULL;

    /* 0: 800mhz (0)
     * 1: 900mhz (1-10)
     * 2: 2.4ghz (11-27)
     */
    int band = 2;

    *ret_spectrum  = NULL;
    *ret_interface = cf_params_interface_new();

    //printf("Definition string: %s\n", definition); //Debug

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0; // not ours / not handled
    }

    interface = strndup(placeholder, placeholder_len);
    printf("interface: %s\n", interface);

    // Only handle our interface type
    if (strstr(interface, "catsniffer_zigbee") != interface) {
        free(interface);
        return 0; // not ours
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
        printf("device: %s\n", device);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        free(interface);
        return 0; // not ours (or reportable error)
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "band", definition)) > 0) {
        if (strncmp(placeholder, "800",  placeholder_len) == 0) band = 0;
        else if (strncmp(placeholder, "900",  placeholder_len) == 0) band = 1;
        else if (strncmp(placeholder, "2400", placeholder_len) == 0) band = 2;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *)"kismet_cap_catsniffer_zigbee",
                         strlen("kismet_cap_catsniffer_zigbee")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *)device, strlen(device)));
        *uuid = strdup(errstr);
    }

    int n_chans = 0;
    int s_chan  = 0;

    if (band == 0) { n_chans = 1;  s_chan = 0;  }
    else if (band == 1) { n_chans = 10; s_chan = 1;  }
    else if (band == 2) { n_chans = 16; s_chan = 11; }

    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * n_chans);

    //iterate i from s_chan to (s_chan + n_chans - 1)
    for (int i = s_chan; i < s_chan + n_chans; i++) {
        char chstr[4];                    // up to "240" safe, but our chans are < 3 digits
        snprintf(chstr, sizeof(chstr), "%d", i);
        (*ret_interface)->channels[i - s_chan] = strdup(chstr);
    }
    (*ret_interface)->channels_len = n_chans;

    //cleanup temporaries
    free(interface);
    free(device);

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
    char *msg, uint32_t *dlt, char **uuid,
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
    //printf("Generating channel commands.\n"); //Debug
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
    uint8_t fragment_buf[BUFFER_SIZE];
    int fragment_len = 0;
    fz_hdr *hdr = (fz_hdr *) buf;

    ssize_t r = 0;

    while (1) {
        if (caph->spindown) {
            printf("capture_thread loop spindown detected.\n");
            break;
        }

        // Read the header
        r = spin_read(localcatsniffer->fd, buf, sizeof(fz_hdr));

        if (r < 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - error reading from serial: %s",
                     localcatsniffer->name, strerror(errno));
            cf_send_error(caph, 0, errstr);
            printf("capture_thread error error reading from serial A - setting spindown\n");
            cf_handler_spindown(caph);
            break;
        }

        if (r == 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection closed", localcatsniffer->name);
            cf_send_error(caph, 0, errstr);
            printf("capture_thread error serial connection closed A - setting spindown\n");
            cf_handler_spindown(caph);
            break;
        }

        if (r < sizeof(fz_hdr)) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection failed to read full header", localcatsniffer->name);
            cf_send_error(caph, 0, errstr);
            printf("capture_thread error reading serial header - setting spindown\n");
            cf_handler_spindown(caph);
            break;
        }

        // Check the magic bytes
        if (memcmp(hdr->magic, magic, 2) != 0) {
            continue;  // Skip if magic bytes don't match
        }

        // Check if the frame type is 0xC0 (frame packet)
        if (hdr->type != 0xC0) {
            continue;  // Skip if not a data frame - IE the frame doesn't bear radio traffic (could be a command response)
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
            printf("capture_thread error reading from serial connection - setting spindown\n");
            cf_handler_spindown(caph);
            break;
        }

        if (r == 0) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection closed", localcatsniffer->name);
            cf_send_error(caph, 0, errstr);
            printf("capture_thread error serial connection closed - setting spindown\n");
            cf_handler_spindown(caph);
            break;
        }

        if (r < pkt_len) {
            snprintf(errstr, BUFFER_SIZE, "%s - serial connection failed to read full packet", localcatsniffer->name);
            cf_send_error(caph, 0, errstr);
            printf("capture_thread error failed to read full packet - setting spindown\n");
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
                    //printf("Reassembled frame (%d bytes): ", fragment_len); //Debug
                    for (int j = 0; j < fragment_len; j++) {
                        printf("%02X ", fragment_buf[j]);
                    }
                    printf("\n");
                    break;
                }
            }
            continue;
        }


        // Process the received data packet (send to Kismet, etc.)
        while (1) {
            struct timeval ts;
            gettimeofday(&ts, NULL);

            /* --------------------------------------------------------------
             * We read:
             *   - header: sizeof(fz_hdr) bytes already in buf[0..sizeof(fz_hdr)-1]
             *   - body  : pkt_len bytes in buf[sizeof(fz_hdr) .. sizeof(fz_hdr)+pkt_len-1]
             *
             * Device frame layout inside `buf` (NOT send_buf):
             *   buf[0..1]   : SOF        (0x40 0x53)
             *   buf[2]      : type       (0xC0)
             *   buf[3..4]   : length (LE)  <we currently treat hdr->pkt_len as 1B +3 trailer>
             *   buf[5..10]  : device fields (6B)
             *   buf[11]     : mac_len (payload length, no FCS)
             *   buf[12..]   : MAC payload (mac_len bytes)
             *   buf[sizeof(fz_hdr)+pkt_len-4] : RSSI (int8_t)
             *   buf[sizeof(fz_hdr)+pkt_len-3] : CRC OK (nonzero good)
             *   buf[sizeof(fz_hdr)+pkt_len-2..-1] : EOF (0x40 0x45)
             * -------------------------------------------------------------- */

            const size_t dev_total = sizeof(fz_hdr) + pkt_len;

            // Channel comes from the *current tuned channel*
            const uint8_t  chan        = localcatsniffer->channel;

            // MAC payload length and pointer inside `buf`
            const uint8_t  mac_len     = buf[11];
            const uint8_t *mac_payload = &buf[12];

            // Trailer fields (relative to whole frame we read into `buf`)
            const int8_t   rssi_dbm    = (int8_t) buf[dev_total - 4];
            const uint8_t  crc_ok      =           buf[dev_total - 3];     /* optional drop */

            // Optional: skip CRC-bad frames
            if (crc_ok == 0) {
                // Ring wasn’t written to; just bail out of the inner loop to read next frame
                break;
            }

            // Allocate TAP header + 802.15.4 MAC payload (no FCS)
            const uint32_t tap_sz = sizeof(_802_15_4_tap) + mac_len;
            uint8_t *tap_pack = (uint8_t *) malloc(tap_sz);
            if (tap_pack == NULL) {
                char errstr[BUFFER_SIZE];
                snprintf(errstr, sizeof(errstr), "%s - out of memory building TAP packet", localcatsniffer->name);
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }

            _802_15_4_tap *tap = (_802_15_4_tap *) tap_pack;
            memset(tap, 0, sizeof(*tap));

            // Header
            tap->version  = kis_htole16(0);
            tap->reserved = kis_htole16(0);
            tap->length   = kis_htole16(sizeof(_802_15_4_tap));

            // TLV 0: FCS present? => 0 (payload has no FCS)
            tap->tlv[0].type   = kis_htole16(0);
            tap->tlv[0].length = kis_htole16(1);
            tap->tlv[0].value  = kis_htole32(0);

            // TLV 1: RSSI (signed 8-bit in low byte; Kismet reads low byte)
            tap->tlv[1].type   = kis_htole16(10);
            tap->tlv[1].length = kis_htole16(1);
            tap->tlv[1].value  = kis_htole32((uint8_t) rssi_dbm);

            // TLV 2: Channel (use length 3 to match other drivers)
            tap->tlv[2].type   = kis_htole16(3);
            tap->tlv[2].length = kis_htole16(3);
            uint32_t ch_val = (0u)                     /* page in byte0 */
                            | (((uint32_t)chan) << 8)  /* channel in byte1 */
                            | (0u << 16);              /* reserved in byte2 */
            tap->tlv[2].value  = kis_htole32(ch_val);

            // Copy MAC payload (no FCS) after the TAP header
            memcpy(tap->payload, mac_payload, mac_len);

            /* // ============================ DEBUG (BEGIN) ============================
            do {
                // Read back fields from the TAP struct in host order for printing
                uint16_t tap_version = le16toh(tap->version);
                uint16_t tap_len     = le16toh(tap->length);

                uint32_t fcs_raw     = le32toh(tap->tlv[0].value);
                uint8_t  fcs_flag    = (uint8_t)(fcs_raw & 0xFF);

                uint32_t rssi_raw    = le32toh(tap->tlv[1].value);
                int8_t   rssi_print  = (int8_t)(rssi_raw & 0xFF);

                uint32_t ch_raw      = le32toh(tap->tlv[2].value);
                uint8_t  page_print  = (uint8_t)(ch_raw & 0xFF);
                uint8_t  chan_print  = (uint8_t)((ch_raw >> 8) & 0xFF);

                fprintf(stderr,
                    "[catsniffer->kismet] TAP ver=%u len=%u | FCS=%u | RSSI=%d dBm | page=%u channel=%u | mac_len=%u | crc_ok=%u\n",
                    (unsigned) tap_version,
                    (unsigned) tap_len,
                    (unsigned) fcs_flag,
                    (int)      rssi_print,
                    (unsigned) page_print,
                    (unsigned) chan_print,
                    (unsigned) mac_len,
                    (unsigned) crc_ok);

                // Hex dump the MAC payload (no FCS)
                fputs("  payload: ", stderr);
                for (uint32_t i = 0; i < mac_len; i++) {
                    fprintf(stderr, "%02X", tap->payload[i]);
                    if (i + 1 < mac_len) fputc(' ', stderr);
                    if ((i + 1) % 16 == 0 && i + 1 < mac_len) {
                        fputc('\n', stderr);
                        fputs("           ", stderr);
                    }
                }
                fputc('\n', stderr);
                fflush(stderr);
            } while (0);
            // ============================= DEBUG (END) ============================= */

            // Send via TAP DLT
            const uint32_t dlt        = KDLT_IEEE802_15_4_TAP;
            const uint32_t wire_len   = mac_len;    // original MAC payload bytes on-air
            const uint32_t packet_sz  = tap_sz;     // bytes we’re sending in this buffer

            int sr = cf_send_data(
                caph,
                /* msg        */ NULL,
                /* msg_type   */ 0,
                /* signal     */ NULL,
                /* gps        */ NULL,
                /* ts         */ ts,
                /* dlt        */ dlt,
                /* original_sz*/ wire_len,
                /* packet_sz  */ packet_sz,
                /* pack       */ tap_pack
            );

            if (sr < 0) {
                char err2[BUFFER_SIZE];
                snprintf(err2, sizeof(err2), "%s - unable to send packet to Kismet server", localcatsniffer->name);
                cf_send_error(caph, 0, err2);
                cf_handler_spindown(caph);
                free(tap_pack);
                break;
            } else if (sr == 0) {
                // ring full; wait and retry on next frame
                cf_handler_wait_ringbuffer(caph);
                free(tap_pack);
                break;
            } else {
                // queued/sent
                free(tap_pack);
                break;
            }
            /* -------------------------------------------------------------- */
        }
    }

    // Reset the TTY to its original settings
    tcsetattr(localcatsniffer->fd, TCSANOW, &localcatsniffer->oldtio);
    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_catsniffer_t localcatsniffer = {
        .baudrate = B115200,
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .fd = -1,
        .channel = 0,
    };

    kis_capture_handler_t *caph = cf_handler_init("catsniffer_zigbee");

    if (caph == NULL) {
        fprintf(stderr,
                "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localcatsniffer.caph = caph;

    cf_handler_set_userdata(caph, &localcatsniffer);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);
    cf_handler_set_capture_cb(caph, capture_thread);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        printf("Invalid options provided. Displaying help.\n");
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_remote_capture(caph);
    cf_jail_filesystem(caph);
    cf_drop_most_caps(caph);
    cf_handler_loop(caph);

    return 0;
}
