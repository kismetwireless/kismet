//Usage: sudo ./kismet_cap_catsniffer_zigbee  --source=catsniffer_zigbee:device=/dev/ttyACM0 --connect localhost:3501 --tcp --disable-retry

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

    /* Every command gets a response; data frames read before the responses to a channel
     * change (STOP, PING, CFG_FREQUENCY, START) were received on the old channel.  Shared
     * between the channel control and capture threads. */
    pthread_mutex_t chan_mutex;
    unsigned int pending_responses;
    struct timeval pending_deadline;

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

/* Account for the responses to n commands about to be sent, optionally with the channel they
 * tune to.  Data frames are dropped until all responses are in, for at most 500ms from the
 * first command still waiting for one; later commands don't extend that, so a lost response
 * doesn't block the capture while hopping. */
void expect_responses(local_catsniffer_t *catsniffer, unsigned int n, int channel) {
    pthread_mutex_lock(&catsniffer->chan_mutex);
    if (channel >= 0)
        catsniffer->channel = channel;
    if (catsniffer->pending_responses == 0) {
        gettimeofday(&catsniffer->pending_deadline, NULL);
        catsniffer->pending_deadline.tv_usec += 500000;
        if (catsniffer->pending_deadline.tv_usec >= 1000000) {
            catsniffer->pending_deadline.tv_sec++;
            catsniffer->pending_deadline.tv_usec -= 1000000;
        }
    }
    catsniffer->pending_responses += n;
    pthread_mutex_unlock(&catsniffer->chan_mutex);
}

int init_interface(kis_capture_handler_t *caph, local_catsniffer_t *catsniffer) {
    int r;

    expect_responses(catsniffer, 3, -1);

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

    /* STOP, PING, CFG_FREQUENCY, START */
    expect_responses(localcatsniffer, 4, channel->channel);

    if (set_channel(caph, localcatsniffer, channel->channel) < 0) {
        snprintf(errstr, STATUS_MAX, "failed to set channel %u", channel->channel);
        cf_send_warning(caph, errstr);
        return 1;
    }

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

    // Only handle our interface type
    if (strstr(interface, "catsniffer_zigbee") != interface) {
        snprintf(msg, STATUS_MAX, "Expected catsniffer_zigbee interface, skipping");
        free(interface);
        return 0; // not ours
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
        // printf("device: %s\n", device);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        free(interface);
        return 0; // not ours (or reportable error)
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "band", definition)) > 0) {
        if (strncmp(placeholder, "800",  placeholder_len) == 0)
            band = 0;
        else if (strncmp(placeholder, "900",  placeholder_len) == 0)
            band = 1;
        else if (strncmp(placeholder, "2400", placeholder_len) == 0)
            band = 2;
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

/* TI Packet Sniffer 2 frames: SOF (0x40 0x53), packet info, 16 bit length (LE), payload,
 * FCS (commands and responses only), EOF (0x40 0x45) */
#define TI_INFO_DATA        0xC0
#define TI_INFO_RESPONSE    0x80
#define TI_MAX_FRAME        512
#define TI_READ_BUF         (TI_MAX_FRAME * 2)

/* A response to one of our commands; count it against a pending channel change */
static void response_received(local_catsniffer_t *localcatsniffer) {
    pthread_mutex_lock(&localcatsniffer->chan_mutex);
    if (localcatsniffer->pending_responses > 0)
        localcatsniffer->pending_responses--;
    pthread_mutex_unlock(&localcatsniffer->chan_mutex);
}

/* Data frame payload: timestamp (6), PHR (1), MAC frame (PHR bytes), RSSI (1), status (1).
 * Returns -1 when the capture has to stop. */
static int handle_data_frame(kis_capture_handler_t *caph, local_catsniffer_t *localcatsniffer,
        const uint8_t *data, uint16_t data_len) {
    uint8_t chan;
    int drop = 0;
    struct timeval ts;

    gettimeofday(&ts, NULL);

    pthread_mutex_lock(&localcatsniffer->chan_mutex);
    if (localcatsniffer->pending_responses > 0) {
        if (timercmp(&ts, &localcatsniffer->pending_deadline, <))
            drop = 1;
        else
            localcatsniffer->pending_responses = 0;
    }
    chan = localcatsniffer->channel;
    pthread_mutex_unlock(&localcatsniffer->chan_mutex);

    /* Received before the channel change completed, so the channel is unknown */
    if (drop)
        return 0;

    if (data_len < 6 + 1 + 2)
        return 0;

    const uint8_t mac_len = data[6];

    if (6 + 1 + mac_len + 2 > data_len)
        return 0;

    const uint8_t *mac_payload = &data[7];
    const int8_t rssi_dbm = (int8_t) data[data_len - 2];
    const uint8_t crc_ok = data[data_len - 1];

    // Skip CRC-bad frames
    if (crc_ok == 0)
        return 0;

    // Allocate TAP header + 802.15.4 MAC payload (no FCS)
    const uint32_t tap_sz = sizeof(_802_15_4_tap) + mac_len;
    uint8_t *tap_pack = (uint8_t *) malloc(tap_sz);
    if (tap_pack == NULL) {
        char errstr[BUFFER_SIZE];
        snprintf(errstr, sizeof(errstr), "%s - out of memory building TAP packet", localcatsniffer->name);
        cf_send_error(caph, 0, errstr);
        cf_handler_spindown(caph);
        return -1;
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

    // Send via TAP DLT
    int sr = cf_send_data(caph, NULL, 0, NULL, NULL, ts, KDLT_IEEE802_15_4_TAP,
            mac_len, tap_sz, tap_pack);

    free(tap_pack);

    if (sr < 0) {
        char err2[BUFFER_SIZE];
        snprintf(err2, sizeof(err2), "%s - unable to send packet to Kismet server", localcatsniffer->name);
        cf_send_error(caph, 0, err2);
        cf_handler_spindown(caph);
        return -1;
    } else if (sr == 0) {
        // ring full; this frame is dropped, wait before the next one
        cf_handler_wait_ringbuffer(caph);
    }

    return 0;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_catsniffer_t *localcatsniffer = (local_catsniffer_t *) caph->userdata;

    char errstr[STATUS_MAX];

    uint8_t buf[TI_READ_BUF];
    size_t buf_len = 0;

    ssize_t r = 0;

    while (1) {
        if (caph->spindown) {
            break;
        }

        /* Wait for data with a timeout so spindown is noticed; a read of 0 bytes after poll
         * reported data, or a hangup, means the device is gone */
        struct pollfd pfd = { .fd = localcatsniffer->fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 1000);

        if (pr < 0) {
            if (errno == EINTR)
                continue;

            snprintf(errstr, STATUS_MAX, "%s - error waiting for serial: %s",
                     localcatsniffer->name, strerror(errno));
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (pr == 0)
            continue;

        r = read(localcatsniffer->fd, buf + buf_len, sizeof(buf) - buf_len);

        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;

            snprintf(errstr, STATUS_MAX, "%s - error reading from serial: %s",
                     localcatsniffer->name, strerror(errno));
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (r == 0) {
            snprintf(errstr, STATUS_MAX, "%s - serial connection closed", localcatsniffer->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        buf_len += r;

        /* Frames don't line up with reads: command responses and data frames of any length
         * come in between, so look for the SOF byte by byte */
        size_t pos = 0;
        int failed = 0;

        while (1) {
            while (pos + 1 < buf_len && !(buf[pos] == 0x40 && buf[pos + 1] == 0x53))
                pos++;

            if (buf_len - pos < 5)
                break;

            const uint8_t info = buf[pos + 2];
            const uint16_t data_len = buf[pos + 3] | (buf[pos + 4] << 8);
            const size_t frame_len = 5 + data_len + (info == TI_INFO_DATA ? 0 : 1) + 2;

            if (frame_len > TI_MAX_FRAME) {
                /* Not a frame start after all */
                pos++;
                continue;
            }

            if (buf_len - pos < frame_len)
                break;

            if (buf[pos + frame_len - 2] != 0x40 || buf[pos + frame_len - 1] != 0x45) {
                pos++;
                continue;
            }

            if (info == TI_INFO_DATA) {
                if (handle_data_frame(caph, localcatsniffer, &buf[pos + 5], data_len) < 0) {
                    failed = 1;
                    break;
                }
            } else if ((info & 0xC0) == TI_INFO_RESPONSE) {
                response_received(localcatsniffer);
            }

            pos += frame_len;
        }

        if (failed)
            break;

        memmove(buf, buf + pos, buf_len - pos);
        buf_len -= pos;
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
        .chan_mutex = PTHREAD_MUTEX_INITIALIZER,
        .pending_responses = 0,
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
