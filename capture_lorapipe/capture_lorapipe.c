#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "../capture_framework.h"
#include "../config.h"

#define BUFFER_SIZE 4096

#ifndef D_BAUDRATE
#define D_BAUDRATE B115200
#endif

#ifndef B9600
#define B9600 9600
#endif
#ifndef B19200
#define B19200 19200
#endif
#ifndef B38400
#define B38400 38400
#endif
#ifndef B57600
#define B57600 57600
#endif
#ifndef B115200
#define B115200 115200
#endif
#ifndef B230400
#define B230400 230400
#endif
#ifndef B460800
#define B460800 460800
#endif
#ifndef B500000
#define B500000 500000
#endif
#ifndef B576000
#define B576000 576000
#endif
#ifndef B921600
#define B921600 921600
#endif
#ifndef B1000000
#define B1000000 1000000
#endif
#ifndef B1152000
#define B1152000 1152000
#endif
#ifndef B1500000
#define B1500000 1500000
#endif
#ifndef B2000000
#define B2000000 2000000
#endif
#ifndef B2500000
#define B2500000 2500000
#endif
#ifndef B3000000
#define B3000000 3000000
#endif
#ifndef B3500000
#define B3500000 3500000
#endif
#ifndef B4000000
#define B4000000 4000000
#endif

typedef struct {
    pthread_mutex_t serial_mutex;

    struct termios oldtio, newtio;

    int fd;

    char *name;
    char *interface;

    int channel;

    speed_t baudrate;

    kis_capture_handler_t *caph;
} local_lorapipe_t;

int get_baud(int baud) {
    switch (baud) {
        case 9600: return B9600;
        case 19200: return B19200;
        case 38400: return B38400;
        case 57600: return B57600;
        case 115200: return B115200;
        case 230400: return B230400;
        case 460800: return B460800;
        case 500000: return B500000;
        case 576000: return B576000;
        case 921600: return B921600;
        case 1000000: return B1000000;
        case 1152000: return B1152000;
        case 1500000: return B1500000;
        case 2000000: return B2000000;
        case 2500000: return B2500000;
        case 3000000: return B3000000;
        case 3500000: return B3500000;
        case 4000000: return B4000000;
        default: return -1;
    }
}

/* inefficient readline that looks for a newline; but we're very low bandwidth so
 * it's probably fine */
static int serial_readline(kis_capture_handler_t *caph, int fd, char *buf, int bufsize) {
    int pos = 0;

    while (pos < bufsize - 1) {
        if (*(volatile int *) &caph->spindown) {
            return -1;
        }

        char c;
        int r = read(fd, &c, 1);

        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (r == 0)
            continue;

        if (c == '\n') {
            if (pos > 0 && buf[pos - 1] == '\r')
                pos--;
            return pos;
        }

        buf[pos++] = (uint8_t) c;
    }

    return -1;
}

// Valid channels
// [FREQUENCY]-[BW]-[SPREAD]-[CODING]-[SYNCWORD]
//    906.875-250-11-5-2b
// [PROTOCOL]-[REGION]-[TYPE]
//    meshtastic-US-shortturbo
//    meshtastic-EU_868-longfast
//    meshtastic-EU433-longturbo
//
// local channel type is a simple string, sent to lorapipe as
//    set radio 906.875,250,11,5,2b

typedef struct {
    double frequency;
    unsigned int bandwidth;
    unsigned int spread;
    unsigned int coding;
    uint8_t syncword;
} lora_radio_def_t;

typedef enum {
    LORA_PRESET_LONG_FAST,
    LORA_PRESET_LONG_SLOW,
    LORA_PRESET_MEDIUM_FAST,
    LORA_PRESET_MEDIUM_SLOW,
    LORA_PRESET_SHORT_FAST,
    LORA_PRESET_SHORT_SLOW,
    LORA_PRESET_LONG_MODERATE,
    LORA_PRESET_LONG_TURBO,
    LORA_PRESET_MEDIUM_TURBO,
    LORA_PRESET_SHORT_TURBO,
    LORA_PRESET_MAX
} lora_preset_type_t;

static const char *lora_preset_type_names[LORA_PRESET_MAX] = {
    [LORA_PRESET_LONG_FAST] = "LONG_FAST",
    [LORA_PRESET_LONG_SLOW] = "LONG_SLOW",
    [LORA_PRESET_MEDIUM_FAST] = "MEDIUM_FAST",
    [LORA_PRESET_MEDIUM_SLOW] = "MEDIUM_SLOW",
    [LORA_PRESET_SHORT_FAST] = "SHORT_FAST",
    [LORA_PRESET_SHORT_SLOW] = "SHORT_SLOW",
    [LORA_PRESET_LONG_MODERATE] = "LONG_MODERATE",
    [LORA_PRESET_LONG_TURBO] = "LONG_TURBO",
    [LORA_PRESET_MEDIUM_TURBO] = "MEDIUM_TURBO",
    [LORA_PRESET_SHORT_TURBO] = "SHORT_TURBO",
};

// Regions from https://meshtastic.org/docs/overview/radio-settings/
typedef enum {
    LORA_REGION_US,
    LORA_REGION_EU_433,
    LORA_REGION_EU_868,
    LORA_REGION_EU_866,
    LORA_REGION_EU_N_868,
    LORA_REGION_CN,
    LORA_REGION_JP,
    LORA_REGION_ANZ,
    LORA_REGION_ANZ_433,
    LORA_REGION_RU,
    LORA_REGION_KR,
    LORA_REGION_TW,
    LORA_REGION_IN,
    LORA_REGION_NZ_865,
    LORA_REGION_TH,
    LORA_REGION_UA_433,
    LORA_REGION_MY_433,
    LORA_REGION_MY_919,
    LORA_REGION_SG_923,
    LORA_REGION_PH_433,
    LORA_REGION_PH_868,
    LORA_REGION_PH_915,
    LORA_REGION_KZ_433,
    LORA_REGION_KZ_863,
    LORA_REGION_NP_865,
    LORA_REGION_BR_902,
    LORA_REGION_ITU1_2M,
    LORA_REGION_ITU2_2M,
    LORA_REGION_ITU3_2M,
    LORA_REGION_ITU2_125CM,
    LORA_REGION_ITU1_70CM,
    LORA_REGION_ITU2_70CM,
    LORA_REGION_ITU3_70CM,
    LORA_REGION_LORA_24,
    LORA_REGION_MAX
} lora_region_t;

static const char *lora_region_names[LORA_REGION_MAX] = {
    [LORA_REGION_US] = "US",
    [LORA_REGION_EU_433] = "EU_433",
    [LORA_REGION_EU_868] = "EU_868",
    [LORA_REGION_EU_866] = "EU_866",
    [LORA_REGION_EU_N_868] = "EU_N_868",
    [LORA_REGION_CN] = "CN",
    [LORA_REGION_JP] = "JP",
    [LORA_REGION_ANZ] = "ANZ",
    [LORA_REGION_ANZ_433] = "ANZ_433",
    [LORA_REGION_RU] = "RU",
    [LORA_REGION_KR] = "KR",
    [LORA_REGION_TW] = "TW",
    [LORA_REGION_IN] = "IN",
    [LORA_REGION_NZ_865] = "NZ_865",
    [LORA_REGION_TH] = "TH",
    [LORA_REGION_UA_433] = "UA_433",
    [LORA_REGION_MY_433] = "MY_433",
    [LORA_REGION_MY_919] = "MY_919",
    [LORA_REGION_SG_923] = "SG_923",
    [LORA_REGION_PH_433] = "PH_433",
    [LORA_REGION_PH_868] = "PH_868",
    [LORA_REGION_PH_915] = "PH_915",
    [LORA_REGION_KZ_433] = "KZ_433",
    [LORA_REGION_KZ_863] = "KZ_863",
    [LORA_REGION_NP_865] = "NP_865",
    [LORA_REGION_BR_902] = "BR_902",
    [LORA_REGION_ITU1_2M] = "ITU1_2M",
    [LORA_REGION_ITU2_2M] = "ITU2_2M",
    [LORA_REGION_ITU3_2M] = "ITU3_2M",
    [LORA_REGION_ITU2_125CM] = "ITU2_125CM",
    [LORA_REGION_ITU1_70CM] = "ITU1_70CM",
    [LORA_REGION_ITU2_70CM] = "ITU2_70CM",
    [LORA_REGION_ITU3_70CM] = "ITU3_70CM",
    [LORA_REGION_LORA_24] = "LORA_24",
};

typedef struct {
    char protocol[32];
    lora_region_t region;
    lora_preset_type_t type;
} lora_preset_def_t;

// Preset bandwidths (kHz), spread factor, coding rate, and the display names hashed to pick
// the default slot, from the meshtastic firmware modemPresetToParams() and
// getModemPresetDisplayName()
static const struct {
    float bandwidth;
    float wide_bandwidth;
    unsigned int spread;
    unsigned int coding;
    const char *display_name;
} lora_preset_params[LORA_PRESET_MAX] = {
    [LORA_PRESET_LONG_FAST] = { 250.0f, 812.5f, 11, 5, "LongFast" },
    [LORA_PRESET_LONG_SLOW] = { 125.0f, 406.25f, 12, 8, "LongSlow" },
    [LORA_PRESET_MEDIUM_FAST] = { 250.0f, 812.5f, 9, 5, "MediumFast" },
    [LORA_PRESET_MEDIUM_SLOW] = { 250.0f, 812.5f, 10, 5, "MediumSlow" },
    [LORA_PRESET_SHORT_FAST] = { 250.0f, 812.5f, 7, 5, "ShortFast" },
    [LORA_PRESET_SHORT_SLOW] = { 250.0f, 812.5f, 8, 5, "ShortSlow" },
    [LORA_PRESET_LONG_MODERATE] = { 125.0f, 406.25f, 11, 8, "LongMod" },
    [LORA_PRESET_LONG_TURBO] = { 500.0f, 1625.0f, 11, 8, "LongTurbo" },
    [LORA_PRESET_MEDIUM_TURBO] = { 500.0f, 1625.0f, 9, 5, "MediumTurbo" },
    [LORA_PRESET_SHORT_TURBO] = { 500.0f, 1625.0f, 7, 5, "ShortTurbo" },
};

// EU_868 lacks the turbo presets; LITE regions only allow LITE_* presets, and NARROW
// and HAM regions only allow NARROW_* and TINY_*, none of which we support
typedef enum {
    LORA_PROFILE_STD,
    LORA_PROFILE_EU868,
    LORA_PROFILE_LITE,
    LORA_PROFILE_NARROW,
    LORA_PROFILE_HAM,
} lora_region_profile_t;

// Region band edges (MHz) from the meshtastic firmware regions[] table
static const struct {
    double freq_start;
    double freq_end;
    bool wide_lora;
    lora_region_profile_t profile;
} lora_region_params[LORA_REGION_MAX] = {
    [LORA_REGION_US] = { 902.0, 928.0, false, LORA_PROFILE_STD },
    [LORA_REGION_EU_433] = { 433.0, 434.0, false, LORA_PROFILE_STD },
    [LORA_REGION_EU_868] = { 869.4, 869.65, false, LORA_PROFILE_EU868 },
    [LORA_REGION_EU_866] = { 865.6, 867.6, false, LORA_PROFILE_LITE },
    [LORA_REGION_EU_N_868] = { 869.4, 869.65, false, LORA_PROFILE_NARROW },
    [LORA_REGION_CN] = { 470.0, 510.0, false, LORA_PROFILE_STD },
    [LORA_REGION_JP] = { 920.5, 923.5, false, LORA_PROFILE_STD },
    [LORA_REGION_ANZ] = { 915.0, 928.0, false, LORA_PROFILE_STD },
    [LORA_REGION_ANZ_433] = { 433.05, 434.79, false, LORA_PROFILE_STD },
    [LORA_REGION_RU] = { 868.7, 869.2, false, LORA_PROFILE_STD },
    [LORA_REGION_KR] = { 920.0, 923.0, false, LORA_PROFILE_STD },
    [LORA_REGION_TW] = { 920.0, 925.0, false, LORA_PROFILE_STD },
    [LORA_REGION_IN] = { 865.0, 867.0, false, LORA_PROFILE_STD },
    [LORA_REGION_NZ_865] = { 864.0, 868.0, false, LORA_PROFILE_STD },
    [LORA_REGION_TH] = { 920.0, 925.0, false, LORA_PROFILE_STD },
    [LORA_REGION_UA_433] = { 433.0, 434.7, false, LORA_PROFILE_STD },
    [LORA_REGION_MY_433] = { 433.0, 435.0, false, LORA_PROFILE_STD },
    [LORA_REGION_MY_919] = { 919.0, 924.0, false, LORA_PROFILE_STD },
    [LORA_REGION_SG_923] = { 917.0, 925.0, false, LORA_PROFILE_STD },
    [LORA_REGION_PH_433] = { 433.0, 434.7, false, LORA_PROFILE_STD },
    [LORA_REGION_PH_868] = { 868.0, 869.4, false, LORA_PROFILE_STD },
    [LORA_REGION_PH_915] = { 915.0, 918.0, false, LORA_PROFILE_STD },
    [LORA_REGION_KZ_433] = { 433.075, 434.775, false, LORA_PROFILE_STD },
    [LORA_REGION_KZ_863] = { 863.0, 868.0, false, LORA_PROFILE_STD },
    [LORA_REGION_NP_865] = { 865.0, 868.0, false, LORA_PROFILE_STD },
    [LORA_REGION_BR_902] = { 902.0, 907.5, false, LORA_PROFILE_STD },
    [LORA_REGION_ITU1_2M] = { 144.0, 146.0, false, LORA_PROFILE_HAM },
    [LORA_REGION_ITU2_2M] = { 144.0, 148.0, false, LORA_PROFILE_HAM },
    [LORA_REGION_ITU3_2M] = { 144.0, 148.0, false, LORA_PROFILE_HAM },
    [LORA_REGION_ITU2_125CM] = { 220.0, 225.0, false, LORA_PROFILE_HAM },
    [LORA_REGION_ITU1_70CM] = { 430.0, 440.0, false, LORA_PROFILE_HAM },
    [LORA_REGION_ITU2_70CM] = { 420.0, 450.0, false, LORA_PROFILE_HAM },
    [LORA_REGION_ITU3_70CM] = { 430.0, 450.0, false, LORA_PROFILE_HAM },
    [LORA_REGION_LORA_24] = { 2400.0, 2483.5, true, LORA_PROFILE_STD },
};

static int parse_uint_field(const char **pos, unsigned long *ret, int base, char term) {
    char *end;
    int first_ok = base == 16 ? isxdigit((unsigned char) **pos) : isdigit((unsigned char) **pos);

    if (!first_ok)
        return -1;

    errno = 0;
    *ret = strtoul(*pos, &end, base);

    if (errno != 0 || end == *pos || *end != term)
        return -1;

    *pos = end + 1;
    return 0;
}

static int parse_radio_def(const char *str, lora_radio_def_t *def) {
    const char *pos = str;
    char *end;
    unsigned long v;

    if (!isdigit((unsigned char) *pos))
        return -1;

    errno = 0;
    def->frequency = strtod(pos, &end);
    if (errno != 0 || end == pos || *end != '-')
        return -1;
    pos = end + 1;

    if (parse_uint_field(&pos, &v, 10, '-') < 0 || v > UINT_MAX)
        return -1;
    def->bandwidth = (unsigned int) v;

    if (parse_uint_field(&pos, &v, 10, '-') < 0 || v > UINT_MAX)
        return -1;
    def->spread = (unsigned int) v;

    if (parse_uint_field(&pos, &v, 10, '-') < 0 || v > UINT_MAX)
        return -1;
    def->coding = (unsigned int) v;

    if (parse_uint_field(&pos, &v, 16, '\0') < 0 || v > 0xFF)
        return -1;
    def->syncword = (uint8_t) v;

    return 0;
}

// Case-insensitive and ignores underscores, so eu433 matches EU_433 and longfast
// matches LONG_FAST
static int preset_name_match(const char *str, size_t len, const char *name) {
    const char *end = str + len;

    while (str < end || *name != '\0') {
        if (str < end && *str == '_') {
            str++;
            continue;
        }

        if (*name == '_') {
            name++;
            continue;
        }

        if (str == end || toupper((unsigned char) *str) != toupper((unsigned char) *name))
            return 0;

        str++;
        name++;
    }

    return 1;
}

static int parse_preset_def(const char *str, lora_preset_def_t *def) {
    const char *h1, *h2;
    size_t len;

    if ((h1 = strchr(str, '-')) == NULL || (h2 = strchr(h1 + 1, '-')) == NULL)
        return -1;

    len = (size_t) (h1 - str);
    if (len == 0 || len >= sizeof(def->protocol))
        return -1;
    memcpy(def->protocol, str, len);
    def->protocol[len] = '\0';

    len = (size_t) (h2 - h1 - 1);
    def->region = LORA_REGION_MAX;
    for (int i = 0; i < LORA_REGION_MAX; i++) {
        if (preset_name_match(h1 + 1, len, lora_region_names[i])) {
            def->region = (lora_region_t) i;
            break;
        }
    }

    if (def->region == LORA_REGION_MAX)
        return -1;

    len = strlen(h2 + 1);
    for (int i = 0; i < LORA_PRESET_MAX; i++) {
        if (preset_name_match(h2 + 1, len, lora_preset_type_names[i])) {
            def->type = (lora_preset_type_t) i;
            return 0;
        }
    }

    return -1;
}

// Default slot as picked by the meshtastic firmware: the djb2 hash of the preset display
// name, modulo the number of bandwidth-sized slots in the region
static int meshtastic_default_freq(lora_region_t region, lora_preset_type_t type, double *freq) {
    double bw;
    uint32_t num_slots;
    uint32_t hash = 5381;

    if (lora_region_params[region].profile == LORA_PROFILE_EU868) {
        if (type == LORA_PRESET_LONG_TURBO || type == LORA_PRESET_MEDIUM_TURBO ||
                type == LORA_PRESET_SHORT_TURBO)
            return -1;
    } else if (lora_region_params[region].profile != LORA_PROFILE_STD) {
        return -1;
    }

    if (lora_region_params[region].wide_lora)
        bw = lora_preset_params[type].wide_bandwidth / 1000;
    else
        bw = lora_preset_params[type].bandwidth / 1000;

    num_slots = (uint32_t) round((lora_region_params[region].freq_end -
                lora_region_params[region].freq_start) / bw);

    if (num_slots == 0)
        return -1;

    for (const char *c = lora_preset_params[type].display_name; *c != '\0'; c++)
        hash = ((hash << 5) + hash) + (unsigned char) *c;

    *freq = lora_region_params[region].freq_start + (bw / 2) + ((hash % num_slots) * bw);

    return 0;
}

// Up to 5 decimals for 2.4GHz slot spacing, trimmed back to at least 3
static void format_freq(char *buf, size_t len, double freq) {
    size_t end;
    char *dot;

    snprintf(buf, len, "%.5f", freq);

    if ((dot = strchr(buf, '.')) == NULL)
        return;

    end = strlen(buf);
    while (end > (size_t) (dot - buf) + 4 && buf[end - 1] == '0')
        buf[--end] = '\0';
}

void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_lorapipe_t *local = (local_lorapipe_t *) caph->userdata;

    lora_radio_def_t radio;
    lora_preset_def_t preset;
    char errstr[STATUS_MAX];
    char freqstr[32];
    char *ret_chan = NULL;

    if (parse_radio_def(chanstr, &radio) == 0) {
        ret_chan = (char *) malloc(64);
        format_freq(freqstr, sizeof(freqstr), radio.frequency);
        snprintf(ret_chan, 64, "%s,%u,%u,%u,%02x", freqstr, radio.bandwidth,
                radio.spread, radio.coding, radio.syncword);
        return ret_chan;
    }

    if (parse_preset_def(chanstr, &preset) == 0) {
        double preset_freq = 0;
        float preset_bw;
        uint8_t preset_sync = 0;

        if (strcasecmp(preset.protocol, "meshtastic") == 0) {
            preset_sync = 0x2b;
        } else {
            snprintf(errstr, STATUS_MAX, "%s - unknown protocol '%s' in preset; a custom "
                    "sync word can be set using FREQ-BW-SF-CR-SYNC channel formats",
                    local->name, preset.protocol);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
            return NULL;
        }

        if (meshtastic_default_freq(preset.region, preset.type, &preset_freq) < 0) {
            snprintf(errstr, STATUS_MAX, "%s - unable to use channel '%s'; the %s preset is not "
                    "available in region %s", local->name, chanstr,
                    lora_preset_type_names[preset.type], lora_region_names[preset.region]);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
            return NULL;
        }

        if (lora_region_params[preset.region].wide_lora)
            preset_bw = lora_preset_params[preset.type].wide_bandwidth;
        else
            preset_bw = lora_preset_params[preset.type].bandwidth;

        ret_chan = (char *) malloc(64);
        format_freq(freqstr, sizeof(freqstr), preset_freq);
        snprintf(ret_chan, 64, "%s,%g,%u,%u,%02x", freqstr, preset_bw,
                lora_preset_params[preset.type].spread, lora_preset_params[preset.type].coding,
                preset_sync);
        return ret_chan;
    }

    snprintf(errstr, STATUS_MAX, "unable to parse requested channel '%s'; expected "
            "FREQ-BW-SF-CR-SYNC (906.875-250-11-5-2b) or PROTOCOL-REGION-TYPE "
            "(meshtastic-US-shortturbo)", chanstr);
    cf_send_message(caph, errstr, MSGFLAG_INFO);
    return NULL;
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

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strstr(interface, "lorapipe") != interface) {
        snprintf(msg, STATUS_MAX, "Expected a 'lorapipe' interface, not matching");
        free(interface);
        return 0;
    }

    free(interface);

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_lorapipe",
                strlen("kismet_cap_lorapipe")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    free(device);

    // Primary advertising channels only -- this datasource doesn't hop
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
    char *msg, uint32_t *dlt, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {

    char *placeholder;
    int placeholder_len;
    char *device = NULL;
    char errstr[STATUS_MAX];
    char *localbaudratestr = NULL;

    local_lorapipe_t *local= (local_lorapipe_t *) caph->userdata;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    local->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        local->name = strndup(placeholder, placeholder_len);
    } else {
        local->name = strdup(local->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX,
            "%s expected device= path to serial device in definition", local->name);
        return -1;
    }

    /*
    localsniffle->channel = 37;
    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        char *chanstr = strndup(placeholder, placeholder_len);
        int chan = atoi(chanstr);
        free(chanstr);
        if (chan < 37 || chan > 39) {
            snprintf(msg, STATUS_MAX,
                "%s channel= must be 37, 38, or 39 (primary advertising channels only)",
                localsniffle->name);
            return -1;
        }
        localsniffle->channel = chan;
    }
    */

    if ((placeholder_len = cf_find_flag(&placeholder, "baud", definition)) > 0) {
        localbaudratestr = strndup(placeholder, placeholder_len);
        int req_baud = atoi(localbaudratestr);
        free(localbaudratestr);
        int b = get_baud(req_baud);
        if (b < 0) {
            snprintf(msg, STATUS_MAX, "%s unsupported baud= value", local->name);
            return -1;
        }
        local->baudrate = b;
    } else {
        local->baudrate = D_BAUDRATE;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
            adler32_csum((unsigned char *) "kismet_cap_lorapipe",
                strlen("kismet_cap_lorapipe")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    pthread_mutex_lock(&local->serial_mutex);

    local->fd = open(device, O_RDWR | O_NOCTTY);

    if (local->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
            local->name, strerror(errno));
        pthread_mutex_unlock(&(local->serial_mutex));
        free(device);
        return -1;
    }

    free(device);

    tcgetattr(local->fd, &local->oldtio);
    local->newtio = local->oldtio;

    cfmakeraw(&local->newtio);

    cfsetispeed(&local->newtio, local->baudrate);
    cfsetospeed(&local->newtio, local->baudrate);

    local->newtio.c_cflag |= (CLOCAL | CREAD | CS8);
    local->newtio.c_cflag &= ~(PARENB | PARODD | CSTOPB | CRTSCTS);
    local->newtio.c_iflag |= IGNPAR;

    // Short read timeout, no minimum - matches capture_nrf_51822.c's approach,
    // needed so sniffle_readline() can check caph->spindown between bytes
    // rather than blocking forever if the dongle stops talking.
    local->newtio.c_cc[VMIN] = 0;
    local->newtio.c_cc[VTIME] = 1;

    if (tcsetattr(local->fd, TCSANOW, &local->newtio) < 0) {
        snprintf(msg, STATUS_MAX, "%s tcsetattr failed - %s",
            local->name, strerror(errno));
        pthread_mutex_unlock(&(local->serial_mutex));
        return -1;
    }

    tcflush(local->fd, TCIFLUSH);

    pthread_mutex_unlock(&(local->serial_mutex));


    return 1;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_lorapipe_t *local = (local_lorapipe_t *) caph->userdata;

    char line[BUFFER_SIZE];
    uint8_t decoded[BUFFER_SIZE];
    char errstr[STATUS_MAX];

    while (1) {
        if (*(volatile int *) &caph->spindown) {
            tcsetattr(local->fd, TCSANOW, &local->oldtio);
            break;
        }

        int line_len = serial_readline(caph, local->fd, line, sizeof(line));

        if (line_len < 0) {
            if (*(volatile int *) &caph->spindown) {
                break;
            }

            snprintf(errstr, STATUS_MAX, "%s error reading from serial device", local->name);
            cf_send_error(caph, 0, errstr);
            cf_handler_spindown(caph);
            break;
        }

        if (line_len < 4) {
            continue;
        }

        struct timeval tv;
        gettimeofday(&tv, NULL);

        while (1) {
            int r = cf_send_data(caph, NULL, 0, NULL, NULL, tv, 0,
                    (uint32_t) line_len, (uint32_t) line_len, (uint8_t *) line);

            if (r < 0) {
                cf_send_error(caph, 0, "unable to send DATA frame");
                cf_handler_spindown(caph);
                break;
            } else if (r == 0) {
                cf_handler_wait_ringbuffer(caph);
                continue;
            } else {
                break;
            }
        }
    }
}

int main(int argc, char *argv[]) {
    local_lorapipe_t local = {
        .name = NULL,
        .interface = NULL,
        .baudrate = D_BAUDRATE,
    };

    pthread_mutex_init(&local.serial_mutex, NULL);

    kis_capture_handler_t *caph = cf_handler_init("lorapipe");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Unable to initialize capture framework\n");
        return -1;
    }

    local.caph = caph;

    cf_handler_set_userdata(caph, &local);

    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_capture_cb(caph, capture_thread);

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_remote_capture(caph);

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    return 0;
}
