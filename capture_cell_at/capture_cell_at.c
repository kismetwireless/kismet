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

    Cell modem capture source for Kismet.

    Communicates with cellular modems via AT commands over serial ports,
    parses serving cell, neighbor cell, and network scan responses, and
    forwards cell observations as JSON to Kismet via cf_send_json().

    Supported vendors and command references:

    Quectel RM500Q series (5G NR + LTE):
      "RG50xQ&RM5xxQ Series AT Commands Manual" V1.2 (2021-08-09)
      Quectel_RG50xQ_RM5xxQ_Series_AT_Commands_Manual_V1.2.pdf
      Commands: AT+QENG="servingcell", AT+QENG="neighbourcell", AT+QSCAN=3,1

    Quectel EG25-G series (LTE Cat 4):
      "EC2x&EG2x&EG9x&EM05 Series AT Commands Manual" V2.1 (2025-03-21)
      Quectel_EC2xEG2xEG9xEM05_Series_AT_Commands_Manual_V2.1.pdf
      Commands: AT+QENG="servingcell", AT+QENG="neighbourcell"

    Telit LM960 (LTE Cat 18):
      "LM960 Series AT Command Reference Guide" Rev.8 (2022-03-21)
      Telit_LM960_Series_AT_Command_Reference_Guide_r8.pdf
      Commands: AT#RFSTS, AT#SERVINFO, AT#MONI, AT#CSURVC

    Sierra Wireless EM9190 (5G NR + LTE):
      "EM9 Series AT Command Reference" Rev.14, 2026-01-01
      41113480 EM9 AT Command Reference r14.pdf
      Commands: AT!GSTATUS?, AT!NRINFO?, AT!NRPCI?, AT!LTEINFO?

    Orbic RC400L / Qualcomm MDM9607 (LTE Cat 4):
      Huawei-style + Qualcomm $QC commands on MDM9607 reference firmware.
      Discovered via binary analysis of atfwd_daemon (GitHub issue #461).
      Commands: AT^SCELLINFO (serving cell), AT$QCRSRP? (multi-cell passive scan)

    Common 3GPP commands (all vendors, per 3GPP TS 27.007):
      AT, ATE0, AT+CGMI, AT+CGMM, AT+CGMR, AT+CGSN, AT+COPS=?
*/

#include "../config.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../capture_framework.h"

/* Maximum AT response size (128 KB should handle even AT+COPS=? floods) */
#define AT_RESP_MAX         (128 * 1024)

/* Maximum single JSON observation */
#define JSON_BUF_MAX        4096

/* Maximum number of observations from a single AT response */
#define MAX_OBS_PER_RESP    64

/* Status/error message buffer */
#define ERRBUF_MAX          STATUS_MAX

/* -----------------------------------------------------------------------
 * Vendor identification
 * ----------------------------------------------------------------------- */

enum modem_vendor {
    VENDOR_UNKNOWN = 0,
    VENDOR_QUECTEL,
    VENDOR_TELIT,
    VENDOR_SIERRA,
    VENDOR_ORBIC,
};

/* -----------------------------------------------------------------------
 * Local state for the capture source
 * ----------------------------------------------------------------------- */

typedef struct {
    int serial_fd;
    char *device_path;
    char *modem_imei;
    char *modem_firmware;
    char *modem_model;
    char *name;

    enum modem_vendor vendor;

    /* Scan intervals in milliseconds */
    unsigned long serving_interval_ms;
    unsigned long neighbor_interval_ms;
    unsigned long fullscan_interval_ms;

    /* Last-run timestamps (ms since epoch) */
    unsigned long serving_last_ms;
    unsigned long neighbor_last_ms;
    unsigned long fullscan_last_ms;

    /* Feature flags detected from modem */
    int has_qeng;
    int has_qscan;
    int has_rfsts;    /* Telit AT#RFSTS */
    int has_servinfo; /* Telit AT#SERVINFO */
    int has_moni;     /* Telit AT#MONI (cell monitor) */
    int has_csurvc;   /* Telit AT#CSURVC (network survey) */
    int has_gstatus;  /* Sierra AT!GSTATUS? */
    int has_lteinfo;  /* Sierra AT!LTEINFO? */
    int has_nrinfo;   /* Sierra AT!NRINFO? */
    int has_scellinfo; /* Orbic/QC AT^SCELLINFO */
    int has_qcrsrp;    /* Orbic/QC AT$QCRSRP? */

    /* Cached serving cell identity from AT#RFSTS / AT!GSTATUS.
     * Used to:
     *  - Supplement AT#RFSTS with PCI from AT#SERVINFO (#346)
     *  - Fix AT#CSURVC TAC=0 by substituting real TAC (#345) */
    unsigned long cached_tac;
    unsigned long cached_cell_id;
    long cached_pci;
    int cached_valid;

    /* Strategy: 0=wardrive (default), 1=stationary, 2=serving_only */
    int strategy;

    /* Debug mode */
    int debug;

    /* Transcript file descriptor for AT I/O logging (-1 = disabled).
     * When enabled, every AT command sent and response received is
     * written with ISO 8601 timestamps for post-hoc analysis. */
    int transcript_fd;
} local_cell_t;

/* -----------------------------------------------------------------------
 * Time helpers
 * ----------------------------------------------------------------------- */

static unsigned long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long)(tv.tv_sec) * 1000 + (unsigned long)(tv.tv_usec) / 1000;
}

/* Write an ISO 8601 timestamp + direction tag + message to the transcript fd.
 * direction: "TX" for commands sent, "RX" for responses received.
 * Safe to call with fd < 0 (no-op). */
static void transcript_write(int fd, const char *direction, const char *data, int len) {
    if (fd < 0 || !data)
        return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    gmtime_r(&tv.tv_sec, &tm);

    char header[64];
    int hlen = snprintf(header, sizeof(header),
                        "[%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ] %s: ",
                        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec,
                        (long)(tv.tv_usec / 1000), direction);

    /* Write header + data + newline atomically-ish */
    write(fd, header, hlen);
    if (len > 0)
        write(fd, data, len);
    else
        write(fd, data, strlen(data));
    write(fd, "\n", 1);
}

/* -----------------------------------------------------------------------
 * Serial I/O via POSIX termios
 * ----------------------------------------------------------------------- */

static int serial_open(const char *path, int baudrate) {
    int fd;
    struct termios tty;
    speed_t speed;

    fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0)
        return -1;

    /* Clear O_NONBLOCK after open (we want blocking reads with timeout) */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(fd, &tty) != 0) {
        close(fd);
        return -1;
    }

    switch (baudrate) {
        case 9600:   speed = B9600;   break;
        case 19200:  speed = B19200;  break;
        case 38400:  speed = B38400;  break;
        case 57600:  speed = B57600;  break;
        case 460800: speed = B460800; break;
        case 921600: speed = B921600; break;
        default:     speed = B115200; break;
    }

    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);

    /* 8N1, no flow control */
    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~CRTSCTS;
    tty.c_cflag |= CREAD | CLOCAL;

    /* Raw mode */
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY | IGNBRK | BRKINT | PARMRK |
                      ISTRIP | INLCR | IGNCR | ICRNL);
    tty.c_oflag &= ~OPOST;

    /* Read with 1 second timeout */
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 10;  /* 1 second in deciseconds */

    tcflush(fd, TCIOFLUSH);
    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void serial_close(int *fd) {
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

/*
 * Send an AT command and collect the full response.
 *
 * Reads until OK, ERROR, +CME ERROR, or timeout.  Returns the number
 * of bytes written to resp_buf (not including the NUL terminator),
 * or -1 on error.
 */
static int at_command_log(int fd, const char *cmd, char *resp_buf,
                         size_t resp_max, int timeout_ms, int transcript_fd) {
    char line_buf[1024];
    ssize_t n;
    size_t resp_len = 0;
    size_t line_pos = 0;
    struct timeval deadline, now_tv;

    if (fd < 0)
        return -1;

    /* Flush input */
    tcflush(fd, TCIFLUSH);

    /* Send command */
    size_t cmd_len = strlen(cmd);
    char *send_buf = malloc(cmd_len + 3);
    if (!send_buf)
        return -1;
    snprintf(send_buf, cmd_len + 3, "%s\r\n", cmd);

    ssize_t written = write(fd, send_buf, strlen(send_buf));
    free(send_buf);
    if (written < 0)
        return -1;

    transcript_write(transcript_fd, "TX", cmd, 0);

    /* Calculate deadline */
    gettimeofday(&deadline, NULL);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_usec += (timeout_ms % 1000) * 1000;
    if (deadline.tv_usec >= 1000000) {
        deadline.tv_sec++;
        deadline.tv_usec -= 1000000;
    }

    resp_buf[0] = '\0';

    while (1) {
        gettimeofday(&now_tv, NULL);
        if (now_tv.tv_sec > deadline.tv_sec ||
            (now_tv.tv_sec == deadline.tv_sec &&
             now_tv.tv_usec >= deadline.tv_usec))
            break;

        /* Set read timeout to remaining time, max 1s */
        long remaining_ms = (deadline.tv_sec - now_tv.tv_sec) * 1000 +
                            (deadline.tv_usec - now_tv.tv_usec) / 1000;
        if (remaining_ms <= 0)
            break;

        struct termios tty;
        tcgetattr(fd, &tty);
        int vtime = (remaining_ms > 1000) ? 10 : (remaining_ms / 100);
        if (vtime < 1) vtime = 1;
        tty.c_cc[VTIME] = vtime;
        tcsetattr(fd, TCSANOW, &tty);

        char c;
        n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            continue;

        /* Build line */
        if (c == '\n' || c == '\r') {
            if (line_pos == 0)
                continue;  /* skip empty lines */

            line_buf[line_pos] = '\0';

            /* Skip echo of the command */
            if (strncmp(line_buf, cmd, strlen(cmd)) == 0) {
                line_pos = 0;
                continue;
            }

            /* Append to response buffer */
            if (resp_len + line_pos + 2 < resp_max) {
                if (resp_len > 0) {
                    resp_buf[resp_len++] = '\n';
                }
                memcpy(resp_buf + resp_len, line_buf, line_pos);
                resp_len += line_pos;
                resp_buf[resp_len] = '\0';
            }

            /* Check for terminal responses */
            if (strcmp(line_buf, "OK") == 0 ||
                strcmp(line_buf, "ERROR") == 0 ||
                strncmp(line_buf, "+CME ERROR", 10) == 0) {
                break;
            }

            line_pos = 0;
        } else {
            if (line_pos < sizeof(line_buf) - 1) {
                line_buf[line_pos++] = c;
            }
        }
    }

    transcript_write(transcript_fd, "RX", resp_buf, (int)resp_len);

    return (int)resp_len;
}

/* Original signature — no transcript, used during probe/identify before
 * the transcript file is opened. */
static int at_command(int fd, const char *cmd, char *resp_buf,
                      size_t resp_max, int timeout_ms) {
    return at_command_log(fd, cmd, resp_buf, resp_max, timeout_ms, -1);
}

/* Transcript-enabled wrapper — used in capture thread and open callback
 * where local_cell_t is available.  Routes through transcript_fd. */
static int at_command_t(local_cell_t *local, const char *cmd, char *resp_buf,
                        size_t resp_max, int timeout_ms) {
    return at_command_log(local->serial_fd, cmd, resp_buf, resp_max,
                          timeout_ms, local->transcript_fd);
}

/* -----------------------------------------------------------------------
 * AT response parsers — produce JSON strings for each cell observation
 *
 * Each parser writes one JSON object per observation into json_out[],
 * returning the number of observations found.
 * ----------------------------------------------------------------------- */

/* Strip surrounding quotes from a field in-place, return pointer to start */
static char *strip_quotes(char *s) {
    if (!s) return s;
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        s[len - 1] = '\0';
        return s + 1;
    }
    return s;
}

/* Split a line on commas into fields array. Modifies line in-place.
 * Returns number of fields. */
static int split_fields(char *line, char **fields, int max_fields) {
    int count = 0;
    char *p = line;

    while (p && count < max_fields) {
        fields[count++] = p;
        char *comma = strchr(p, ',');
        if (comma) {
            *comma = '\0';
            p = comma + 1;
        } else {
            break;
        }
    }

    /* Strip quotes from each field */
    for (int i = 0; i < count; i++) {
        /* Trim leading whitespace */
        while (*fields[i] == ' ') fields[i]++;
        fields[i] = strip_quotes(fields[i]);
    }

    return count;
}

/* Try to parse a decimal integer from a string. Returns 1 on success. */
static int parse_int(const char *s, long *out) {
    if (!s || !*s || strcmp(s, "-") == 0)
        return 0;
    char *end;
    long val = strtol(s, &end, 10);
    if (end == s || *end != '\0')
        return 0;
    *out = val;
    return 1;
}

/* Try to parse a hex integer from a string. Returns 1 on success. */
static int parse_hex(const char *s, unsigned long *out) {
    if (!s || !*s || strcmp(s, "-") == 0)
        return 0;
    char *end;
    unsigned long val = strtoul(s, &end, 16);
    if (end == s || *end != '\0')
        return 0;
    *out = val;
    return 1;
}

/* Map raw RAT string to normalized name */
static const char *normalize_rat(const char *raw) {
    if (!raw) return NULL;
    if (strcmp(raw, "LTE") == 0)       return "LTE";
    if (strcmp(raw, "NR5G-SA") == 0)   return "NR";
    if (strcmp(raw, "NR5G-NSA") == 0)  return "NR";
    if (strcmp(raw, "NR") == 0)        return "NR";
    if (strcmp(raw, "WCDMA") == 0)     return "WCDMA";
    if (strcmp(raw, "GSM") == 0)       return "GSM";
    if (strcmp(raw, "CDMA") == 0)      return "CDMA";
    return NULL;
}

/* Map COPS numeric RAT code to string */
static const char *cops_rat_name(int code) {
    switch (code) {
        case 0:  return "GSM";
        case 2:  return "WCDMA";
        case 7:  return "LTE";
        case 12: return "NR";
        default: return NULL;
    }
}

/*
 * Build a JSON object string from cell observation fields.
 * Only includes fields that have valid values.
 * Returns number of bytes written (not including NUL), or -1 on error.
 */
static int build_cell_json(char *buf, size_t buf_sz,
                           const char *rat, const char *duplex,
                           long mcc, int have_mcc,
                           long mnc, int have_mnc,
                           unsigned long cell_id, int have_cell_id,
                           long pci, int have_pci,
                           unsigned long tac, int have_tac,
                           long earfcn, int have_earfcn,
                           long band, int have_band,
                           long bandwidth, int have_bandwidth,
                           long rsrp, int have_rsrp,
                           long rsrq, int have_rsrq,
                           long sinr, int have_sinr,
                           long rssi, int have_rssi,
                           const char *obs_type,
                           int is_serving,
                           const char *operator_name) {
    int pos = 0;
    int first = 1;

#define JSON_START() pos += snprintf(buf + pos, buf_sz - pos, "{")
#define JSON_STR(key, val) do { \
    if (val) { \
        pos += snprintf(buf + pos, buf_sz - pos, "%s\"%s\":\"%s\"", \
                        first ? "" : ",", key, val); \
        first = 0; \
    } \
} while (0)
#define JSON_LONG(key, val, have) do { \
    if (have) { \
        pos += snprintf(buf + pos, buf_sz - pos, "%s\"%s\":%ld", \
                        first ? "" : ",", key, val); \
        first = 0; \
    } \
} while (0)
#define JSON_ULONG(key, val, have) do { \
    if (have) { \
        pos += snprintf(buf + pos, buf_sz - pos, "%s\"%s\":%lu", \
                        first ? "" : ",", key, val); \
        first = 0; \
    } \
} while (0)
#define JSON_BOOL(key, val) do { \
    pos += snprintf(buf + pos, buf_sz - pos, "%s\"%s\":%s", \
                    first ? "" : ",", key, val ? "true" : "false"); \
    first = 0; \
} while (0)
#define JSON_END() pos += snprintf(buf + pos, buf_sz - pos, "}")

    if ((size_t)pos >= buf_sz)
        return -1;

    JSON_START();
    JSON_STR("rat", rat);
    JSON_STR("duplex", duplex);
    JSON_LONG("mcc", mcc, have_mcc);
    JSON_LONG("mnc", mnc, have_mnc);
    JSON_ULONG("cell_id", cell_id, have_cell_id);
    JSON_LONG("pci", pci, have_pci);
    JSON_ULONG("tac", tac, have_tac);
    JSON_LONG("earfcn", earfcn, have_earfcn);
    JSON_LONG("band", band, have_band);
    JSON_LONG("bandwidth", bandwidth, have_bandwidth);
    JSON_LONG("rsrp", rsrp, have_rsrp);
    JSON_LONG("rsrq", rsrq, have_rsrq);
    JSON_LONG("sinr", sinr, have_sinr);
    JSON_LONG("rssi", rssi, have_rssi);
    JSON_STR("observation_type", obs_type);
    JSON_BOOL("is_serving", is_serving);
    JSON_STR("operator_name", operator_name);
    JSON_END();

#undef JSON_START
#undef JSON_STR
#undef JSON_LONG
#undef JSON_ULONG
#undef JSON_BOOL
#undef JSON_END

    return pos;
}

/*
 * Insert a data-lineage prov block before the closing brace of a
 * cell_observation JSON object, in place. src=at; origin names the AT command
 * that produced the observation. This mirrors the capture_cell_diag DIAG
 * source's prov block ({"src":"diag",...}) so phy_cell can attribute which
 * pipe supplied identity vs signal for each tower and merge without dupes.
 * No-op if the buffer lacks room or is not a JSON object.
 */
static void inject_prov(char *json, size_t json_sz, const char *imei,
                        const char *origin) {
    size_t len = strlen(json);
    if (len < 2 || json[len - 1] != '}')
        return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    double captured_at = (double)tv.tv_sec + (double)tv.tv_usec / 1e6;

    char prov[256];
    int n = snprintf(prov, sizeof(prov),
                     ",\"prov\":{\"src\":\"at\",\"origin\":\"%s\",\"imei\":\"%s\","
                     "\"captured_at\":%.3f}",
                     origin ? origin : "at", imei ? imei : "", captured_at);
    if (n < 0 || len + (size_t)n >= json_sz)
        return;

    json[len - 1] = '\0';              /* drop the closing brace */
    memcpy(json + len - 1, prov, (size_t)n);
    json[len - 1 + n] = '}';           /* restore it after the prov block */
    json[len + n] = '\0';
}

/*
 * Parse AT+QENG="servingcell" response.
 * Handles LTE, NR5G-SA, and NR5G-NSA secondary.
 *
 * Quectel RM500Q/RG502Q (5G):
 *   "RG50xQ&RM5xxQ Series AT Commands Manual" V1.2, 2021-08-09, §5
 *
 * Quectel EG25-G/EC25/EG9x/EM05 (LTE):
 *   "EC2x&EG2x&EG9x&EM05 Series AT Commands Manual" V2.1, 2025-03-21, §6
 *
 * LTE field order (both manuals):
 *   +QENG: "servingcell","state","LTE","FDD/TDD",
 *     MCC,MNC,cellID(hex),PCID,EARFCN,band,UL_BW,DL_BW,
 *     TAC(hex),RSRP,RSRQ,RSSI,SINR,CQI
 *
 * NR5G-SA field order (RM5xxQ manual only):
 *   +QENG: "servingcell","state","NR5G-SA","FDD/TDD",
 *     MCC,MNC,cellID(hex),PCID,TAC(hex),ARFCN,band,NR_DL_BW,
 *     RSRP,RSRQ,SINR,scs,srxlev
 */
static int parse_qeng_serving(const char *response, char json_out[][JSON_BUF_MAX],
                              int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        /* Trim whitespace */
        while (*line == ' ') line++;

        if (strncmp(line, "+QENG:", 6) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* Skip past "+QENG:" prefix */
        char *body = line + 6;
        while (*body == ' ') body++;

        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        if (nf < 3) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *header = fields[0];

        if (strcmp(header, "servingcell") == 0 && nf >= 3) {
            const char *rat_raw = fields[2];
            const char *rat = normalize_rat(rat_raw);
            if (!rat) {
                line = strtok_r(NULL, "\n", &saveptr);
                continue;
            }

            long mcc = 0, mnc = 0, pci = 0, earfcn = 0, band = 0, bw = 0;
            long rsrp = 0, rsrq = 0, sinr = 0;
            unsigned long cell_id = 0, tac = 0;
            int h_mcc = 0, h_mnc = 0, h_pci = 0, h_earfcn = 0, h_band = 0, h_bw = 0;
            int h_rsrp = 0, h_rsrq = 0, h_sinr = 0, h_cell_id = 0, h_tac = 0;
            const char *duplex = (nf > 3) ? fields[3] : NULL;

            if (strcmp(rat_raw, "LTE") == 0) {
                /* +QENG: "servingcell","state","LTE","FDD/TDD",
                 *   MCC,MNC,cellID,PCID,EARFCN,band,UL_BW,DL_BW,
                 *   TAC,RSRP,RSRQ,RSSI,SINR,CQI */
                if (nf > 4)  h_mcc = parse_int(fields[4], &mcc);
                if (nf > 5)  h_mnc = parse_int(fields[5], &mnc);
                if (nf > 6)  h_cell_id = parse_hex(fields[6], &cell_id);
                if (nf > 7)  h_pci = parse_int(fields[7], &pci);
                if (nf > 8)  h_earfcn = parse_int(fields[8], &earfcn);
                if (nf > 9)  h_band = parse_int(fields[9], &band);
                if (nf > 11) h_bw = parse_int(fields[11], &bw);
                if (nf > 12) h_tac = parse_hex(fields[12], &tac);
                if (nf > 13) h_rsrp = parse_int(fields[13], &rsrp);
                if (nf > 14) h_rsrq = parse_int(fields[14], &rsrq);
                /* fields[15] = RSSI */
                if (nf > 16) h_sinr = parse_int(fields[16], &sinr);
            } else if (strcmp(rat_raw, "NR5G-SA") == 0) {
                /* +QENG: "servingcell","state","NR5G-SA","FDD/TDD",
                 *   MCC,MNC,cellID,PCID,TAC,ARFCN,band,NR_DL_BW,
                 *   RSRP,RSRQ,SINR,scs,srxlev */
                if (nf > 4)  h_mcc = parse_int(fields[4], &mcc);
                if (nf > 5)  h_mnc = parse_int(fields[5], &mnc);
                if (nf > 6)  h_cell_id = parse_hex(fields[6], &cell_id);
                if (nf > 7)  h_pci = parse_int(fields[7], &pci);
                if (nf > 8)  h_tac = parse_hex(fields[8], &tac);
                if (nf > 9)  h_earfcn = parse_int(fields[9], &earfcn);
                if (nf > 10) h_band = parse_int(fields[10], &band);
                if (nf > 11) h_bw = parse_int(fields[11], &bw);
                if (nf > 12) h_rsrp = parse_int(fields[12], &rsrp);
                if (nf > 13) h_rsrq = parse_int(fields[13], &rsrq);
                if (nf > 14) h_sinr = parse_int(fields[14], &sinr);
            }

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            rat, duplex,
                            mcc, h_mcc, mnc, h_mnc,
                            cell_id, h_cell_id, pci, h_pci,
                            tac, h_tac, earfcn, h_earfcn,
                            band, h_band, bw, h_bw,
                            rsrp, h_rsrp, rsrq, h_rsrq,
                            sinr, h_sinr, 0, 0,
                            "serving", 1, NULL);
            obs_count++;

        } else if (strcmp(header, "NR5G-NSA") == 0) {
            /* +QENG: "NR5G-NSA",MCC,MNC,PCID,RSRP,RSRQ,ARFCN,band,... */
            long mcc = 0, mnc = 0, pci = 0, rsrp = 0, rsrq = 0, earfcn = 0, band = 0;
            int h_mcc = 0, h_mnc = 0, h_pci = 0, h_rsrp = 0, h_rsrq = 0;
            int h_earfcn = 0, h_band = 0;

            if (nf > 1) h_mcc = parse_int(fields[1], &mcc);
            if (nf > 2) h_mnc = parse_int(fields[2], &mnc);
            if (nf > 3) h_pci = parse_int(fields[3], &pci);
            if (nf > 4) h_rsrp = parse_int(fields[4], &rsrp);
            if (nf > 5) h_rsrq = parse_int(fields[5], &rsrq);
            if (nf > 6) h_earfcn = parse_int(fields[6], &earfcn);
            if (nf > 7) h_band = parse_int(fields[7], &band);

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "NR", NULL,
                            mcc, h_mcc, mnc, h_mnc,
                            0, 0, pci, h_pci,
                            0, 0, earfcn, h_earfcn,
                            band, h_band, 0, 0,
                            rsrp, h_rsrp, rsrq, h_rsrq,
                            0, 0, 0, 0,
                            "serving_secondary", 1, NULL);
            obs_count++;
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Parse AT+QENG="neighbourcell" response.
 *
 * Quectel EG25-G/EC25/RM500Q (all Quectel LTE modems):
 *   Same manuals as parse_qeng_serving above.
 *
 * LTE intra-frequency: +QENG: "neighbourcell intra","LTE",EARFCN,PCID,RSRQ,RSRP,RSSI,...
 * LTE inter-frequency: +QENG: "neighbourcell inter","LTE",EARFCN,PCID,RSRQ,RSRP,RSSI,...
 *
 */
static int parse_qeng_neighbor(const char *response, char json_out[][JSON_BUF_MAX],
                               int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "+QENG:", 6) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *body = line + 6;
        while (*body == ' ') body++;

        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        if (nf < 2) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *header = fields[0];

        if (strncmp(header, "neighbourcell", 13) == 0) {
            const char *obs_type = "observation";

            const char *rat_raw = (nf > 1) ? fields[1] : NULL;
            const char *rat = normalize_rat(rat_raw);
            if (!rat) {
                line = strtok_r(NULL, "\n", &saveptr);
                continue;
            }

            if (strcmp(rat, "LTE") == 0) {
                /* +QENG: "neighbourcell intra","LTE",EARFCN,PCID,RSRQ,RSRP,RSSI,... */
                long earfcn = 0, pci = 0, rsrq = 0, rsrp = 0, rssi = 0;
                int h_earfcn = 0, h_pci = 0, h_rsrq = 0, h_rsrp = 0, h_rssi = 0;

                if (nf > 2) h_earfcn = parse_int(fields[2], &earfcn);
                if (nf > 3) h_pci = parse_int(fields[3], &pci);
                if (nf > 4) h_rsrq = parse_int(fields[4], &rsrq);
                if (nf > 5) h_rsrp = parse_int(fields[5], &rsrp);
                if (nf > 6) h_rssi = parse_int(fields[6], &rssi);

                build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                                rat, NULL,
                                0, 0, 0, 0,
                                0, 0, pci, h_pci,
                                0, 0, earfcn, h_earfcn,
                                0, 0, 0, 0,
                                rsrp, h_rsrp, rsrq, h_rsrq,
                                0, 0, rssi, h_rssi,
                                obs_type, 0, NULL);
                obs_count++;
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Parse AT+QSCAN=3,1 response (full band scan).
 *
 * Quectel RM500Q/RG502Q (5G modules only):
 *   "RG50xQ&RM5xxQ Series AT Commands Manual" V1.2, 2021-08-09, §5
 *   Not available on EC2x/EG2x/EG9x/EM05 series.
 *
 * +QSCAN: "RAT",MCC,MNC,EARFCN,PCI,RSRP,RSRQ,?,band,cellID(hex),TAC(hex),...
 */
static int parse_qscan(const char *response, char json_out[][JSON_BUF_MAX],
                        int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "+QSCAN:", 7) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *body = line + 7;
        while (*body == ' ') body++;

        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        if (nf < 1) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        const char *rat = normalize_rat(fields[0]);
        if (!rat) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* +QSCAN: "RAT",MCC,MNC,EARFCN,PCI,RSRP,RSRQ,?,band,cellID,TAC,... */
        long mcc = 0, mnc = 0, earfcn = 0, pci = 0, rsrp = 0, rsrq = 0, band = 0;
        unsigned long cell_id = 0, tac = 0;
        int h_mcc = 0, h_mnc = 0, h_earfcn = 0, h_pci = 0;
        int h_rsrp = 0, h_rsrq = 0, h_band = 0, h_cell_id = 0, h_tac = 0;

        if (nf > 1) h_mcc = parse_int(fields[1], &mcc);
        if (nf > 2) h_mnc = parse_int(fields[2], &mnc);
        if (nf > 3) h_earfcn = parse_int(fields[3], &earfcn);
        if (nf > 4) h_pci = parse_int(fields[4], &pci);
        if (nf > 5) h_rsrp = parse_int(fields[5], &rsrp);
        if (nf > 6) h_rsrq = parse_int(fields[6], &rsrq);
        if (nf > 8) h_band = parse_int(fields[8], &band);
        if (nf > 9) h_cell_id = parse_hex(fields[9], &cell_id);
        if (nf > 10) h_tac = parse_hex(fields[10], &tac);

        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        rat, NULL,
                        mcc, h_mcc, mnc, h_mnc,
                        cell_id, h_cell_id, pci, h_pci,
                        tac, h_tac, earfcn, h_earfcn,
                        band, h_band, 0, 0,
                        rsrp, h_rsrp, rsrq, h_rsrq,
                        0, 0, 0, 0,
                        "observation", 0, NULL);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/* -----------------------------------------------------------------------
 * Modem identification
 * ----------------------------------------------------------------------- */

/*
 * Probe a serial port: send AT, then read firmware and IMEI.
 * Returns 1 on success (populates fw_buf, imei_buf), 0 on failure.
 */
static int identify_modem(const char *path, char *fw_buf, size_t fw_sz,
                          char *imei_buf, size_t imei_sz) {
    char resp[4096];

    int fd = serial_open(path, 115200);
    if (fd < 0)
        return 0;

    /* Basic AT check — very short timeout since responding modems reply
     * in milliseconds.  Non-AT ports (DM, NMEA, etc.) will time out here
     * quickly, which is critical when scanning many ports at startup. */
    int n = at_command(fd, "AT", resp, sizeof(resp), 150);
    if (n < 0 || strstr(resp, "OK") == NULL) {
        close(fd);
        return 0;
    }

    /* Firmware version */
    n = at_command(fd, "AT+CGMR", resp, sizeof(resp), 3000);
    if (n > 0) {
        /* First non-empty, non-OK, non-error line is the firmware */
        char *saveptr = NULL;
        char *line = strtok_r(resp, "\n", &saveptr);
        fw_buf[0] = '\0';
        while (line) {
            while (*line == ' ') line++;
            if (*line && strcmp(line, "OK") != 0 &&
                strncmp(line, "+CME", 4) != 0) {
                strncpy(fw_buf, line, fw_sz - 1);
                fw_buf[fw_sz - 1] = '\0';
                break;
            }
            line = strtok_r(NULL, "\n", &saveptr);
        }
    }

    if (!fw_buf[0]) {
        close(fd);
        return 0;
    }

    /* IMEI */
    n = at_command(fd, "AT+CGSN", resp, sizeof(resp), 3000);
    imei_buf[0] = '\0';
    if (n > 0) {
        char *saveptr = NULL;
        char *line = strtok_r(resp, "\n", &saveptr);
        while (line) {
            while (*line == ' ') line++;
            if (*line && strcmp(line, "OK") != 0 &&
                strncmp(line, "+CME", 4) != 0) {
                strncpy(imei_buf, line, imei_sz - 1);
                imei_buf[imei_sz - 1] = '\0';
                break;
            }
            line = strtok_r(NULL, "\n", &saveptr);
        }
    }

    close(fd);
    return 1;
}

/* Detect modem vendor from firmware string.
 *
 * Quectel firmware starts with model name: RM500Q*, EG25*, EC25*, RM502Q*, etc.
 * Telit firmware is a version number like 32.01.110 — identified by AT+CGMI.
 */
static enum modem_vendor detect_vendor(int fd) {
    char resp[4096];

    /* Try AT+CGMI (manufacturer identification) */
    int n = at_command(fd, "AT+CGMI", resp, sizeof(resp), 3000);
    if (n > 0) {
        if (strstr(resp, "Quectel") != NULL)
            return VENDOR_QUECTEL;
        if (strstr(resp, "Telit") != NULL)
            return VENDOR_TELIT;
        if (strstr(resp, "Sierra") != NULL)
            return VENDOR_SIERRA;
        /* Orbic RC400L reports "Manufacturer" or "Reliance" or "Sino" via CGMI
         * (cheap ODM firmware quirk — varies by unit) */
        if (strstr(resp, "Reliance") != NULL || strstr(resp, "Sino") != NULL ||
            strstr(resp, "Orbic") != NULL)
            return VENDOR_ORBIC;
    }

    return VENDOR_UNKNOWN;
}

static const char *vendor_name(enum modem_vendor v) {
    switch (v) {
        case VENDOR_QUECTEL: return "Quectel";
        case VENDOR_TELIT:   return "Telit";
        case VENDOR_SIERRA:  return "Sierra";
        case VENDOR_ORBIC:   return "Orbic";
        default:             return "Unknown";
    }
}

/*
 * Parse Telit AT#RFSTS response.
 *
 * Telit LM960/LM960A18:
 *   "LM960 Series AT Command Reference Guide" Rev.8, 2022-03-21, §5.6.1.26
 *
 * Format (LTE):
 *   #RFSTS: "MCC MNC",EARFCN,RSRP,TXPWR,RSRQ,TAC(hex),BAND,,DRX,MIMO,SFN,CellID,"IMEI","Operator",MODE,DUPLEX
 *
 * Example from Telit documentation:
 *   #RFSTS: "311 480",66536,-103,-68,-15,0D00,255,,1280,1,0,033C416,"000000000000000","Verizon",3,66
 *
 * Note: Band field 255 means "not available" and must be filtered.
 */
static int parse_rfsts(const char *response, char json_out[][JSON_BUF_MAX],
                       int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "#RFSTS:", 7) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *body = line + 7;
        while (*body == ' ') body++;

        /* Parse MCC MNC from the quoted first field */
        long mcc = -1, mnc = -1;
        int h_mcc = 0, h_mnc = 0;
        char *quote1 = strchr(body, '"');
        if (quote1) {
            char *quote2 = strchr(quote1 + 1, '"');
            if (quote2) {
                char plmn[32];
                size_t plen = quote2 - quote1 - 1;
                if (plen < sizeof(plmn)) {
                    memcpy(plmn, quote1 + 1, plen);
                    plmn[plen] = '\0';
                    /* Format is "MCC MNC" with space separator */
                    char *space = strchr(plmn, ' ');
                    if (space) {
                        *space = '\0';
                        h_mcc = parse_int(plmn, &mcc);
                        h_mnc = parse_int(space + 1, &mnc);
                    }
                }
                /* Advance body past the closing quote + comma */
                body = quote2 + 1;
                if (*body == ',') body++;
            }
        }

        /* Remaining fields: EARFCN,RSRP,TXPWR,RSRQ,TAC,BAND,,DRX,MIMO,SFN,CellID,"IMEI","Operator",MODE,DUPLEX */
        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        long earfcn = 0, rsrp = 0, rsrq = 0, band = 0;
        unsigned long tac = 0, cell_id = 0;
        int h_earfcn = 0, h_rsrp = 0, h_rsrq = 0, h_band = 0;
        int h_tac = 0, h_cell_id = 0;
        char *operator_name = NULL;

        if (nf > 0) h_earfcn = parse_int(fields[0], &earfcn);
        if (nf > 1) h_rsrp = parse_int(fields[1], &rsrp);
        /* fields[2] = TXPWR (skip) */
        if (nf > 3) h_rsrq = parse_int(fields[3], &rsrq);
        if (nf > 4) h_tac = parse_hex(fields[4], &tac);
        if (nf > 5) {
            h_band = parse_int(fields[5], &band);
            if (band == 255) h_band = 0; /* 255 = not available */
        }
        /* fields[6] = empty, fields[7] = DRX, fields[8] = MIMO, fields[9] = SFN */
        if (nf > 10) h_cell_id = parse_hex(fields[10], &cell_id);
        /* fields[11] = IMEI */
        if (nf > 12 && fields[12][0] != '\0')
            operator_name = fields[12];

        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        "LTE", NULL,
                        mcc, h_mcc, mnc, h_mnc,
                        cell_id, h_cell_id, 0, 0, /* no PCI in RFSTS */
                        tac, h_tac, earfcn, h_earfcn,
                        band, h_band, 0, 0,
                        rsrp, h_rsrp, rsrq, h_rsrq,
                        0, 0, 0, 0,
                        "serving", 1, operator_name);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Parse Telit AT#SERVINFO response.
 *
 * Telit LM960/LM960A18:
 *   "LM960 Series AT Command Reference Guide" Rev.8, 2022-03-21, §5.6.1.27
 *
 * Format (LTE):
 *   #SERVINFO: EARFCN,RSSI,"operator","MCCMNC",cell_id(hex),TAC(hex),DRX,SD,RSRP
 *
 * Example:
 *   #SERVINFO: 66786,-62,"T-Mobile","310260",3089F02,2D18,1280,3,-94
 *
 * Note: field[6] is DRX (not PCI as incorrectly documented in some sources).
 * SERVINFO does NOT include PCI on LTE. PCI comes from AT#MONI or AT#CSURVC.
 * Used as fallback when AT#RFSTS is unavailable.
 */
static int parse_servinfo(const char *response, char json_out[][JSON_BUF_MAX],
                          int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "#SERVINFO:", 10) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *body = line + 10;
        while (*body == ' ') body++;

        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        long earfcn = 0, rssi = 0, rsrp = 0;
        unsigned long cell_id = 0, tac = 0;
        long mcc = -1, mnc = -1;
        int h_earfcn = 0, h_rssi = 0, h_rsrp = 0;
        int h_cell_id = 0, h_tac = 0, h_mcc = 0, h_mnc = 0;
        char *operator_name = NULL;

        if (nf > 0) h_earfcn = parse_int(fields[0], &earfcn);
        if (nf > 1) h_rssi = parse_int(fields[1], &rssi);
        if (nf > 2 && fields[2][0] != '\0')
            operator_name = fields[2];
        /* fields[3] = "MCCMNC" */
        if (nf > 3 && strlen(fields[3]) >= 5) {
            char mcc_str[4] = {fields[3][0], fields[3][1], fields[3][2], '\0'};
            h_mcc = parse_int(mcc_str, &mcc);
            h_mnc = parse_int(fields[3] + 3, &mnc);
        }
        if (nf > 4) h_cell_id = parse_hex(fields[4], &cell_id);
        if (nf > 5) h_tac = parse_hex(fields[5], &tac);
        /* fields[6] = DRX (NOT PCI — confirmed against Rev.8 §5.6.1.27) */
        /* fields[7] = SD (Service Domain) */
        if (nf > 8) h_rsrp = parse_int(fields[8], &rsrp);

        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        "LTE", NULL,
                        mcc, h_mcc, mnc, h_mnc,
                        cell_id, h_cell_id, 0, 0, /* no PCI in SERVINFO */
                        tac, h_tac, earfcn, h_earfcn,
                        0, 0, 0, 0,
                        rsrp, h_rsrp, 0, 0,
                        0, 0, rssi, h_rssi,
                        "serving", 1, operator_name);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Extract a numeric value from a "Key:Value" token in a space-delimited string.
 * Finds the key, then parses the value up to the next space or end of string.
 * Works with both decimal (e.g., "RSRP:-102") and hex (e.g., "Id:6DE11D2").
 * Returns 1 on success.
 */
static int extract_kv_int(const char *str, const char *key, long *out) {
    char *p = strstr(str, key);
    if (!p) return 0;
    p += strlen(key);
    /* Copy value to a NUL-terminated buffer */
    char val[32];
    int i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\r' && p[i] != '\n' && i < (int)sizeof(val) - 1) {
        val[i] = p[i];
        i++;
    }
    val[i] = '\0';
    return parse_int(val, out);
}

static int extract_kv_hex(const char *str, const char *key, unsigned long *out) {
    char *p = strstr(str, key);
    if (!p) return 0;
    p += strlen(key);
    char val[32];
    int i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\r' && p[i] != '\n' && i < (int)sizeof(val) - 1) {
        val[i] = p[i];
        i++;
    }
    val[i] = '\0';
    return parse_hex(val, out);
}

/*
 * Parse Telit AT#MONI response.
 *
 * Telit LM960/LM960A18:
 *   "LM960 Series AT Command Reference Guide" Rev.8, 2022-03-21, §5.6.1.24
 *
 * Serving cell format (AT#MONI=0 then AT#MONI):
 *   #MONI: <netname> RSRP:<rsrp> RSRQ:<rsrq> TAC:<tac> Id:<id> EARFCN:<earfcn> PWR:<dBm>dbm DRX:<drx>
 *   #MONI: Cc:<cc> Nc:<nc> RSRP:<rsrp> RSRQ:<rsrq> TAC:<tac> Id:<id> EARFCN:<earfcn> PWR:<dBm>dbm DRX:<drx>
 *
 * Neighbor cell format (AT#MONI=1 or AT#MONI=2 then AT#MONI):
 *   #MONI: RSRP:<rsrp> RSRQ:<rsrq> Id:<id> EARFCN:<earfcn> PWR:<dBm>dbm
 *
 * Id is cell ID in hex for serving, PCI in hex for neighbors.
 */
static int parse_moni(const char *response, char json_out[][JSON_BUF_MAX],
                      int max_obs, int is_serving) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "#MONI:", 6) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *body = line + 6;
        while (*body == ' ') body++;

        long rsrp = 0, rsrq = 0, rssi = 0, earfcn = 0;
        long mcc = -1, mnc = -1;
        unsigned long tac = 0, cell_id = 0;
        long pci = 0;
        int h_rsrp = 0, h_rsrq = 0, h_rssi = 0, h_earfcn = 0;
        int h_mcc = 0, h_mnc = 0, h_tac = 0, h_cell_id = 0, h_pci = 0;
        char *operator_name = NULL;

        /* Extract key:value pairs from the space-delimited response */
        h_mcc = extract_kv_int(body, "Cc:", &mcc);
        h_mnc = extract_kv_int(body, "Nc:", &mnc);
        h_rsrp = extract_kv_int(body, "RSRP:", &rsrp);
        h_rsrq = extract_kv_int(body, "RSRQ:", &rsrq);
        h_tac = extract_kv_hex(body, "TAC:", &tac);
        h_earfcn = extract_kv_int(body, "EARFCN:", &earfcn);
        h_rssi = extract_kv_int(body, "PWR:", &rssi);

        /* Id field: cell ID (hex) for serving, PCI (hex) for neighbors */
        unsigned long id_val = 0;
        if (extract_kv_hex(body, "Id:", &id_val)) {
            if (is_serving) {
                cell_id = id_val;
                h_cell_id = 1;
            } else {
                pci = (long)id_val;
                h_pci = 1;
            }
        }

        /* Network name: first token if it doesn't start with a known key */
        if (body[0] != '\0' && strncmp(body, "Cc:", 3) != 0 &&
            strncmp(body, "RSRP:", 5) != 0 && strncmp(body, "PSC:", 4) != 0) {
            /* Network name is the first space-delimited token */
            static char name_buf[64];
            int ni = 0;
            while (body[ni] && body[ni] != ' ' && ni < (int)sizeof(name_buf) - 1)
                name_buf[ni] = body[ni], ni++;
            name_buf[ni] = '\0';
            if (ni > 0)
                operator_name = name_buf;
        }

        const char *obs_type = is_serving ? "serving" : "observation";

        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        "LTE", NULL,
                        mcc, h_mcc, mnc, h_mnc,
                        cell_id, h_cell_id, pci, h_pci,
                        tac, h_tac, earfcn, h_earfcn,
                        0, 0, 0, 0,
                        rsrp, h_rsrp, rsrq, h_rsrq,
                        0, 0, rssi, h_rssi,
                        obs_type, is_serving, operator_name);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Parse Telit AT#CSURVC response.
 *
 * Telit LM960/LM960A18:
 *   "LM960 Series AT Command Reference Guide" Rev.8, 2022-03-21, §5.6.9.2
 *
 * 4G serving/carrier cell format (11 fields):
 *   <earfcn>,<rxLev>,<mcc>,<mnc>,<cellId>,<tac>,<pci>,<cellStatus>,<rsrp>,<rsrq>,<bandwidth>
 *
 * 4G neighbor cell format (6 fields):
 *   <earfcn>,<rxLev>,<pci>,<cellStatus>,<rsrp>,<rsrq>
 *
 * MCC/MNC are hex. CellId and TAC are decimal by default (#CSURVF=0).
 * Lines starting with "Network survey" are status lines and should be skipped.
 *
 * The command takes 30-60 seconds to complete (max 3 minutes per manual).
 * Should only be used in stationary strategy.
 */
static int parse_csurvc(const char *response, char json_out[][JSON_BUF_MAX],
                        int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        /* Skip status lines and terminal responses */
        if (strncmp(line, "Network survey", 14) == 0 ||
            strcmp(line, "OK") == 0 || strcmp(line, "ERROR") == 0 ||
            line[0] == '\0') {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* Must start with a digit (EARFCN) */
        if (!isdigit((unsigned char)line[0])) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *fields[32];
        char line_copy[2048];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        int nf = split_fields(line_copy, fields, 32);

        if (nf >= 11) {
            /* Serving/carrier cell: earfcn,rxLev,mcc,mnc,cellId,tac,pci,cellStatus,rsrp,rsrq,bandwidth */
            long earfcn = 0, rssi = 0, rsrp = 0, rsrq = 0, pci = 0, bandwidth = 0;
            long mcc = 0, mnc = 0, cell_id_l = 0;
            unsigned long cell_id = 0, tac = 0;
            int h_earfcn = 0, h_rssi = 0, h_rsrp = 0, h_rsrq = 0;
            int h_mcc = 0, h_mnc = 0, h_cell_id = 0, h_tac = 0;
            int h_pci = 0, h_bandwidth = 0;

            h_earfcn = parse_int(fields[0], &earfcn);
            h_rssi = parse_int(fields[1], &rssi);
            /* MCC/MNC: manual says hex but observed output is decimal */
            h_mcc = parse_int(fields[2], &mcc);
            h_mnc = parse_int(fields[3], &mnc);
            if (parse_int(fields[4], &cell_id_l)) {
                cell_id = (unsigned long)cell_id_l;
                h_cell_id = 1;
            }
            if (parse_int(fields[5], &cell_id_l)) {
                tac = (unsigned long)cell_id_l;
                h_tac = 1;
            }
            h_pci = parse_int(fields[6], &pci);
            /* fields[7] = cellStatus (skip for now) */
            h_rsrp = parse_int(fields[8], &rsrp);
            h_rsrq = parse_int(fields[9], &rsrq);
            h_bandwidth = parse_int(fields[10], &bandwidth);

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "LTE", NULL,
                            mcc, h_mcc, mnc, h_mnc,
                            cell_id, h_cell_id, pci, h_pci,
                            tac, h_tac, earfcn, h_earfcn,
                            0, 0, bandwidth, h_bandwidth,
                            rsrp, h_rsrp, rsrq, h_rsrq,
                            0, 0, rssi, h_rssi,
                            "survey", 0, NULL);
            obs_count++;

        } else if (nf >= 6) {
            /* Neighbor cell: earfcn,rxLev,pci,cellStatus,rsrp,rsrq */
            long earfcn = 0, rssi = 0, rsrp = 0, rsrq = 0, pci = 0;
            int h_earfcn = 0, h_rssi = 0, h_rsrp = 0, h_rsrq = 0, h_pci = 0;

            h_earfcn = parse_int(fields[0], &earfcn);
            h_rssi = parse_int(fields[1], &rssi);
            h_pci = parse_int(fields[2], &pci);
            /* fields[3] = cellStatus (skip) */
            h_rsrp = parse_int(fields[4], &rsrp);
            h_rsrq = parse_int(fields[5], &rsrq);

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "LTE", NULL,
                            0, 0, 0, 0,
                            0, 0, pci, h_pci,
                            0, 0, earfcn, h_earfcn,
                            0, 0, 0, 0,
                            rsrp, h_rsrp, rsrq, h_rsrq,
                            0, 0, rssi, h_rssi,
                            "observation", 0, NULL);
            obs_count++;

        } else if (nf == 3) {
            /* 3GPP TS 36.101 style WCDMA: uarfcn,rxLev,scrcode... (skip) */
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Parse Sierra Wireless AT!GSTATUS? response.
 *
 * Sierra EM9190/EM919x:
 *   "EM9 Series AT Command Reference" Rev.14, 2026-01-01
 *
 * The response is a multi-line key-value format with tab/space delimiters.
 * Fields vary by RAT (LTE vs NR5G). Key fields are extracted by searching
 * for known labels in the full response text.
 *
 * Also fetches PCI from AT!NRPCI? or AT!LTEINFO? as !GSTATUS lacks PCI.
 *
 * Example NR5G SA response:
 *   !GSTATUS:
 *   Current Time:  423212         Temperature: 36
 *   System mode:   NR5G           PS state:    Not attached
 *   NR5G TAC:        2d6600       NR5G Cell ID:    1C649D138 (7621693752)
 *   NR5G MCC-MNC:    310-260
 *   NR5G band:       n41          NR5G Carrier ID: 0
 *   NR5G dl bw:      20 MHz
 *   NR5G Rx chan:    521232
 *   NR5G RSRP (dBm): -104        NR5G RSRQ (dB):  -15
 *   NR5G SINR (dB):   0.5
 */
/*
 * Extract a whitespace-delimited token after a label in a multiline response.
 * Copies the token to a NUL-terminated buffer for safe parsing.
 * Returns pointer to static buffer, or NULL if label not found.
 */
static const char *extract_gstatus_field(const char *response, const char *label) {
    static char field_buf[64];
    char *p = strstr(response, label);
    if (!p) return NULL;
    p += strlen(label);
    while (*p == ' ' || *p == '\t') p++;
    int i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\t' && p[i] != '\r' && p[i] != '\n'
           && i < (int)sizeof(field_buf) - 1)
        field_buf[i] = p[i], i++;
    field_buf[i] = '\0';
    return field_buf;
}

static int parse_gstatus(const char *response, int serial_fd,
                         char json_out[][JSON_BUF_MAX], int max_obs) {
    if (max_obs < 1) return 0;

    /* Detect RAT from "System mode:" */
    const char *rat = "LTE";
    const char *f = extract_gstatus_field(response, "System mode:");
    if (f) {
        if (strstr(f, "NR5G") || strcmp(f, "NR5G") == 0)
            rat = "NR";
        else if (strstr(f, "LTE") || strcmp(f, "LTE") == 0)
            rat = "LTE";
    }

    long mcc = -1, mnc = -1, rsrp = 0, rsrq = 0, band = 0, bandwidth = 0;
    unsigned long tac = 0, cell_id = 0;
    long earfcn = 0, pci = -1;
    int h_mcc = 0, h_mnc = 0, h_rsrp = 0, h_rsrq = 0, h_band = 0;
    int h_tac = 0, h_cell_id = 0, h_earfcn = 0, h_pci = 0;
    int h_bandwidth = 0, h_sinr = 0;
    long sinr = 0;
    char *p;

    /* Parse MCC-MNC (format: "310-260") — same label prefix for both RATs */
    const char *mcc_mnc_label = (strcmp(rat, "NR") == 0) ? "NR5G MCC-MNC:" : "MCC-MNC:";
    f = extract_gstatus_field(response, mcc_mnc_label);
    if (f) {
        char mcc_mnc_buf[16];
        strncpy(mcc_mnc_buf, f, sizeof(mcc_mnc_buf) - 1);
        mcc_mnc_buf[sizeof(mcc_mnc_buf) - 1] = '\0';
        char *dash = strchr(mcc_mnc_buf, '-');
        if (dash) {
            *dash = '\0';
            h_mcc = parse_int(mcc_mnc_buf, &mcc);
            h_mnc = parse_int(dash + 1, &mnc);
        }
    }

    /* Cell ID: "... Cell ID:    1C649D138 (7621693752)" — use decimal in parens */
    if ((p = strstr(response, "Cell ID:")) != NULL) {
        char *paren = strchr(p, '(');
        if (paren) {
            paren++;
            char cid_buf[32];
            int bi = 0;
            while (paren[bi] && paren[bi] != ')' && bi < (int)sizeof(cid_buf) - 1)
                cid_buf[bi] = paren[bi], bi++;
            cid_buf[bi] = '\0';
            long v;
            if (parse_int(cid_buf, &v)) {
                cell_id = (unsigned long)v;
                h_cell_id = 1;
            }
        }
    }

    /* TAC (hex) */
    const char *tac_label = (strcmp(rat, "NR") == 0) ? "NR5G TAC:" : "TAC:";
    f = extract_gstatus_field(response, tac_label);
    if (f) h_tac = parse_hex(f, &tac);

    /* Band: "n41" or "B66" */
    const char *band_label = (strcmp(rat, "NR") == 0) ? "NR5G band:" : "LTE band:";
    f = extract_gstatus_field(response, band_label);
    if (f) {
        const char *bp = f;
        if (*bp == 'n' || *bp == 'N' || *bp == 'B' || *bp == 'b') bp++;
        h_band = parse_int(bp, &band);
    }

    /* DL bandwidth */
    const char *bw_label = (strcmp(rat, "NR") == 0) ? "NR5G dl bw:" : "LTE dl bw:";
    f = extract_gstatus_field(response, bw_label);
    if (f) h_bandwidth = parse_int(f, &bandwidth);

    /* Rx channel (EARFCN / NR-ARFCN) */
    const char *chan_label = (strcmp(rat, "NR") == 0) ? "NR5G Rx chan:" : "LTE Rx chan:";
    f = extract_gstatus_field(response, chan_label);
    if (f) h_earfcn = parse_int(f, &earfcn);

    /* RSRP — NR uses "NR5G RSRP (dBm):", LTE uses "PCC Rx0 RSRP:" */
    const char *rsrp_label = (strcmp(rat, "NR") == 0) ? "NR5G RSRP (dBm):" : "PCC Rx0 RSRP:";
    f = extract_gstatus_field(response, rsrp_label);
    if (f) h_rsrp = parse_int(f, &rsrp);

    /* RSRQ */
    const char *rsrq_label = (strcmp(rat, "NR") == 0) ? "NR5G RSRQ (dB):" : "RSRQ (dB):";
    f = extract_gstatus_field(response, rsrq_label);
    if (f) h_rsrq = parse_int(f, &rsrq);

    /* SINR — may be fractional (e.g. "0.5"), truncate to integer */
    const char *sinr_label = (strcmp(rat, "NR") == 0) ? "NR5G SINR (dB):" : "SINR (dB):";
    f = extract_gstatus_field(response, sinr_label);
    if (f) {
        h_sinr = parse_int(f, &sinr);
        if (!h_sinr) {
            char *end;
            double v = strtod(f, &end);
            if (end != f) { sinr = (long)v; h_sinr = 1; }
        }
    }

    /* PCI — from AT!NRPCI? (NR) or AT!LTEINFO? serving line (LTE) */
    if (serial_fd >= 0) {
        if (strcmp(rat, "NR") == 0) {
            char pci_resp[256];
            int n = at_command(serial_fd, "AT!NRPCI?", pci_resp, sizeof(pci_resp), 2000);
            if (n > 0) {
                f = extract_gstatus_field(pci_resp, "!NRPCI:");
                if (f) h_pci = parse_int(f, &pci);
            }
        } else {
            /* LTE — parse AT!LTEINFO? serving line for PCI and MCC/MNC.
             *
             * EM9 Series AT Command Reference Rev.14, 2026-01-01:
             * Serving line format (space-delimited, after header):
             *   EARFCN MCC MNC TAC CID(hex) Bd D U SNR PCI RSRQ RSRP RSSI RXLV
             *
             * Example:
             *   66786 310 260 11544 03089F02 66 5 5 -1 236 -14.9 -103.3 -66.6 20
             */
            char lte_resp[4096];
            int n = at_command(serial_fd, "AT!LTEINFO?", lte_resp, sizeof(lte_resp), 5000);
            if (n > 0 && strstr(lte_resp, "Serving:")) {
                /* Find the data line after "Serving:" header line */
                char *serving = strstr(lte_resp, "Serving:");
                char *data_line = NULL;
                if (serving) {
                    /* Skip to next line */
                    char *nl = strchr(serving, '\n');
                    if (nl) {
                        data_line = nl + 1;
                        while (*data_line == ' ') data_line++;
                    }
                }
                if (data_line && *data_line && strncmp(data_line, "IntraFreq", 9) != 0) {
                    /* Parse space-delimited serving line */
                    char srv_copy[512];
                    strncpy(srv_copy, data_line, sizeof(srv_copy) - 1);
                    srv_copy[sizeof(srv_copy) - 1] = '\0';
                    /* Truncate at newline */
                    char *nl2 = strchr(srv_copy, '\n');
                    if (nl2) *nl2 = '\0';

                    /* Split on whitespace */
                    char *fields[20];
                    int nf = 0;
                    char *tok = strtok(srv_copy, " \t");
                    while (tok && nf < 20) {
                        fields[nf++] = tok;
                        tok = strtok(NULL, " \t");
                    }
                    /* EARFCN MCC MNC TAC CID Bd D U SNR PCI RSRQ RSRP RSSI RXLV */
                    /*   0     1   2   3   4  5  6 7  8   9   10   11   12   13  */
                    if (nf >= 10) {
                        if (!h_mcc) h_mcc = parse_int(fields[1], &mcc);
                        if (!h_mnc) h_mnc = parse_int(fields[2], &mnc);
                        h_pci = parse_int(fields[9], &pci);
                    }
                }
            }
        }
    }

    build_cell_json(json_out[0], JSON_BUF_MAX,
                    rat, NULL,
                    mcc, h_mcc, mnc, h_mnc,
                    cell_id, h_cell_id, pci, h_pci,
                    tac, h_tac, earfcn, h_earfcn,
                    band, h_band, bandwidth, h_bandwidth,
                    rsrp, h_rsrp, rsrq, h_rsrq,
                    sinr, h_sinr, 0, 0,
                    "serving", 1, NULL);
    return 1;
}

/*
 * Parse Sierra AT!LTEINFO? neighbor cells.
 *
 * Sierra EM919x:
 *   "EM9 Series AT Command Reference" Rev.14, 2026-01-01
 *
 * IntraFreq neighbors (same EARFCN as serving, derived from serving line):
 *   PCI  RSRQ   RSRP   RSSI RXLV
 *   322 -19.2 -108.3  -79.7  20
 *
 * InterFreq neighbors (different EARFCN):
 *   EARFCN ThresholdLow ThresholdHi Priority PCI  RSRQ   RSRP   RSSI RXLV
 *
 * The serving_earfcn is used to set EARFCN for IntraFreq neighbors.
 */
static int parse_lteinfo_neighbors(const char *response, long serving_earfcn,
                                   char json_out[][JSON_BUF_MAX], int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    int in_intra = 0, in_inter = 0;

    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        /* Detect section headers */
        if (strncmp(line, "IntraFreq:", 10) == 0) {
            in_intra = 1; in_inter = 0;
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }
        if (strncmp(line, "InterFreq:", 10) == 0) {
            in_intra = 0; in_inter = 1;
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }
        /* Stop at other sections */
        if (strncmp(line, "Serving:", 8) == 0 ||
            strncmp(line, "CA SCell", 8) == 0 ||
            strncmp(line, "WCDMA:", 6) == 0 ||
            strcmp(line, "OK") == 0) {
            in_intra = 0; in_inter = 0;
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* Skip header/empty lines */
        if (!isdigit((unsigned char)line[0]) &&
            line[0] != '-') {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* Parse data line — split on whitespace manually (strtok conflicts
         * with outer strtok_r on some platforms) */
        char line_copy[512];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        char *fields[20];
        int nf = 0;
        char *wp = line_copy;
        while (*wp && nf < 20) {
            while (*wp == ' ' || *wp == '\t') wp++;
            if (!*wp || *wp == '\n' || *wp == '\r') break;
            fields[nf++] = wp;
            while (*wp && *wp != ' ' && *wp != '\t' && *wp != '\n' && *wp != '\r') wp++;
            if (*wp) { *wp = '\0'; wp++; }
        }

        if (in_intra && nf >= 3) {
            /* IntraFreq: PCI RSRQ RSRP RSSI RXLV */
            long pci = 0, rsrp = 0;
            int h_pci = parse_int(fields[0], &pci);
            /* RSRQ and RSRP may be fractional (-19.2, -108.3) — truncate */
            long rsrq = 0, rsrp_l = 0;
            char *dot;
            if (nf > 1) {
                dot = strchr(fields[1], '.');
                if (dot) *dot = '\0';
                parse_int(fields[1], &rsrq);
            }
            if (nf > 2) {
                dot = strchr(fields[2], '.');
                if (dot) *dot = '\0';
                parse_int(fields[2], &rsrp_l);
                rsrp = rsrp_l;
            }

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "LTE", NULL,
                            0, 0, 0, 0,
                            0, 0, pci, h_pci,
                            0, 0, serving_earfcn, (serving_earfcn > 0),
                            0, 0, 0, 0,
                            rsrp, (nf > 2), rsrq, (nf > 1),
                            0, 0, 0, 0,
                            "observation", 0, NULL);
            obs_count++;

        } else if (in_inter && nf >= 7) {
            /* InterFreq: EARFCN ThresholdLow ThresholdHi Priority PCI RSRQ RSRP RSSI RXLV */
            long earfcn = 0, pci = 0, rsrp = 0, rsrq = 0;
            int h_earfcn = parse_int(fields[0], &earfcn);
            int h_pci = parse_int(fields[4], &pci);
            char *dot;
            if (nf > 5) {
                dot = strchr(fields[5], '.');
                if (dot) *dot = '\0';
                parse_int(fields[5], &rsrq);
            }
            if (nf > 6) {
                dot = strchr(fields[6], '.');
                if (dot) *dot = '\0';
                parse_int(fields[6], &rsrp);
            }

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "LTE", NULL,
                            0, 0, 0, 0,
                            0, 0, pci, h_pci,
                            0, 0, earfcn, h_earfcn,
                            0, 0, 0, 0,
                            rsrp, (nf > 6), rsrq, (nf > 5),
                            0, 0, 0, 0,
                            "observation", 0, NULL);
            obs_count++;
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/* -----------------------------------------------------------------------
 * Orbic RC400L / Qualcomm MDM9607 parsers
 *
 * AT^SCELLINFO — Huawei-style serving cell info (registered mode).
 *   Returns key:value pairs on separate lines.
 *
 * AT$QCRSRP? — Qualcomm multi-cell passive scan.
 *   Returns PCI,EARFCN,"RSRP" triplets.  In COPS=2 (deregistered) mode,
 *   scans ALL configured bands and returns every visible cell.
 *
 * Reference: GitHub issue #461, binary analysis of atfwd_daemon on
 *   MDM9607.LE.2.0-00193-STD.PROD-1 firmware.
 * ----------------------------------------------------------------------- */

/* EARFCN → LTE band and DL frequency lookup (3GPP TS 36.101 Tables 5.7.3-1, 5.5-1).
 *
 * Each entry: N_offs_DL (low EARFCN), N_offs_DL_hi (high EARFCN), band,
 *             F_DL_low (kHz), channel widths supported (MHz, bitmask).
 *
 * Frequency: F_DL(kHz) = F_DL_low + 100 * (EARFCN - N_offs_DL)
 * Channel width bitmask: bit0=1.4 bit1=3 bit2=5 bit3=10 bit4=15 bit5=20 */
typedef struct {
    long n_offs_dl;     /* Low EARFCN */
    long n_offs_dl_hi;  /* High EARFCN */
    long band;
    long f_dl_low_khz;  /* DL low edge frequency (kHz) */
    int  bw_mask;       /* Supported channel widths bitmask */
} earfcn_band_entry_t;

#define BW_1_4  (1 << 0)
#define BW_3    (1 << 1)
#define BW_5    (1 << 2)
#define BW_10   (1 << 3)
#define BW_15   (1 << 4)
#define BW_20   (1 << 5)

static const earfcn_band_entry_t earfcn_table[] = {
    /*  N_offs_DL  hi     band  F_DL_low(kHz)  BW mask */
    {0,     599,    1,  2110000, BW_5|BW_10|BW_15|BW_20},
    {600,   1199,   2,  1930000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {1200,  1949,   3,  1805000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {1950,  2399,   4,  2110000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {2400,  2649,   5,  869000,  BW_1_4|BW_3|BW_5|BW_10},
    {2650,  2749,   6,  875000,  BW_5|BW_10},
    {2750,  3449,   7,  2620000, BW_5|BW_10|BW_15|BW_20},
    {3450,  3799,   8,  925000,  BW_1_4|BW_3|BW_5|BW_10},
    {3800,  4149,   9,  1844900, BW_5|BW_10|BW_15|BW_20},
    {4150,  4749,   10, 2110000, BW_5|BW_10|BW_15|BW_20},
    {4750,  4949,   11, 1475900, BW_5|BW_10},
    {5010,  5179,   12, 729000,  BW_1_4|BW_3|BW_5|BW_10},
    {5180,  5279,   13, 746000,  BW_5|BW_10},
    {5280,  5379,   14, 758000,  BW_5|BW_10},
    {5730,  5849,   17, 734000,  BW_5|BW_10},
    {5850,  5999,   18, 860000,  BW_5|BW_10|BW_15},
    {6000,  6149,   19, 875000,  BW_5|BW_10|BW_15},
    {6150,  6449,   20, 791000,  BW_5|BW_10|BW_15|BW_20},
    {6450,  6599,   21, 1495900, BW_5|BW_10|BW_15},
    {8040,  8689,   25, 1930000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {8690,  9039,   26, 859000,  BW_1_4|BW_3|BW_5|BW_10|BW_15},
    {9040,  9209,   27, 852000,  BW_1_4|BW_3|BW_5|BW_10},
    {9210,  9659,   28, 758000,  BW_3|BW_5|BW_10|BW_15|BW_20},
    {9770,  9869,   30, 2350000, BW_5|BW_10},
    {9870,  9919,   31, 462500,  BW_1_4|BW_3|BW_5},
    {36000, 36199,  33, 1900000, BW_5|BW_10|BW_15|BW_20},
    {36200, 36349,  34, 2010000, BW_5|BW_10|BW_15},
    {36350, 36949,  35, 1850000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {36950, 37549,  36, 1930000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {37550, 37749,  37, 1910000, BW_5|BW_10|BW_15|BW_20},
    {37750, 38249,  38, 2570000, BW_5|BW_10|BW_15|BW_20},
    {38250, 38649,  39, 1880000, BW_5|BW_10|BW_15|BW_20},
    {38650, 39649,  40, 2300000, BW_5|BW_10|BW_15|BW_20},
    {39650, 41589,  41, 2496000, BW_5|BW_10|BW_15|BW_20},
    {41590, 43589,  42, 3400000, BW_5|BW_10|BW_15|BW_20},
    {43590, 45589,  43, 3600000, BW_5|BW_10|BW_15|BW_20},
    {45590, 46589,  44, 703000,  BW_3|BW_5|BW_10|BW_15|BW_20},
    {46590, 46789,  45, 1447000, BW_5|BW_10|BW_15|BW_20},
    {46790, 54539,  46, 5150000, BW_10|BW_20},
    {54540, 55239,  47, 5855000, BW_10|BW_20},
    {55240, 56739,  48, 3550000, BW_5|BW_10|BW_15|BW_20},
    {65536, 66435,  65, 2110000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {66436, 67335,  66, 2110000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {67336, 67535,  67, 738000,  BW_5|BW_10|BW_15|BW_20},
    {67536, 67835,  68, 753000,  BW_5|BW_10|BW_15},
    {67836, 68335,  69, 2570000, BW_5|BW_10|BW_15|BW_20},
    {68336, 68585,  70, 1995000, BW_5|BW_10|BW_15|BW_20},
    {68586, 68935,  71, 617000,  BW_5|BW_10|BW_15|BW_20},
};

#define EARFCN_TABLE_SIZE (sizeof(earfcn_table) / sizeof(earfcn_table[0]))

/* Look up band from EARFCN */
static long earfcn_to_band(long earfcn) {
    for (int i = 0; i < (int)EARFCN_TABLE_SIZE; i++) {
        if (earfcn >= earfcn_table[i].n_offs_dl && earfcn <= earfcn_table[i].n_offs_dl_hi)
            return earfcn_table[i].band;
    }
    return 0;
}

/* Compute DL center frequency in kHz from EARFCN.
 * Returns 0 if EARFCN is not in a known band. */
static long earfcn_to_freq_khz(long earfcn) {
    for (int i = 0; i < (int)EARFCN_TABLE_SIZE; i++) {
        if (earfcn >= earfcn_table[i].n_offs_dl && earfcn <= earfcn_table[i].n_offs_dl_hi)
            return earfcn_table[i].f_dl_low_khz + 100 * (earfcn - earfcn_table[i].n_offs_dl);
    }
    return 0;
}

/*
 * Parse AT^SCELLINFO response (Orbic RC400L, registered mode).
 *
 * Response format — key:value pairs on separate lines:
 *   ^SCELLINFO:
 *   CELL_ID:50896642
 *   LAC_ID:11544
 *   RSSI:71
 *   RSRP:-105
 *   RSRQ:-15
 *   BAND:4
 *   CHANNEL:2300
 *   SINR:1.0
 *   CGI:310260
 *   TX_PWR:0
 *   PCI:236
 */
static int parse_scellinfo(const char *response, char json_out[][JSON_BUF_MAX],
                           int max_obs) {
    if (max_obs < 1 || !response)
        return 0;

    /* Must contain the ^SCELLINFO marker */
    if (strstr(response, "^SCELLINFO") == NULL)
        return 0;

    /* Extract key:value pairs into a simple map */
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    long pci = 0, earfcn = 0, band = 0, rsrp = 0, rsrq = 0, sinr = 0;
    unsigned long cell_id = 0, tac = 0;
    long mcc = 0, mnc = 0;
    int h_pci = 0, h_earfcn = 0, h_band = 0, h_rsrp = 0, h_rsrq = 0, h_sinr = 0;
    int h_cell_id = 0, h_tac = 0, h_mcc = 0, h_mnc = 0;

    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);
    while (line) {
        while (*line == ' ' || *line == '\r') line++;

        /* Skip the header line and non-key:value lines */
        if (*line == '^' || *line == '\0' || strchr(line, ':') == NULL) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *colon = strchr(line, ':');
        *colon = '\0';
        char *key = line;
        char *val = colon + 1;
        /* Trim trailing whitespace from val */
        size_t vlen = strlen(val);
        while (vlen > 0 && (val[vlen - 1] == '\r' || val[vlen - 1] == ' '))
            val[--vlen] = '\0';

        if (strcmp(key, "PCI") == 0)
            h_pci = parse_int(val, &pci);
        else if (strcmp(key, "CHANNEL") == 0)
            h_earfcn = parse_int(val, &earfcn);
        else if (strcmp(key, "BAND") == 0)
            h_band = parse_int(val, &band);
        else if (strcmp(key, "RSRP") == 0)
            h_rsrp = parse_int(val, &rsrp);
        else if (strcmp(key, "RSRQ") == 0)
            h_rsrq = parse_int(val, &rsrq);
        else if (strcmp(key, "SINR") == 0) {
            /* SINR may be fractional (e.g. "1.0") — truncate */
            char *dot = strchr(val, '.');
            if (dot) *dot = '\0';
            h_sinr = parse_int(val, &sinr);
        } else if (strcmp(key, "CELL_ID") == 0) {
            h_cell_id = parse_int(val, (long *)&cell_id);
        } else if (strcmp(key, "LAC_ID") == 0) {
            h_tac = parse_int(val, (long *)&tac);
        } else if (strcmp(key, "CGI") == 0) {
            /* CGI is PLMN as concatenated MCC+MNC, e.g. "310260" */
            if (strlen(val) >= 5) {
                char mcc_buf[4] = {val[0], val[1], val[2], '\0'};
                h_mcc = parse_int(mcc_buf, &mcc);
                h_mnc = parse_int(val + 3, &mnc);
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);

    if (!h_pci && !h_earfcn)
        return 0;

    /* Derive band from EARFCN if not reported */
    if (!h_band && h_earfcn) {
        band = earfcn_to_band(earfcn);
        h_band = (band > 0);
    }

    int len = build_cell_json(json_out[0], JSON_BUF_MAX,
                              "LTE", NULL,
                              mcc, h_mcc, mnc, h_mnc,
                              cell_id, h_cell_id, pci, h_pci,
                              tac, h_tac, earfcn, h_earfcn,
                              band, h_band, 0, 0,
                              rsrp, h_rsrp, rsrq, h_rsrq,
                              sinr, h_sinr, 0, 0,
                              "serving", 1, NULL);

    /* Append DL frequency derived from EARFCN */
    if (len > 0 && h_earfcn) {
        long freq = earfcn_to_freq_khz(earfcn);
        if (freq > 0 && len > 1 && json_out[0][len - 1] == '}') {
            json_out[0][len - 1] = '\0';
            snprintf(json_out[0] + len - 1, JSON_BUF_MAX - len,
                     ",\"freq_khz\":%ld}", freq);
        }
    }

    return 1;
}

/*
 * Parse AT$QCRSRP? response (Orbic RC400L, passive multi-cell scan).
 *
 * Response format — comma-separated PCI,EARFCN,"RSRP" triplets:
 *   $QCRSRP: 310,2050,"-115.80",001,2050,"-118.80",263,2050,"-125.00",
 *            001,5230,"-096.20",310,5230,"-097.00",001,975,"-113.70",
 *            007,975,"-115.50",310,975,"-110.90"
 *
 * In COPS=2 (deregistered) mode, returns ALL visible cells across ALL bands.
 * In registered mode, returns only the serving cell.
 */
static int parse_qcrsrp(const char *response, char json_out[][JSON_BUF_MAX],
                        int max_obs) {
    if (!response || max_obs < 1)
        return 0;

    /* Find the data payload after "$QCRSRP:" */
    const char *marker = strstr(response, "$QCRSRP:");
    if (!marker)
        return 0;
    marker += 8; /* skip "$QCRSRP:" */
    while (*marker == ' ') marker++;

    /* Copy payload for destructive parsing */
    char *data = strdup(marker);
    if (!data) return 0;

    /* Strip newlines and quotes */
    char *wp = data, *rp = data;
    while (*rp) {
        if (*rp != '"' && *rp != '\n' && *rp != '\r')
            *wp++ = *rp;
        rp++;
    }
    *wp = '\0';

    /* Split on commas and process in groups of 3 */
    int obs_count = 0;
    char *fields[256];
    int nf = 0;
    char *p = data;
    while (p && nf < 256) {
        while (*p == ' ') p++;
        if (!*p) break;
        fields[nf++] = p;
        char *comma = strchr(p, ',');
        if (comma) {
            *comma = '\0';
            p = comma + 1;
        } else {
            break;
        }
    }

    for (int i = 0; i + 2 < nf && obs_count < max_obs; i += 3) {
        long pci = 0, earfcn = 0, rsrp = 0;
        int h_pci = 0, h_earfcn = 0, h_rsrp = 0;

        h_pci = parse_int(fields[i], &pci);
        h_earfcn = parse_int(fields[i + 1], &earfcn);

        /* RSRP is a float string like "-115.80" — truncate to integer */
        if (fields[i + 2] && *fields[i + 2]) {
            char *dot = strchr(fields[i + 2], '.');
            if (dot) *dot = '\0';
            h_rsrp = parse_int(fields[i + 2], &rsrp);
        }

        if (!h_pci && !h_earfcn)
            continue;

        long band = earfcn_to_band(earfcn);
        long freq = earfcn_to_freq_khz(earfcn);

        int len = build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                                  "LTE", NULL,
                                  0, 0, 0, 0,
                                  0, 0, pci, h_pci,
                                  0, 0, earfcn, h_earfcn,
                                  band, (band > 0), 0, 0,
                                  rsrp, h_rsrp, 0, 0,
                                  0, 0, 0, 0,
                                  "observation", 0, NULL);

        /* Append DL frequency derived from EARFCN */
        if (len > 0 && freq > 0 && json_out[obs_count][len - 1] == '}') {
            json_out[obs_count][len - 1] = '\0';
            snprintf(json_out[obs_count] + len - 1, JSON_BUF_MAX - len,
                     ",\"freq_khz\":%ld}", freq);
        }

        obs_count++;
    }

    free(data);
    return obs_count;
}

/* -----------------------------------------------------------------------
 * Scan serial ports for AT-responding modems
 * ----------------------------------------------------------------------- */

static int find_modem_ports(char ports[][256], int max_ports) {
    glob_t g;
    int count = 0;

    if (glob("/dev/ttyUSB*", 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++) {
            strncpy(ports[count], g.gl_pathv[i], 255);
            ports[count][255] = '\0';
            count++;
        }
    }
    globfree(&g);

    if (glob("/dev/ttyACM*", 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++) {
            strncpy(ports[count], g.gl_pathv[i], 255);
            ports[count][255] = '\0';
            count++;
        }
    }
    globfree(&g);

    /* Optional extra paths from CELLAT_EXTRA_PORTS — space-separated list of
     * literal paths or globs. Used to add modems reachable via non-USB
     * transports (e.g. AT-over-TCP exposed as a PTY via a socat shim:
     *   socat PTY,raw,echo=0,link=/tmp/cfw3212-at TCP:<host>:5555 &
     *   CELLAT_EXTRA_PORTS=/tmp/cfw3212-at kismet -c cellat-<imei>
     * ). Space-separated chosen over colon-separated because device by-id
     * paths can contain colons (cf. RC400L SN:<hex> form, #472). */
    const char *extra = getenv("CELLAT_EXTRA_PORTS");
    if (extra && *extra) {
        char *copy = strdup(extra);
        if (copy) {
            char *saveptr = NULL, *tok;
            for (tok = strtok_r(copy, " ", &saveptr);
                 tok && count < max_ports;
                 tok = strtok_r(NULL, " ", &saveptr)) {
                if (glob(tok, 0, NULL, &g) == 0) {
                    for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++) {
                        strncpy(ports[count], g.gl_pathv[i], 255);
                        ports[count][255] = '\0';
                        count++;
                    }
                    globfree(&g);
                }
            }
            free(copy);
        }
    }

    return count;
}

/*
 * Get the USB device path for a ttyUSB/ttyACM port via sysfs.
 * For /dev/ttyUSB0 whose sysfs device link resolves to e.g.
 *   /sys/devices/.../usb2/2-1/2-1:1.0/ttyUSB0
 * the USB device path is the grandparent: "2-1".
 * Returns 1 on success (usb_dev filled), 0 on failure.
 */
static int get_usb_device_id(const char *port_path, char *usb_dev, size_t usb_dev_sz) {
    char sysfs_path[512];
    char resolved[512];
    const char *port_name;

    /* Extract port name: /dev/ttyUSB0 → ttyUSB0 */
    port_name = strrchr(port_path, '/');
    if (port_name)
        port_name++;
    else
        port_name = port_path;

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/tty/%s/device", port_name);

    if (realpath(sysfs_path, resolved) == NULL)
        return 0;

    /* resolved is e.g. /sys/.../2-1/2-1:1.0/ttyUSB0
     * We want the component two levels up: the USB device (e.g. "2-1").
     * Walk up: strip ttyUSB0, strip 2-1:1.0, take basename. */
    char *slash1 = strrchr(resolved, '/');  /* → /ttyUSB0 */
    if (!slash1) return 0;
    *slash1 = '\0';

    char *slash2 = strrchr(resolved, '/');  /* → /2-1:1.0 */
    if (!slash2) return 0;
    *slash2 = '\0';

    char *dev_name = strrchr(resolved, '/');  /* → /2-1 */
    if (!dev_name) return 0;
    dev_name++;

    strncpy(usb_dev, dev_name, usb_dev_sz - 1);
    usb_dev[usb_dev_sz - 1] = '\0';
    return 1;
}

/*
 * Get the USB interface number for a ttyUSB port via sysfs.
 * For a sysfs config:interface like "2-1:1.4", returns 4.
 * Returns -1 on failure.
 */
static int get_usb_interface_num(const char *port_path) {
    char sysfs_path[512];
    char resolved[512];
    const char *port_name;

    port_name = strrchr(port_path, '/');
    if (port_name)
        port_name++;
    else
        port_name = port_path;

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/tty/%s/device", port_name);

    if (realpath(sysfs_path, resolved) == NULL)
        return -1;

    /* resolved: /sys/.../2-1/2-1:1.4/ttyUSB2
     * Parent dir (2-1:1.4) contains the interface number after the dot */
    char *slash = strrchr(resolved, '/');
    if (!slash) return -1;
    *slash = '\0';

    char *iface_dir = strrchr(resolved, '/');
    if (!iface_dir) return -1;
    iface_dir++;

    /* Find the dot in "2-1:1.4" */
    char *dot = strrchr(iface_dir, '.');
    if (!dot) return -1;

    return atoi(dot + 1);
}

/*
 * Scan serial ports for modems, probing only one AT-responding port per
 * physical USB device.  Uses sysfs to group ports by parent USB device,
 * then tries each port in a group until one responds to AT commands.
 * Once a port responds for a device, remaining ports in that group are
 * skipped.  Falls back to probing all ports if sysfs is unavailable.
 *
 * Calls the callback for each identified modem.  If the callback returns
 * non-zero, scanning stops immediately (early exit for find-by-IMEI).
 */
typedef int (*modem_scan_cb)(const char *port, const char *fw,
                             const char *imei, void *ctx);

static int scan_modems(modem_scan_cb cb, void *ctx) {
    char all_ports[64][256];
    char usb_devs[64][64];
    int if_nums[64];
    int n_all = find_modem_ports(all_ports, 64);
    int found = 0;

    /* Resolve USB device IDs and interface numbers for grouping/sorting */
    for (int i = 0; i < n_all; i++) {
        if (!get_usb_device_id(all_ports[i], usb_devs[i], sizeof(usb_devs[i])))
            usb_devs[i][0] = '\0';  /* No sysfs — treat as unique */
        if_nums[i] = get_usb_interface_num(all_ports[i]);
    }

    /* Sort by USB device ID, then by interface number descending.
     * AT command ports tend to be higher-numbered interfaces, so trying
     * them first minimizes timeouts on non-AT ports (DM, NMEA, etc.). */
    for (int i = 0; i < n_all - 1; i++) {
        for (int j = i + 1; j < n_all; j++) {
            int swap = 0;
            int cmp = strcmp(usb_devs[i], usb_devs[j]);
            if (cmp > 0)
                swap = 1;
            else if (cmp == 0 && if_nums[i] < if_nums[j])
                swap = 1;  /* Same device, higher interface first */
            if (swap) {
                char tmp_port[256], tmp_dev[64];
                int tmp_if;
                memcpy(tmp_port, all_ports[i], 256);
                memcpy(all_ports[i], all_ports[j], 256);
                memcpy(all_ports[j], tmp_port, 256);
                memcpy(tmp_dev, usb_devs[i], 64);
                memcpy(usb_devs[i], usb_devs[j], 64);
                memcpy(usb_devs[j], tmp_dev, 64);
                tmp_if = if_nums[i]; if_nums[i] = if_nums[j]; if_nums[j] = tmp_if;
            }
        }
    }

    /* Track which USB devices we've already identified */
    char done_devs[64][64];
    int n_done = 0;

    for (int i = 0; i < n_all; i++) {
        /* If this port's USB device was already identified, skip it */
        if (usb_devs[i][0]) {
            int skip = 0;
            for (int j = 0; j < n_done; j++) {
                if (strcmp(done_devs[j], usb_devs[i]) == 0) { skip = 1; break; }
            }
            if (skip)
                continue;
        }

        char fw_buf[256], imei_buf[64];
        if (!identify_modem(all_ports[i], fw_buf, sizeof(fw_buf),
                            imei_buf, sizeof(imei_buf)))
            continue;

        /* This port responded — mark its USB device as done */
        if (usb_devs[i][0] && n_done < 64) {
            strncpy(done_devs[n_done], usb_devs[i], 63);
            done_devs[n_done][63] = '\0';
            n_done++;
        }

        found++;
        if (cb && cb(all_ports[i], fw_buf, imei_buf, ctx))
            return found;  /* Early exit requested by callback */
    }

    return found;
}

/* --- Callback context types for scan_modems --- */

typedef struct {
    const char *target_imei;
    char *path_out;
    size_t path_sz;
    char *fw_out;
    size_t fw_sz;
    char *imei_out;
    size_t imei_sz;
} find_imei_ctx_t;

static int find_imei_cb(const char *port, const char *fw,
                        const char *imei, void *ctx) {
    find_imei_ctx_t *c = (find_imei_ctx_t *)ctx;
    if (strcmp(imei, c->target_imei) != 0)
        return 0;  /* Not a match, keep scanning */

    strncpy(c->path_out, port, c->path_sz - 1);
    c->path_out[c->path_sz - 1] = '\0';
    if (c->fw_out) {
        strncpy(c->fw_out, fw, c->fw_sz - 1);
        c->fw_out[c->fw_sz - 1] = '\0';
    }
    if (c->imei_out) {
        strncpy(c->imei_out, imei, c->imei_sz - 1);
        c->imei_out[c->imei_sz - 1] = '\0';
    }
    return 1;  /* Found — stop scanning */
}

/*
 * Find a serial port with a modem matching the given IMEI.
 * Uses sysfs to skip redundant ports on multi-port USB devices.
 * If fw_out/imei_out are non-NULL, copies the firmware and IMEI strings
 * from the successful probe so the caller doesn't need to re-identify.
 * Returns 1 on match (path_out filled), 0 if not found.
 */
static int find_port_by_imei(const char *imei, char *path_out, size_t path_sz,
                             char *fw_out, size_t fw_sz,
                             char *imei_out, size_t imei_sz) {
    find_imei_ctx_t ctx = {
        .target_imei = imei,
        .path_out = path_out, .path_sz = path_sz,
        .fw_out = fw_out, .fw_sz = fw_sz,
        .imei_out = imei_out, .imei_sz = imei_sz,
    };
    scan_modems(find_imei_cb, &ctx);
    return path_out[0] != '\0' ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * Capture framework callbacks
 * ----------------------------------------------------------------------- */

/* Callback context for list_callback's scan */
typedef struct {
    cf_params_list_interface_t **interfaces;
    int n_found;
} list_ctx_t;

static int list_modem_cb(const char *port, const char *fw,
                         const char *imei, void *ctx) {
    list_ctx_t *c = (list_ctx_t *)ctx;

    /* Skip modems that don't report an IMEI — they can't be addressed */
    if (!imei[0])
        return 0;

    c->interfaces[c->n_found] = (cf_params_list_interface_t *)
        malloc(sizeof(cf_params_list_interface_t));
    memset(c->interfaces[c->n_found], 0, sizeof(cf_params_list_interface_t));

    char iface_name[512];
    snprintf(iface_name, sizeof(iface_name), "cellat-%s", imei);
    c->interfaces[c->n_found]->interface = strdup(iface_name);

    char hw_desc[512];
    snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s", fw, imei);
    c->interfaces[c->n_found]->hardware = strdup(hw_desc);

    c->n_found++;
    return 0;  /* Keep scanning */
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    /* Allocate worst-case — 32 modems max */
    *interfaces = (cf_params_list_interface_t **)
        malloc(sizeof(cf_params_list_interface_t *) * 32);

    list_ctx_t ctx = { .interfaces = *interfaces, .n_found = 0 };
    scan_modems(list_modem_cb, &ctx);

    return ctx.n_found;
}

/*
 * Probe callback — validates that a definition looks like a cellat IMEI source.
 * Does NOT scan serial ports (that happens in open_callback) because scanning
 * all ports can take 60+ seconds with many USB devices, which exceeds Kismet's
 * 10-second probe timeout.  We only validate the format and generate a UUID.
 */
int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                   char *msg, char **uuid,
                   cf_params_interface_t **ret_interface,
                   cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char buf[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Extract IMEI from cellat-<IMEI> */
    const char *imei = NULL;
    if (strncmp(interface, "cellat-", 7) == 0)
        imei = interface + 7;

    if (imei == NULL || strlen(imei) != 15) {
        free(interface);
        return 0;
    }

    /* Verify all digits */
    for (int i = 0; i < 15; i++) {
        if (!isdigit(imei[i])) {
            free(interface);
            return 0;
        }
    }

    /* Hardware description is unknown until open — just report the IMEI */
    char hw_desc[512];
    snprintf(hw_desc, sizeof(hw_desc), "Cell modem IMEI:%s", imei);
    (*ret_interface)->hardware = strdup(hw_desc);

    /* UUID — stable across port renumbering, based on IMEI only */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        uint32_t hash;
        snprintf(buf, STATUS_MAX, "cellat%s", imei);
        hash = adler32_csum((unsigned char *)buf, strlen(buf));
        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                 adler32_csum((unsigned char *)"kismet_cap_cell_at",
                              strlen("kismet_cap_cell_at")) & 0xFFFFFFFF,
                 hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    free(interface);
    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                  char *msg, uint32_t *dlt, char **uuid,
                  cf_params_interface_t **ret_interface,
                  cf_params_spectrum_t **ret_spectrum) {
    local_cell_t *local = (local_cell_t *)caph->userdata;
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char device_path[512];
    char fw_buf[256], imei_buf[64];
    char resp[4096];
    char buf[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Extract IMEI from cellat-<IMEI> */
    const char *imei = NULL;
    if (strncmp(interface, "cellat-", 7) == 0)
        imei = interface + 7;

    if (imei == NULL || strlen(imei) != 15) {
        snprintf(msg, STATUS_MAX, "Invalid cell modem definition '%s' — expected cellat-<15-digit IMEI>",
                 interface);
        free(interface);
        return -1;
    }

    /* Verify all digits */
    for (int i = 0; i < 15; i++) {
        if (!isdigit(imei[i])) {
            snprintf(msg, STATUS_MAX, "Invalid IMEI in '%s' — must be 15 digits", interface);
            free(interface);
            return -1;
        }
    }

    /* Save IMEI before freeing interface string */
    char imei_def[16];
    strncpy(imei_def, imei, 15);
    imei_def[15] = '\0';

    /* Resolve IMEI to serial port — also retrieves fw/imei in one pass */
    if (!find_port_by_imei(imei_def, device_path, sizeof(device_path),
                           fw_buf, sizeof(fw_buf), imei_buf, sizeof(imei_buf))) {
        snprintf(msg, STATUS_MAX, "Modem IMEI %s not found on any serial port", imei_def);
        free(interface);
        return -1;
    }

    free(interface);

    /* Open serial for ongoing use */
    local->serial_fd = serial_open(device_path, 115200);
    if (local->serial_fd < 0) {
        snprintf(msg, STATUS_MAX, "Failed to open %s: %s",
                 device_path, strerror(errno));
        return -1;
    }

    local->device_path = strdup(device_path);
    local->modem_firmware = strdup(fw_buf);
    local->modem_imei = strdup(imei_buf);

    /* Detect vendor and capabilities */
    local->has_qeng = 0;
    local->has_qscan = 0;
    local->has_rfsts = 0;
    local->has_servinfo = 0;
    local->has_moni = 0;
    local->has_csurvc = 0;

    local->vendor = detect_vendor(local->serial_fd);

    if (local->vendor == VENDOR_QUECTEL) {
        /* All Quectel LTE/5G modems support QENG */
        local->has_qeng = 1;

        /* RM500Q and RM502Q support QSCAN */
        if (strncmp(fw_buf, "RM500Q", 6) == 0 || strncmp(fw_buf, "RM502Q", 6) == 0)
            local->has_qscan = 1;

        /* Build model string from firmware prefix */
        char model_buf[64];
        /* Extract model: everything before the first non-alnum after letters+digits */
        int mi = 0;
        while (fw_buf[mi] && mi < 20 &&
               (isalnum(fw_buf[mi]) || fw_buf[mi] == '-'))
            mi++;
        snprintf(model_buf, sizeof(model_buf), "Quectel %.*s", mi, fw_buf);
        local->modem_model = strdup(model_buf);

    } else if (local->vendor == VENDOR_TELIT) {
        /* Probe Telit-specific commands */
        int n = at_command_t(local,"AT#RFSTS",
                           resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "#RFSTS:"))
            local->has_rfsts = 1;

        n = at_command_t(local,"AT#SERVINFO",
                       resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "#SERVINFO:"))
            local->has_servinfo = 1;

        /* Probe AT#MONI — set to mode 0 and query */
        n = at_command_t(local,"AT#MONI=0",
                       resp, sizeof(resp), 3000);
        if (n >= 0 && strstr(resp, "OK")) {
            n = at_command_t(local,"AT#MONI",
                           resp, sizeof(resp), 3000);
            if (n > 0 && strstr(resp, "#MONI:"))
                local->has_moni = 1;
        }

        /* Probe AT#CSURVC — just check if the command is recognized
         * (don't run a full scan during probe, that takes 30-60s) */
        n = at_command_t(local,"AT#CSURVC=?",
                       resp, sizeof(resp), 3000);
        if (n >= 0 && strstr(resp, "OK"))
            local->has_csurvc = 1;

        /* Build model string from AT+CGMM if available */
        char model_resp[256];
        n = at_command_t(local,"AT+CGMM", model_resp, sizeof(model_resp), 3000);
        if (n > 0) {
            char *saveptr2 = NULL;
            char *mline = strtok_r(model_resp, "\n", &saveptr2);
            while (mline) {
                while (*mline == ' ') mline++;
                if (*mline && strcmp(mline, "OK") != 0 && strncmp(mline, "+CME", 4) != 0) {
                    char mbuf[64];
                    snprintf(mbuf, sizeof(mbuf), "Telit %s", mline);
                    local->modem_model = strdup(mbuf);
                    break;
                }
                mline = strtok_r(NULL, "\n", &saveptr2);
            }
        }
        if (!local->modem_model)
            local->modem_model = strdup("Telit");

    } else if (local->vendor == VENDOR_SIERRA) {
        /* Enable advanced AT commands (default password) */
        at_command_t(local,"AT!ENTERCND=\"A710\"",
                   resp, sizeof(resp), 3000);

        /* Probe Sierra-specific commands */
        int n = at_command_t(local,"AT!GSTATUS?",
                           resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "!GSTATUS:"))
            local->has_gstatus = 1;

        n = at_command_t(local,"AT!LTEINFO?",
                       resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "!LTEINFO:") && !strstr(resp, "Not Available"))
            local->has_lteinfo = 1;

        n = at_command_t(local,"AT!NRINFO?",
                       resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "!NRINFO:"))
            local->has_nrinfo = 1;

        /* Build model string from AT+CGMM */
        char model_resp[256];
        n = at_command_t(local,"AT+CGMM", model_resp, sizeof(model_resp), 3000);
        if (n > 0) {
            char *saveptr2 = NULL;
            char *mline = strtok_r(model_resp, "\n", &saveptr2);
            while (mline) {
                while (*mline == ' ') mline++;
                if (*mline && strcmp(mline, "OK") != 0 && strncmp(mline, "+CME", 4) != 0) {
                    char mbuf[64];
                    snprintf(mbuf, sizeof(mbuf), "Sierra %s", mline);
                    local->modem_model = strdup(mbuf);
                    break;
                }
                mline = strtok_r(NULL, "\n", &saveptr2);
            }
        }
        if (!local->modem_model)
            local->modem_model = strdup("Sierra");

    } else if (local->vendor == VENDOR_ORBIC) {
        /* Probe Orbic/Qualcomm MDM9607 commands */
        int n = at_command_t(local,"AT^SCELLINFO",
                           resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "^SCELLINFO"))
            local->has_scellinfo = 1;

        n = at_command_t(local,"AT$QCRSRP?",
                       resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "$QCRSRP"))
            local->has_qcrsrp = 1;

        /* Build model string from AT+CGMM */
        char model_resp[256];
        n = at_command_t(local,"AT+CGMM", model_resp, sizeof(model_resp), 3000);
        if (n > 0) {
            char *saveptr2 = NULL;
            char *mline = strtok_r(model_resp, "\n", &saveptr2);
            while (mline) {
                while (*mline == ' ') mline++;
                if (*mline && strcmp(mline, "OK") != 0 && strncmp(mline, "+CME", 4) != 0) {
                    char mbuf[64];
                    snprintf(mbuf, sizeof(mbuf), "Orbic %s", mline);
                    local->modem_model = strdup(mbuf);
                    break;
                }
                mline = strtok_r(NULL, "\n", &saveptr2);
            }
        }
        if (!local->modem_model)
            local->modem_model = strdup("Orbic");

    } else {
        /* Unknown vendor — try probing for common commands */
        local->modem_model = strdup(fw_buf);

        int n = at_command_t(local,"AT+QENG=\"servingcell\"",
                           resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "+QENG:")) {
            local->has_qeng = 1;
            local->vendor = VENDOR_QUECTEL;
        }

        if (!local->has_qeng) {
            n = at_command_t(local,"AT#RFSTS",
                           resp, sizeof(resp), 5000);
            if (n > 0 && strstr(resp, "#RFSTS:")) {
                local->has_rfsts = 1;
                local->vendor = VENDOR_TELIT;
            }
        }

        if (!local->has_qeng && !local->has_rfsts) {
            /* Try Sierra as last resort */
            n = at_command_t(local,"AT!GSTATUS?",
                           resp, sizeof(resp), 5000);
            if (n > 0 && strstr(resp, "!GSTATUS:")) {
                local->has_gstatus = 1;
                local->vendor = VENDOR_SIERRA;
            }
        }

        /* Try Orbic/Qualcomm MDM9607 commands */
        if (!local->has_qeng && !local->has_rfsts && !local->has_gstatus) {
            n = at_command_t(local,"AT^SCELLINFO",
                           resp, sizeof(resp), 5000);
            if (n > 0 && strstr(resp, "^SCELLINFO")) {
                local->has_scellinfo = 1;
                local->vendor = VENDOR_ORBIC;
            }
            n = at_command_t(local,"AT$QCRSRP?",
                           resp, sizeof(resp), 5000);
            if (n > 0 && strstr(resp, "$QCRSRP")) {
                local->has_qcrsrp = 1;
                if (local->vendor == VENDOR_UNKNOWN)
                    local->vendor = VENDOR_ORBIC;
            }
        }
    }

    if (!local->has_qeng && !local->has_rfsts && !local->has_servinfo &&
        !local->has_gstatus && !local->has_scellinfo && !local->has_qcrsrp) {
        snprintf(msg, STATUS_MAX, "Modem on %s does not support any known cell survey commands", device_path);
        serial_close(&local->serial_fd);
        return -1;
    }

    /* Disable echo */
    at_command_t(local,"ATE0", resp, sizeof(resp), 2000);

    /* Parse strategy option */
    local->strategy = 0;  /* default: wardrive */
    if ((placeholder_len = cf_find_flag(&placeholder, "strategy", definition)) > 0) {
        char *strat = strndup(placeholder, placeholder_len);
        if (strcmp(strat, "stationary") == 0)
            local->strategy = 1;
        else if (strcmp(strat, "serving_only") == 0)
            local->strategy = 2;
        free(strat);
    }

    /* Parse debug option.
     * Default: ON during development.  Set KISMET_CELLAT_DEBUG=0 to disable,
     * or pass debug=false in the source definition.
     * TODO: flip default to 0 before public release. */
    local->debug = 1;
    const char *debug_env = getenv("KISMET_CELLAT_DEBUG");
    if (debug_env && (strcmp(debug_env, "0") == 0 || strcmp(debug_env, "false") == 0))
        local->debug = 0;
    if ((placeholder_len = cf_find_flag(&placeholder, "debug", definition)) > 0) {
        char *dbg = strndup(placeholder, placeholder_len);
        if (strcmp(dbg, "false") == 0 || strcmp(dbg, "0") == 0)
            local->debug = 0;
        else if (strcmp(dbg, "true") == 0 || strcmp(dbg, "1") == 0)
            local->debug = 1;
        free(dbg);
    }

    /* Parse transcript file option — logs all AT I/O with timestamps.
     * If debug is on and no transcript path specified, auto-create one
     * in /tmp/ based on IMEI. */
    if ((placeholder_len = cf_find_flag(&placeholder, "transcript", definition)) > 0) {
        char *path = strndup(placeholder, placeholder_len);
        local->transcript_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (local->transcript_fd >= 0) {
            snprintf(buf, sizeof(buf), "%s AT transcript logging to %s",
                     local->name, path);
            cf_send_message(caph, buf, MSGFLAG_INFO);
            transcript_write(local->transcript_fd, "INFO",
                             "transcript opened — capture starting", 0);
        } else {
            snprintf(buf, sizeof(buf), "%s failed to open transcript file %s: %s",
                     local->name, path, strerror(errno));
            cf_send_message(caph, buf, MSGFLAG_ERROR);
        }
        free(path);
    } else if (local->debug && local->transcript_fd < 0) {
        /* Auto-transcript in debug mode */
        char auto_path[256];
        snprintf(auto_path, sizeof(auto_path), "/tmp/kismet_cellat_%s.log",
                 local->modem_imei ? local->modem_imei : "unknown");
        local->transcript_fd = open(auto_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (local->transcript_fd >= 0) {
            snprintf(buf, sizeof(buf), "%s AT transcript (auto) to %s",
                     local->name, auto_path);
            cf_send_message(caph, buf, MSGFLAG_INFO);
            transcript_write(local->transcript_fd, "INFO",
                             "transcript opened (debug auto) — capture starting", 0);
        }
    }

    /* Set scan intervals based on strategy */
    switch (local->strategy) {
        case 1:  /* stationary */
            local->serving_interval_ms = 2000;
            local->neighbor_interval_ms = 5000;
            local->fullscan_interval_ms = 60000;
            break;
        case 2:  /* serving_only */
            local->serving_interval_ms = 2000;
            local->neighbor_interval_ms = 0;  /* disabled */
            local->fullscan_interval_ms = 0;  /* disabled */
            break;
        default:  /* wardrive */
            local->serving_interval_ms = 2000;
            local->neighbor_interval_ms = 5000;
            local->fullscan_interval_ms = 0;  /* disabled in wardrive */
            break;
    }

    /* Build interface info */
    char hw_desc[512];
    snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s", local->modem_model, imei_buf);

    local->name = strdup(hw_desc);
    (*ret_interface)->capif = strdup(device_path);
    (*ret_interface)->hardware = strdup(hw_desc);

    /* UUID */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        uint32_t hash;
        snprintf(buf, STATUS_MAX, "cellat%s", imei_def);
        hash = adler32_csum((unsigned char *)buf, strlen(buf));
        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                 adler32_csum((unsigned char *)"kismet_cap_cell_at",
                              strlen("kismet_cap_cell_at")) & 0xFFFFFFFF,
                 hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    snprintf(buf, STATUS_MAX, "Cell modem %s opened on %s (strategy: %s)",
             local->modem_model, device_path,
             local->strategy == 1 ? "stationary" :
             local->strategy == 2 ? "serving_only" : "wardrive");
    cf_send_message(caph, buf, MSGFLAG_INFO);

    /* Query modem and SIM status at startup for diagnostics */
    {
        char status_resp[1024];
        int n;

        /* SIM status */
        n = at_command_t(local, "AT+CPIN?", status_resp, sizeof(status_resp), 3000);
        if (n > 0) {
            char *cpin = strstr(status_resp, "+CPIN:");
            if (cpin) {
                char *val = cpin + 6;
                while (*val == ' ') val++;
                char *end = strchr(val, '\n');
                if (end) *end = '\0';
                snprintf(buf, STATUS_MAX, "%s SIM: %s", local->name, val);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            } else if (strstr(status_resp, "ERROR")) {
                snprintf(buf, STATUS_MAX, "%s SIM: not present or not accessible",
                         local->name);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
        }

        /* Registration status */
        n = at_command_t(local, "AT+CEREG?", status_resp, sizeof(status_resp), 3000);
        if (n > 0) {
            char *cereg = strstr(status_resp, "+CEREG:");
            if (cereg) {
                /* +CEREG: <n>,<stat>[,<tac>,<ci>,...] */
                char *body = cereg + 7;
                while (*body == ' ') body++;
                long stat = 0;
                char *comma = strchr(body, ',');
                if (comma) {
                    parse_int(comma + 1, &stat);
                }
                const char *stat_str;
                switch (stat) {
                    case 0: stat_str = "not registered, not searching"; break;
                    case 1: stat_str = "registered, home"; break;
                    case 2: stat_str = "not registered, searching"; break;
                    case 3: stat_str = "registration denied"; break;
                    case 4: stat_str = "unknown"; break;
                    case 5: stat_str = "registered, roaming"; break;
                    default: stat_str = "unknown"; break;
                }
                snprintf(buf, STATUS_MAX, "%s EPS registration: %s (%ld)",
                         local->name, stat_str, stat);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
        }

        /* Current operator
         * +COPS: <mode>[,<format>,<oper>[,<AcT>]]
         * mode: 0=auto, 1=manual, 2=deregistered, 3=set_format, 4=manual/auto */
        n = at_command_t(local, "AT+COPS?", status_resp, sizeof(status_resp), 3000);
        if (n > 0) {
            char *cops = strstr(status_resp, "+COPS:");
            if (cops) {
                char *body = cops + 6;
                while (*body == ' ') body++;
                long cops_mode = -1;
                char *cops_end;
                long cops_val = strtol(body, &cops_end, 10);
                if (cops_end != body)
                    cops_mode = cops_val;

                const char *mode_str;
                switch (cops_mode) {
                    case 0: mode_str = "automatic"; break;
                    case 1: mode_str = "manual"; break;
                    case 2: mode_str = "deregistered"; break;
                    case 3: mode_str = "set format only"; break;
                    case 4: mode_str = "manual/automatic"; break;
                    default: mode_str = "unknown"; break;
                }

                /* Extract operator name if present (quoted string) */
                char *quote1 = strchr(body, '"');
                if (quote1) {
                    char *quote2 = strchr(quote1 + 1, '"');
                    if (quote2) {
                        *quote2 = '\0';
                        snprintf(buf, STATUS_MAX, "%s operator: %s (COPS mode %ld: %s)",
                                 local->name, quote1 + 1, cops_mode, mode_str);
                    } else {
                        snprintf(buf, STATUS_MAX, "%s operator: COPS mode %ld (%s)",
                                 local->name, cops_mode, mode_str);
                    }
                } else {
                    snprintf(buf, STATUS_MAX, "%s operator: none (COPS mode %ld: %s)",
                             local->name, cops_mode, mode_str);
                }
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
        }

        /* IMSI and ICCID — log at DEBUG (sensitive) */
        if (local->debug) {
            n = at_command_t(local, "AT+CIMI", status_resp, sizeof(status_resp), 3000);
            if (n > 0 && strstr(status_resp, "OK")) {
                char *saveptr = NULL;
                char *line = strtok_r(status_resp, "\n", &saveptr);
                while (line) {
                    while (*line == ' ') line++;
                    if (*line && strcmp(line, "OK") != 0 && strncmp(line, "+CME", 4) != 0) {
                        snprintf(buf, STATUS_MAX, "%s IMSI: %s", local->name, line);
                        cf_send_message(caph, buf, MSGFLAG_DEBUG);
                        break;
                    }
                    line = strtok_r(NULL, "\n", &saveptr);
                }
            }

            /* Try common ICCID commands */
            n = at_command_t(local, "AT+ICCID", status_resp, sizeof(status_resp), 3000);
            if (n <= 0 || strstr(status_resp, "ERROR"))
                n = at_command_t(local, "AT+QCCID", status_resp, sizeof(status_resp), 3000);
            if (n > 0 && !strstr(status_resp, "ERROR")) {
                char *iccid = strstr(status_resp, "ICCID:");
                if (!iccid) iccid = strstr(status_resp, "QCCID:");
                if (iccid) {
                    char *val = strchr(iccid, ':') + 1;
                    while (*val == ' ' || *val == '"') val++;
                    char *end = val;
                    while (*end && *end != '"' && *end != '\n' && *end != '\r') end++;
                    *end = '\0';
                    snprintf(buf, STATUS_MAX, "%s ICCID: %s", local->name, val);
                    cf_send_message(caph, buf, MSGFLAG_DEBUG);
                }
            }
        }
    }

    return 1;
}

/*
 * Capture thread — runs scan loop on configured intervals.
 *
 * This runs in its own thread, isolated from the framework IO thread.
 * We can block on serial reads safely.
 */
void capture_thread(kis_capture_handler_t *caph) {
    local_cell_t *local = (local_cell_t *)caph->userdata;
    char resp[AT_RESP_MAX];
    char errstr[ERRBUF_MAX];
    struct timeval tv;

    /* Static array for JSON observations */
    static char json_obs[MAX_OBS_PER_RESP][JSON_BUF_MAX];

    while (!caph->shutdown) {
        unsigned long now = now_ms();
        int did_work = 0;

        /* --- Serving cell scan --- */
        if (local->serving_interval_ms > 0 &&
            (now - local->serving_last_ms) >= local->serving_interval_ms) {

            local->serving_last_ms = now;

            int n = 0;
            int obs_count = 0;

            if (local->has_qeng) {
                n = at_command_t(local,"AT+QENG=\"servingcell\"",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_qeng_serving(resp, json_obs, MAX_OBS_PER_RESP);
            } else if (local->has_rfsts) {
                n = at_command_t(local,"AT#RFSTS",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_rfsts(resp, json_obs, MAX_OBS_PER_RESP);

                /* #346: Inject cached PCI from prior CSURVC/MONI observations */
                if (obs_count > 0 && local->cached_pci > 0) {
                    for (int i = 0; i < obs_count; i++) {
                        if (strstr(json_obs[i], "\"pci\"") == NULL) {
                            size_t len = strlen(json_obs[i]);
                            if (len > 1 && json_obs[i][len - 1] == '}') {
                                json_obs[i][len - 1] = '\0';
                                snprintf(json_obs[i] + len - 1,
                                         JSON_BUF_MAX - len,
                                         ",\"pci\":%ld}", local->cached_pci);
                            }
                        }
                    }
                }

                /* Cache serving cell identity for CSURVC TAC fix (#345)
                 * and future PCI enrichment (#346) */
                if (obs_count > 0) {
                    /* Extract tac and cell_id from the JSON we just built */
                    for (int i = 0; i < obs_count; i++) {
                        char *tac_p = strstr(json_obs[i], "\"tac\":");
                        char *cid_p = strstr(json_obs[i], "\"cell_id\":");
                        if (tac_p && cid_p) {
                            unsigned long t = strtoul(tac_p + 6, NULL, 10);
                            unsigned long c = strtoul(cid_p + 10, NULL, 10);
                            if (t > 0 && c > 0) {
                                local->cached_tac = t;
                                local->cached_cell_id = c;
                                local->cached_valid = 1;
                            }
                        }
                    }
                }
            } else if (local->has_servinfo) {
                n = at_command_t(local,"AT#SERVINFO",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_servinfo(resp, json_obs, MAX_OBS_PER_RESP);
            } else if (local->has_gstatus) {
                n = at_command_t(local,"AT!GSTATUS?",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_gstatus(resp, local->serial_fd,
                                              json_obs, MAX_OBS_PER_RESP);
            } else if (local->has_scellinfo) {
                n = at_command_t(local,"AT^SCELLINFO",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_scellinfo(resp, json_obs, MAX_OBS_PER_RESP);
            }

            if (local->debug && obs_count > 0) {
                snprintf(errstr, ERRBUF_MAX, "%s serving: %d observations",
                         local->name, obs_count);
                cf_send_message(caph, errstr, MSGFLAG_DEBUG);
            }

            const char *serving_origin =
                local->has_qeng      ? "AT+QENG=servingcell" :
                local->has_rfsts     ? "AT#RFSTS" :
                local->has_servinfo  ? "AT#SERVINFO" :
                local->has_gstatus   ? "AT!GSTATUS?" :
                local->has_scellinfo ? "AT^SCELLINFO" : "at";

            for (int i = 0; i < obs_count; i++) {
                inject_prov(json_obs[i], JSON_BUF_MAX, local->modem_imei,
                            serving_origin);
                gettimeofday(&tv, NULL);
                int r = cf_send_json(caph, NULL, 0, NULL, NULL,
                                     tv, "CellModem", json_obs[i]);
                if (r < 0) {
                    snprintf(errstr, ERRBUF_MAX,
                             "%s failed to send JSON to Kismet", local->name);
                    cf_send_error(caph, 0, errstr);
                    goto done;
                }
                if (r == 0) {
                    cf_handler_wait_ringbuffer(caph);
                }
            }

            if (n < 0) {
                snprintf(errstr, ERRBUF_MAX, "%s serial error on serving cell query",
                         local->name);
                cf_send_error(caph, 0, errstr);
                goto done;
            }

            did_work = 1;
        }

        /* --- Neighbor cell scan (Quectel QENG, Telit MONI, Sierra LTEINFO, or Orbic QCRSRP) --- */
        if ((local->has_qeng || local->has_moni || local->has_gstatus || local->has_qcrsrp) &&
            local->neighbor_interval_ms > 0 &&
            (now - local->neighbor_last_ms) >= local->neighbor_interval_ms) {

            local->neighbor_last_ms = now;

            int obs_count = 0;

            if (local->has_qeng) {
                int n = at_command_t(local,"AT+QENG=\"neighbourcell\"",
                                   resp, sizeof(resp), 10000);
                if (n > 0)
                    obs_count = parse_qeng_neighbor(resp, json_obs, MAX_OBS_PER_RESP);

            } else if (local->has_moni) {
                /* AT#MONI=1 (intra-freq) + AT#MONI=2 (inter-freq) */
                for (int mode = 1; mode <= 2; mode++) {
                    char moni_cmd[16];
                    snprintf(moni_cmd, sizeof(moni_cmd), "AT#MONI=%d", mode);
                    at_command_t(local,moni_cmd, resp, sizeof(resp), 3000);

                    int n = at_command_t(local,"AT#MONI",
                                       resp, sizeof(resp), 3000);
                    if (n > 0) {
                        int cnt = parse_moni(resp, json_obs + obs_count,
                                             MAX_OBS_PER_RESP - obs_count, 0);
                        obs_count += cnt;
                    }
                }
                /* Reset to mode 0 for next serving cell query */
                at_command_t(local,"AT#MONI=0", resp, sizeof(resp), 2000);

            } else if (local->has_gstatus) {
                /* Sierra AT!LTEINFO? — includes serving + intra/inter neighbors.
                 * Need the serving EARFCN for intra-freq neighbors. */
                int n = at_command_t(local,"AT!LTEINFO?",
                                   resp, sizeof(resp), 5000);
                if (n > 0 && strstr(resp, "Serving:") &&
                    !strstr(resp, "Not Available")) {
                    /* Extract serving EARFCN from the serving data line */
                    long srv_earfcn = 0;
                    char *srv = strstr(resp, "Serving:");
                    if (srv) {
                        char *nl = strchr(srv, '\n');
                        if (nl) {
                            char *dl = nl + 1;
                            while (*dl == ' ') dl++;
                            /* First token is EARFCN — copy to buffer */
                            char earfcn_buf[16];
                            int ebi = 0;
                            while (dl[ebi] && dl[ebi] != ' ' && dl[ebi] != '\t'
                                   && ebi < (int)sizeof(earfcn_buf) - 1)
                                earfcn_buf[ebi] = dl[ebi], ebi++;
                            earfcn_buf[ebi] = '\0';
                            parse_int(earfcn_buf, &srv_earfcn);
                        }
                    }
                    obs_count = parse_lteinfo_neighbors(resp, srv_earfcn,
                                                        json_obs, MAX_OBS_PER_RESP);
                }
            } else if (local->has_qcrsrp) {
                /* AT$QCRSRP? — returns all visible cells across all bands.
                 * Most useful in COPS=2 (deregistered) mode for passive scanning. */
                int n = at_command_t(local,"AT$QCRSRP?",
                                   resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_qcrsrp(resp, json_obs, MAX_OBS_PER_RESP);
            }

            if (local->debug && obs_count > 0) {
                snprintf(errstr, ERRBUF_MAX, "%s observation: %d cells",
                         local->name, obs_count);
                cf_send_message(caph, errstr, MSGFLAG_DEBUG);
            }

            const char *neighbor_origin =
                local->has_qeng    ? "AT+QENG=neighbourcell" :
                local->has_moni    ? "AT#MONI" :
                local->has_gstatus ? "AT!LTEINFO?" :
                local->has_qcrsrp  ? "AT$QCRSRP?" : "at";

            for (int i = 0; i < obs_count; i++) {
                inject_prov(json_obs[i], JSON_BUF_MAX, local->modem_imei,
                            neighbor_origin);
                gettimeofday(&tv, NULL);
                int r = cf_send_json(caph, NULL, 0, NULL, NULL,
                                     tv, "CellModem", json_obs[i]);
                if (r < 0) {
                    snprintf(errstr, ERRBUF_MAX,
                             "%s failed to send JSON to Kismet", local->name);
                    cf_send_error(caph, 0, errstr);
                    goto done;
                }
                if (r == 0) {
                    cf_handler_wait_ringbuffer(caph);
                }
            }

            did_work = 1;
        }

        /* --- Full band scan (AT+QSCAN or AT#CSURVC) --- */
        if ((local->has_qscan || local->has_csurvc) &&
            local->fullscan_interval_ms > 0 &&
            (now - local->fullscan_last_ms) >= local->fullscan_interval_ms) {

            int n = 0;
            int obs_count = 0;

            if (local->has_qscan) {
                snprintf(errstr, ERRBUF_MAX, "%s starting full band scan (AT+QSCAN=3,1)",
                         local->name);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                /* QSCAN can take up to 2 minutes */
                n = at_command_t(local,"AT+QSCAN=3,1",
                               resp, sizeof(resp), 120000);
                if (n > 0)
                    obs_count = parse_qscan(resp, json_obs, MAX_OBS_PER_RESP);

            } else if (local->has_csurvc) {
                snprintf(errstr, ERRBUF_MAX, "%s starting network survey (AT#CSURVC)",
                         local->name);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                /* CSURVC can take up to 3 minutes */
                n = at_command_t(local,"AT#CSURVC",
                               resp, sizeof(resp), 180000);
                if (n > 0)
                    obs_count = parse_csurvc(resp, json_obs, MAX_OBS_PER_RESP);
            }

            /* Update timestamp AFTER scan completes — these scans block
             * for 30s-3min, so using the pre-scan 'now' would cause the
             * next iteration to immediately re-trigger */
            local->fullscan_last_ms = now_ms();

            /* #345: Fix CSURVC TAC=0 — substitute cached serving TAC
             * when a survey observation has TAC=0 and a matching CellID */
            if (obs_count > 0 && local->cached_valid) {
                for (int i = 0; i < obs_count; i++) {
                    char *tac_p = strstr(json_obs[i], "\"tac\":0,");
                    if (!tac_p) tac_p = strstr(json_obs[i], "\"tac\":0}");
                    if (tac_p) {
                        /* Check if this observation's cell_id matches cached */
                        char cid_needle[32];
                        snprintf(cid_needle, sizeof(cid_needle),
                                 "\"cell_id\":%lu", local->cached_cell_id);
                        if (strstr(json_obs[i], cid_needle)) {
                            /* Replace tac:0 with cached TAC */
                            char new_tac[32];
                            snprintf(new_tac, sizeof(new_tac),
                                     "\"tac\":%lu", local->cached_tac);
                            /* Rebuild the JSON string with corrected TAC */
                            char fixed[JSON_BUF_MAX];
                            size_t prefix_len = tac_p - json_obs[i];
                            memcpy(fixed, json_obs[i], prefix_len);
                            /* Find end of "tac":0 */
                            char *old_end = tac_p + 5; /* skip "tac":0 */
                            int new_tac_len = strlen(new_tac);
                            memcpy(fixed + prefix_len, new_tac, new_tac_len);
                            strcpy(fixed + prefix_len + new_tac_len, old_end);
                            strncpy(json_obs[i], fixed, JSON_BUF_MAX - 1);
                            json_obs[i][JSON_BUF_MAX - 1] = '\0';
                        }
                    }
                }
            }

            /* #346: Cache PCI from CSURVC serving cell for RFSTS enrichment.
             * CSURVC 11-field lines have PCI — extract from first observation
             * that matches the cached serving cell_id. */
            if (obs_count > 0 && local->cached_valid) {
                char cid_needle[32];
                snprintf(cid_needle, sizeof(cid_needle),
                         "\"cell_id\":%lu", local->cached_cell_id);
                for (int i = 0; i < obs_count; i++) {
                    if (strstr(json_obs[i], cid_needle)) {
                        char *pci_p = strstr(json_obs[i], "\"pci\":");
                        if (pci_p) {
                            long pv = strtol(pci_p + 6, NULL, 10);
                            if (pv > 0)
                                local->cached_pci = pv;
                        }
                        break;
                    }
                }
            }

            if (local->debug && obs_count > 0) {
                snprintf(errstr, ERRBUF_MAX, "%s full scan: %d observations",
                         local->name, obs_count);
                cf_send_message(caph, errstr, MSGFLAG_DEBUG);

                const char *fullscan_origin =
                    local->has_qscan ? "AT+QSCAN=3,1" : "AT#CSURVC";

                for (int i = 0; i < obs_count; i++) {
                    inject_prov(json_obs[i], JSON_BUF_MAX, local->modem_imei,
                                fullscan_origin);
                    gettimeofday(&tv, NULL);
                    int r = cf_send_json(caph, NULL, 0, NULL, NULL,
                                         tv, "CellModem", json_obs[i]);
                    if (r < 0) {
                        snprintf(errstr, ERRBUF_MAX,
                                 "%s failed to send JSON to Kismet", local->name);
                        cf_send_error(caph, 0, errstr);
                        goto done;
                    }
                    if (r == 0) {
                        cf_handler_wait_ringbuffer(caph);
                    }
                }
            }

            did_work = 1;
        }

        /* Avoid busy loop — sleep 250ms if no work was done */
        if (!did_work) {
            usleep(250000);
        }
    }

done:
    serial_close(&local->serial_fd);
    cf_handler_spindown(caph);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    local_cell_t local = {
        .serial_fd = -1,
        .device_path = NULL,
        .modem_imei = NULL,
        .modem_firmware = NULL,
        .modem_model = NULL,
        .name = NULL,
        .serving_interval_ms = 2000,
        .neighbor_interval_ms = 5000,
        .fullscan_interval_ms = 0,
        .serving_last_ms = 0,
        .neighbor_last_ms = 0,
        .fullscan_last_ms = 0,
        .vendor = VENDOR_UNKNOWN,
        .has_qeng = 0,
        .has_qscan = 0,
        .has_rfsts = 0,
        .has_servinfo = 0,
        .has_moni = 0,
        .has_csurvc = 0,
        .has_gstatus = 0,
        .has_lteinfo = 0,
        .has_nrinfo = 0,
        .has_scellinfo = 0,
        .has_qcrsrp = 0,
        .cached_tac = 0,
        .cached_cell_id = 0,
        .cached_pci = -1,
        .cached_valid = 0,
        .strategy = 0,
        .debug = 0,
        .transcript_fd = -1,
    };

    kis_capture_handler_t *caph = cf_handler_init("cellat");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    cf_handler_set_userdata(caph, &local);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_capture_cb(caph, capture_thread);

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture */
    cf_handler_remote_capture(caph);

    /* Jail filesystem — serial devices need to be accessible */
    cf_jail_filesystem(caph);

    /* Drop most capabilities but keep what we need for serial */
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    /* Cleanup */
    if (local.serial_fd >= 0)
        close(local.serial_fd);
    if (local.transcript_fd >= 0)
        close(local.transcript_fd);
    free(local.device_path);
    free(local.modem_imei);
    free(local.modem_firmware);
    free(local.modem_model);
    free(local.name);

    return 0;
}
