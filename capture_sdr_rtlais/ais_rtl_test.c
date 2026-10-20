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

    Copyright (C) 2026 by Mike Kershaw <dragorn@kismetwireless.net>
*/

/*
 * Standalone AIS receiver for testing the AIS demodulator outside of Kismet.
 *
 * Reads from an rtlsdr (or a cu8 recording at 288k centered on 162MHz),
 * demodulates both AIS channels, and prints each frame as a timestamped
 * AIVDM sentence with a short decode of the common fields to the terminal
 * and to a log file.
 *
 *   ais_rtl_test [-d index|serial] [-g gain] [-p ppm] [-T] [-l logfile] [-r file.cu8]
 *
 * This tool and ais_demod.c/.h have no Kismet dependencies; build with
 * Makefile.ais_rtl_test, which defines HAVE_LIBRTLSDR_BIAS_T when the
 * installed librtlsdr supports bias-tee control.
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <rtl-sdr.h>

#include "ais_demod.h"

#define BUF_LENGTH      (4 * 16384)
#define STATS_INTERVAL  30

static volatile sig_atomic_t do_exit = 0;

static FILE *logfile = NULL;
static unsigned int seq_id = 0;
static unsigned long type_counts[64];

static void sighandler(int signum) {
    (void) signum;
    do_exit = 1;
}

/* MSB-first bit field access; reads past the end return 0 */
static uint32_t get_uint(const uint8_t *buf, size_t len, size_t start, size_t nbits) {
    uint32_t v = 0;
    size_t i, b;

    for (i = 0; i < nbits; i++) {
        b = start + i;
        v <<= 1;
        if (b / 8 < len && (buf[b / 8] >> (7 - (b % 8))) & 1)
            v |= 1;
    }

    return v;
}

static int32_t get_int(const uint8_t *buf, size_t len, size_t start, size_t nbits) {
    uint32_t v = get_uint(buf, len, start, nbits);

    if (nbits < 32 && (v & (1U << (nbits - 1))))
        v |= ~((1U << nbits) - 1);

    return (int32_t) v;
}

static int has_bits(size_t len, size_t start, size_t nbits) {
    return start + nbits <= len * 8;
}

/* 6-bit text, '@' terminated, trailing spaces trimmed */
static void get_string(const uint8_t *buf, size_t len, size_t start, size_t nbits,
        char *out, size_t out_len) {
    size_t i, o = 0;
    uint32_t v;

    for (i = 0; i + 6 <= nbits && has_bits(len, start + i, 6) && o + 1 < out_len; i += 6) {
        v = get_uint(buf, len, start + i, 6);
        if (v == 0)
            break;
        out[o++] = (char) (v < 32 ? v + 64 : v);
    }

    while (o > 0 && out[o - 1] == ' ')
        o--;

    out[o] = 0;
}

static int append(char *out, size_t out_len, size_t *pos, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static int append(char *out, size_t out_len, size_t *pos, const char *fmt, ...) {
    va_list ap;
    int r;

    if (*pos >= out_len)
        return 0;

    va_start(ap, fmt);
    r = vsnprintf(out + *pos, out_len - *pos, fmt, ap);
    va_end(ap);

    if (r > 0)
        *pos += ((size_t) r < out_len - *pos) ? (size_t) r : out_len - *pos - 1;

    return r;
}

static void append_position(const uint8_t *buf, size_t len, char *out, size_t out_len,
        size_t *pos, size_t lon_off, size_t lon_len, size_t lat_off, size_t lat_len,
        double divisor) {
    double lon, lat;

    if (!has_bits(len, lat_off, lat_len))
        return;

    lon = get_int(buf, len, lon_off, lon_len) / divisor;
    lat = get_int(buf, len, lat_off, lat_len) / divisor;

    if (lon < -180 || lon > 180 || lat < -90 || lat > 90)
        append(out, out_len, pos, " pos n/a");
    else
        append(out, out_len, pos, " pos %.5f,%.5f", lat, lon);
}

static void append_sog_cog_hdg(const uint8_t *buf, size_t len, char *out, size_t out_len,
        size_t *pos, size_t sog_off, size_t cog_off, size_t hdg_off) {
    uint32_t sog = get_uint(buf, len, sog_off, 10);
    uint32_t cog = get_uint(buf, len, cog_off, 12);

    if (sog != 1023)
        append(out, out_len, pos, " sog %.1fkn", sog / 10.0);

    if (cog < 3600)
        append(out, out_len, pos, " cog %.1f", cog / 10.0);

    if (hdg_off != 0) {
        uint32_t hdg = get_uint(buf, len, hdg_off, 9);
        if (hdg < 360)
            append(out, out_len, pos, " hdg %u", hdg);
    }
}

/* Short human-readable summary of the common message types */
static void summarize(const uint8_t *buf, size_t len, char *out, size_t out_len) {
    size_t pos = 0;
    uint32_t type, mmsi;
    char str[128];

    out[0] = 0;

    if (!has_bits(len, 0, 38)) {
        append(out, out_len, &pos, "short frame (%zu bytes)", len);
        return;
    }

    type = get_uint(buf, len, 0, 6);
    mmsi = get_uint(buf, len, 8, 30);

    append(out, out_len, &pos, "type %2u mmsi %09u", type, mmsi);

    switch (type) {
        case 1:
        case 2:
        case 3:
            append(out, out_len, &pos, " [Class A pos] status %u", get_uint(buf, len, 38, 4));
            append_position(buf, len, out, out_len, &pos, 61, 28, 89, 27, 600000.0);
            append_sog_cog_hdg(buf, len, out, out_len, &pos, 50, 116, 128);
            break;

        case 4:
        case 11:
            append(out, out_len, &pos, " [%s] utc %04u-%02u-%02u %02u:%02u:%02u",
                    type == 4 ? "Base station" : "UTC response",
                    get_uint(buf, len, 38, 14), get_uint(buf, len, 52, 4),
                    get_uint(buf, len, 56, 5), get_uint(buf, len, 61, 5),
                    get_uint(buf, len, 66, 6), get_uint(buf, len, 72, 6));
            append_position(buf, len, out, out_len, &pos, 79, 28, 107, 27, 600000.0);
            break;

        case 5:
            append(out, out_len, &pos, " [Class A static]");
            get_string(buf, len, 70, 42, str, sizeof(str));
            append(out, out_len, &pos, " callsign '%s'", str);
            get_string(buf, len, 112, 120, str, sizeof(str));
            append(out, out_len, &pos, " name '%s'", str);
            append(out, out_len, &pos, " shiptype %u imo %u",
                    get_uint(buf, len, 232, 8), get_uint(buf, len, 40, 30));
            get_string(buf, len, 302, 120, str, sizeof(str));
            append(out, out_len, &pos, " dest '%s'", str);
            break;

        case 9:
            append(out, out_len, &pos, " [SAR aircraft] alt %um", get_uint(buf, len, 38, 12));
            append_position(buf, len, out, out_len, &pos, 61, 28, 89, 27, 600000.0);
            break;

        case 18:
        case 19:
            append(out, out_len, &pos, " [Class B pos]");
            append_position(buf, len, out, out_len, &pos, 57, 28, 85, 27, 600000.0);
            append_sog_cog_hdg(buf, len, out, out_len, &pos, 46, 112, 124);
            if (type == 19) {
                get_string(buf, len, 143, 120, str, sizeof(str));
                append(out, out_len, &pos, " name '%s' shiptype %u", str,
                        get_uint(buf, len, 263, 8));
            }
            break;

        case 21:
            append(out, out_len, &pos, " [AtoN] atontype %u", get_uint(buf, len, 38, 5));
            get_string(buf, len, 43, 120, str, sizeof(str));
            append(out, out_len, &pos, " name '%s'", str);
            append_position(buf, len, out, out_len, &pos, 164, 28, 192, 27, 600000.0);
            if (has_bits(len, 269, 1) && get_uint(buf, len, 269, 1))
                append(out, out_len, &pos, " virtual");
            break;

        case 24:
            if (get_uint(buf, len, 38, 2) == 0) {
                get_string(buf, len, 40, 120, str, sizeof(str));
                append(out, out_len, &pos, " [Class B static A] name '%s'", str);
            } else {
                append(out, out_len, &pos, " [Class B static B] shiptype %u",
                        get_uint(buf, len, 40, 8));
                get_string(buf, len, 48, 18, str, sizeof(str));
                append(out, out_len, &pos, " vendor '%s'", str);
                get_string(buf, len, 90, 42, str, sizeof(str));
                append(out, out_len, &pos, " callsign '%s'", str);
            }
            break;

        case 27:
            append(out, out_len, &pos, " [Long range]");
            append_position(buf, len, out, out_len, &pos, 44, 18, 62, 17, 600.0);
            break;

        default:
            break;
    }
}

/* Encode as NMEA AIVDM sentences, 60 armored characters per sentence; the
 * sentences are written to out separated by newlines */
static void to_aivdm(const uint8_t *buf, size_t len, char channel, char *out, size_t out_len) {
    char armor[(AIS_MAX_PAYLOAD_BYTES * 8 + 5) / 6 + 1];
    char body[128];
    size_t nbits = len * 8;
    size_t nchars = (nbits + 5) / 6;
    size_t fill = nchars * 6 - nbits;
    size_t i, s, nsent, pos = 0;
    uint8_t cs;
    char seq[4] = "";
    char *c;

    for (i = 0; i < nchars; i++) {
        uint32_t v = get_uint(buf, len, i * 6, 6) + 48;
        if (v > 87)
            v += 8;
        armor[i] = (char) v;
    }
    armor[nchars] = 0;

    nsent = nchars == 0 ? 1 : (nchars + 59) / 60;

    if (nsent > 1)
        snprintf(seq, sizeof(seq), "%u", seq_id++ % 10);

    out[0] = 0;

    for (s = 0; s < nsent; s++) {
        snprintf(body, sizeof(body), "AIVDM,%zu,%zu,%s,%c,%.60s,%zu",
                nsent, s + 1, seq, channel, armor + s * 60,
                s == nsent - 1 ? fill : (size_t) 0);

        cs = 0;
        for (c = body; *c; c++)
            cs ^= (uint8_t) *c;

        append(out, out_len, &pos, "%s!%s*%02X", s > 0 ? "\n" : "", body, cs);
    }
}

static void emit(const char *line) {
    fputs(line, stdout);
    fputc('\n', stdout);
    fflush(stdout);

    if (logfile != NULL) {
        fputs(line, logfile);
        fputc('\n', logfile);
        fflush(logfile);
    }
}

static void frame_cb(void *ctx, int channel, const uint8_t *payload,
        size_t payload_len, float level_dbfs) {
    char ts[64];
    char hex[AIS_MAX_PAYLOAD_BYTES * 2 + 1];
    char aivdm[512];
    char summary[512];
    char line[1536];
    struct timeval tv;
    struct tm tm;
    char chan = channel == AIS_CHANNEL_A ? 'A' : 'B';
    char *sent, *saveptr = NULL;
    size_t i;

    (void) ctx;

    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);

    for (i = 0; i < payload_len && i < AIS_MAX_PAYLOAD_BYTES; i++)
        snprintf(hex + i * 2, 3, "%02x", payload[i]);
    hex[i * 2] = 0;

    if (payload_len > 0)
        type_counts[(payload[0] >> 2) & 0x3F]++;

    summarize(payload, payload_len, summary, sizeof(summary));
    to_aivdm(payload, payload_len, chan, aivdm, sizeof(aivdm));

    snprintf(line, sizeof(line), "%s.%03dZ ch %c %6.1f dBFS  %s",
            ts, (int) (tv.tv_usec / 1000), chan, level_dbfs, summary);
    emit(line);

    for (sent = strtok_r(aivdm, "\n", &saveptr); sent != NULL;
            sent = strtok_r(NULL, "\n", &saveptr)) {
        snprintf(line, sizeof(line), "    %s", sent);
        emit(line);
    }

    snprintf(line, sizeof(line), "    hex %s", hex);
    emit(line);
}

static void print_stats(ais_demod_t *demod, time_t start) {
    char line[512];
    size_t pos = 0;
    int t;

    snprintf(line, sizeof(line),
            "# stats %lds: A %lu frames / %lu crc fail, B %lu frames / %lu crc fail",
            (long) (time(NULL) - start),
            ais_demod_frames(demod, AIS_CHANNEL_A), ais_demod_crc_errors(demod, AIS_CHANNEL_A),
            ais_demod_frames(demod, AIS_CHANNEL_B), ais_demod_crc_errors(demod, AIS_CHANNEL_B));
    emit(line);

    line[0] = 0;
    append(line, sizeof(line), &pos, "# types:");
    for (t = 0; t < 64; t++) {
        if (type_counts[t])
            append(line, sizeof(line), &pos, " %d=%lu", t, type_counts[t]);
    }
    emit(line);
}

static int nearest_gain(rtlsdr_dev_t *dev, int target) {
    int count, i, nearest, *gains;

    count = rtlsdr_get_tuner_gains(dev, NULL);
    if (count <= 0)
        return target;

    gains = malloc(sizeof(int) * count);
    if (gains == NULL)
        return target;

    count = rtlsdr_get_tuner_gains(dev, gains);
    nearest = gains[0];
    for (i = 0; i < count; i++) {
        if (abs(target - gains[i]) < abs(target - nearest))
            nearest = gains[i];
    }
    free(gains);

    return nearest;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Standalone AIS receiver test tool (Kismet AIS demodulator)\n\n"
            "usage: %s [options]\n"
            "  -d <index|serial>   rtlsdr device (default 0)\n"
            "  -g <gain>           tuner gain in dB (default auto)\n"
            "  -p <ppm>            frequency correction in ppm (default 0)\n"
            "  -T                  enable bias-tee\n"
            "  -l <file>           log file (default ais_rtl_test.log, '-' for none)\n"
            "  -r <file>           read cu8 IQ at 288k centered on 162MHz instead of a\n"
            "                      device ('-' for stdin)\n"
            "  -s <seconds>        stats interval (default %d, 0 to disable)\n",
            argv0, STATS_INTERVAL);
}

int main(int argc, char *argv[]) {
    const char *dev_str = "0";
    const char *log_path = "ais_rtl_test.log";
    const char *read_path = NULL;
    double gain = -1;
    int ppm = 0;
    int biast = 0;
    int stats_interval = STATS_INTERVAL;
    int opt, r, dev_index, n_read;
    rtlsdr_dev_t *dev = NULL;
    ais_demod_t *demod;
    FILE *infile = NULL;
    uint8_t *buf;
    size_t got;
    time_t start, last_stats;
    struct sigaction sa;
    char line[256];

    while ((opt = getopt(argc, argv, "d:g:p:Tl:r:s:h")) != -1) {
        switch (opt) {
            case 'd': dev_str = optarg; break;
            case 'g': gain = atof(optarg); break;
            case 'p': ppm = atoi(optarg); break;
            case 'T': biast = 1; break;
            case 'l': log_path = optarg; break;
            case 'r': read_path = optarg; break;
            case 's': stats_interval = atoi(optarg); break;
            default:
                usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }

    if (strcmp(log_path, "-") != 0) {
        logfile = fopen(log_path, "a");
        if (logfile == NULL) {
            fprintf(stderr, "failed to open log file %s: %s\n", log_path, strerror(errno));
            return 1;
        }
    }

    buf = malloc(BUF_LENGTH);
    demod = ais_demod_new(frame_cb, NULL);
    if (buf == NULL || demod == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (read_path != NULL) {
        if (strcmp(read_path, "-") == 0) {
            infile = stdin;
        } else if ((infile = fopen(read_path, "rb")) == NULL) {
            fprintf(stderr, "failed to open %s: %s\n", read_path, strerror(errno));
            return 1;
        }

        snprintf(line, sizeof(line), "# reading cu8 IQ from %s", read_path);
        emit(line);
    } else {
        dev_index = rtlsdr_get_index_by_serial(dev_str);
        if (dev_index < 0)
            dev_index = atoi(dev_str);

        if (rtlsdr_get_device_count() == 0) {
            fprintf(stderr, "no rtlsdr devices found\n");
            return 1;
        }

        if (rtlsdr_open(&dev, dev_index) < 0) {
            fprintf(stderr, "failed to open rtlsdr device %s\n", dev_str);
            return 1;
        }

        if (gain < 0) {
            rtlsdr_set_tuner_gain_mode(dev, 0);
        } else {
            int g = nearest_gain(dev, (int) (gain * 10));
            rtlsdr_set_tuner_gain_mode(dev, 1);
            if (rtlsdr_set_tuner_gain(dev, g) < 0)
                fprintf(stderr, "WARNING: failed to set gain %.1f\n", g / 10.0);
            gain = g / 10.0;
        }

        if (ppm != 0 && rtlsdr_set_freq_correction(dev, ppm) < 0)
            fprintf(stderr, "WARNING: failed to set ppm correction %d\n", ppm);

        if (rtlsdr_set_center_freq(dev, AIS_DEMOD_CENTER_FREQ) < 0 ||
                rtlsdr_set_sample_rate(dev, AIS_DEMOD_SAMPLE_RATE) < 0) {
            fprintf(stderr, "failed to tune rtlsdr device\n");
            rtlsdr_close(dev);
            return 1;
        }

        if (biast) {
#ifdef HAVE_LIBRTLSDR_BIAS_T
            if (rtlsdr_set_bias_tee(dev, 1) < 0)
                fprintf(stderr, "WARNING: failed to enable bias-tee\n");
#else
            fprintf(stderr, "WARNING: bias-tee not supported by this librtlsdr build\n");
#endif
        }

        rtlsdr_reset_buffer(dev);

        snprintf(line, sizeof(line),
                "# rtlsdr %d (%s) @ %.3f MHz, %d S/s, gain %s, ppm %d; channels A 161.975 B 162.025",
                dev_index, rtlsdr_get_device_name(dev_index),
                AIS_DEMOD_CENTER_FREQ / 1e6, AIS_DEMOD_SAMPLE_RATE,
                gain < 0 ? "auto" : "manual", ppm);
        emit(line);
    }

    if (logfile != NULL)
        fprintf(stderr, "# logging to %s\n", log_path);

    start = last_stats = time(NULL);

    while (!do_exit) {
        if (infile != NULL) {
            got = fread(buf, 1, BUF_LENGTH, infile);
            if (got == 0)
                break;
        } else {
            r = rtlsdr_read_sync(dev, buf, BUF_LENGTH, &n_read);
            if (r < 0) {
                fprintf(stderr, "rtlsdr read failed (%d)\n", r);
                break;
            }
            got = (size_t) n_read;
        }

        ais_demod_process_cu8(demod, buf, got);

        if (stats_interval > 0 && time(NULL) - last_stats >= stats_interval) {
            print_stats(demod, start);
            last_stats = time(NULL);
        }
    }

    print_stats(demod, start);

    if (dev != NULL)
        rtlsdr_close(dev);
    if (infile != NULL && infile != stdin)
        fclose(infile);
    if (logfile != NULL)
        fclose(logfile);

    ais_demod_free(demod);
    free(buf);

    return 0;
}

